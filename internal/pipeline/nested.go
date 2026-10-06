package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"luk/internal/config"
	"luk/internal/jobchan"
	"luk/internal/runproto"
	"luk/internal/runstep"
)

// maxOutChunk caps the data of an o or e frame to the wrapper: base64
// keeps the packet under jobchan.MaxPacket.
const maxOutChunk = 32 << 10

// nestedJobs relays the nested jobs of one step (luk-job run of its
// program), one at a time, between the channel of its unit and lukd run.
// The reader of the channel hands it the job, in, go and stop frames
// that come before the status frame; all its methods are called by that
// reader, only run works on its own.
type nestedJobs struct {
	d    *Dispatcher
	ctx  context.Context
	j    Job
	p    *config.Pipeline
	step int
	dir  string
	meta runstep.WorkMeta
	ch   *jobchan.Conn
	req  *nestedReq // the last request, nil before the first
}

// nested is the relay of the nested jobs of step of p, whose program
// talks over ch, on the work directory dir with meta.json m.
func (d *Dispatcher) nested(ctx context.Context, j Job, p *config.Pipeline, step int, dir string, m runstep.WorkMeta, ch *jobchan.Conn) *nestedJobs {
	return &nestedJobs{d: d, ctx: ctx, j: j, p: p, step: step, dir: dir, meta: m, ch: ch}
}

// nestedReq is one request: its job frame, its in frames up to go and,
// once answered (exit or refused sent, or the step no longer listens),
// nothing more sent for it.
type nestedReq struct {
	job     string
	ins     []nestedIn // owned by run after go
	n       int        // in frames seen
	names   map[string]bool
	gone    bool // go came
	stopped bool // stop came
	refused bool
	cancel  context.CancelFunc // of the job, set at go
	done    chan struct{}      // closed when run ended

	mu       sync.Mutex
	answered bool
}

type nestedIn struct {
	name string
	fd   *os.File
}

// send sends f for r unless r is answered; exit and refused answer it.
func (r *nestedReq) send(ch *jobchan.Conn, f jobchan.Frame, fd *os.File) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.answered {
		return errors.New("nested job answered")
	}
	if f.T == jobchan.TExit || f.T == jobchan.TRefused {
		r.answered = true
	}
	return ch.Send(f, fd)
}

func (r *nestedReq) isAnswered() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.answered
}

// silence answers r without a frame: the wrapper reads no more.
func (r *nestedReq) silence() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answered = true
}

func (r *nestedReq) closeIns() {
	for _, in := range r.ins {
		in.fd.Close()
	}
	r.ins = nil
}

// frame takes one nested frame of the wrapper, with its descriptor. A
// violation of the protocol (a frame out of order, an invalid input, a
// second job while one runs) is returned and fails the step. Every
// frame is checked, also those of a refused request, which are then
// dropped. A send error is left to the reads of the channel.
func (n *nestedJobs) frame(f jobchan.Frame, fd *os.File) error {
	r := n.req
	if f.T == jobchan.TJob {
		if r != nil && !r.isAnswered() {
			return fmt.Errorf("nested job %s while job %s runs", f.Job, r.job)
		}
		if r != nil && r.done != nil {
			<-r.done
		}
		r = &nestedReq{job: f.Job, names: map[string]bool{}}
		n.req = r
		if !slices.Contains(n.p.Steps[n.step-1].Jobs, f.Job) {
			r.refused = true
			reason := fmt.Sprintf("job %s: not allowed for pipeline %s step %d", f.Job, n.p.Name, n.step)
			r.send(n.ch, jobchan.Frame{T: jobchan.TRefused, Reason: reason}, nil)
		}
		return nil
	}
	if r == nil || (f.T == jobchan.TIn || f.T == jobchan.TGo) && (r.gone || r.stopped) || f.T == jobchan.TStop && r.stopped {
		closeFile(fd)
		return fmt.Errorf("unexpected frame %q", f.T)
	}
	switch f.T {
	case jobchan.TIn:
		if err := r.checkIn(f.Name, fd); err != nil {
			fd.Close()
			return err
		}
		if r.refused {
			fd.Close()
			return nil
		}
		r.ins = append(r.ins, nestedIn{f.Name, fd})
	case jobchan.TGo:
		r.gone = true
		if !r.refused {
			n.start(r)
		}
	case jobchan.TStop:
		r.stopped = true
		switch {
		case r.cancel != nil:
			// run answers exit 1.
			r.cancel()
		case !r.isAnswered():
			r.closeIns()
			r.send(n.ch, jobchan.Frame{T: jobchan.TExit, Status: jobchan.Status(1)}, nil)
		}
	default:
		closeFile(fd)
		return fmt.Errorf("unexpected frame %q", f.T)
	}
	return nil
}

// checkIn checks the next in frame of r: at most jobchan.MaxFiles, valid
// and distinct names, regular files.
func (r *nestedReq) checkIn(name string, fd *os.File) error {
	r.n++
	var st unix.Stat_t
	switch {
	case r.n > jobchan.MaxFiles:
		return fmt.Errorf("job %s: more than %d inputs", r.job, jobchan.MaxFiles)
	case !runstep.ValidName(name):
		return fmt.Errorf("job %s: in: %q: invalid name", r.job, name)
	case r.names[name]:
		return fmt.Errorf("job %s: in: %q: sent twice", r.job, name)
	case unix.Fstat(int(fd.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("job %s: in: %q: not a regular file", r.job, name)
	}
	r.names[name] = true
	return nil
}

// start runs the job of r on its own.
func (n *nestedJobs) start(r *nestedReq) {
	ctx, cancel := context.WithCancel(n.ctx)
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		defer cancel()
		n.run(ctx, r)
	}()
}

// stop stops the running job, which answers exit 1.
func (n *nestedJobs) stop() {
	if r := n.req; r != nil && r.cancel != nil {
		r.cancel()
	}
}

// end stops the running job and answers nothing more: the wrapper sent
// its status (it reads no more) or the channel is over.
func (n *nestedJobs) end() {
	r := n.req
	if r == nil {
		return
	}
	r.silence()
	if r.cancel != nil {
		r.cancel()
	} else {
		r.closeIns()
	}
}

// wait waits for the end of the running job, after end.
func (n *nestedJobs) wait() {
	if r := n.req; r != nil && r.done != nil {
		<-r.done
	}
}

// run asks lukd run for the job of r and answers exit with its status: 1
// when it was stopped (ctx), when lukd run or its channel failed.
func (n *nestedJobs) run(ctx context.Context, r *nestedReq) {
	status := n.ask(ctx, r)
	if ctx.Err() != nil {
		status = 1
	}
	r.send(n.ch, jobchan.Frame{T: jobchan.TExit, Status: jobchan.Status(status)}, nil)
}

// ask runs the job of r as askUnit runs a step: the inputs are the in
// frames of r, else the set of the step (opened fresh), and meta.json of
// the step; its output goes to the wrapper as o and e frames, its results
// as out frames with their descriptors. It returns the exit status; an
// error is written as an e frame and gives 1.
func (n *nestedJobs) ask(ctx context.Context, r *nestedReq) int {
	ins := r.ins
	defer func() {
		for _, in := range ins {
			in.fd.Close()
		}
	}()
	errw := frameWriter{r: r, ch: n.ch, t: jobchan.TStderr}
	fail := func(err error) int {
		if ctx.Err() == nil {
			fmt.Fprintf(errw, "lukd: job %s: %v\n", r.job, err)
		}
		return 1
	}
	if len(ins) == 0 {
		var err error
		if ins, err = openSet(n.dir); err != nil {
			return fail(err)
		}
	}
	var regular []string
	for _, in := range ins {
		regular = append(regular, in.name)
	}

	nch, remote, err := jobchan.Pair()
	if err != nil {
		return fail(err)
	}
	var closeRemote sync.Once
	defer closeRemote.Do(func() { remote.Close() })
	var sender sync.WaitGroup
	onStarted := func() {
		closeRemote.Do(func() { remote.Close() })
		sender.Add(1)
		go func() {
			defer sender.Done()
			sendNestedInputs(nch, n.dir, ins)
		}()
	}
	var ended atomic.Bool
	res := make(chan unitResult, 1)
	go func() { res <- n.readNested(nch, r, &ended) }()

	req := runproto.StepRequest{Pipeline: n.p.Name, Step: n.step, ID: n.j.Entry.ID, Job: r.job,
		Env: runstep.StepMeta(n.meta, runstep.SetNames(regular))}
	outw := frameWriter{r: r, ch: n.ch, t: jobchan.TStdout}
	askErr := runproto.AskStep(ctx, n.d.RunSocket, req, remote, onStarted, outw, errw)
	closeRemote.Do(func() { remote.Close() })
	var ee runproto.ExitError
	if ctx.Err() != nil || askErr != nil && !errors.As(askErr, &ee) {
		nch.Close()
	} else {
		ended.Store(true)
		nch.SetReadDeadline(time.Now().Add(resultGap))
	}
	u := <-res
	nch.Close()
	sender.Wait()

	exited := errors.As(askErr, &ee)
	switch {
	case ctx.Err() != nil:
		return 1
	case askErr != nil && !exited:
		return fail(askErr)
	case u.err != nil:
		fail(u.err)
		if exited {
			return int(ee)
		}
		return 1
	case exited:
		return int(ee)
	case u.status == nil:
		return fail(errors.New("channel closed before the results"))
	}
	return 0
}

// openSet opens the files of in/ of the work directory dir, the input
// set of the step.
func openSet(dir string) ([]nestedIn, error) {
	ents, err := os.ReadDir(filepath.Join(dir, "in"))
	if err != nil {
		return nil, err
	}
	var ins []nestedIn
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		fd, err := os.OpenFile(filepath.Join(dir, "in", e.Name()), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			for _, in := range ins {
				in.fd.Close()
			}
			return nil, err
		}
		ins = append(ins, nestedIn{e.Name(), fd})
	}
	return ins, nil
}

// sendNestedInputs sends meta.json of the work directory dir, then ins,
// each closed once sent, then go. An error ends it quietly: the result
// comes from the frames of the job.
func sendNestedInputs(ch *jobchan.Conn, dir string, ins []nestedIn) {
	meta, err := os.OpenFile(filepath.Join(dir, "meta.json"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	err = ch.Send(jobchan.Frame{T: jobchan.TMeta}, meta)
	meta.Close()
	if err != nil {
		return
	}
	for _, in := range ins {
		err := ch.Send(jobchan.Frame{T: jobchan.TIn, Name: in.name}, in.fd)
		in.fd.Close()
		if err != nil {
			return
		}
	}
	ch.Send(jobchan.Frame{T: jobchan.TGo}, nil)
}

// readNested reads the channel of the job of r, as readResults reads that
// of a step: the status frame, then the results up to end, each passed on
// to the wrapper as an out frame with its descriptor. A nested job of the
// job itself is refused. After a non-zero status or the first violation
// it only drops the frames up to end.
func (n *nestedJobs) readNested(nch *jobchan.Conn, r *nestedReq, ended *atomic.Bool) (u unitResult) {
	defer nch.Close()
	seen := map[string]bool{}
	count := 0
	drop := false
	for {
		if u.status != nil || ended.Load() {
			nch.SetReadDeadline(time.Now().Add(resultGap))
		}
		f, fd, err := nch.Recv()
		var ne net.Error
		switch {
		case drop && err != nil:
			return u
		case u.status == nil && (errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)):
			return u
		case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
			u.err = errors.New("channel closed before the results")
			return u
		case errors.As(err, &ne) && ne.Timeout():
			u.err = fmt.Errorf("no result for %s", formatGap(resultGap))
			return u
		case err != nil:
			u.err = err
			return u
		}
		switch {
		case drop:
			closeFile(fd)
			if f.T == jobchan.TEnd {
				return u
			}
			continue
		case u.status == nil:
			switch f.T {
			case jobchan.TStatus:
				u.status = f.Status
				drop = *u.status != 0
			case jobchan.TJob:
				nch.Send(jobchan.Frame{T: jobchan.TRefused, Reason: "a nested job runs no nested jobs"}, nil)
			case jobchan.TIn, jobchan.TGo, jobchan.TStop:
				// The rest of the refused request.
				closeFile(fd)
			default:
				closeFile(fd)
				err = fmt.Errorf("unexpected frame %q", f.T)
			}
		default:
			switch f.T {
			case jobchan.TOut:
				count++
				err = checkResult(f.Name, fd, count, seen)
				if err == nil {
					err = r.send(n.ch, jobchan.Frame{T: jobchan.TOut, Name: f.Name}, fd)
				}
				fd.Close()
			case jobchan.TRefuse:
				err = fmt.Errorf("out: %q: %s", f.Name, runstep.FailText([]byte(f.Reason)))
			case jobchan.TEnd:
				return u
			default:
				closeFile(fd)
				err = fmt.Errorf("unexpected frame %q", f.T)
			}
		}
		if err != nil {
			u.err = err
			drop = true
		}
	}
}

// frameWriter writes to the wrapper as frames of type t for r, in chunks
// of at most maxOutChunk bytes.
type frameWriter struct {
	r  *nestedReq
	ch *jobchan.Conn
	t  string
}

func (w frameWriter) Write(p []byte) (int, error) {
	for done := 0; done < len(p); {
		k := min(len(p)-done, maxOutChunk)
		if err := w.r.send(w.ch, jobchan.Frame{T: w.t, Data: p[done : done+k]}, nil); err != nil {
			return done, err
		}
		done += k
	}
	return len(p), nil
}
