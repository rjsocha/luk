package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"luk/internal/btrfs"
	"luk/internal/config"
	"luk/internal/jobchan"
	"luk/internal/runproto"
	"luk/internal/runstep"
	"luk/internal/wire"
)

// kind of a step that runs as a unit of lukd run.
type unitKind int

const (
	kindRun   unitKind = iota // run: <program> or run: {job}, out/ is the next set
	kindTee                   // run with tee: true, out/ must stay empty
	kindRelay                 // relay: <job>, out/ must stay empty
)

func (k unitKind) String() string {
	switch k {
	case kindTee:
		return "tee"
	case kindRelay:
		return "relay"
	}
	return "run"
}

// resultGap is the most a unit may stay silent after its status frame,
// or after its end while frames are still to be read.
var resultGap = jobchan.ResultGap

// place clones a result into out/ (btrfs.Place), replaced by tests.
var place = btrfs.Place

// unitStep runs step i+1 of p as a unit of lukd run on set in the work
// directory dir: it sends meta.json and the files of in/ over a channel
// of its own, relays the nested jobs the program asks for, and clones the
// results into out/ under temporary names. The pipeline timeout counts
// from the s frame: a wait for a unit slot is not work. It returns the
// next set (set itself for tee and relay) and the output tail.
func (d *Dispatcher) unitStep(j Job, p *config.Pipeline, step int, kind unitKind, set []file, dir string) ([]file, string, error) {
	out, logf, err := openWork(j, p, step, set, dir)
	if err != nil {
		return nil, "", err
	}
	w := &capWriter{f: logf, left: logCap}
	err = d.askUnit(j, p, step, kind, dir, out, w)
	if cerr := logf.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err == nil {
		err = w.err
	}
	if err != nil {
		return nil, w.tail(), err
	}
	if kind != kindRun {
		return set, w.tail(), nil
	}
	next, err := readOut(out)
	if err != nil {
		return nil, w.tail(), fmt.Errorf("out: %w", err)
	}
	return next, w.tail(), nil
}

// askUnit asks lukd run for the unit of the step, feeds it the work
// directory dir and receives its results into out; the output goes to w.
func (d *Dispatcher) askUnit(j Job, p *config.Pipeline, step int, kind unitKind, dir, out string, w io.Writer) error {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	m, names, err := runstep.ReadWork(r)
	r.Close()
	if err != nil {
		return err
	}
	outDir, err := os.Open(out)
	if err != nil {
		return err
	}
	defer outDir.Close()
	ch, remote, err := jobchan.Pair()
	if err != nil {
		return err
	}
	var closeRemote sync.Once
	defer closeRemote.Do(func() { remote.Close() })

	tok := d.units.wait()
	var started atomic.Bool
	defer func() { d.units.end(tok, started.Load()) }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var interrupted, timedOut atomic.Bool
	go func() {
		select {
		case <-d.stop:
			interrupted.Store(true)
			cancel()
		case <-ctx.Done():
		}
	}()

	var sender sync.WaitGroup
	var timer atomic.Pointer[time.Timer]
	timeout := stepTimeout(p)
	onStarted := func() {
		started.Store(true)
		d.units.start(tok)
		closeRemote.Do(func() { remote.Close() })
		timer.Store(time.AfterFunc(timeout, func() {
			timedOut.Store(true)
			cancel()
		}))
		sender.Add(1)
		go func() {
			defer sender.Done()
			sendInputs(ch, dir)
		}()
	}

	var ended atomic.Bool
	nj := d.nested(ctx, j, p, step, dir, m, ch)
	res := make(chan unitResult, 1)
	go func() { res <- d.readResults(ch, kind, outDir, &ended, nj) }()

	req := runproto.StepRequest{Pipeline: p.Name, Step: step, ID: j.Entry.ID, Env: runstep.StepMeta(m, names)}
	askErr := runproto.AskStep(ctx, d.RunSocket, req, remote, onStarted, w, w)
	if t := timer.Load(); t != nil {
		t.Stop()
	}
	closeRemote.Do(func() { remote.Close() })
	var ee runproto.ExitError
	if ctx.Err() != nil || askErr != nil && !errors.As(askErr, &ee) {
		// The exchange is over without the unit: what it may still send
		// does not count.
		ch.Close()
	} else {
		// The unit ended: what it sent is queued, and it sends nothing
		// more. The reader keeps the deadline for each further frame.
		ended.Store(true)
		ch.SetReadDeadline(time.Now().Add(resultGap))
	}
	u := <-res
	ch.Close()
	nj.wait()
	sender.Wait()

	switch {
	case interrupted.Load():
		return errInterrupted
	case timedOut.Load():
		return fmt.Errorf("timeout after %v", timeout)
	case u.status == nil && u.err != nil:
		return u.err
	case u.status == nil && askErr != nil:
		return askErr
	case u.status == nil:
		return errors.New("channel closed before the results")
	case *u.status != 0 && u.fail != "":
		return stepFailed(u.fail)
	case *u.status != 0:
		return runproto.ExitError(*u.status)
	case u.err != nil:
		return u.err
	}
	return askErr
}

// sendInputs sends meta.json of the work directory dir, then each file of
// its in/ in name order, then go. An error ends it quietly: the step
// result comes from the frames of the unit.
func sendInputs(ch *jobchan.Conn, dir string) {
	send := func(f jobchan.Frame, p string) error {
		fd, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer fd.Close()
		return ch.Send(f, fd)
	}
	if send(jobchan.Frame{T: jobchan.TMeta}, filepath.Join(dir, "meta.json")) != nil {
		return
	}
	ents, err := os.ReadDir(filepath.Join(dir, "in"))
	if err != nil {
		return
	}
	for _, e := range ents {
		if send(jobchan.Frame{T: jobchan.TIn, Name: e.Name()}, filepath.Join(dir, "in", e.Name())) != nil {
			return
		}
	}
	ch.Send(jobchan.Frame{T: jobchan.TGo}, nil)
}

// unitResult is what the channel of a unit brought: the status frame
// (nil without one), its fail text, and the first violation.
type unitResult struct {
	status *int
	fail   string
	err    error
}

// readResults owns the reads of ch: the frames of nested jobs (handed to
// nj) until the status frame, then the results up to end, each cloned
// into out under a temporary name. After a non-zero status or the first
// violation it only drops the frames up to end, so the wrapper ends as
// it would otherwise; a violation stops the nested job. It closes ch
// when it ends, so that a unit still sending fails at once. Once the
// status came or the unit ended (ended), every read waits at most
// resultGap: only the silence of the unit counts, not the time lukd
// takes to place a result.
func (d *Dispatcher) readResults(ch *jobchan.Conn, kind unitKind, out *os.File, ended *atomic.Bool, nj *nestedJobs) (u unitResult) {
	defer ch.Close()
	defer nj.end()
	seen := map[string]bool{}
	n := 0
	drop := false
	for {
		if u.status != nil || ended.Load() {
			ch.SetReadDeadline(time.Now().Add(resultGap))
		}
		f, fd, err := ch.Recv()
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
				// The wrapper reads no more: a nested job still
				// running is stopped without an answer.
				nj.end()
				u.status, u.fail = f.Status, f.Fail
				drop = *u.status != 0
			case jobchan.TJob, jobchan.TIn, jobchan.TGo, jobchan.TStop:
				err = nj.frame(f, fd)
			default:
				closeFile(fd)
				err = fmt.Errorf("unexpected frame %q", f.T)
			}
		default:
			switch f.T {
			case jobchan.TOut:
				n++
				err = placeResult(out, f.Name, fd, kind, n, seen)
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
			nj.stop()
		}
	}
}

// placeResult checks the n-th result name of a step of kind and clones
// it from fd into out.
func placeResult(out *os.File, name string, fd *os.File, kind unitKind, n int, seen map[string]bool) error {
	if n <= jobchan.MaxFiles && kind != kindRun {
		return fmt.Errorf("%s step wrote out/%s", kind, printableName(name))
	}
	if err := checkResult(name, fd, n, seen); err != nil {
		return err
	}
	if err := place(out, name, fd, 0o440, true); err != nil {
		return fmt.Errorf("out: %w", err)
	}
	return nil
}

// checkResult checks the n-th result name of a unit with its
// descriptor fd: at most jobchan.MaxFiles, a regular file, a valid name
// not seen before.
func checkResult(name string, fd *os.File, n int, seen map[string]bool) error {
	var st unix.Stat_t
	switch {
	case n > jobchan.MaxFiles:
		return fmt.Errorf("out: more than %d entries", jobchan.MaxFiles)
	case unix.Fstat(int(fd.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("out: %q: not a regular file", name)
	case !runstep.ValidName(name):
		return fmt.Errorf("out: %q: invalid name", name)
	case seen[name]:
		return fmt.Errorf("out: %q: sent twice", name)
	}
	seen[name] = true
	return nil
}

// printableName is name as it is when it holds no control character and
// fits a file name, else quoted: it comes from the unit unchecked.
func printableName(name string) string {
	if wire.HasControl(name) || len(name) > wire.MaxNameLen {
		return strconv.Quote(name)
	}
	return name
}

// formatGap is d as a step error names it: 1m, 90s as 1m30s, 200ms.
func formatGap(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	}
	return d.String()
}

func closeFile(f *os.File) {
	if f != nil {
		f.Close()
	}
}
