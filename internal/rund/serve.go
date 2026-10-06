package rund

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"luk/internal/config"
	"luk/internal/queue"
	"luk/internal/runproto"
	"luk/internal/runstep"
	"luk/internal/workspace"
)

// Runner starts and stops the transient units.
type Runner interface {
	// Run runs argv to the end with stdin (nil: /dev/null) and returns its
	// exit status; err means it could not run. Run may close stdin once
	// argv started, which then holds it.
	Run(ctx context.Context, argv []string, stdin *os.File, stdout, stderr io.Writer) (int, error)
	// Stop stops the unit.
	Stop(unit string) error
	// Active reports whether the unit is still running or has a job
	// pending; a unit that is not loaded is not active.
	Active(unit string) (bool, error)
}

// Server handles one connection.
type Server struct {
	Config string
	Jobs   string
	// Locks is the RuntimeDirectory of lukd-run@: the state locks of the
	// jobs with `state: locked`, the unit slots (slot/<n>.lock) and the
	// workspace locks; empty means DefaultLocks.
	Locks string
	// Owner must own the config, run.d and its files and the lukd
	// configuration (root), and every directory above them from Top (/
	// when empty) down.
	Owner uint32
	Top   string
	// Lukd is the lukd binary: the wrapper and ExecStartPre of every unit
	// and the helper units that create and remove the workspaces.
	Lukd string
	// PeerUID returns the uid of the connected process.
	PeerUID func() (uint32, error)
	Runner  Runner
	Log     *slog.Logger
}

type refusal struct{ error }

// DefaultLocks is the RuntimeDirectory= of lukd-run@.service, shared by
// its instances and kept between them.
const DefaultLocks = "/run/lukd-run"

var (
	// lockPoll is how often a run waiting for its state lock or a unit
	// slot retries.
	lockPoll = 250 * time.Millisecond
	// activePoll is how often a stopped run checks whether its unit
	// became inactive.
	activePoll = 250 * time.Millisecond
	// stopGrace is how long past the unit timeout a stopped run waits for
	// its unit to become inactive.
	stopGrace = 2 * time.Minute
	// requestTimeout bounds receiving the request, writing the started
	// frame and answering a refusal.
	requestTimeout = 5 * time.Second
	// helperTimeout bounds a create or remove helper: its RuntimeMaxSec
	// plus a minute for systemd to end it.
	helperTimeout = workspace.HelperTimeout + time.Minute
)

// errPeerData is the protocol error of a peer that sends anything after
// its request.
var errPeerData = errors.New("peer sent data after its request")

// errNotCreated is the refusal of a step whose workspace was not created;
// the reason goes to the journal.
var errNotCreated = errors.New("workspace not created")

// Serve runs the step request of conn: the peer check, the request, the
// unit slot, the workspace, the unit. Receiving the request and answering
// a refusal must end within requestTimeout, the unit with its output
// within its timeout plus stopGrace, so a peer that stops sending or
// reading cannot hold the connection; the wait for a slot or a state lock
// has no deadline.
func (s *Server) Serve(conn *net.UnixConn) error {
	// A missing directory of run.yaml is a missing run.yaml: the
	// defaults.
	if err := CheckParents(filepath.Dir(s.Config), s.Top, s.Owner); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: %w", s.Config, err)
	}
	g, err := LoadGlobal(s.Config, s.Owner)
	if err != nil {
		return err
	}
	want, err := g.ServiceUID()
	if err != nil {
		return fmt.Errorf("service user: %w", err)
	}
	got, err := s.PeerUID()
	if err != nil {
		return fmt.Errorf("peer: %w", err)
	}
	if got != want {
		return fmt.Errorf("peer uid %d refused, want %d", got, want)
	}
	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	fw := runproto.NewFrameWriter(conn)
	err = s.serve(g, conn, fw)
	var r refusal
	if errors.As(err, &r) {
		conn.SetWriteDeadline(time.Now().Add(requestTimeout))
		io.WriteString(fw.Stream(runproto.Stderr), "lukd run: "+r.Error()+"\n")
		fw.Exit(1)
	}
	return err
}

func (s *Server) serve(g *Global, conn *net.UnixConn, fw *runproto.FrameWriter) error {
	req, ch, err := runproto.ReadStepRequest(conn)
	if err != nil {
		return refusal{err}
	}
	// Run closes it once the unit holds it; this covers every other way
	// out.
	defer ch.Close()
	if !config.ValidPipelineName(req.Pipeline) {
		return refusal{fmt.Errorf("pipeline %q: invalid name", req.Pipeline)}
	}
	if !queue.IsID(req.ID) {
		return refusal{fmt.Errorf("id %q: not a queue entry id", req.ID)}
	}
	if req.Job != "" && !config.ValidJobName(req.Job) {
		return refusal{fmt.Errorf("job %q: unknown", req.Job)}
	}
	u, lk, err := s.what(g, req)
	if err != nil {
		return err
	}
	box := &Box{Root: g.Root, Config: filepath.Dir(g.Config), Hide: slices.Concat(g.Hide, lk.Paths), Lukd: s.Lukd}
	ws := u.Workspace(box)
	// The step-bound variables come from the checked request, the
	// workspace-bound ones from run.yaml, the free-form metadata from the
	// request after CleanStepMeta.
	argv, err := u.Argv(box, runstep.UnitVars(ws, req.ID, req.Pipeline, req.Step, req.Env))
	if err != nil {
		s.Log.Error("unit refused", append(u.attrs(), "err", err)...)
		return refusal{fmt.Errorf("%s: unavailable", u.what())}
	}

	// No deadline while waiting for a slot or the state lock: the wait
	// ends with the run holding it, or when the peer closes.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	gone, spoke := watch(conn)
	// A nested job runs inside a step that holds a slot.
	if req.Job == "" {
		free, err := s.slot(g.Limits.Units.Max, gone)
		if errors.Is(err, errGone) {
			return s.left(u, "a unit slot", spoke)
		}
		if err != nil {
			s.Log.Error("unit slot", append(u.attrs(), "err", err)...)
			return refusal{fmt.Errorf("%s: unit slot unavailable", u.what())}
		}
		defer free()
	}
	if err := conn.SetWriteDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	if err := fw.Started(); err != nil {
		return err
	}
	if u.State == StateLocked {
		unlock, err := s.lock(u.Job, u.Pipeline, gone)
		if errors.Is(err, errGone) {
			return s.left(u, "the state lock", spoke)
		}
		if err != nil {
			s.Log.Error("state lock", append(u.attrs(), "err", err)...)
			return refusal{fmt.Errorf("job %s: state lock unavailable", u.Job)}
		}
		defer unlock()
	}

	// The lock keeps prune away from the workspace from before its
	// creation until after its removal.
	hold, err := workspace.Hold(s.locks(), u.Name)
	if err != nil {
		s.Log.Error("workspace lock", append(u.attrs(), "err", err)...)
		return refusal{errNotCreated}
	}
	defer func() {
		if err := hold.Release(); err != nil {
			s.Log.Warn("workspace lock not released", "unit", u.Name, "err", err)
		}
	}()
	code, err := s.helper(g.Root, "create", u.Name)
	if err != nil || code != 0 {
		s.Log.Error("workspace not created", "unit", u.Name, "exit", code, "err", err)
		return refusal{errNotCreated}
	}

	attrs := append(u.attrs(), "user", cmp.Or(u.User, u.Dynamic), "workspace", ws)
	if u.State != "" {
		attrs = append(attrs, "state", u.State)
	}
	s.Log.Info("job start", attrs...)
	// The unit ends by RuntimeMaxSec=timeout; past stopGrace more a peer
	// that does not read fails the writes and reads as gone.
	if err := conn.SetDeadline(time.Now().Add(u.Timeout + stopGrace)); err != nil {
		return err
	}
	settled, err := s.run(u, argv, ch, fw, gone, spoke)
	if settled {
		s.remove(g.Root, u.Name)
	} else {
		s.Log.Warn("unit still active: workspace left to prune, unit slot and state lock released", u.attrs()...)
	}
	return err
}

// run runs the unit u by argv with the channel ch as its stdin and its
// output as frames of fw, and writes its exit frame. When gone closes
// first, it stops the unit and waits until it is inactive. settled is
// false when the unit may still be active.
func (s *Server) run(u *Unit, argv []string, ch *os.File, fw *runproto.FrameWriter, gone <-chan struct{}, spoke func() bool) (settled bool, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := s.Runner.Run(ctx, argv, ch, fw.Stream(runproto.Stdout), fw.Stream(runproto.Stderr))
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			s.Log.Error("job failed to start", append(u.attrs(), "err", r.err)...)
			return true, refusal{fmt.Errorf("%s: %v", u.what(), r.err)}
		}
		s.Log.Info("job end", append(u.attrs(), "exit", r.code)...)
		return true, fw.Exit(r.code)
	case <-gone:
		var perr error
		if spoke() {
			perr = errPeerData
			s.Log.Warn("peer sent data during the run, stopping the job", u.attrs()...)
		} else {
			s.Log.Warn("peer closed, stopping the job", u.attrs()...)
		}
		err := s.Runner.Stop(u.Name)
		cancel()
		<-done
		if err := s.settle(u.Job, u.Name, err, time.Now().Add(u.Timeout+stopGrace)); err != nil {
			return false, errors.Join(perr, err)
		}
		return true, perr
	}
}

// left is the end of a step whose peer left while it waited for what: a
// close is no error, a byte from the peer is errPeerData.
func (s *Server) left(u *Unit, what string, spoke func() bool) error {
	if spoke() {
		s.Log.Warn("peer sent data while waiting for "+what, u.attrs()...)
		return errPeerData
	}
	s.Log.Warn("peer closed while waiting for "+what, u.attrs()...)
	return nil
}

// helper runs the helper unit of action on unit, bounded by
// helperTimeout.
func (s *Server) helper(root, action, unit string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()
	return s.Runner.Run(ctx, workspace.HelperArgv(s.Lukd, root, action, unit), nil, io.Discard, io.Discard)
}

// remove runs the remove helper of unit. A failure is logged and changes
// nothing else: the helper counts the workspace it leaves.
func (s *Server) remove(root, unit string) {
	code, err := s.helper(root, "remove", unit)
	if err != nil || code != 0 {
		s.Log.Warn("workspace not removed", "unit", unit, "exit", code, "err", err)
	}
}

// watch reads conn until the peer closes it, sends a byte (a protocol
// error: the peer only reads once its request is sent) or a read deadline
// passes, then closes gone; spoke, once gone closed, reports whether the
// peer sent a byte.
func watch(conn *net.UnixConn) (gone <-chan struct{}, spoke func() bool) {
	c := make(chan struct{})
	var n int
	go func() {
		var b [1]byte
		n, _ = conn.Read(b[:])
		close(c)
	}()
	return c, func() bool {
		<-c
		return n > 0
	}
}

// what names u in a refusal: the job, or the step of a run program.
func (u *Unit) what() string {
	if u.Job != "" {
		return "job " + u.Job
	}
	return fmt.Sprintf("pipeline %s step %d", u.Pipeline, u.Step)
}

// attrs are the journal attributes of u: the job of a job, the unit, the
// pipeline and the step.
func (u *Unit) attrs() []any {
	var a []any
	if u.Job != "" {
		a = append(a, "job", u.Job)
	}
	return append(a, "unit", u.Name, "pipeline", u.Pipeline, "step", u.Step)
}

// settle returns once unit, whose stop gave err and whose systemd-run has
// ended, is inactive, so the state lock and the workspace go only with the
// unit. A failed stop (the unit not loaded yet when it ran) is retried;
// then the unit is polled until it is inactive, at most until deadline
// (the unit timeout plus stopGrace: RuntimeMaxSec ends the unit by then).
func (s *Server) settle(job, unit string, err error, deadline time.Time) error {
	if err != nil {
		s.Log.Warn("stop failed, stopping again", "job", job, "unit", unit, "err", err)
		if err = s.Runner.Stop(unit); err != nil {
			s.Log.Warn("stop failed", "job", job, "unit", unit, "err", err)
		}
	}
	for {
		active, aerr := s.Runner.Active(unit)
		if aerr == nil && !active {
			return nil
		}
		if time.Now().After(deadline) {
			if aerr == nil {
				aerr = errors.New("still active")
			}
			return errors.Join(err, fmt.Errorf("unit %s: %w", unit, aerr))
		}
		time.Sleep(activePoll)
	}
}

var errGone = errors.New("peer closed")

func (s *Server) locks() string { return cmp.Or(s.Locks, DefaultLocks) }

// slot takes a unit slot, the exclusive lock of one of
// <Locks>/slot/1.lock to <max>.lock, trying all of them every lockPoll
// until one is free or gone closes. The slot lasts until free or the end
// of the process.
func (s *Server) slot(max int, gone <-chan struct{}) (free func(), err error) {
	dir := filepath.Join(s.locks(), "slot")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for {
		for n := 1; n <= max; n++ {
			f, err := tryFlock(filepath.Join(dir, strconv.Itoa(n)+".lock"))
			if err != nil {
				return nil, err
			}
			if f != nil {
				return func() { f.Close() }, nil
			}
		}
		select {
		case <-gone:
			return nil, errGone
		case <-time.After(lockPoll):
		}
	}
}

// lock takes the exclusive lock of job on pipeline,
// <Locks>/<job>/<pipeline>.lock, waiting until it is free or gone closes.
// The lock lasts until unlock or the end of the process.
func (s *Server) lock(job, pipeline string, gone <-chan struct{}) (unlock func(), err error) {
	dir := filepath.Join(s.locks(), job)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for {
		f, err := tryFlock(filepath.Join(dir, pipeline+".lock"))
		if err != nil {
			return nil, err
		}
		if f != nil {
			return func() { f.Close() }, nil
		}
		select {
		case <-gone:
			return nil, errGone
		case <-time.After(lockPoll):
		}
	}
}

// tryFlock opens the lock file p (created 0600, not following a symlink)
// and takes its exclusive lock without waiting; nil, nil while another
// process holds it.
func tryFlock(p string) (*os.File, error) {
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return f, nil
	}
	f.Close()
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
		return nil, nil
	}
	return nil, fmt.Errorf("flock %s: %w", p, err)
}

// Systemd runs the units with systemd-run and stops them with systemctl.
type Systemd struct{}

func (Systemd) Run(ctx context.Context, argv []string, stdin *os.File, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Start()
	// systemd-run holds stdin now and passes it on to the unit; an end
	// kept here would keep the channel open after the unit ended.
	if stdin != nil {
		stdin.Close()
	}
	if err == nil {
		err = cmd.Wait()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func (Systemd) Stop(unit string) error {
	out, err := exec.Command("systemctl", "stop", unit+".service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop %s: %v: %s", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (Systemd) Active(unit string) (bool, error) {
	out, err := exec.Command("systemctl", "show", "-p", "ActiveState", "-p", "Job", unit+".service").Output()
	if err != nil {
		return false, fmt.Errorf("systemctl show %s: %v", unit, err)
	}
	return unitActive(string(out))
}

// unitActive reads the ActiveState and Job of systemctl show: active
// unless inactive or failed with no job pending.
func unitActive(show string) (bool, error) {
	state, job := "", ""
	for _, l := range strings.Split(show, "\n") {
		if v, ok := strings.CutPrefix(l, "ActiveState="); ok {
			state = v
		} else if v, ok := strings.CutPrefix(l, "Job="); ok {
			job = v
		}
	}
	switch state {
	case "":
		return false, fmt.Errorf("no ActiveState in %q", show)
	case "inactive", "failed":
		return job != "", nil
	}
	return true, nil
}
