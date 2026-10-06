package rund

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"luk/internal/config"
	"luk/internal/queue"
	"luk/internal/runproto"
	"luk/internal/runstep"
)

// Runner starts and stops the transient units.
type Runner interface {
	// Run runs argv to the end and returns its exit status; err means it
	// could not run.
	Run(ctx context.Context, argv []string, stdout, stderr io.Writer) (int, error)
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
	// Locks holds the lock files of the jobs with `state: locked`; empty
	// means DefaultLocks.
	Locks string
	// Owner must own the config, run.d and its files (root).
	Owner uint32
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
	// lockPoll is how often a run waiting for its state lock retries.
	lockPoll = 250 * time.Millisecond
	// activePoll is how often a stopped run checks whether its unit
	// became inactive.
	activePoll = 250 * time.Millisecond
	// stopGrace is how long past the job timeout a stopped run waits for
	// its unit to become inactive.
	stopGrace = 2 * time.Minute
)

// Serve runs the request of conn: the peer check, the request, the job.
func (s *Server) Serve(conn io.ReadWriter) error {
	g, err := LoadGlobal(s.Config, s.Owner)
	if err != nil {
		return err
	}
	want, err := g.PeerUID()
	if err != nil {
		return err
	}
	got, err := s.PeerUID()
	if err != nil {
		return fmt.Errorf("peer: %w", err)
	}
	if got != want {
		return fmt.Errorf("peer uid %d refused, want %d", got, want)
	}
	fw := runproto.NewFrameWriter(conn)
	br := bufio.NewReaderSize(conn, runproto.MaxRequest)
	err = s.serve(g, got, br, fw)
	var r refusal
	if errors.As(err, &r) {
		io.WriteString(fw.Stream(runproto.Stderr), "lukd run: "+r.Error()+"\n")
		fw.Exit(1)
	}
	return err
}

func (s *Server) serve(g *Global, peer uint32, br *bufio.Reader, fw *runproto.FrameWriter) error {
	req, err := runproto.ReadRequest(br)
	if err != nil {
		return refusal{err}
	}
	if !config.ValidJobName(req.Job) {
		return refusal{fmt.Errorf("job %q: unknown", req.Job)}
	}
	jobs, err := LoadJobs(s.Jobs, s.Owner)
	if err != nil {
		s.Log.Error("run.d refused", "err", err)
		return refusal{fmt.Errorf("job %s: unavailable", req.Job)}
	}
	job, ok := jobs.OK[req.Job]
	if !ok {
		if e := jobs.Bad[req.Job]; e != nil {
			s.Log.Error("job refused", "job", req.Job, "err", e)
			return refusal{fmt.Errorf("job %s: invalid, see the journal of lukd-run@.service", req.Job)}
		}
		return refusal{fmt.Errorf("job %q: unknown", req.Job)}
	}
	work, pipeline, gid, err := CheckWork(g.Root, req.Work, peer)
	if err != nil {
		return refusal{err}
	}
	vars, err := JobEnv(g.Root, work, peer)
	if err != nil {
		return refusal{err}
	}
	unit := UnitName(req.Job)
	argv := job.Argv(unit, req.Job, pipeline, work, GroupName(gid), vars)
	who := job.User
	if who == "" {
		who = DynamicUser(req.Job, pipeline)
	}

	gone := make(chan struct{})
	go func() {
		io.Copy(io.Discard, br)
		close(gone)
	}()
	if job.State == StateLocked {
		unlock, err := s.lock(req.Job, pipeline, gone)
		if errors.Is(err, errGone) {
			s.Log.Warn("peer closed while waiting for the state lock", "job", req.Job, "pipeline", pipeline)
			return nil
		}
		if err != nil {
			s.Log.Error("state lock", "job", req.Job, "pipeline", pipeline, "err", err)
			return refusal{fmt.Errorf("job %s: state lock unavailable", req.Job)}
		}
		defer unlock()
	}
	attrs := []any{"job", req.Job, "unit", unit, "user", who, "work", work, "pipeline", pipeline}
	if job.State != "" {
		attrs = append(attrs, "state", job.State)
	}
	s.Log.Info("job start", attrs...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := s.Runner.Run(ctx, argv, fw.Stream(runproto.Stdout), fw.Stream(runproto.Stderr))
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			s.Log.Error("job failed to start", "job", req.Job, "unit", unit, "err", r.err)
			return refusal{fmt.Errorf("job %s: %v", req.Job, r.err)}
		}
		s.Log.Info("job end", "job", req.Job, "unit", unit, "exit", r.code)
		return fw.Exit(r.code)
	case <-gone:
		s.Log.Warn("peer closed, stopping the job", "job", req.Job, "unit", unit)
		err := s.Runner.Stop(unit)
		cancel()
		<-done
		return s.settle(req.Job, unit, err, time.Now().Add(time.Duration(job.Timeout)+stopGrace))
	}
}

// settle returns once unit, whose stop gave err and whose systemd-run has
// ended, is inactive, so the state lock goes only with the job. A failed
// stop (the unit not loaded yet when it ran) is retried; then the unit is
// polled until it is inactive, at most until deadline (the job timeout
// plus stopGrace: RuntimeMaxSec ends the job by then).
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

// lock takes the exclusive lock of job on pipeline,
// <Locks>/<job>/<pipeline>.lock, waiting until it is free or gone closes.
// The lock lasts until unlock or the end of the process.
func (s *Server) lock(job, pipeline string, gone <-chan struct{}) (unlock func(), err error) {
	base := s.Locks
	if base == "" {
		base = DefaultLocks
	}
	dir := filepath.Join(base, job)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, pipeline+".lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, fmt.Errorf("flock %s: %w", f.Name(), err)
		}
		select {
		case <-gone:
			f.Close()
			return nil, errGone
		case <-time.After(lockPoll):
		}
	}
}

// CheckWork resolves work and requires a step work directory
// <root>/work/<id>/<pipeline>/<step> owned by uid: <id> a queue entry id,
// <pipeline> a valid pipeline name, <step> a step number, and no control
// character, white space, "$" or "%" anywhere in the resolved path, which
// goes into the systemd-run command line and the unit file. It returns the
// resolved path, the pipeline name and the gid of the directory.
func CheckWork(root, work string, uid uint32) (string, string, uint32, error) {
	if !filepath.IsAbs(work) {
		return "", "", 0, fmt.Errorf("work %q: not absolute", work)
	}
	base, err := filepath.EvalSymlinks(filepath.Join(root, "work"))
	if err != nil {
		return "", "", 0, fmt.Errorf("work: %w", err)
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(work))
	if err != nil {
		return "", "", 0, fmt.Errorf("work %q: %w", work, err)
	}
	rel, ok := strings.CutPrefix(real, base+string(filepath.Separator))
	if !ok {
		return "", "", 0, fmt.Errorf("work %q: not under %s", work, base)
	}
	if strings.ContainsFunc(real, unsafePathRune) {
		return "", "", 0, fmt.Errorf("work %q: control character, white space, $ or %% in the path", work)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 3 || !queue.IsID(parts[0]) || !config.ValidPipelineName(parts[1]) || !isStep(parts[2]) {
		return "", "", 0, fmt.Errorf("work %q: not a step work directory %s/<id>/<pipeline>/<step>", work, base)
	}
	fi, err := os.Lstat(real)
	if err != nil {
		return "", "", 0, err
	}
	if !fi.IsDir() {
		return "", "", 0, fmt.Errorf("work %q: not a directory", work)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != uid {
		return "", "", 0, fmt.Errorf("work %q: owned by uid %d, not the peer", work, st.Uid)
	}
	return real, parts[1], st.Gid, nil
}

// JobEnv is the LUK_* metadata environment (runstep.Env) of work, a step
// work directory accepted by CheckWork, with root as LUK_ROOT. The
// directory must still be owned by uid when opened; its meta.json is read
// with runstep.ReadWork and must name the id, the pipeline and the step of
// the path.
func JobEnv(root, work string, uid uint32) ([]string, error) {
	r, err := os.OpenRoot(work)
	if err != nil {
		return nil, fmt.Errorf("work %q: %w", work, err)
	}
	defer r.Close()
	fi, err := r.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("work %q: %w", work, err)
	}
	if st := fi.Sys().(*syscall.Stat_t); !fi.IsDir() || st.Uid != uid {
		return nil, fmt.Errorf("work %q: not a directory owned by the peer", work)
	}
	m, names, err := runstep.ReadWork(r)
	if err != nil {
		return nil, fmt.Errorf("work %q: %w", work, err)
	}
	step := filepath.Base(work)
	pipeline := filepath.Base(filepath.Dir(work))
	id := filepath.Base(filepath.Dir(filepath.Dir(work)))
	if m.Server.ID != id || m.Pipeline != pipeline || strconv.Itoa(m.Step) != step {
		return nil, fmt.Errorf("work %q: meta.json names id %q, pipeline %q, step %d, not those of the path", work, m.Server.ID, m.Pipeline, m.Step)
	}
	return runstep.Env(work, root, m, names), nil
}

// unsafePathRune reports a rune refused in a work path: systemd-run and
// the unit file give it a meaning of its own.
func unsafePathRune(r rune) bool {
	return unicode.IsControl(r) || unicode.IsSpace(r) || r == '$' || r == '%' || r == utf8.RuneError
}

// isStep reports whether s is a step number as in a work directory: 1-based
// decimal without leading zeros.
func isStep(s string) bool {
	if s == "" || s[0] == '0' {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// GroupName is the name of gid, or gid in decimal when it has none.
func GroupName(gid uint32) string {
	id := strconv.FormatUint(uint64(gid), 10)
	if g, err := user.LookupGroupId(id); err == nil {
		return g.Name
	}
	return id
}

// UnitName is a unique transient unit name for job.
func UnitName(job string) string {
	b := make([]byte, 6)
	rand.Read(b)
	id := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, job)
	return "lukd-run-" + id + "-" + hex.EncodeToString(b)
}

// Systemd runs the units with systemd-run and stops them with systemctl.
type Systemd struct{}

func (Systemd) Run(ctx context.Context, argv []string, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
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
