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
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"

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
	// Owner must own the config, run.d and its files and the lukd
	// configuration (root), and every directory above them from Top (/
	// when empty) down.
	Owner uint32
	Top   string
	// Checker is the lukd binary whose run check-work (CheckWorkCmd)
	// starts every job.
	Checker string
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
	// requestTimeout bounds receiving the request and answering a
	// refusal.
	requestTimeout = 5 * time.Second
)

// Serve runs the request of conn: the peer check, the request, the job.
// Receiving the request and answering a refusal must end within
// requestTimeout, the job with its output within its timeout plus
// stopGrace, so a peer that stops sending or reading cannot hold the
// connection.
func (s *Server) Serve(conn net.Conn) error {
	// A missing directory of run.yaml is a missing run.yaml: the
	// defaults.
	if err := CheckParents(filepath.Dir(s.Config), s.Top, s.Owner); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: %w", s.Config, err)
	}
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
	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	fw := runproto.NewFrameWriter(conn)
	br := bufio.NewReaderSize(conn, runproto.MaxRequest)
	err = s.serve(g, got, conn, br, fw)
	var r refusal
	if errors.As(err, &r) {
		io.WriteString(fw.Stream(runproto.Stderr), "lukd run: "+r.Error()+"\n")
		fw.Exit(1)
	}
	return err
}

func (s *Server) serve(g *Global, peer uint32, conn net.Conn, br *bufio.Reader, fw *runproto.FrameWriter) error {
	req, err := runproto.ReadRequest(br)
	if err != nil {
		return refusal{err}
	}
	if !config.ValidJobName(req.Job) {
		return refusal{fmt.Errorf("job %q: unknown", req.Job)}
	}
	err = CheckParents(filepath.Dir(s.Jobs), s.Top, s.Owner)
	var jobs *Jobs
	if err == nil {
		jobs, err = LoadJobs(s.Jobs, s.Owner)
	}
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
	pipeline, err := ParseWork(g.Root, req.Work)
	if err != nil {
		s.Log.Warn("work directory refused", "job", req.Job, "err", err)
		return refusal{errWork}
	}
	lk, ok := s.allowed(g, req.Job, pipeline)
	if !ok {
		return refusal{fmt.Errorf("job %s: pipeline %s not allowed", req.Job, pipeline)}
	}
	work := req.Work
	_, ino, err := CheckWork(g.Root, work, peer)
	if err != nil {
		s.Log.Warn("work directory refused", "job", req.Job, "err", err)
		return refusal{errWork}
	}
	// The group that reads the work directory is the peer's own, not
	// the group of the directory, which the peer may change.
	group, err := PeerGroup(peer)
	if err != nil {
		s.Log.Error("peer group", "uid", peer, "err", err)
		return refusal{fmt.Errorf("job %s: unavailable", req.Job)}
	}
	// The path-bound variables come from the checked path and run.yaml,
	// the free-form metadata from the request: lukd run never reads the
	// work directory.
	vars := runstep.Vars(work, g.Root, req.Env)
	unit := UnitName(req.Job)
	box := &Box{
		Root: g.Root, Config: filepath.Dir(g.Config), Hide: slices.Concat(g.Hide, lk.Paths),
		Lukd: s.Checker, Work: ino,
	}
	argv, err := job.Argv(box, unit, req.Job, pipeline, work, group, vars)
	if err != nil {
		s.Log.Error("job refused", "job", req.Job, "err", err)
		return refusal{fmt.Errorf("job %s: unavailable", req.Job)}
	}
	who := job.User
	if who == "" {
		who = DynamicUser(req.Job, pipeline)
	}

	// No read deadline while waiting for the state lock: the wait ends
	// with the run holding it, and a refusal still has the write
	// deadline of the request.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
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
	// The job ends by RuntimeMaxSec=timeout; past stopGrace more a peer
	// that does not read fails the writes and reads as gone.
	if err := conn.SetDeadline(time.Now().Add(time.Duration(job.Timeout) + stopGrace)); err != nil {
		return err
	}

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

// workFlags opens a directory below root without following a symlink and
// without blocking on whatever luk put in its place.
const workFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

// errWork is the only answer the peer gets for a refused work directory;
// the reason goes to the journal.
var errWork = errors.New("work directory refused")

// ParseWork checks work lexically: an absolute, clean path
// <root>/work/<id>/<pipeline>/<step> with <id> a queue entry id,
// <pipeline> a valid pipeline name, <step> a step number, and no control
// character, white space, "$" or "%" anywhere, as it goes into the
// systemd-run command line and the unit file. It returns the pipeline.
func ParseWork(root, work string) (string, error) {
	if !filepath.IsAbs(work) {
		return "", fmt.Errorf("work %q: not absolute", work)
	}
	if filepath.Clean(work) != work {
		return "", fmt.Errorf("work %q: not clean", work)
	}
	base := filepath.Join(root, "work")
	rel, ok := strings.CutPrefix(work, base+string(filepath.Separator))
	if !ok {
		return "", fmt.Errorf("work %q: not under %s", work, base)
	}
	if strings.ContainsFunc(work, unsafePathRune) {
		return "", fmt.Errorf("work %q: control character, white space, $ or %% in the path", work)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 3 || !queue.IsID(parts[0]) || !config.ValidPipelineName(parts[1]) || !isStep(parts[2]) {
		return "", fmt.Errorf("work %q: not a step work directory %s/<id>/<pipeline>/<step>", work, base)
	}
	return parts[1], nil
}

// Inode is the identity of a directory: its device and inode number.
type Inode struct{ Dev, Ino uint64 }

// CheckWork requires work to pass ParseWork and to be a directory owned by
// uid, reached from root (which may be a symlink: it is root's
// configuration) through work, <id>, <pipeline> and <step>, each opened
// with workFlags: no symlink, nothing but a directory, no blocking open.
// It returns the pipeline and the identity of the directory.
func CheckWork(root, work string, uid uint32) (string, Inode, error) {
	st, err := walkWork(root, work, syscall.O_RDONLY|syscall.O_NONBLOCK, workFlags)
	if err != nil {
		return "", Inode{}, err
	}
	if st.Uid != uid {
		return "", Inode{}, fmt.Errorf("work %q: owned by uid %d, not the peer", work, st.Uid)
	}
	pipeline, _ := ParseWork(root, work)
	return pipeline, Inode{uint64(st.Dev), st.Ino}, nil
}

// CheckWorkCmd is the subcommand of lukd run that starts every job: lukd
// run check-work <root> <work> <dev> <ino> -- <command> <work> runs
// VerifyWork and then executes the command in its place.
const CheckWorkCmd = "check-work"

// VerifyWork requires work, inside the namespace of a job, to be the
// directory want: reached from root as CheckWork does, without following a
// symlink below root, and with the same device and inode. It needs no
// privileges: every directory is opened with O_PATH.
func VerifyWork(root, work string, want Inode) error {
	const path = unix.O_PATH | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	st, err := walkWork(root, work, unix.O_PATH, path)
	if err != nil {
		return err
	}
	if got := (Inode{uint64(st.Dev), st.Ino}); got != want {
		return fmt.Errorf("work %q: device %d inode %d, not the checked %d %d", work, got.Dev, got.Ino, want.Dev, want.Ino)
	}
	return nil
}

// walkWork opens root with rootFlags (following a symlink: it is root's
// configuration), then every element of work below it with flags, each a
// directory, and returns the stat of work. work must pass ParseWork.
func walkWork(root, work string, rootFlags, flags int) (*syscall.Stat_t, error) {
	if _, err := ParseWork(root, work); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(root, rootFlags|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("root %s: %w", root, err)
	}
	var st syscall.Stat_t
	rel, _ := filepath.Rel(root, work)
	for _, name := range strings.Split(rel, string(filepath.Separator)) {
		next, err := syscall.Openat(fd, name, flags, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("work %q: %s: %w", work, name, err)
		}
		fd = next
		// O_PATH|O_NOFOLLOW opens a symlink itself.
		if err := syscall.Fstat(fd, &st); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("work %q: %w", work, err)
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			syscall.Close(fd)
			return nil, fmt.Errorf("work %q: %s: not a directory", work, name)
		}
	}
	syscall.Close(fd)
	return &st, nil
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

// lookupGroupID is user.LookupGroupId, replaced by tests.
var lookupGroupID = user.LookupGroupId

// GroupName is the name of gid, or gid in decimal when it has none or one
// that is not a plain account name (white space would split
// SupplementaryGroups=).
func GroupName(gid uint32) string {
	id := strconv.FormatUint(uint64(gid), 10)
	if g, err := lookupGroupID(id); err == nil && account.MatchString(g.Name) {
		return g.Name
	}
	return id
}

// PeerGroup is the primary group of uid, by name (see GroupName).
func PeerGroup(uid uint32) (string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return "", err
	}
	return GroupName(uint32(gid)), nil
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
