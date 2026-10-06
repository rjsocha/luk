// Package wrap is the wrapper of a unit of lukd run, the main process of
// the unit: it receives the inputs over the channel of the unit, clones
// them into the workspace, runs the command as a child, relays the nested
// jobs of luk-job run while it runs and sends the results back. See SPEC,
// Service, Channel of a unit, and Pipelines, Step contract.
package wrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"luk/internal/btrfs"
	"luk/internal/jobchan"
	"luk/internal/runstep"
)

type Wrapper struct {
	Ch        *jobchan.Conn
	Workspace string
	Argv      []string  // command and its arguments (the workspace last)
	Env       []string  // nil: os.Environ()
	Stdout    io.Writer // the unit's stdout and stderr
	Stderr    io.Writer
}

// waitDelay bounds the wait for the output of the command once it ended,
// when Stdout or Stderr is not a file: a child it left may hold the pipe.
const waitDelay = time.Second

// Run receives the inputs, runs the command, relays nested jobs while it
// runs and sends the results. It returns the exit status of the process
// (the command's, 1 after a refusal or an error before the command).
// A cancelled ctx kills the process group of the command.
func (w *Wrapper) Run(ctx context.Context) int {
	if len(w.Argv) == 0 || !filepath.IsAbs(w.Argv[0]) {
		return w.notStarted(errors.New("the command is not an absolute path"))
	}
	ws, err := os.OpenFile(w.Workspace, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return w.notStarted(err)
	}
	defer ws.Close()
	for _, d := range []string{"in", "out", runstep.TmpDir, runstep.LukDir} {
		if err := unix.Mkdirat(int(ws.Fd()), d, 0o700); err != nil {
			return w.notStarted(fmt.Errorf("mkdir %s: %w", d, err))
		}
	}
	in, err := openDir(ws, "in")
	if err != nil {
		return w.notStarted(err)
	}
	err = w.receive(ctx, ws, in)
	in.Close()
	if err != nil {
		return w.notStarted(err)
	}
	luk, err := openDir(ws, runstep.LukDir)
	if err != nil {
		return w.notStarted(err)
	}
	defer luk.Close()
	l, err := jobchan.ListenIn(luk, runstep.SocketName)
	if err != nil {
		return w.notStarted(err)
	}

	cmd := exec.Command(w.Argv[0], w.Argv[1:]...)
	cmd.Dir = w.Workspace
	cmd.Env = w.Env
	cmd.Stdout, cmd.Stderr = w.Stdout, w.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		l.Close()
		return w.notStarted(err)
	}
	// waited keeps a late cancel from signalling the group long after the
	// command ended. A cancel between the reap in Wait and waited still
	// reaches -pid: the group id stays in use while members of the group
	// live, else the kill fails with ESRCH.
	var mu sync.Mutex
	waited := false
	stopKill := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if !waited {
			unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		}
	})
	n := startNested(w.Ch, l)
	cmd.Wait()
	mu.Lock()
	waited = true
	mu.Unlock()
	stopKill()
	n.stop()

	status := exitStatus(cmd.ProcessState)
	fail := ""
	if status != 0 {
		fail = readFail(ws)
	}
	return w.results(ws, status, fail)
}

func (w *Wrapper) notStarted(err error) int {
	fmt.Fprintf(w.Stderr, "lukd: job not started: %v\n", err)
	return 1
}

// openDir opens the directory name in dir, not through a symlink.
func openDir(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// regular reports whether f is a regular file.
func regular(f *os.File) bool {
	var st unix.Stat_t
	return unix.Fstat(int(f.Fd()), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
}

// receive reads the frames of lukd process until go: meta first and once,
// cloned to meta.json, then each input cloned into in/, mode 0400.
func (w *Wrapper) receive(ctx context.Context, ws, in *os.File) error {
	stop := context.AfterFunc(ctx, func() { w.Ch.SetReadDeadline(time.Now()) })
	defer func() {
		stop()
		w.Ch.SetReadDeadline(time.Time{})
	}()
	meta := false
	names := map[string]bool{}
	for {
		f, fd, err := w.Ch.Recv()
		switch {
		case ctx.Err() != nil:
			closeFile(fd)
			return ctx.Err()
		case errors.Is(err, io.EOF):
			return errors.New("channel closed before go")
		case err != nil:
			return err
		}
		switch {
		case f.T == jobchan.TGo && meta:
			return nil
		case f.T == jobchan.TMeta && !meta:
			meta = true
			if !regular(fd) {
				err = errors.New("meta.json: not a regular file")
			} else {
				err = btrfs.Place(ws, "meta.json", fd, 0o400, true)
			}
		case f.T == jobchan.TIn && meta:
			switch {
			case !runstep.ValidName(f.Name):
				err = fmt.Errorf("input %q: invalid name", f.Name)
			case names[f.Name]:
				err = fmt.Errorf("input %q: repeated", f.Name)
			case len(names) == jobchan.MaxFiles:
				err = fmt.Errorf("more than %d inputs", jobchan.MaxFiles)
			case !regular(fd):
				err = fmt.Errorf("input %q: not a regular file", f.Name)
			default:
				names[f.Name] = true
				err = btrfs.Place(in, f.Name, fd, 0o400, true)
			}
		default:
			err = fmt.Errorf("unexpected frame %q", f.T)
		}
		closeFile(fd)
		if err != nil {
			return err
		}
	}
}

func closeFile(f *os.File) {
	if f != nil {
		f.Close()
	}
}

// exitStatus is the exit status of the command, 128 + the signal that
// killed it.
func exitStatus(ps *os.ProcessState) int {
	if st, ok := ps.Sys().(syscall.WaitStatus); ok && st.Signaled() {
		return 128 + int(st.Signal())
	}
	return ps.ExitCode()
}

// readFail returns the text of the fail file of the workspace: at most
// runstep.MaxFail bytes of a regular file, empty when there is none.
func readFail(ws *os.File) string {
	fd, err := unix.Openat(int(ws.Fd()), runstep.FailFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	f := os.NewFile(uintptr(fd), runstep.FailFile)
	defer f.Close()
	if !regular(f) {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(f, runstep.MaxFail))
	return runstep.FailText(b)
}

type outFile struct {
	name string
	f    *os.File
}

// results sends the status, then the entries of out/ or the refusal of
// one, then end. It returns the exit status of the wrapper.
func (w *Wrapper) results(ws *os.File, status int, fail string) int {
	if err := w.Ch.Send(jobchan.Frame{T: jobchan.TStatus, Status: jobchan.Status(status), Fail: fail}, nil); err != nil {
		fmt.Fprintf(w.Stderr, "lukd: results: %v\n", err)
		return 1
	}
	files, refuse := openResults(ws)
	defer func() {
		for _, o := range files {
			closeFile(o.f)
		}
	}()
	code := status
	send := files
	if refuse != nil {
		send = nil
		code = 1
		if err := w.Ch.Send(*refuse, nil); err != nil {
			fmt.Fprintf(w.Stderr, "lukd: results: %v\n", err)
			return 1
		}
	}
	for i, o := range send {
		err := w.Ch.Send(jobchan.Frame{T: jobchan.TOut, Name: o.name}, o.f)
		o.f.Close()
		files[i].f = nil
		if err != nil {
			fmt.Fprintf(w.Stderr, "lukd: results: %v\n", err)
			return 1
		}
	}
	if err := w.Ch.Send(jobchan.Frame{T: jobchan.TEnd}, nil); err != nil {
		fmt.Fprintf(w.Stderr, "lukd: results: %v\n", err)
		return 1
	}
	return code
}

// openResults opens the top-level entries of out/ in name order, at most
// jobchan.MaxFiles + 1 of them (lukd process refuses that many, so which
// ones does not matter when out/ holds more). The first
// entry that is not a regular file, or whose name is not valid UTF-8,
// ends it with its refusal.
func openResults(ws *os.File) ([]outFile, *jobchan.Frame) {
	refuse := func(name, reason string) *jobchan.Frame {
		return &jobchan.Frame{T: jobchan.TRefuse, Name: name, Reason: reason}
	}
	out, err := openDir(ws, "out")
	if err != nil {
		var errno unix.Errno
		if errors.As(err, &errno) {
			return nil, refuse("out", errno.Error())
		}
		return nil, refuse("out", err.Error())
	}
	defer out.Close()
	// Any MaxFiles+1 entries will do: lukd process refuses that many.
	names, err := out.Readdirnames(jobchan.MaxFiles + 1)
	if err != nil && err != io.EOF {
		return nil, refuse("out", err.Error())
	}
	slices.Sort(names)
	var files []outFile
	for _, name := range names {
		if !utf8.ValidString(name) {
			return files, refuse(strings.ToValidUTF8(name, "?"), "invalid name")
		}
		fd, err := unix.Openat(int(out.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		switch {
		case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENXIO):
			return files, refuse(name, "not a regular file")
		case err != nil:
			return files, refuse(name, err.Error())
		}
		f := os.NewFile(uintptr(fd), name)
		files = append(files, outFile{name, f})
		if !regular(f) {
			return files, refuse(name, "not a regular file")
		}
	}
	return files, nil
}
