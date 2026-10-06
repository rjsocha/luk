package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"luk/internal/btrfs"
	"luk/internal/jobchan"
	"luk/internal/runstep"
)

// exitCode ends luk-job with the code and no message.
type exitCode int

func (c exitCode) Error() string { return fmt.Sprintf("exit status %d", int(c)) }

// askRun asks the wrapper of the step on work (its socket
// <work>/.luk/run.sock) for the nested job job, with files as its inputs
// (none: the input set of the step), and relays its output; its results
// are cloned into the directory out (empty: the job must have none).
// luk-job exits with the job's exit status. A cancelled ctx closes the
// connection, which stops the job.
func askRun(ctx context.Context, work, job string, files []string, out string, stdout, stderr io.Writer) error {
	var outDir *os.File
	if out != "" {
		d, err := openDir(out)
		if err != nil {
			return err
		}
		outDir = d
		defer outDir.Close()
	}
	ins, err := openFiles(files)
	defer func() {
		for _, f := range ins {
			f.Close()
		}
	}()
	if err != nil {
		return err
	}

	luk, err := os.Open(filepath.Join(work, runstep.LukDir))
	if err != nil {
		return err
	}
	c, err := jobchan.DialIn(luk, runstep.SocketName)
	luk.Close()
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	interrupted := func(err error) error {
		if ctx.Err() != nil {
			return errors.New("interrupted, job stopped")
		}
		return err
	}

	if err := c.Send(jobchan.Frame{T: jobchan.TJob, Job: job}, nil); err != nil {
		return interrupted(err)
	}
	for _, f := range ins {
		if err := c.Send(jobchan.Frame{T: jobchan.TIn, Name: filepath.Base(f.Name())}, f); err != nil {
			return interrupted(err)
		}
	}
	if err := c.Send(jobchan.Frame{T: jobchan.TGo}, nil); err != nil {
		return interrupted(err)
	}
	for {
		f, fd, err := c.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = errors.New("connection closed before the exit status")
			}
			return interrupted(err)
		}
		switch f.T {
		case jobchan.TStdout:
			_, err = stdout.Write(f.Data)
		case jobchan.TStderr:
			_, err = stderr.Write(f.Data)
		case jobchan.TOut:
			err = placeResult(outDir, job, f.Name, fd)
			fd.Close()
		case jobchan.TExit:
			if *f.Status != 0 {
				return exitCode(*f.Status)
			}
			return nil
		case jobchan.TRefused:
			return errors.New(f.Reason)
		default:
			if fd != nil {
				fd.Close()
			}
			err = fmt.Errorf("unexpected frame %q", f.T)
		}
		if err != nil {
			return err
		}
	}
}

// openDir opens the directory p of --out.
func openDir(p string) (*os.File, error) {
	d, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("--out: %w", err)
	}
	fi, err := d.Stat()
	switch {
	case err != nil:
		err = fmt.Errorf("--out: %w", err)
	case !fi.IsDir():
		err = fmt.Errorf("--out %s: not a directory", p)
	}
	if err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// openFiles opens the --file paths: regular files, not symlinks, with
// valid and distinct base names. On an error it returns the files opened
// so far with it.
func openFiles(paths []string) ([]*os.File, error) {
	if len(paths) > jobchan.MaxFiles {
		return nil, fmt.Errorf("--file: more than %d files", jobchan.MaxFiles)
	}
	var files []*os.File
	seen := map[string]bool{}
	for _, p := range paths {
		name := filepath.Base(p)
		switch {
		case !runstep.ValidName(name):
			return files, fmt.Errorf("--file %s: invalid name", p)
		case seen[name]:
			return files, fmt.Errorf("--file %s: listed twice", name)
		}
		seen[name] = true
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ELOOP) {
			return files, fmt.Errorf("--file %s: not a regular file", p)
		}
		if err != nil {
			return files, fmt.Errorf("--file %s: %w", p, err)
		}
		files = append(files, os.NewFile(uintptr(fd), p))
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return files, fmt.Errorf("--file %s: %w", p, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return files, fmt.Errorf("--file %s: not a regular file", p)
		}
	}
	return files, nil
}

// placeResult clones the result name of job from fd into out (nil
// without --out), under a temporary name renamed once complete; an
// existing name is refused.
func placeResult(out *os.File, job, name string, fd *os.File) error {
	switch {
	case !runstep.ValidName(name):
		return fmt.Errorf("job %s: out: %q: invalid name", job, name)
	case out == nil:
		return fmt.Errorf("job %s wrote out/%s", job, name)
	}
	err := btrfs.Place(out, name, fd, 0o400, true)
	if errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("--out: %s exists", name)
	}
	if err != nil {
		return fmt.Errorf("--out: %w", err)
	}
	return nil
}
