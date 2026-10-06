package workspace

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// LockDir holds the workspace locks below the lock directory of lukd run
// (/run/lukd-run): <locks>/ws/<unit>.lock.
const LockDir = "ws"

// Lock is the lock of a workspace, held by lukd run from before the
// create helper until after the remove helper, so prune never removes a
// workspace that is being set up or used.
type Lock struct {
	dir  *os.File
	f    *os.File
	name string
}

// Hold creates and locks <locks>/ws/<unit>.lock, a fresh file (unit
// names are random), creating ws/ (0700) when missing.
func Hold(locks, unit string) (*Lock, error) {
	if !ValidUnit(unit) {
		return nil, errName
	}
	base, err := os.OpenFile(locks, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	p := filepath.Join(locks, LockDir)
	if err := unix.Mkdirat(int(base.Fd()), LockDir, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	dfd, err := unix.Openat(int(base.Fd()), LockDir, dirFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	dir := os.NewFile(uintptr(dfd), p)
	name := unit + ".lock"
	fd, err := unix.Openat(dfd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		dir.Close()
		return nil, &os.PathError{Op: "open", Path: filepath.Join(p, name), Err: err}
	}
	f := os.NewFile(uintptr(fd), filepath.Join(p, name))
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Unlinkat(dfd, name, 0)
		f.Close()
		dir.Close()
		return nil, fmt.Errorf("flock %s: %w", f.Name(), err)
	}
	return &Lock{dir: dir, f: f, name: name}, nil
}

// Release removes the lock file and then drops the lock.
func (l *Lock) Release() error {
	err := unix.Unlinkat(int(l.dir.Fd()), l.name, 0)
	l.f.Close()
	l.dir.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", l.f.Name(), err)
	}
	return nil
}

// tryLock takes the lock of unit without waiting, read-only (prune runs
// with a read-only /run): free is false while lukd run holds it. A
// missing lock file is free; the returned file, nil then, is closed by
// the caller once the workspace is removed.
func tryLock(locks, unit string) (f *os.File, free bool, err error) {
	p := filepath.Join(locks, LockDir, unit+".lock")
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, &os.PathError{Op: "open", Path: p, Err: err}
	}
	f = os.NewFile(uintptr(fd), p)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); errors.Is(err, unix.EWOULDBLOCK) {
		f.Close()
		return nil, false, nil
	} else if err != nil {
		f.Close()
		return nil, false, fmt.Errorf("flock %s: %w", p, err)
	}
	return f, true, nil
}
