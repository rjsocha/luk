package workspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// maxCount caps the count file read.
const maxCount = 4 << 10

// Count is count.json: the workspaces lukd run could not remove and when
// that number last changed.
type Count struct {
	Leftover int    `json:"leftover"`
	Updated  string `json:"updated"`
}

// AddLeftover raises the count in dir by one: a remove failed.
func AddLeftover(dir string, now time.Time) error {
	return updateCount(dir, now, func(old int) int { return old + 1 })
}

// SetLeftover sets the count in dir to n, the workspaces prune could not
// remove; the file is written only when the count changed or is missing.
func SetLeftover(dir string, n int, now time.Time) error {
	return updateCount(dir, now, func(int) int { return n })
}

// ReadCount reads the count file at path; nil, nil when it is missing.
func ReadCount(path string) (*Count, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decodeCount(f, path)
}

func decodeCount(f *os.File, path string) (*Count, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCount+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxCount {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxCount)
	}
	var c Count
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// updateCount replaces the count in dir with next(old) under an exclusive
// flock on the lock file, through a temporary file renamed over it; the
// file is 0640 and of the group of dir, so the group luk of CountDir can
// read it.
func updateCount(dir string, now time.Time, next func(int) int) error {
	d, err := os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer d.Close()
	dfd := int(d.Fd())
	lock, err := unix.Openat(dfd, LockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Join(dir, LockName), err)
	}
	defer unix.Close(lock)
	if err := unix.Flock(lock, unix.LOCK_EX); err != nil {
		return fmt.Errorf("flock %s: %w", filepath.Join(dir, LockName), err)
	}
	old, err := readCountAt(dfd, filepath.Join(dir, CountName))
	if err != nil {
		return err
	}
	n := 0
	if old != nil {
		n = old.Leftover
	}
	if old != nil && next(n) == n {
		return nil
	}
	b, err := json.Marshal(Count{Leftover: next(n), Updated: now.UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(dfd, &st); err != nil {
		return err
	}
	tmp := "." + CountName + ".tmp-" + random12()
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o640)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Join(dir, tmp), err)
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dir, tmp))
	err = writeCount(f, b, int(st.Gid))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(dfd, tmp, dfd, CountName)
	}
	if err != nil {
		unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("%s: %w", filepath.Join(dir, CountName), err)
	}
	return nil
}

func writeCount(f *os.File, b []byte, gid int) error {
	if err := unix.Fchown(int(f.Fd()), -1, gid); err != nil {
		return err
	}
	if err := unix.Fchmod(int(f.Fd()), 0o640); err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// readCountAt reads the count file in the directory dfd; nil, nil when it
// is missing.
func readCountAt(dfd int, path string) (*Count, error) {
	fd, err := unix.Openat(dfd, CountName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	return decodeCount(f, path)
}
