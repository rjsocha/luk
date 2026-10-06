package btrfs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// ficlone is unix.IoctlFileClone, replaced by tests.
var ficlone = unix.IoctlFileClone

// Clone makes dst, an empty file open for writing, a copy of src: a
// clone sharing the blocks (FICLONE) when both lie on the same btrfs,
// else a copy, decided per file. The copy reads at explicit offsets: src
// may be a descriptor received from another process, whose file offset
// it shares.
func Clone(dst, src *os.File) error {
	err := ficlone(int(dst.Fd()), int(src.Fd()))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EXDEV), errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.EINVAL):
		return copyAt(dst, src)
	}
	return fmt.Errorf("clone: %w", err)
}

// copyAt copies src to dst with copy_file_range at explicit offsets; a
// kernel or filesystem pair without it falls back to pread and write.
func copyAt(dst, src *os.File) error {
	fi, err := src.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	var roff, woff int64
	for roff < size {
		n, err := unix.CopyFileRange(int(src.Fd()), &roff, int(dst.Fd()), &woff, int(min(size-roff, 1<<30)), 0)
		if err != nil {
			if errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
				_, err = io.Copy(io.NewOffsetWriter(dst, woff), io.NewSectionReader(src, roff, size-roff))
			}
			return err
		}
		if n == 0 {
			break
		}
	}
	return nil
}

// Place puts a copy of src into dir as name: Clone into a new temporary
// file .<name>.tmp-<random>, chmod to mode, then rename it to name. With
// noReplace an existing name is kept and the error wraps EEXIST. On any
// failure the temporary file is removed.
func Place(dir *os.File, name string, src *os.File, mode os.FileMode, noReplace bool) error {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return fmt.Errorf("place %q: invalid name", name)
	}
	dfd := int(dir.Fd())
	tmp := "." + name + ".tmp-" + rand.Text()
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("place %s: %w", name, err)
	}
	dst := os.NewFile(uintptr(fd), tmp)
	err = Clone(dst, src)
	if err == nil {
		err = dst.Chmod(mode)
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		var flags uint
		if noReplace {
			flags = unix.RENAME_NOREPLACE
		}
		err = unix.Renameat2(dfd, tmp, dfd, name, flags)
	}
	if err != nil {
		unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("place %s: %w", name, err)
	}
	return nil
}
