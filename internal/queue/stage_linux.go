package queue

import (
	"os"

	"golang.org/x/sys/unix"
)

// preallocate takes the space of a file of size bytes at once.
func preallocate(f *os.File, size int64) error {
	return unix.Fallocate(int(f.Fd()), 0, 0, size)
}
