//go:build !linux

package queue

import (
	"errors"
	"os"
)

// preallocate is not supported here: the file is sparse.
func preallocate(*os.File, int64) error { return errors.New("queue: no fallocate") }
