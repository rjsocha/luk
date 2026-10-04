//go:build !linux

package queue

import (
	"context"
	"errors"
)

// Watch is not supported on this system.
func Watch(ctx context.Context, dirs []string) (*Watcher, error) {
	return nil, errors.New("queue: watch needs inotify (linux)")
}
