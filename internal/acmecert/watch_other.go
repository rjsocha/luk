//go:build !linux

package acmecert

import (
	"context"
	"errors"
)

// watchDir is not supported on this system: requests are polled.
func watchDir(ctx context.Context, dir string) (<-chan struct{}, error) {
	return nil, errors.New("acme: watch needs inotify (linux)")
}
