package acmecert

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
)

// watchDir signals when a renewal request may have arrived in dir: a
// <name>.renew file renamed into it or written. Signals coalesce; it stops
// when ctx is done.
func watchDir(ctx context.Context, dir string) (<-chan struct{}, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify: %w", err)
	}
	if _, err := syscall.InotifyAddWatch(fd, dir, syscall.IN_MOVED_TO|syscall.IN_CLOSE_WRITE|syscall.IN_ONLYDIR); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("inotify %s: %w", dir, err)
	}
	f := os.NewFile(uintptr(fd), "inotify")
	c := make(chan struct{}, 1)
	go func() {
		<-ctx.Done()
		f.Close()
	}()
	go func() {
		buf := make([]byte, 64*(syscall.SizeofInotifyEvent+syscall.NAME_MAX+1))
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			for off := 0; off+syscall.SizeofInotifyEvent <= n; {
				mask := binary.NativeEndian.Uint32(buf[off+4:])
				l := int(binary.NativeEndian.Uint32(buf[off+12:]))
				off += syscall.SizeofInotifyEvent
				name, _, _ := bytes.Cut(buf[off:off+l], []byte{0})
				off += l
				if mask&syscall.IN_Q_OVERFLOW != 0 || bytes.HasSuffix(name, []byte(RenewSuffix)) && !bytes.HasPrefix(name, []byte(".")) {
					select {
					case c <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return c, nil
}
