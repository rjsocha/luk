package queue

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	dirMask   = syscall.IN_CREATE | syscall.IN_ONLYDIR
	entryMask = syscall.IN_MOVED_TO | syscall.IN_MOVE_SELF | syscall.IN_ONLYDIR
)

// Watch signals a commit in any of dirs with inotify: meta.json renamed into
// an entry directory. Every queue directory must be watchable; it stops
// when ctx is done.
func Watch(ctx context.Context, dirs []string) (*Watcher, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify: %w", err)
	}
	f := os.NewFile(uintptr(fd), "inotify")
	c := make(chan struct{}, 1)
	rc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("inotify: %w", err)
	}
	w := &watch{rc: rc, c: c, queues: map[int]string{}, entries: map[int]string{}}
	for _, dir := range dirs {
		wd, err := syscall.InotifyAddWatch(fd, dir, dirMask)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("inotify %s: %w", dir, err)
		}
		w.queues[wd] = dir
	}
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, d := range ents {
			if d.IsDir() && d.Name() != FailedName {
				w.addEntry(filepath.Join(dir, d.Name()))
			}
		}
	}
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		f.Close()
	}()
	go func() {
		defer close(done)
		w.read(f)
	}()
	return &Watcher{C: c, done: done}, nil
}

type watch struct {
	rc      syscall.RawConn
	c       chan struct{}
	queues  map[int]string
	entries map[int]string
}

func (w *watch) wake() {
	select {
	case w.c <- struct{}{}:
	default:
	}
}

// addEntry watches an entry directory for its commit; one committed before
// the watch was in place wakes at once.
func (w *watch) addEntry(dir string) {
	w.rc.Control(func(fd uintptr) {
		if wd, err := syscall.InotifyAddWatch(int(fd), dir, entryMask); err == nil {
			w.entries[wd] = dir
		}
	})
	if _, err := os.Stat(filepath.Join(dir, "meta.json")); err == nil {
		w.wake()
	}
}

func (w *watch) read(f *os.File) {
	buf := make([]byte, 64*(syscall.SizeofInotifyEvent+syscall.NAME_MAX+1))
	for {
		n, err := f.Read(buf)
		if err != nil {
			return
		}
		for off := 0; off+syscall.SizeofInotifyEvent <= n; {
			wd := int(int32(binary.NativeEndian.Uint32(buf[off:])))
			mask := binary.NativeEndian.Uint32(buf[off+4:])
			l := int(binary.NativeEndian.Uint32(buf[off+12:]))
			off += syscall.SizeofInotifyEvent
			name, _, _ := bytes.Cut(buf[off:off+l], []byte{0})
			off += l
			w.event(wd, mask, string(name))
		}
	}
}

func (w *watch) event(wd int, mask uint32, name string) {
	switch {
	case mask&syscall.IN_Q_OVERFLOW != 0:
		w.wake()
	case mask&syscall.IN_IGNORED != 0:
		delete(w.queues, wd)
		delete(w.entries, wd)
	case w.queues[wd] != "":
		if name == FailedName || mask&syscall.IN_ISDIR == 0 {
			return
		}
		w.addEntry(filepath.Join(w.queues[wd], name))
	case w.entries[wd] != "":
		if mask&syscall.IN_MOVE_SELF != 0 {
			w.rc.Control(func(fd uintptr) { syscall.InotifyRmWatch(int(fd), uint32(wd)) })
		} else if name == "meta.json" {
			w.wake()
		}
	}
}
