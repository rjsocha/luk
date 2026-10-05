package queue

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startWatch(t *testing.T, dirs ...string) *Watcher {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	w, err := Watch(ctx, dirs)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		<-w.Done()
	})
	return w
}

func receive(t *testing.T, dir, id string) Entry {
	t.Helper()
	e, _, _, err := New(0, nil).Receive(context.Background(), dir, id, strings.NewReader("x"), 0, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func commitEntry(t *testing.T, e Entry) {
	t.Helper()
	if err := New(0, nil).Commit(e, map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
}

func woken(w *Watcher, d time.Duration) bool {
	select {
	case <-w.C:
		return true
	case <-time.After(d):
		return false
	}
}

func TestWatchWakesOnCommit(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	early := receive(t, a, "early")
	w := startWatch(t, a, b)
	e := receive(t, b, "id-1")
	if woken(w, 200*time.Millisecond) {
		t.Fatal("woken before commit")
	}
	commitEntry(t, e)
	if !woken(w, time.Second) {
		t.Fatal("no wakeup on commit")
	}
	commitEntry(t, early)
	if !woken(w, time.Second) {
		t.Fatal("no wakeup on commit of an entry received before the watch")
	}
}

func TestWatchCoalesces(t *testing.T) {
	dir := t.TempDir()
	w := startWatch(t, dir)
	for i := range 20 {
		commitEntry(t, receive(t, dir, "id-"+string(rune('a'+i))))
	}
	time.Sleep(300 * time.Millisecond)
	n := 0
	for woken(w, 200*time.Millisecond) {
		n++
	}
	if n == 0 || n > 3 {
		t.Fatalf("%d wakeups for 20 commits", n)
	}
}

func TestWatchStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w, err := Watch(ctx, []string{t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-w.Done():
	case <-time.After(time.Second):
		t.Fatal("watcher still running")
	}
}

func TestWatchMissingDir(t *testing.T) {
	if _, err := Watch(context.Background(), []string{filepath.Join(t.TempDir(), "none")}); err == nil {
		t.Fatal("watch of a missing dir succeeded")
	}
}
