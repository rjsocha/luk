package queue

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAcceptedMark: the mark persisted under the root keeps the order
// increasing across a restart with a wall clock moved back, it covers
// every value handed out (a crash cannot reuse one), and it survives.
func TestAcceptedMark(t *testing.T) {
	p := filepath.Join(t.TempDir(), "accepted.json")
	start := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	var elapsed time.Duration
	a := newAccepted(start, func() time.Duration { return elapsed })
	if err := a.Persist(p, func(err error) { t.Errorf("mark: %v", err) }); err != nil {
		t.Fatal(err)
	}
	var last Acceptance
	for _, d := range []time.Duration{time.Second, 30 * time.Second, 2 * time.Minute, 2*time.Minute + 1, 10 * time.Minute} {
		elapsed = d
		last = a.Next()
		m, err := readMark(p)
		if err != nil {
			t.Fatal(err)
		}
		if m < last.NS {
			t.Fatalf("mark %d below the handed out %d", m, last.NS)
		}
	}
	// A restart (or a crash) with the wall clock an hour back.
	elapsed = 0
	b := newAccepted(start.Add(-time.Hour), func() time.Duration { return elapsed })
	if err := b.Persist(p, func(err error) { t.Errorf("mark: %v", err) }); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		n := b.Next()
		if n.Compare(last) <= 0 {
			t.Fatalf("%v not after %v of the previous process", n, last)
		}
		last = n
		elapsed += time.Millisecond
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("mark file: %v", err)
	}
}

// TestAcceptedMarkCorrupt: a mark that does not read is an error naming
// the file, never a silent start from the wall clock.
func TestAcceptedMarkCorrupt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "accepted.json")
	if err := os.WriteFile(p, []byte("{garbage"), 0o640); err != nil {
		t.Fatal(err)
	}
	err := NewAccepted().Persist(p, func(error) {})
	if err == nil || !strings.Contains(err.Error(), p) {
		t.Fatalf("corrupt mark: %v", err)
	}
}

// TestAcceptedMarkImplausible: a mark that is negative, overflows with the
// window or lies far beyond the wall clock is an error naming the file.
func TestAcceptedMarkImplausible(t *testing.T) {
	for _, mark := range []string{"-1", "9223372036854775807", "9223372036854775000", "9000000000000000000"} {
		p := filepath.Join(t.TempDir(), "accepted.json")
		if err := os.WriteFile(p, []byte(`{"mark":`+mark+`}`), 0o640); err != nil {
			t.Fatal(err)
		}
		err := NewAccepted().Persist(p, func(error) {})
		if err == nil || !strings.Contains(err.Error(), p) {
			t.Fatalf("mark %s: %v", mark, err)
		}
	}
}

// TestAcceptedMarkWriteFails: a mark that cannot be moved goes to onErr,
// the value is handed out anyway and the next call writes it again.
func TestAcceptedMarkWriteFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "accepted.json")
	start := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	var elapsed time.Duration
	a := newAccepted(start, func() time.Duration { return elapsed })
	var errs []error
	if err := a.Persist(p, func(err error) { errs = append(errs, err) }); err != nil {
		t.Fatal(err)
	}
	moved := dir + ".moved"
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	elapsed = 2 * time.Minute
	first := a.Next()
	if len(errs) != 1 {
		t.Fatalf("onErr called %d times", len(errs))
	}
	if want := start.Add(2 * time.Minute).UnixNano(); first.NS != want {
		t.Fatalf("value %d not handed out, want %d", first.NS, want)
	}
	elapsed += time.Second
	a.Next()
	if len(errs) != 2 {
		t.Fatalf("write not retried: onErr called %d times", len(errs))
	}
	if err := os.Rename(moved, dir); err != nil {
		t.Fatal(err)
	}
	elapsed += time.Second
	last := a.Next()
	if len(errs) != 2 {
		t.Fatalf("onErr after recovery: %v", errs)
	}
	m, err := readMark(p)
	if err != nil || m < last.NS {
		t.Fatalf("mark %d (%v) below the handed out %d", m, err, last.NS)
	}
}
