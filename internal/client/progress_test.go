package client

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestProgressKnownSize(t *testing.T) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	var w bytes.Buffer
	p := newProgress(strings.NewReader(strings.Repeat("x", 2048)), &w, 2048, c.now)
	buf := make([]byte, 1024)
	if _, err := p.Read(buf); err != nil {
		t.Fatal(err)
	}
	if w.Len() != 0 {
		t.Fatalf("printed before the interval: %q", w.String())
	}
	c.t = c.t.Add(500 * time.Millisecond)
	if _, err := p.Read(buf); err != nil {
		t.Fatal(err)
	}
	out := w.String()
	for _, want := range []string{"\r", "2.0 KiB / 2.0 KiB", "100%", "4.0 KiB/s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q lacks %q", out, want)
		}
	}
	c.t = c.t.Add(time.Second)
	p.Finish()
	last := w.String()[len(out):]
	if !strings.HasSuffix(last, "\n") || !strings.Contains(last, "2.0 KiB in 1.5s") || !strings.Contains(last, "1.3 KiB/s") {
		t.Fatalf("summary %q", last)
	}
}

func TestProgressETA(t *testing.T) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	var w bytes.Buffer
	p := newProgress(strings.NewReader(strings.Repeat("x", 4096)), &w, 4096, c.now)
	p.Read(make([]byte, 1024))
	c.t = c.t.Add(time.Second)
	p.Read(make([]byte, 1024))
	if out := w.String(); !strings.Contains(out, "50%") || !strings.Contains(out, "ETA 0:01") {
		t.Fatalf("%q", out)
	}
}

func TestProgressStream(t *testing.T) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	var w bytes.Buffer
	p := newProgress(strings.NewReader(strings.Repeat("x", 3<<20)), &w, -1, c.now)
	p.Read(make([]byte, 1<<20))
	c.t = c.t.Add(time.Second)
	p.Read(make([]byte, 1<<20))
	out := w.String()
	if !strings.Contains(out, "2.0 MiB") || !strings.Contains(out, "2.0 MiB/s") || strings.Contains(out, "%") || strings.Contains(out, "ETA") {
		t.Fatalf("%q", out)
	}
}

func TestProgressNothingReadPrintsNothing(t *testing.T) {
	var w bytes.Buffer
	p := newProgress(strings.NewReader("x"), &w, 1, time.Now)
	p.Finish()
	if w.Len() != 0 {
		t.Fatalf("%q", w.String())
	}
}

func TestProgressPassesData(t *testing.T) {
	var w bytes.Buffer
	p := newProgress(strings.NewReader("hello"), &w, 5, time.Now)
	b, err := io.ReadAll(p)
	if err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestHumanBytes(t *testing.T) {
	for in, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB"} {
		if got := HumanBytes(in); got != want {
			t.Errorf("%d: %q want %q", in, got, want)
		}
	}
}
