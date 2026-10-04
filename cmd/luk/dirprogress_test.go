package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"luk/internal/client"
	"luk/internal/wire"
)

// stepClock returns a clock that starts at t0 and moves by step on every
// call.
func stepClock(step time.Duration) func() time.Time {
	t := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(step)
		return t
	}
}

// manualClock is a clock the test moves.
type manualClock struct{ t time.Time }

func (c *manualClock) now() time.Time          { return c.t }
func (c *manualClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newManualClock() *manualClock {
	return &manualClock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
}
func fixedWidth(w int) func() int { return func() int { return w } }
func lastLine(buf *bytes.Buffer) string {
	s := buf.String()
	return s[strings.LastIndex(s, "\r\x1b[K")+4:]
}
func mib(f float64) int64                          { return int64(f * (1 << 20)) }
func entry(name string, size int64) wire.ListEntry { return wire.ListEntry{Name: name, Size: &size} }

func TestPairText(t *testing.T) {
	for _, c := range []struct {
		done, size int64
		want       string
	}{
		{0, 0, "0/0 B"},
		{512, 900, "512/900 B"},
		{512, 2048, "0.5/2.0 KiB"},
		{mib(12), mib(45), "12.0/45.0 MiB"},
		{mib(120.4), mib(248), "120.4/248.0 MiB"},
		{mib(512), 3 << 30, "0.5/3.0 GiB"},
		{mib(3), -1, "3.0 MiB"},
	} {
		if got := pairText(c.done, c.size); got != c.want {
			t.Errorf("pairText(%d, %d) = %q, want %q", c.done, c.size, got, c.want)
		}
	}
}

func TestDurAndETA(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "0.0s", 3 * time.Second: "3.0s", 16520 * time.Millisecond: "16.5s", 125300 * time.Millisecond: "2m5.3s",
	} {
		if got := durText(d); got != want {
			t.Errorf("durText(%v) = %q, want %q", d, got, want)
		}
	}
	for d, want := range map[time.Duration]string{
		8 * time.Second: "0:08", 754 * time.Second: "12:34", 3723 * time.Second: "1:02:03",
	} {
		if got := etaText(d); got != want {
			t.Errorf("etaText(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestMiddleCut(t *testing.T) {
	for _, c := range []struct {
		s    string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"2026/10/04/test-149.bin", 15, "2026/1...49.bin"},
		{"2026/10/04/test-149.bin", 16, "2026/10...49.bin"},
		{"zażółć-gęślą-jaźń", 9, "zaż...aźń"},
		{"abcdefgh", 4, "abcd"},
		{"abcdefgh", -3, ""},
	} {
		if got := middleCut(c.s, c.n); got != c.want {
			t.Errorf("middleCut(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
}

func TestDirLiveLine(t *testing.T) {
	clk := newManualClock()
	var buf bytes.Buffer
	l := newDirLive(&buf, fixedWidth(120), clk.now)
	sizes := []int64{mib(10), mib(45), -1}
	l.init(sizes)
	// A skipped file leaves the total.
	l.begin(1, "first.bin", sizes[0])
	if got := lastLine(&buf); got != "[1/3] first.bin  0.0/10.0 MiB  0 B/s   total 0.0/55.0 MiB" {
		t.Fatalf("begin: %q", got)
	}
	l.end(true)
	l.clear()

	l.begin(2, "2026/10/04/test-149.bin", sizes[1])
	l.transfer(mib(45))
	clk.advance(time.Second)
	l.add(int(mib(12)))
	if got := lastLine(&buf); got != "[2/3] 2026/10/04/test-149.bin  12.0/45.0 MiB  12.0 MiB/s   total 12.0/45.0 MiB" {
		t.Fatalf("no ETA before 3s: %q", got)
	}
	// Within the interval no render.
	n := buf.Len()
	clk.advance(dirLiveInterval / 2)
	l.add(1)
	if buf.Len() != n {
		t.Fatalf("rendered within the interval: %q", buf.String()[n:])
	}
	clk.advance(2 * time.Second)
	l.add(int(mib(3)) - 1)
	if got := lastLine(&buf); got != "[2/3] 2026/10/04/test-149.bin  15.0/45.0 MiB  4.8 MiB/s   total 15.0/45.0 MiB  ETA 0:06" {
		t.Fatalf("ETA: %q", got)
	}
	// Narrow terminal: the name is cut in the middle to fit.
	l.width = fixedWidth(80)
	clk.advance(time.Second)
	l.add(int(mib(15)))
	got := lastLine(&buf)
	if got != "[2/3] 2026/1...49.bin  30.0/45.0 MiB  7.3 MiB/s   total 30.0/45.0 MiB  ETA 0:02" || len([]rune(got)) != 79 {
		t.Fatalf("narrow: %q (%d)", got, len([]rune(got)))
	}
	// Narrower than the fields: the line is cut at the width.
	l.width = fixedWidth(30)
	clk.advance(time.Second)
	l.add(1)
	if got := lastLine(&buf); got != "[2/3]   30.0/45.0 MiB  5.9 Mi" {
		t.Fatalf("too narrow: %q", got)
	}
	// Unknown width: 80.
	l.width = fixedWidth(0)
	clk.advance(time.Second)
	l.add(int(mib(15)) - 1)
	l.end(false)
	if got := lastLine(&buf); got != "[2/3] 2026/10/04/test-149.bin  45.0/45.0 MiB  7.4 MiB/s   total 45.0/45.0 MiB" {
		t.Fatalf("width 0: %q", got)
	}
	l.clear()
	if !strings.HasSuffix(buf.String(), "\r\x1b[K") || l.shown {
		t.Fatal("not cleared")
	}
	// A size the listing did not give joins the total once known; a
	// failed file counts with what it transferred.
	l.begin(3, "c", sizes[2])
	if got := lastLine(&buf); got != "[3/3] c  0 B  0 B/s   total 45.0/45.0 MiB" {
		t.Fatalf("unknown size: %q", got)
	}
	l.transfer(mib(5))
	l.add(int(mib(1)))
	l.end(false)
	if l.total != mib(46) || l.done != mib(46) {
		t.Fatalf("total %d done %d", l.total, l.done)
	}
	// A nil live line does nothing.
	var none *dirLive
	none.init(sizes)
	none.begin(1, "x", 1)
	none.transfer(1)
	none.add(1)
	none.end(false)
	none.clear()
}

func TestDirGetLines(t *testing.T) {
	tempConfig(t)
	keyFile, _ := newKeyFile(t)
	signer, err := client.LoadSigner(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	listing := `[{"name":"a","size":1,"sha256":"` + sumOf("a") + `"},{"name":"gone","size":4},{"name":"d/c","size":3}]`
	u, pin, err := client.ParseGetURL(fakeDir(t, listing, "gone"))
	if err != nil {
		t.Fatal(err)
	}
	opts := client.GetOptions{URL: u, Pin: pin, Signer: signer}
	ents, err := client.List(context.Background(), opts, true)
	if err != nil {
		t.Fatal(err)
	}
	run := func(live bool) (string, string) {
		dest := t.TempDir()
		var out, errOut, term bytes.Buffer
		d := &dirGet{ctx: context.Background(), base: u, opts: opts, out: &out, errOut: &errOut, now: stepClock(time.Second)}
		if live {
			d.live = newDirLive(&term, fixedWidth(80), stepClock(time.Second))
		}
		if err := d.run(dest, ents); err == nil {
			t.Fatal("no error for the missing file")
		}
		if live {
			// Every permanent line comes after the live line was cleared.
			if !strings.HasSuffix(term.String(), "\r\x1b[K") {
				t.Fatalf("live line left: %q", term.String())
			}
			if !strings.Contains(term.String(), "\r\x1b[K[3/3] d/c  3/3 B  ") || !strings.Contains(term.String(), "total 4/4 B") {
				t.Fatalf("live: %q", term.String())
			}
		}
		return out.String(), errOut.String()
	}
	out, errs := run(false)
	if out != "get a  1 B  1.0s\nget d/c  3 B  1.0s\n2 downloaded, 0 skipped, 1 failed, 4 B in 7.0s, 0 B/s\n" ||
		!strings.HasPrefix(errs, "luk: gone: ") {
		t.Fatalf("plain: %q %q", out, errs)
	}
	out, errs = run(true)
	if out != "get a  1 B  1.0s\nget d/c  3 B  1.0s\n2 downloaded, 0 skipped, 1 failed, 4 B in 7.0s, 0 B/s\n" ||
		!strings.HasPrefix(errs, "luk: gone: ") {
		t.Fatalf("live: %q %q", out, errs)
	}
}
