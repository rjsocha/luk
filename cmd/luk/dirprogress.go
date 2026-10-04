package main

import (
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"luk/internal/client"
)

const (
	// dirLiveInterval is the least time between two renders of the live
	// line while bytes come in.
	dirLiveInterval = 200 * time.Millisecond
	// dirETAAfter is how long the run downloads before the live line shows
	// an ETA.
	dirETAAfter = 3 * time.Second
	// defaultWidth is the terminal width when it cannot be read.
	defaultWidth = 80
)

// dirLive is the live line of a directory download on a terminal:
// the current file among all, its bytes and rate, and the bytes of the
// run against the bytes to transfer with an ETA. A nil *dirLive does
// nothing.
type dirLive struct {
	w     io.Writer
	width func() int
	now   func() time.Time

	count   int   // files in the listing
	total   int64 // bytes to transfer
	done    int64 // bytes transferred in the run
	started time.Time

	index     int
	name      string
	size      int64 // -1: unknown
	counted   int64 // what this file adds to total
	fileDone  int64
	fileStart time.Time

	last  time.Time
	shown bool
}

func newDirLive(w io.Writer, width func() int, now func() time.Time) *dirLive {
	return &dirLive{w: w, width: width, now: now}
}

// init sets the files of the run; the total starts as the sum of their
// known sizes.
func (l *dirLive) init(sizes []int64) {
	if l == nil {
		return
	}
	l.count = len(sizes)
	for _, s := range sizes {
		if s > 0 {
			l.total += s
		}
	}
}

// begin shows the file index (from 1) of the given size (-1: unknown).
func (l *dirLive) begin(index int, name string, size int64) {
	if l == nil {
		return
	}
	l.index, l.name, l.size = index, name, size
	l.counted, l.fileDone, l.fileStart = max(size, 0), 0, time.Time{}
	l.render(l.now())
}

// transfer marks the start of the body of the current file, of size bytes
// (-1: unknown); a size the listing did not give joins the total.
func (l *dirLive) transfer(size int64) {
	if l == nil {
		return
	}
	t := l.now()
	l.fileStart = t
	if l.started.IsZero() {
		l.started = t
	}
	if l.size < 0 && size >= 0 {
		l.size, l.counted = size, size
		l.total += size
	}
}

// add counts n bytes of the current file.
func (l *dirLive) add(n int) {
	if l == nil || n <= 0 {
		return
	}
	l.fileDone += int64(n)
	l.done += int64(n)
	if t := l.now(); t.Sub(l.last) >= dirLiveInterval {
		l.render(t)
	}
}

// end closes the current file: a skipped one leaves the total, a
// downloaded or failed one counts in it with what was transferred.
func (l *dirLive) end(skipped bool) {
	if l == nil {
		return
	}
	if skipped {
		l.total -= l.counted
	} else {
		l.total += l.fileDone - l.counted
	}
	l.counted = 0
}

// clear removes the live line so a permanent line can follow.
func (l *dirLive) clear() {
	if l == nil || !l.shown {
		return
	}
	fmt.Fprint(l.w, "\r\x1b[K")
	l.shown = false
}

func (l *dirLive) render(t time.Time) {
	l.last = t
	fmt.Fprintf(l.w, "\r\x1b[K%s", l.line(t))
	l.shown = true
}

// line is the live line fitted to the terminal width.
func (l *dirLive) line(t time.Time) string {
	digits := len(fmt.Sprint(l.count))
	head := fmt.Sprintf("[%*d/%d] ", digits, l.index, l.count)
	var rate int64
	if !l.fileStart.IsZero() {
		rate = rateOf(l.fileDone, t.Sub(l.fileStart))
	}
	tail := fmt.Sprintf("  %s  %s/s   total %s", pairText(l.fileDone, l.size), client.HumanBytes(rate), pairText(l.done, l.total))
	if el := t.Sub(l.started); !l.started.IsZero() && el >= dirETAAfter && l.done > 0 && l.total > l.done {
		left := float64(l.total-l.done) / float64(l.done) * el.Seconds()
		tail += "  ETA " + etaText(time.Duration(left*float64(time.Second)))
	}
	width := defaultWidth
	if l.width != nil {
		if w := l.width(); w > 0 {
			width = w
		}
	}
	room := width - 1 - utf8.RuneCountInString(head) - utf8.RuneCountInString(tail)
	return cutRunes(head+middleCut(l.name, room)+tail, width-1)
}

// middleCut shortens s to n runes by replacing its middle with "...".
func middleCut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n < 5 {
		return string(r[:max(n, 0)])
	}
	keep := n - 3
	front := (keep + 1) / 2
	return string(r[:front]) + "..." + string(r[len(r)-(keep-front):])
}

// cutRunes keeps the first n runes of s.
func cutRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:max(n, 0)])
}

// pairText is "done/size UNIT" in the unit of size: 12.0/45.0 MiB,
// 512/900 B; done alone for an unknown size.
func pairText(done, size int64) string {
	if size < 0 {
		return client.HumanBytes(done)
	}
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d/%d B", done, size)
	}
	div, i := float64(1), 0
	for v := float64(size); v >= unit && i < 4; i++ {
		v /= unit
		div *= unit
	}
	return fmt.Sprintf("%.1f/%.1f %ciB", float64(done)/div, float64(size)/div, "KMGT"[i-1])
}

// etaText is m:ss, or h:mm:ss from an hour.
func etaText(d time.Duration) string {
	s := int64(d.Round(time.Second) / time.Second)
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

// durText is a duration of a summary: 3.0s, or 2m5.3s from a minute.
func durText(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return d.Round(100 * time.Millisecond).String()
}

func rateOf(n int64, d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(float64(n) / d.Seconds())
}

// countReader reports every read to add.
type countReader struct {
	r   io.Reader
	add func(int)
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.add(n)
	return n, err
}
