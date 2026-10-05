package main

import (
	"fmt"
	"io"
	"slices"
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
// the current file among all (the first of the files in flight, with the
// number of the others), its bytes and rate, and the bytes of the run
// against the bytes to transfer with an ETA. A nil *dirLive does
// nothing. It is not safe for concurrent use.
type dirLive struct {
	w     io.Writer
	width func() int
	now   func() time.Time

	count   int   // files in the listing
	total   int64 // bytes to transfer
	done    int64 // bytes transferred in the run
	started time.Time

	// active are the files in flight, in the order they began.
	active []*liveFile

	last  time.Time
	shown bool
}

// liveFile is a file of the live line between begin and end. A nil
// *liveFile does nothing.
type liveFile struct {
	l         *dirLive
	index     int
	name      string
	size      int64 // -1: unknown
	counted   int64 // what this file adds to total
	fileDone  int64
	fileStart time.Time
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

// begin shows the file index (from 1) of the given size (-1: unknown)
// and returns it, nil for a nil l.
func (l *dirLive) begin(index int, name string, size int64) *liveFile {
	if l == nil {
		return nil
	}
	f := &liveFile{l: l, index: index, name: name, size: size, counted: max(size, 0)}
	l.active = append(l.active, f)
	l.render(l.now())
	return f
}

// transfer marks the start of the body of the file, of size bytes (-1:
// unknown); a size the listing did not give joins the total.
func (f *liveFile) transfer(size int64) {
	if f == nil {
		return
	}
	l := f.l
	t := l.now()
	f.fileStart = t
	if l.started.IsZero() {
		l.started = t
	}
	if f.size < 0 && size >= 0 {
		f.size, f.counted = size, size
		l.total += size
	}
}

// add counts n bytes of the file.
func (f *liveFile) add(n int) {
	if f == nil || n <= 0 {
		return
	}
	l := f.l
	f.fileDone += int64(n)
	l.done += int64(n)
	if t := l.now(); t.Sub(l.last) >= dirLiveInterval {
		l.render(t)
	}
}

// end closes the file: a skipped one leaves the total, a downloaded or
// failed one counts in it with what was transferred.
func (f *liveFile) end(skipped bool) {
	if f == nil {
		return
	}
	l := f.l
	if skipped {
		l.total -= f.counted
	} else {
		l.total += f.fileDone - f.counted
	}
	f.counted = 0
	if i := slices.Index(l.active, f); i >= 0 {
		l.active = slices.Delete(l.active, i, i+1)
	}
}

// clear removes the live line so a permanent line can follow.
func (l *dirLive) clear() {
	if l == nil || !l.shown {
		return
	}
	fmt.Fprint(l.w, "\r\x1b[K")
	l.shown = false
}

// redraw shows the line again after clear while files are in flight.
func (l *dirLive) redraw() {
	if l == nil || l.shown || len(l.active) == 0 {
		return
	}
	l.render(l.now())
}

func (l *dirLive) render(t time.Time) {
	l.last = t
	fmt.Fprintf(l.w, "\r\x1b[K%s", l.line(t))
	l.shown = true
}

// line is the live line fitted to the terminal width: the first file in
// flight, "+N" after its place for N others.
func (l *dirLive) line(t time.Time) string {
	f := &liveFile{size: -1}
	if len(l.active) > 0 {
		f = l.active[0]
	}
	digits := len(fmt.Sprint(l.count))
	head := fmt.Sprintf("[%*d/%d] ", digits, f.index, l.count)
	if n := len(l.active) - 1; n > 0 {
		head = fmt.Sprintf("[%*d/%d +%d] ", digits, f.index, l.count, n)
	}
	var rate int64
	if !f.fileStart.IsZero() {
		rate = rateOf(f.fileDone, t.Sub(f.fileStart))
	}
	tail := fmt.Sprintf("  %s  %s/s   total %s", pairText(f.fileDone, f.size), client.HumanBytes(rate), pairText(l.done, l.total))
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
	return cutRunes(head+middleCut(f.name, room)+tail, width-1)
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
