package client

import (
	"fmt"
	"io"
	"sync"
	"time"
)

const progressInterval = 200 * time.Millisecond

// progressReader reports on w how much of the body the transport has read.
// total < 0 means the size is unknown.
type progressReader struct {
	r     io.Reader
	w     io.Writer
	total int64
	now   func() time.Time
	start time.Time
	last  time.Time
	n     int64
}

func newProgress(r io.Reader, w io.Writer, total int64, now func() time.Time) *progressReader {
	return &progressReader{r: r, w: w, total: total, now: now}
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		t := p.now()
		if p.start.IsZero() {
			p.start, p.last = t, t
		}
		p.n += int64(n)
		if t.Sub(p.last) >= progressInterval {
			p.last = t
			fmt.Fprintf(p.w, "\r\x1b[K%s", p.line(t))
		}
	}
	return n, err
}

func (p *progressReader) line(t time.Time) string {
	return progressLine(p.n, p.total, t.Sub(p.start))
}

// progressLine is the live line of n of total bytes moved in el; total <
// 0 means the size is unknown.
func progressLine(n, total int64, el time.Duration) string {
	rate := rateOf(n, el)
	if total < 0 {
		return fmt.Sprintf("%s  %s/s", HumanBytes(n), HumanBytes(rate))
	}
	pct := 100.0
	if total > 0 {
		pct = float64(n) * 100 / float64(total)
	}
	s := fmt.Sprintf("%s / %s  %.0f%%  %s/s", HumanBytes(n), HumanBytes(total), pct, HumanBytes(rate))
	if rate > 0 && n < total {
		eta := time.Duration(float64(total-n) / float64(rate) * float64(time.Second))
		s += fmt.Sprintf("  ETA %d:%02d", int(eta.Minutes()), int(eta.Seconds())%60)
	}
	return s
}

// partsMeter reports the progress of an upload in parts on w: the bytes
// of the verified parts plus those of the parts in flight. A failed
// attempt takes its bytes back, but the line never goes back: it holds
// until the count passes what it showed. A nil meter reports nothing.
type partsMeter struct {
	mu    sync.Mutex
	w     io.Writer
	total int64
	now   func() time.Time
	start time.Time
	last  time.Time
	n     int64
	shown int64
}

func newPartsMeter(w io.Writer, total int64, now func() time.Time) *partsMeter {
	if w == nil {
		return nil
	}
	return &partsMeter{w: w, total: total, now: now}
}

// add counts d more bytes (fewer when negative).
func (m *partsMeter) add(d int64) {
	if m == nil || d == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.now()
	if m.start.IsZero() {
		m.start, m.last = t, t
	}
	m.n += d
	m.shown = max(m.shown, m.n)
	if d > 0 && t.Sub(m.last) >= progressInterval {
		m.last = t
		fmt.Fprintf(m.w, "\r\x1b[K%s", progressLine(m.shown, m.total, t.Sub(m.start)))
	}
}

// restart counts from zero again, for an upload sent anew; the line holds
// what it showed until the new count passes it.
func (m *partsMeter) restart() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n = 0
}

// finish replaces the live line with a summary of the bytes that arrived;
// it prints nothing when no part went out.
func (m *partsMeter) finish() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.start.IsZero() {
		return
	}
	el := m.now().Sub(m.start)
	fmt.Fprintf(m.w, "\r\x1b[K%s in %s, %s/s\n", HumanBytes(m.n), el.Round(100*time.Millisecond), HumanBytes(rateOf(m.n, el)))
}

// Finish replaces the live line with a summary; it prints nothing when no
// body byte was read.
func (p *progressReader) Finish() {
	if p.start.IsZero() {
		return
	}
	el := p.now().Sub(p.start)
	fmt.Fprintf(p.w, "\r\x1b[K%s in %s, %s/s\n", HumanBytes(p.n), el.Round(100*time.Millisecond), HumanBytes(rateOf(p.n, el)))
}

func rateOf(n int64, d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(float64(n) / d.Seconds())
}

// HumanBytes is n in binary units with one decimal: 512 B, 1.5 MiB.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, i := float64(n), 0
	for ; v >= unit && i < 4; i++ {
		v /= unit
	}
	return fmt.Sprintf("%.1f %ciB", v, "KMGT"[i-1])
}
