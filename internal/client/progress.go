package client

import (
	"fmt"
	"io"
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
	el := t.Sub(p.start)
	rate := rateOf(p.n, el)
	if p.total < 0 {
		return fmt.Sprintf("%s  %s/s", HumanBytes(p.n), HumanBytes(rate))
	}
	pct := 100.0
	if p.total > 0 {
		pct = float64(p.n) * 100 / float64(p.total)
	}
	s := fmt.Sprintf("%s / %s  %.0f%%  %s/s", HumanBytes(p.n), HumanBytes(p.total), pct, HumanBytes(rate))
	if rate > 0 && p.n < p.total {
		eta := time.Duration(float64(p.total-p.n) / float64(rate) * float64(time.Second))
		s += fmt.Sprintf("  ETA %d:%02d", int(eta.Minutes()), int(eta.Seconds())%60)
	}
	return s
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
