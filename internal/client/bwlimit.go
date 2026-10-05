package client

import (
	"context"
	"io"
	"sync"
	"time"
)

// limitReader paces reads to rate bytes per second: a read waits until the
// bytes already delivered fit the budget, so the burst is one chunk.
type limitReader struct {
	ctx   context.Context
	r     io.Reader
	rate  int64
	start time.Time
	n     int64
}

func newLimitReader(ctx context.Context, r io.Reader, rate int64) *limitReader {
	return &limitReader{ctx: ctx, r: r, rate: rate}
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.start.IsZero() {
		l.start = time.Now()
	}
	due := l.start.Add(time.Duration(float64(l.n) / float64(l.rate) * float64(time.Second)))
	if d := time.Until(due); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-l.ctx.Done():
			t.Stop()
			return 0, l.ctx.Err()
		}
	}
	if err := l.ctx.Err(); err != nil {
		return 0, err
	}
	if chunk := max(l.rate/10, 1); int64(len(p)) > chunk {
		p = p[:chunk]
	}
	n, err := l.r.Read(p)
	l.n += int64(n)
	return n, err
}

// pacer is a rate of rate bytes per second shared by the readers it
// paces, so parts sent in parallel share one --bwlimit.
type pacer struct {
	mu    sync.Mutex
	rate  int64
	start time.Time
	n     int64
}

func newPacer(rate int64) *pacer {
	if rate <= 0 {
		return nil
	}
	return &pacer{rate: rate}
}

// reader paces r by p; a nil p leaves r as it is.
func (p *pacer) reader(ctx context.Context, r io.Reader) io.Reader {
	if p == nil {
		return r
	}
	return &pacedReader{p: p, ctx: ctx, r: r}
}

type pacedReader struct {
	p   *pacer
	ctx context.Context
	r   io.Reader
}

// Read books its chunk in the budget before it waits, so readers in
// parallel queue behind each other instead of bursting together.
func (pr *pacedReader) Read(b []byte) (int, error) {
	p := pr.p
	chunk := min(int64(len(b)), max(p.rate/10, 1))
	p.mu.Lock()
	if p.start.IsZero() {
		p.start = time.Now()
	}
	due := p.start.Add(time.Duration(float64(p.n) / float64(p.rate) * float64(time.Second)))
	p.n += chunk
	p.mu.Unlock()
	if d := time.Until(due); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-pr.ctx.Done():
			t.Stop()
			pr.unbook(chunk)
			return 0, pr.ctx.Err()
		}
	}
	n, err := pr.r.Read(b[:chunk])
	pr.unbook(chunk - int64(n))
	return n, err
}

func (pr *pacedReader) unbook(k int64) {
	if k > 0 {
		pr.p.mu.Lock()
		pr.p.n -= k
		pr.p.mu.Unlock()
	}
}
