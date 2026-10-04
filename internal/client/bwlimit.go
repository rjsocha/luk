package client

import (
	"context"
	"io"
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
