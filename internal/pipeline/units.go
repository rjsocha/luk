package pipeline

import (
	"sync"
	"time"

	"luk/internal/status"
)

// unitGauge counts the units of the run steps for status.json: running
// from the s frame to the end of the step, waiting from the connection to
// the s frame. Nested jobs are not counted.
type unitGauge struct {
	mu      sync.Mutex
	running int
	next    uint64
	waiting map[uint64]time.Time
}

// wait counts a step that asks for its unit; the token names it.
func (g *unitGauge) wait() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.waiting == nil {
		g.waiting = map[uint64]time.Time{}
	}
	g.next++
	g.waiting[g.next] = time.Now()
	return g.next
}

// start moves the step tok from waiting to running.
func (g *unitGauge) start(tok uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.waiting, tok)
	g.running++
}

// end drops the step tok, running when started.
func (g *unitGauge) end(tok uint64, started bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if started {
		g.running--
		return
	}
	delete(g.waiting, tok)
}

func (g *unitGauge) snapshot(now time.Time) (running, waiting int, oldestWait int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, t := range g.waiting {
		oldestWait = max(oldestWait, int64(now.Sub(t)/time.Second))
	}
	return g.running, len(g.waiting), oldestWait
}

// Units is the gauge of the units of the run steps at now.
func (d *Dispatcher) Units(now time.Time) status.Units {
	r, w, o := d.units.snapshot(now)
	return status.Units{Running: r, Waiting: w, OldestWait: o}
}
