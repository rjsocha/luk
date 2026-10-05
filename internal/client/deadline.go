package client

import (
	"context"
	"io"
	"sync"
	"time"
)

const (
	// defaultDecision is the decision timeout: the wait for the headers of
	// an answer.
	defaultDecision = 60 * time.Second
	// defaultIdle is the idle timeout: the longest wait for the server
	// while the body moves, and for the answer after the body.
	defaultIdle = 2 * time.Minute
)

// orDefault is d, def for 0; a negative d is an error.
func orDefault(d, def time.Duration, what string) (time.Duration, error) {
	if d < 0 {
		return 0, &negativeError{what, d}
	}
	if d == 0 {
		return def, nil
	}
	return d, nil
}

type negativeError struct {
	what string
	d    time.Duration
}

func (e *negativeError) Error() string { return "negative " + e.what + " " + e.d.String() }

// decider cancels a request that has no decision within its wait.
// Whichever of decide and the timer runs first wins, so a decided request
// is never cut.
type decider struct {
	mu       sync.Mutex
	decided  bool
	timedOut bool
	t        *time.Timer
}

func newDecider(wait time.Duration, cancel context.CancelFunc) *decider {
	d := &decider{}
	d.t = time.AfterFunc(wait, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if !d.decided {
			d.timedOut = true
			cancel()
		}
	})
	return d
}

// decide marks the request decided unless the timer cut it first, and
// reports whether it is decided.
func (d *decider) decide() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.timedOut {
		d.decided = true
	}
	return d.decided
}

func (d *decider) stop() { d.t.Stop() }

// watchdog cancels a request that waits for the server longer than its
// idle time: it is armed only while luk waits for the server, never while
// the server waits for luk (a slow source, a slow output, --bwlimit).
type watchdog struct {
	idle   time.Duration
	cancel context.CancelFunc
	mu     sync.Mutex
	gen    int
	t      *time.Timer
	off    bool
	fired  bool
}

func newWatchdog(idle time.Duration, cancel context.CancelFunc) *watchdog {
	return &watchdog{idle: idle, cancel: cancel}
}

// arm starts the idle time anew.
func (w *watchdog) arm() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.off {
		return
	}
	w.gen++
	g := w.gen
	if w.t != nil {
		w.t.Stop()
	}
	w.t = time.AfterFunc(w.idle, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.gen == g && !w.off {
			w.fired = true
			w.cancel()
		}
	})
}

// disarm stops the idle time until the next arm.
func (w *watchdog) disarm() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gen++
	if w.t != nil {
		w.t.Stop()
		w.t = nil
	}
}

// stop disarms the watchdog for good and reports whether it fired.
func (w *watchdog) stop() bool {
	w.disarm()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.off = true
	return w.fired
}

// hasFired reports whether the watchdog cut the request.
func (w *watchdog) hasFired() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fired
}

// stalledError is a request the watchdog cut.
type stalledError struct{ idle time.Duration }

func (e *stalledError) Error() string { return "no progress for " + seconds(e.idle) }

// sendIdle is a request body: the watchdog runs from the moment a chunk is
// handed to the transport until it asks for the next one, and after the
// last one until the answer comes.
type sendIdle struct {
	r io.Reader
	w *watchdog
}

func (s *sendIdle) Read(p []byte) (int, error) {
	s.w.disarm()
	n, err := s.r.Read(p)
	s.w.arm()
	return n, err
}

// readIdle is an answer body: the watchdog runs during each read, and a
// read it cut fails with a stalledError. Close also ends the request
// context (done).
type readIdle struct {
	r    io.ReadCloser
	w    *watchdog
	done context.CancelFunc
}

func (r *readIdle) Read(p []byte) (int, error) {
	r.w.arm()
	n, err := r.r.Read(p)
	r.w.disarm()
	if err != nil && err != io.EOF && r.w.hasFired() {
		err = &stalledError{r.w.idle}
	}
	return n, err
}

func (r *readIdle) Close() error {
	err := r.r.Close()
	r.w.stop()
	r.done()
	return err
}
