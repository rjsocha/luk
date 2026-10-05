package queue

import (
	"sync"
	"time"
)

// Acceptance is the acceptance order of a queue entry: when the receive
// role committed it, in Unix nanoseconds (NS), and Seq, which orders
// entries committed within the same nanosecond by one process.
type Acceptance struct {
	NS  int64
	Seq int
}

// Compare orders a and b: by NS, then by Seq.
func (a Acceptance) Compare(b Acceptance) int {
	switch {
	case a.NS < b.NS:
		return -1
	case a.NS > b.NS:
		return 1
	case a.Seq < b.Seq:
		return -1
	case a.Seq > b.Seq:
		return 1
	}
	return 0
}

// Accepted hands out acceptance orders that never go backwards while the
// process runs: the wall clock read once at the start plus the time
// elapsed since, measured on the monotonic clock, so a step of the wall
// clock (NTP, an administrator) does not reorder the entries of the
// process. Two calls within the same nanosecond get increasing Seq. A new
// process starts from the wall clock again: a wall clock moved back by
// more than the restart took can order its first entries before the last
// ones of the previous process.
type Accepted struct {
	start   time.Time
	elapsed func() time.Duration

	mu   sync.Mutex
	last Acceptance
}

// NewAccepted starts the acceptance clock of the process.
func NewAccepted() *Accepted {
	start := time.Now()
	return newAccepted(start, func() time.Duration { return time.Since(start) })
}

func newAccepted(start time.Time, elapsed func() time.Duration) *Accepted {
	return &Accepted{start: start, elapsed: elapsed}
}

// Next is the acceptance order of an entry committed now.
func (a *Accepted) Next() Acceptance {
	a.mu.Lock()
	defer a.mu.Unlock()
	ns := a.start.UnixNano() + int64(a.elapsed())
	if ns <= a.last.NS {
		a.last.Seq++
	} else {
		a.last = Acceptance{NS: ns}
	}
	return a.last
}
