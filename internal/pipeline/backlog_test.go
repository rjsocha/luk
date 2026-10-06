package pipeline

import (
	"testing"
	"time"
)

func TestQueueStatusOldest(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - store: a\n")
	now := time.Now()
	if q := QueueStatus(e.cfg, now); q.Entries != 0 || q.OldestID != "" || q.OldestAge != nil {
		t.Fatalf("%+v", q)
	}
	e.enqueue(t, "20261006T100000Z-0a1b2c3d", "up", "p")
	e.enqueue(t, "20261006T100500Z-0a1b2c3e", "up", "p")
	q := QueueStatus(e.cfg, now)
	if q.Entries != 2 || q.OldestID != "20261006T100000Z-0a1b2c3d" || q.OldestReceived == "" || q.OldestAge == nil || *q.OldestAge < 0 {
		t.Fatalf("%+v", q)
	}
}
