package pipeline

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"luk/internal/status"
)

// none parks no entry.
func none(string) bool { return false }

func TestQueueStatusSkipsParked(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - store: a\n")
	now := time.Now()
	e.enqueue(t, "20261006T100000Z-0a1b2c3d", "up", "p")
	e.enqueue(t, "20261006T100500Z-0a1b2c3e", "up", "p")
	parked := func(dir string) bool { return filepath.Base(dir) == "20261006T100000Z-0a1b2c3d" }
	q := QueueStatus(e.cfg, now, parked)
	if q.Entries != 1 || q.OldestID != "20261006T100500Z-0a1b2c3e" {
		t.Fatalf("%+v", q)
	}
}

func TestQueueStatusOldest(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - store: a\n")
	now := time.Now()
	if q := QueueStatus(e.cfg, now, none); q.Entries != 0 || q.OldestID != "" || q.OldestAge != nil {
		t.Fatalf("%+v", q)
	}
	e.enqueue(t, "20261006T100000Z-0a1b2c3d", "up", "p")
	e.enqueue(t, "20261006T100500Z-0a1b2c3e", "up", "p")
	q := QueueStatus(e.cfg, now, none)
	if q.Entries != 2 || q.OldestID != "20261006T100000Z-0a1b2c3d" || q.OldestReceived == "" || q.OldestAge == nil || *q.OldestAge < 0 {
		t.Fatalf("%+v", q)
	}
}

func TestQueueStatusAgeSecondDirAndTie(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - store: a\n")
	dir2 := filepath.Join(e.root, "data", "queue", "up2")
	if err := os.MkdirAll(dir2, 0o750); err != nil {
		t.Fatal(err)
	}
	ep := *e.cfg.Endpoint["up"]
	ep.Path = dir2
	e.cfg.Endpoint["up2"] = &ep
	now := time.Date(2026, 10, 6, 10, 10, 0, 0, time.UTC)
	same := func(j *Job) {
		j.Sidecar.Accepted, j.Sidecar.AcceptedSeq = 5, 1
		j.Sidecar.Received = now.Add(-90 * time.Second).Format(time.RFC3339)
	}
	e.enqueueWith(t, "20261006T100000Z-0000000b", "up", same, "p")
	e.enqueueWith(t, "20261006T100000Z-0000000a", "up2", same, "p")
	q := QueueStatus(e.cfg, now, none)
	if q.Entries != 2 || q.OldestID != "20261006T100000Z-0000000a" || q.OldestAge == nil || *q.OldestAge != 90 {
		t.Fatalf("%+v", q)
	}
	if q.OldestReceived != now.Add(-90*time.Second).Format(time.RFC3339) {
		t.Fatalf("%+v", q)
	}
	e.enqueueWith(t, "20261006T100100Z-0000000c", "up2", func(j *Job) {
		j.Sidecar.Accepted = 1
		j.Sidecar.Received = now.Format(time.RFC3339)
	}, "p")
	if q := QueueStatus(e.cfg, now, none); q.Entries != 3 || q.OldestID != "20261006T100100Z-0000000c" || *q.OldestAge != 0 {
		t.Fatalf("%+v", q)
	}
}

func TestRefreshRuntime(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - store: a\n")
	d := e.dispatcher()
	sp := filepath.Join(e.root, "status.json")
	d.SetStatus(status.New(sp))
	cp := filepath.Join(t.TempDir(), "count.json")
	old := countPath
	countPath = cp
	t.Cleanup(func() { countPath = old })
	ws := func() map[string]any {
		b, err := os.ReadFile(sp)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		w, _ := m["workspaces"].(map[string]any)
		return w
	}
	d.RefreshRuntime(time.Now())
	if w := ws(); w != nil {
		t.Fatalf("missing count: %v", w)
	}
	os.WriteFile(cp, []byte(`{"leftover":2,"updated":"2026-10-06T10:00:00Z"}`), 0o640)
	d.RefreshRuntime(time.Now())
	if w := ws(); w["leftover"] != float64(2) || w["updated"] != "2026-10-06T10:00:00Z" || w["error"] != nil {
		t.Fatalf("%v", w)
	}
	os.WriteFile(cp, []byte(`not json`), 0o640)
	d.RefreshRuntime(time.Now())
	if w := ws(); w["leftover"] != float64(0) || w["error"] == nil {
		t.Fatalf("%v", w)
	}
	warned := false
	for _, r := range e.logs.records(t) {
		warned = warned || r["msg"] == "workspace count not read"
	}
	if !warned {
		t.Fatal("no warning logged")
	}
}
