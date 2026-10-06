package pipeline

import (
	"path/filepath"
	"time"

	"luk/internal/config"
	"luk/internal/queue"
	"luk/internal/status"
	"luk/internal/workspace"
)

// QueueStatus describes the committed queue entries of every queue
// directory at now: their number and the oldest by acceptance order.
func QueueStatus(cfg *config.Config, now time.Time) status.Queue {
	var q status.Queue
	var best queue.Entry
	var bestAt queue.Acceptance
	for _, dir := range QueueDirs(cfg) {
		es, err := queue.Pending(dir)
		if err != nil || len(es) == 0 {
			continue
		}
		q.Entries += len(es)
		at := queue.AcceptanceOf(filepath.Join(es[0].Dir, "meta.json"))
		if c := at.Compare(bestAt); best.ID == "" || c < 0 || (c == 0 && es[0].ID < best.ID) {
			best, bestAt = es[0], at
		}
	}
	if best.ID == "" {
		return q
	}
	q.OldestID = best.ID
	var since time.Time
	if j, err := LoadJob(best); err == nil {
		q.OldestReceived = j.Sidecar.Received
		since, _ = time.Parse(time.RFC3339, j.Sidecar.Received)
	}
	if since.IsZero() && bestAt.NS != 0 {
		since = time.Unix(0, bestAt.NS)
	}
	age := max(int64(now.Sub(since)/time.Second), 0)
	if since.IsZero() {
		age = 0
	}
	q.OldestAge = &age
	return q
}

// countPath is the count file of the leftover workspaces.
var countPath = filepath.Join(workspace.CountDir, workspace.CountName)

// RefreshRuntime writes the units, the queue and the count of leftover
// workspaces at now to the status. A count that cannot be read is
// reported in the workspaces record, not as 0.
func (d *Dispatcher) RefreshRuntime(now time.Time) {
	if d.status == nil {
		return
	}
	var ws *status.Workspaces
	c, err := workspace.ReadCount(countPath)
	switch {
	case err != nil:
		d.log.Warn("workspace count not read", "error", err)
		ws = &status.Workspaces{Error: err.Error()}
	case c != nil:
		ws = &status.Workspaces{Leftover: c.Leftover, Updated: c.Updated}
	}
	if err := d.status.SetRuntime(d.Units(now), QueueStatus(d.config(), now), ws); err != nil {
		d.log.Warn("status not written", "error", err)
	}
}
