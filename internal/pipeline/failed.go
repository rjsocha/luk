package pipeline

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"luk/internal/config"
	"luk/internal/queue"
	"luk/internal/status"
	"luk/internal/wire"
)

// ErrUnknownID is returned for an id with no failure record.
var ErrUnknownID = errors.New("no failure record with this id")

// FailedDir holds the failure records of the queue directory qdir.
func FailedDir(qdir string) string { return filepath.Join(qdir, queue.FailedName) }

// recordExt is the extension of a failure record: failed/<id>.json.
const recordExt = ".json"

// Record is the failure record of an upload whose pipelines all ended,
// one or more of them failed: what the upload was and how each pipeline
// ended. It holds nothing of the content: the queue entry is deleted
// once the record is written, and the sender has to send the upload
// again. Origin is the backup hostname of the upload, else the sender;
// Secret the secret storage of a secret upload; FailedAt when the record
// was written.
type Record struct {
	ID          string    `json:"id"`
	Endpoint    string    `json:"endpoint"`
	Sender      string    `json:"sender"`
	Origin      string    `json:"origin"`
	Received    string    `json:"received"`
	Accepted    int64     `json:"accepted,omitempty"`
	AcceptedSeq int       `json:"accepted_seq,omitempty"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	Client      wire.Meta `json:"client"`
	Secret      string    `json:"secret,omitempty"`
	FailedAt    string    `json:"failed_at"`
	Pipelines   []Outcome `json:"pipelines"`

	path string
	at   time.Time
}

// newRecord is the failure record of j whose pipelines ended with results.
func newRecord(j Job, results []Outcome, now time.Time) Record {
	sc := j.Sidecar
	out := Record{
		ID: j.Entry.ID, Endpoint: sc.Endpoint, Sender: sc.Sender, Origin: cmp.Or(j.Vars.Hostname, j.Vars.Sender, sc.Sender),
		Received: sc.Received, Accepted: sc.Accepted, AcceptedSeq: sc.AcceptedSeq, Size: sc.Size, SHA256: sc.SHA256,
		Client: sc.Client, Secret: j.Secret, FailedAt: now.UTC().Format(time.RFC3339),
		Pipelines: append([]Outcome(nil), results...),
	}
	sort.SliceStable(out.Pipelines, func(a, b int) bool { return out.Pipelines[a].Pipeline < out.Pipelines[b].Pipeline })
	return out
}

// failedNames are the pipelines of results that did not end ok.
func failedNames(results []Outcome) []string {
	var out []string
	for _, o := range results {
		if o.Failed() {
			out = append(out, o.Pipeline)
		}
	}
	sort.Strings(out)
	return out
}

// writeRecord writes r as failed/<id>.json of the queue directory qdir
// (temporary file, sync, rename). A failed sync of the directory after the
// rename is returned wrapped in queue.ErrNotSynced: the record is in
// place.
func writeRecord(qdir string, r Record) error {
	dir := FailedDir(qdir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+r.ID+recordExt+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, r.ID+recordExt))
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("%w: %w", queue.ErrNotSynced, err)
	}
	return nil
}

// QueueDirs returns the queue directories of the endpoints, their secret
// queues included, sorted.
func QueueDirs(cfg *config.Config) []string {
	seen := map[string]bool{}
	var dirs []string
	for _, e := range cfg.Endpoint {
		ps := []string{e.Path}
		if e.Secret != nil {
			ps = append(ps, e.Secret.Path)
		}
		for _, p := range ps {
			if p != "" && !seen[p] {
				seen[p] = true
				dirs = append(dirs, p)
			}
		}
	}
	sort.Strings(dirs)
	return dirs
}

// ListFailed returns the failure records of every queue directory, oldest
// first. Records that cannot be read are skipped.
func ListFailed(cfg *config.Config) ([]Record, error) {
	var out []Record
	var errs []error
	for _, qdir := range QueueDirs(cfg) {
		dir := FailedDir(qdir)
		ents, err := os.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, d := range ents {
			name := d.Name()
			if !d.Type().IsRegular() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, recordExt) {
				continue
			}
			if r, err := readRecord(filepath.Join(dir, name)); err == nil {
				out = append(out, r)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].at.Equal(out[j].at) {
			return out[i].at.Before(out[j].at)
		}
		return out[i].ID < out[j].ID
	})
	return out, errors.Join(errs...)
}

func readRecord(path string) (Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Record{}, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return Record{}, fmt.Errorf("%s: %w", path, err)
	}
	r.ID, r.path = strings.TrimSuffix(filepath.Base(path), recordExt), path
	if at, err := time.Parse(time.RFC3339, r.FailedAt); err == nil {
		r.at = at
	}
	return r, nil
}

// At is when the record was written; zero when unknown.
func (r Record) At() time.Time { return r.at }

func findFailed(cfg *config.Config, id string) (Record, error) {
	if id == "" || strings.HasPrefix(id, ".") || filepath.Base(id) != id {
		return Record{}, fmt.Errorf("%q: %w", id, ErrUnknownID)
	}
	for _, qdir := range QueueDirs(cfg) {
		p := filepath.Join(FailedDir(qdir), id+recordExt)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		return readRecord(p)
	}
	return Record{}, fmt.Errorf("%s: %w", id, ErrUnknownID)
}

// FailedCounts counts the failure records per pipeline that did not end
// ok (failed or not run) and sender.
func FailedCounts(cfg *config.Config) map[status.Key]int {
	list, _ := ListFailed(cfg)
	counts := map[status.Key]int{}
	for _, r := range list {
		for _, o := range r.Pipelines {
			if o.Failed() {
				counts[status.Key{Pipeline: o.Pipeline, Sender: r.Sender}]++
			}
		}
	}
	return counts
}

// RemoveFailed deletes the failure record id.
func RemoveFailed(cfg *config.Config, id string) error {
	r, err := findFailed(cfg, id)
	if err != nil {
		return err
	}
	return os.Remove(r.path)
}

// ExpireFailed removes the failure records written longer than age ago;
// age 0 keeps them. A record without a readable time is kept.
func ExpireFailed(cfg *config.Config, age time.Duration, now time.Time, log *slog.Logger) {
	if age <= 0 {
		return
	}
	list, err := ListFailed(cfg)
	if err != nil {
		log.Warn("failure records: listing", "error", err)
	}
	for _, r := range list {
		if r.at.IsZero() || now.Sub(r.at) <= age {
			continue
		}
		if err := os.Remove(r.path); err != nil {
			log.Warn("failure record not removed", "id", r.ID, "error", err)
			continue
		}
		log.Info("failure record expired", "id", r.ID, "pipelines", strings.Join(failedNames(r.Pipelines), ","))
	}
}

// EntryIDs returns the ids of the entries in every queue directory.
func EntryIDs(cfg *config.Config) map[string]bool {
	ids := map[string]bool{}
	for _, qdir := range QueueDirs(cfg) {
		ents, _ := os.ReadDir(qdir)
		for _, d := range ents {
			if d.IsDir() && d.Name() != queue.FailedName {
				ids[d.Name()] = true
			}
		}
	}
	return ids
}

// RefreshFailed recomputes the failed counts of the status from the
// failure records.
func (d *Dispatcher) RefreshFailed() {
	if d.status == nil {
		return
	}
	d.failMu.Lock()
	defer d.failMu.Unlock()
	if err := d.status.SetFailed(FailedCounts(d.config())); err != nil {
		d.log.Warn("status not written", "error", err)
	}
}

// Pickup submits the accepted entries of every queue directory that are not
// in flight or parked: the fallback of the commit watch. It looks into the
// queue directories of every configuration since the start. Parked entries
// due are settled again first.
func (d *Dispatcher) Pickup() {
	d.retryParked()
	for _, qdir := range d.queueDirs() {
		pending, err := queue.Pending(qdir)
		if err != nil {
			continue
		}
		for _, e := range pending {
			if d.running(e.Dir) {
				continue
			}
			j, err := LoadJob(e)
			if err != nil {
				continue
			}
			if err := d.Submit(j); err != nil {
				return
			}
		}
	}
}

func (d *Dispatcher) running(dir string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.busy(dir)
}

// Maintain is the janitor pass of the queue: expiry of failure records,
// failed counts and pickup of committed entries.
func (d *Dispatcher) Maintain(now time.Time) {
	cfg := d.config()
	ExpireFailed(cfg, cfg.Limits.Failed.MaxAge(), now, d.log)
	d.RefreshFailed()
	d.Pickup()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
