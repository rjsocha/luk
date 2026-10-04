package pipeline

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"luk/internal/config"
	"luk/internal/queue"
	"luk/internal/status"
)

// ErrUnknownID is returned for an id with no failed entry.
var ErrUnknownID = errors.New("no failed entry with this id")

// FailedDir holds the failed entries of the queue directory qdir.
func FailedDir(qdir string) string { return filepath.Join(qdir, queue.FailedName) }

// FailedEntry is an entry in a failed/ directory.
type FailedEntry struct {
	ID, Dir string
	Meta    QueueMeta
	// At is the newest failure time; zero when none is readable.
	At time.Time
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

// ListFailed returns the failed entries of every queue directory, oldest
// failure first. Entries with an unreadable meta.json are skipped.
func ListFailed(cfg *config.Config) ([]FailedEntry, error) {
	var out []FailedEntry
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
			if !d.IsDir() {
				continue
			}
			if f, err := readFailed(filepath.Join(dir, d.Name())); err == nil {
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.Before(out[j].At)
		}
		return out[i].ID < out[j].ID
	})
	return out, errors.Join(errs...)
}

func readFailed(dir string) (FailedEntry, error) {
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return FailedEntry{}, err
	}
	f := FailedEntry{ID: filepath.Base(dir), Dir: dir}
	if err := json.Unmarshal(b, &f.Meta); err != nil {
		return FailedEntry{}, err
	}
	for _, x := range f.Meta.Failed {
		if at, err := time.Parse(time.RFC3339, x.At); err == nil && at.After(f.At) {
			f.At = at
		}
	}
	return f, nil
}

func findFailed(cfg *config.Config, id string) (FailedEntry, error) {
	if id == "" || id == "." || id == ".." || filepath.Base(id) != id {
		return FailedEntry{}, fmt.Errorf("%q: %w", id, ErrUnknownID)
	}
	for _, qdir := range QueueDirs(cfg) {
		dir := filepath.Join(FailedDir(qdir), id)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		return readFailed(dir)
	}
	return FailedEntry{}, fmt.Errorf("%s: %w", id, ErrUnknownID)
}

// FailedCounts counts the failed entries per failed pipeline and sender.
func FailedCounts(cfg *config.Config) map[status.Key]int {
	list, _ := ListFailed(cfg)
	counts := map[status.Key]int{}
	for _, f := range list {
		for _, x := range f.Meta.Failed {
			counts[status.Key{Pipeline: x.Pipeline, Sender: f.Meta.Sidecar.Sender}]++
		}
	}
	return counts
}

// RemoveFailed deletes the failed entry id and its work directories.
func RemoveFailed(cfg *config.Config, id string) error {
	f, err := findFailed(cfg, id)
	if err != nil {
		return err
	}
	return removeFailed(cfg, f)
}

func removeFailed(cfg *config.Config, f FailedEntry) error {
	if err := os.RemoveAll(f.Dir); err != nil {
		return err
	}
	if w := cfg.WorkDir(); w != "" {
		return os.RemoveAll(filepath.Join(w, f.ID))
	}
	return nil
}

// RetryFailed moves the failed entry id back into its queue directory with
// the given failed pipelines (all when none) left to run and returns them;
// the work directories of the others are removed.
func RetryFailed(cfg *config.Config, id string, pipelines []string) ([]string, error) {
	f, err := findFailed(cfg, id)
	if err != nil {
		return nil, err
	}
	var failed []string
	for _, x := range f.Meta.Failed {
		failed = append(failed, x.Pipeline)
	}
	run := failed
	if len(pipelines) > 0 {
		run = nil
		for _, p := range pipelines {
			if !slices.Contains(failed, p) {
				return nil, fmt.Errorf("%s: pipeline %q did not fail (failed: %s)", id, p, strings.Join(failed, ","))
			}
			if !slices.Contains(run, p) {
				run = append(run, p)
			}
		}
	}
	if len(run) == 0 {
		return nil, fmt.Errorf("%s: no failed pipeline", id)
	}
	if w := cfg.WorkDir(); w != "" {
		for _, p := range failed {
			if !slices.Contains(run, p) {
				if err := os.RemoveAll(filepath.Join(w, id, p)); err != nil {
					return nil, err
				}
			}
		}
	}
	m := f.Meta
	m.Pipelines, m.Failed = run, nil
	e := queue.Entry{Dir: f.Dir, ID: id}
	if err := queue.New(0, nil).Commit(e, m); err != nil && !errors.Is(err, queue.ErrNotSynced) {
		return nil, err
	}
	return run, moveEntry(f.Dir, filepath.Join(filepath.Dir(filepath.Dir(f.Dir)), id))
}

// ExpireFailed removes failed entries whose newest failure is older than
// age, with their work directories; age 0 keeps them. An entry without a
// readable failure time is kept.
func ExpireFailed(cfg *config.Config, age time.Duration, now time.Time, log *slog.Logger) {
	if age <= 0 {
		return
	}
	list, err := ListFailed(cfg)
	if err != nil {
		log.Warn("failed entries: listing", "error", err)
	}
	for _, f := range list {
		if f.At.IsZero() || now.Sub(f.At) <= age {
			continue
		}
		if err := removeFailed(cfg, f); err != nil {
			log.Warn("failed entry not removed", "id", f.ID, "error", err)
			continue
		}
		log.Info("failed entry expired", "id", f.ID, "pipelines", strings.Join(f.Meta.Pipelines, ","))
	}
}

// EntryIDs returns the ids of the entries in every queue directory and its
// failed/ directory.
func EntryIDs(cfg *config.Config) map[string]bool {
	ids := map[string]bool{}
	for _, qdir := range QueueDirs(cfg) {
		for _, dir := range []string{qdir, FailedDir(qdir)} {
			ents, _ := os.ReadDir(dir)
			for _, d := range ents {
				if d.IsDir() && !(dir == qdir && d.Name() == queue.FailedName) {
					ids[d.Name()] = true
				}
			}
		}
	}
	return ids
}

// RefreshFailed recomputes the failed counts of the status from the failed/
// directories.
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
// in flight or parked, such as those put back by `lukd queue retry`. It
// looks into the queue directories of every configuration since the
// start. Parked entries due are settled again first.
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

// Maintain is the janitor pass of the queue: expiry of failed entries,
// failed counts and pickup of entries put back into the queue.
func (d *Dispatcher) Maintain(now time.Time) {
	cfg := d.config()
	ExpireFailed(cfg, cfg.Limits.Failed.MaxAge(), now, d.log)
	d.RefreshFailed()
	d.Pickup()
}

func moveEntry(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
		return err
	}
	if _, err := os.Lstat(to); err == nil {
		return fmt.Errorf("%s: already exists", to)
	}
	if err := os.Rename(from, to); err != nil {
		return err
	}
	for _, dir := range []string{filepath.Dir(from), filepath.Dir(to)} {
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
