// Package pipeline runs the pipelines of accepted queue entries.
package pipeline

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"luk/internal/config"
	"luk/internal/gpgkeys"
	"luk/internal/queue"
	"luk/internal/status"
	"luk/internal/store"
	"luk/internal/watch"
)

var ErrClosed = errors.New("pipeline: dispatcher closed")

var errNotSupported = errors.New("not supported yet")

var hookRun = func(Job, string) {}

// hookQueue runs before the dispatcher changes a queue entry whose
// pipelines all ended: op is "commit" (meta.json of a failed entry),
// "move" (to failed/) or "remove"; an error fails that change.
var hookQueue = func(op string, e queue.Entry) error { return nil }

// QueueMeta is the meta.json of a queue entry: everything needed to rebuild
// the Job after a restart. Expires holds the expiry of each storage the
// upload is stored into (none: the sidecar expires for every storage).
// Failed holds the pipelines that failed so far. Secret is the storage of
// a secret upload, whose only pipeline is SecretPipeline. Stages holds the
// queue group and order of the grouped pipelines as configured at receipt
// (none: every pipeline runs concurrently).
type QueueMeta struct {
	Pipelines []string          `json:"pipelines"`
	Stages    map[string]Stage  `json:"stages,omitempty"`
	Vars      store.Vars        `json:"vars"`
	Sidecar   store.Sidecar     `json:"sidecar"`
	Expires   map[string]string `json:"expires,omitempty"`
	Failed    []Failure         `json:"failed,omitempty"`
	Replace   *Replace          `json:"replace,omitempty"`
	Secret    string            `json:"secret,omitempty"`
}

// SecretPipeline is the pipeline of a secret upload (endpoint secret): a
// single store into the secret storage. The name of a configured pipeline
// never starts with a dot.
const SecretPipeline = ".secret"

// Lookup is the pipeline name of cfg; SecretPipeline is the store into the
// storage secret (empty: it does not exist).
func Lookup(cfg *config.Config, name, secret string) (*config.Pipeline, bool) {
	if name == SecretPipeline {
		if secret == "" {
			return nil, false
		}
		return &config.Pipeline{Name: name, Queue: config.Queue{Concurrency: 1}, Steps: []config.Step{{Store: config.StringList{secret}}}}, true
	}
	p, ok := cfg.Pipeline[name]
	return p, ok
}

// Stage is the queue group of a pipeline and its order in the group.
type Stage struct {
	Group string `json:"group"`
	Order int    `json:"order"`
}

// Stages returns the stages of the grouped pipelines among names in cfg;
// nil when none of them has a group.
func Stages(cfg *config.Config, names []string) map[string]Stage {
	var out map[string]Stage
	for _, n := range names {
		if p, ok := cfg.Pipeline[n]; ok && p.Queue.Group != "" {
			if out == nil {
				out = map[string]Stage{}
			}
			out[n] = Stage{Group: p.Queue.Group, Order: p.Queue.Order}
		}
	}
	return out
}

// schedule splits names into the pipelines without a stage (free) and the
// groups, sorted by name, each a list of its orders ascending, each order
// the sorted names of its pipelines.
func schedule(names []string, stages map[string]Stage) (free []string, groups [][][]string) {
	byGroup := map[string][]string{}
	for _, n := range names {
		if st, ok := stages[n]; ok {
			byGroup[st.Group] = append(byGroup[st.Group], n)
		} else {
			free = append(free, n)
		}
	}
	for _, g := range sortedKeys(byGroup) {
		ns := byGroup[g]
		slices.SortFunc(ns, func(a, b string) int {
			return cmp.Or(cmp.Compare(stages[a].Order, stages[b].Order), strings.Compare(a, b))
		})
		var levels [][]string
		for i, n := range ns {
			if i == 0 || stages[n].Order != stages[ns[i-1]].Order {
				levels = append(levels, nil)
			}
			levels[len(levels)-1] = append(levels[len(levels)-1], n)
		}
		groups = append(groups, levels)
	}
	return free, groups
}

// Replace is the target of a link replace: the stored file Name, whose
// sidecar has the id ID, in Storage. A store into that storage puts the
// content in place of it instead of rendering a path; Updated is the time
// recorded in its sidecar.
type Replace struct {
	Storage string `json:"storage"`
	Name    string `json:"name"`
	ID      string `json:"id"`
	Updated string `json:"updated"`
}

// Failure is one failed pipeline of an entry: the step (0 before the first
// step), the error (at most status.MaxError bytes) and when it failed.
type Failure struct {
	Pipeline string `json:"pipeline"`
	Step     int    `json:"step"`
	Error    string `json:"error"`
	At       string `json:"at"`
}

type Job struct {
	Entry     queue.Entry
	Pipelines []string
	Stages    map[string]Stage
	Vars      store.Vars
	Sidecar   store.Sidecar
	Expires   map[string]string
	Failed    []Failure
	Replace   *Replace
	Secret    string
}

func (j Job) Meta() QueueMeta {
	return QueueMeta{Pipelines: j.Pipelines, Stages: j.Stages, Vars: j.Vars, Sidecar: j.Sidecar, Expires: j.Expires, Failed: j.Failed, Replace: j.Replace, Secret: j.Secret}
}

// LoadJob rebuilds a Job from the meta.json of an accepted entry.
func LoadJob(e queue.Entry) (Job, error) {
	b, err := os.ReadFile(filepath.Join(e.Dir, "meta.json"))
	if err != nil {
		return Job{}, err
	}
	var m QueueMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return Job{}, fmt.Errorf("%s: %w", e.Dir, err)
	}
	return Job{Entry: e, Pipelines: m.Pipelines, Stages: m.Stages, Vars: m.Vars, Sidecar: m.Sidecar, Expires: m.Expires, Failed: m.Failed, Replace: m.Replace, Secret: m.Secret}, nil
}

type Dispatcher struct {
	// cfg is the current configuration; a job takes it when a pipeline
	// starts and keeps it until the pipeline ends (see Reload).
	cfg atomic.Pointer[config.Config]
	q   *queue.Queue
	log *slog.Logger
	// keys holds the WKD client settings; the key directory, the cache and
	// its freshness come from the configuration of the pipeline.
	keys *gpgkeys.Resolver

	status *status.Store
	// failMu orders the failed counts written to the status.
	failMu sync.Mutex
	// watchMu orders the watch evaluations written to the status.
	watchMu sync.Mutex

	mu       sync.Mutex
	closed   bool
	stop     chan struct{}
	inflight map[string]struct{}
	// parked holds the entries, by directory, whose pipelines all ended
	// but that could not be moved to failed/ or removed (see settle).
	parked map[string]*parked
	now    func() time.Time
	slots  map[string]*slots
	// dirs is every queue directory of a configuration seen since the
	// start, so entries of an endpoint removed by a reload still run.
	dirs map[string]bool
	wg   sync.WaitGroup
}

func NewDispatcher(cfg *config.Config, q *queue.Queue, log *slog.Logger) *Dispatcher {
	d := &Dispatcher{q: q, log: log, inflight: map[string]struct{}{}, stop: make(chan struct{}),
		parked: map[string]*parked{}, now: time.Now,
		slots: map[string]*slots{}, dirs: map[string]bool{}, keys: &gpgkeys.Resolver{}}
	d.Reload(cfg)
	return d
}

// Reload makes cfg the configuration of the pipelines started from now on.
// Running pipelines keep theirs; a new concurrency limit of a pipeline
// applies to the runs started after it, without stopping running ones.
func (d *Dispatcher) Reload(cfg *config.Config) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for name, p := range cfg.Pipeline {
		sl := d.slots[name]
		if sl == nil {
			sl = &slots{wake: make(chan struct{})}
			d.slots[name] = sl
		}
		sl.setLimit(max(p.Queue.Concurrency, 1))
	}
	for _, dir := range QueueDirs(cfg) {
		d.dirs[dir] = true
	}
	d.cfg.Store(cfg)
}

// config is the current configuration.
func (d *Dispatcher) config() *config.Config { return d.cfg.Load() }

// queueDirs returns every queue directory known since the start, sorted.
func (d *Dispatcher) queueDirs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return sortedKeys(d.dirs)
}

func (d *Dispatcher) slotsOf(name string) *slots {
	d.mu.Lock()
	defer d.mu.Unlock()
	sl := d.slots[name]
	if sl == nil {
		sl = &slots{limit: 1, wake: make(chan struct{})}
		d.slots[name] = sl
	}
	return sl
}

// resolver is the recipient resolver of the gpg settings of cfg.
func (d *Dispatcher) resolver(cfg *config.Config) *gpgkeys.Resolver {
	r := *d.keys
	r.Dir, r.Cache, r.Fresh = cfg.GPG.Keys, cfg.GPGCacheDir(), time.Duration(cfg.GPG.WKD.Cache)
	return &r
}

// slots bounds the concurrent runs of one pipeline; the limit may change
// while runs hold slots.
type slots struct {
	mu    sync.Mutex
	used  int
	limit int
	// wake is closed and replaced whenever a slot may have become free.
	wake chan struct{}
}

func (s *slots) setLimit(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limit = n
	close(s.wake)
	s.wake = make(chan struct{})
}

// acquire waits for a free slot; false when stop is closed first.
func (s *slots) acquire(stop <-chan struct{}) bool {
	for {
		s.mu.Lock()
		if s.used < s.limit {
			s.used++
			s.mu.Unlock()
			return true
		}
		w := s.wake
		s.mu.Unlock()
		select {
		case <-w:
		case <-stop:
			return false
		}
	}
}

func (s *slots) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.used--
	close(s.wake)
	s.wake = make(chan struct{})
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// SetStatus makes the dispatcher record every pipeline result (done or
// failed; an interruption is not a result) in st. Call it before Submit.
func (d *Dispatcher) SetStatus(st *status.Store) { d.status = st }

// Submit starts the job in the background; an entry already in flight,
// parked or no longer in the queue (finished meanwhile) is ignored. After
// Close it returns ErrClosed and the entry stays in the queue for the
// next start.
func (d *Dispatcher) Submit(j Job) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return ErrClosed
	}
	if d.busy(j.Entry.Dir) {
		d.mu.Unlock()
		return nil
	}
	if _, err := os.Stat(filepath.Join(j.Entry.Dir, "meta.json")); err != nil {
		d.mu.Unlock()
		return nil
	}
	d.inflight[j.Entry.Dir] = struct{}{}
	d.wg.Add(1)
	d.mu.Unlock()
	go d.run(j)
	return nil
}

// Close stops accepting jobs and interrupts run steps (their process groups
// are killed) and pipelines still waiting for a slot; store steps finish. An
// entry with an interrupted pipeline stays in the queue for Resume. See Wait.
func (d *Dispatcher) Close() {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.stop)
	}
	d.mu.Unlock()
}

// Wait blocks until every submitted job finished.
func (d *Dispatcher) Wait() { d.wg.Wait() }

func (d *Dispatcher) run(j Job) {
	defer d.wg.Done()
	defer func() {
		d.mu.Lock()
		delete(d.inflight, j.Entry.Dir)
		d.mu.Unlock()
	}()
	var wg sync.WaitGroup
	var interrupted atomic.Bool
	var mu sync.Mutex
	var names []string
	for _, name := range j.Pipelines {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	remaining := slices.Clone(names)
	failed := slices.Clone(j.Failed)
	if j.Replace != nil {
		stop, fails := d.runReplace(j, names)
		if stop {
			return
		}
		failed, names = fails, nil
	}
	// done records the end of the pipeline name, f its failure.
	done := func(name string, f *Failure) {
		mu.Lock()
		defer mu.Unlock()
		remaining = slices.DeleteFunc(remaining, func(n string) bool { return n == name })
		if f != nil {
			failed = slices.DeleteFunc(failed, func(x Failure) bool { return x.Pipeline == name })
			failed = append(failed, *f)
		}
		if len(remaining) > 0 {
			d.finished(j, remaining, failed)
		}
	}
	// runOne runs the pipeline name and reports whether it failed.
	runOne := func(name string) bool {
		stop, f := d.runPipeline(j, name)
		if stop {
			interrupted.Store(true)
			return false
		}
		done(name, f)
		return f != nil
	}
	free, groups := schedule(names, j.Stages)
	for _, name := range free {
		wg.Go(func() { runOne(name) })
	}
	for _, levels := range groups {
		wg.Go(func() {
			for i, level := range levels {
				if i > 0 {
					select {
					case <-d.stop:
						interrupted.Store(true)
						return
					default:
					}
				}
				var lw sync.WaitGroup
				var lmu sync.Mutex
				var bad []string
				for _, name := range level {
					lw.Go(func() {
						if runOne(name) {
							lmu.Lock()
							bad = append(bad, name)
							lmu.Unlock()
						}
					})
				}
				lw.Wait()
				if len(bad) > 0 {
					// The later orders of the group never run: they fail
					// with the first failed pipeline as the reason.
					reason := fmt.Sprintf("not run: %s failed", slices.Min(bad))
					for _, later := range levels[i+1:] {
						for _, name := range later {
							done(name, d.skip(j, name, reason))
						}
					}
					return
				}
				if interrupted.Load() {
					return
				}
			}
		})
	}
	wg.Wait()
	if interrupted.Load() {
		return
	}
	d.settle(j, failed)
}

// parked is an entry whose pipelines all ended (failed holds the failed
// ones) but that could not be moved to failed/ or removed; it is retried
// at next, the n-th time.
type parked struct {
	job    Job
	failed []Failure
	n      int
	next   time.Time
}

// parkMax is the longest wait between two tries of a parked entry.
const parkMax = time.Hour

// busy reports whether the entry dir runs or is parked; d.mu held.
func (d *Dispatcher) busy(dir string) bool {
	_, run := d.inflight[dir]
	_, park := d.parked[dir]
	return run || park
}

// settle ends the entry of j whose pipelines all ended: it goes to
// failed/ when a pipeline failed, else it is removed. When that fails
// (a full disk, an I/O error) the entry stays in the queue and is parked:
// its pipelines never run again in this process, Pickup only retries the
// move or the removal, after a minute, doubling up to parkMax.
func (d *Dispatcher) settle(j Job, failed []Failure) {
	var ok bool
	if len(failed) > 0 {
		ok = d.moveFailed(j, failed)
	} else {
		if w := d.config().WorkDir(); w != "" {
			os.Remove(filepath.Join(w, j.Entry.ID))
		}
		ok = d.remove(j.Entry)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if ok {
		delete(d.parked, j.Entry.Dir)
		return
	}
	p := d.parked[j.Entry.Dir]
	if p == nil {
		p = &parked{job: j, failed: failed}
		d.parked[j.Entry.Dir] = p
	}
	p.n++
	wait := parkMax
	if p.n <= 7 {
		wait = min(time.Minute<<(p.n-1), parkMax)
	}
	p.next = d.now().Add(wait)
	d.log.Error("queue entry parked: its pipelines are not run again, the entry is retried", "id", j.Entry.ID, "attempt", p.n, "retry", wait)
}

// retryParked settles again the parked entries due now.
func (d *Dispatcher) retryParked() {
	now := d.now()
	var due []*parked
	d.mu.Lock()
	for dir, p := range d.parked {
		if _, ok := d.inflight[dir]; ok || d.closed || now.Before(p.next) {
			continue
		}
		d.inflight[dir] = struct{}{}
		due = append(due, p)
	}
	d.mu.Unlock()
	for _, p := range due {
		d.settle(p.job, p.failed)
		d.mu.Lock()
		delete(d.inflight, p.job.Entry.Dir)
		d.mu.Unlock()
	}
}

// remove deletes the entry e; true when it is gone or no longer pending
// (meta.json removed, the start cleanup takes the rest).
func (d *Dispatcher) remove(e queue.Entry) bool {
	err := hookQueue("remove", e)
	if err == nil {
		err = d.q.Remove(e)
	}
	if err == nil {
		return true
	}
	if _, serr := os.Lstat(filepath.Join(e.Dir, "meta.json")); errors.Is(serr, fs.ErrNotExist) {
		d.log.Warn("queue entry removed in part", "id", e.ID, "error", err)
		return true
	}
	d.log.Error("queue entry not removed", "id", e.ID, "error", err)
	return false
}

// moveFailed keeps only the failed pipelines in meta.json and moves the
// entry to failed/ of its queue directory; true when it is there. The
// rename needs no free blocks, so it is done even when meta.json could not
// be written: the entry then keeps the meta.json of its last update.
func (d *Dispatcher) moveFailed(j Job, failed []Failure) bool {
	slices.SortFunc(failed, func(a, b Failure) int { return strings.Compare(a.Pipeline, b.Pipeline) })
	m := j.Meta()
	m.Failed = failed
	m.Pipelines = nil
	for _, f := range failed {
		m.Pipelines = append(m.Pipelines, f.Pipeline)
	}
	cerr := hookQueue("commit", j.Entry)
	if cerr == nil {
		cerr = d.q.Commit(j.Entry, m)
	}
	if errors.Is(cerr, queue.ErrNotSynced) {
		d.log.Warn("queue entry updated", "id", j.Entry.ID, "error", cerr)
		cerr = nil
	}
	err := hookQueue("move", j.Entry)
	if err == nil {
		err = moveEntry(j.Entry.Dir, filepath.Join(FailedDir(filepath.Dir(j.Entry.Dir)), j.Entry.ID))
	}
	if err != nil {
		if _, serr := os.Lstat(j.Entry.Dir); errors.Is(serr, fs.ErrNotExist) {
			// Renamed; only a directory sync failed.
			d.log.Warn("queue entry moved to failed", "id", j.Entry.ID, "error", err)
			err = nil
		}
	}
	if err != nil {
		d.log.Error("queue entry not moved to failed", "id", j.Entry.ID, "error", err, "meta_error", cerr)
		return false
	}
	if cerr != nil {
		d.log.Error("queue entry moved to failed without its failures recorded", "id", j.Entry.ID, "pipelines", strings.Join(m.Pipelines, ","), "error", cerr)
	} else {
		d.log.Warn("queue entry failed", "id", j.Entry.ID, "pipelines", strings.Join(m.Pipelines, ","))
	}
	d.RefreshFailed()
	return true
}

// errorText is the error with as much of the output tail as fits in
// status.MaxError.
func errorText(err error, output string) string {
	s := err.Error()
	if budget := status.MaxError - len(s) - 1; output != "" && budget > 0 {
		s += "\n" + output[max(0, len(output)-budget):]
	}
	return status.CapError(s)
}

// report records the result in the status file.
func (d *Dispatcher) report(j Job, name string, step int, err error, output string) {
	if d.status == nil {
		return
	}
	r := status.Result{
		Pipeline: name, Sender: j.Sidecar.Sender, ID: j.Entry.ID, Received: j.Sidecar.Received,
		Tags: j.Vars.Tags, Size: j.Sidecar.Size,
	}
	if err != nil {
		r.Step, r.Error = step, errorText(err, output)
	}
	if werr := d.status.Record(r); werr != nil {
		d.log.Warn("status not written", "id", j.Entry.ID, "pipeline", name, "error", werr)
	}
}

// skip records the pipeline name as failed without running it (step 0)
// for the reason.
func (d *Dispatcher) skip(j Job, name, reason string) *Failure {
	err := errors.New(reason)
	d.report(j, name, 0, err, "")
	d.log.Warn("pipeline skipped", "id", j.Entry.ID, "pipeline", name, "reason", reason)
	return &Failure{Pipeline: name, Step: 0, Error: errorText(err, ""), At: time.Now().UTC().Format(time.RFC3339)}
}

// finished records in the queue entry that only the remaining pipelines
// still have to run, so Resume after an interruption skips the others, and
// which failed so far.
func (d *Dispatcher) finished(j Job, remaining []string, failed []Failure) {
	m := j.Meta()
	m.Pipelines = slices.Clone(remaining)
	m.Failed = slices.Clone(failed)
	if err := d.q.Commit(j.Entry, m); err != nil {
		d.log.Warn("queue entry not updated", "id", j.Entry.ID, "remaining", remaining, "error", err)
	}
}

// runPipeline reports whether the pipeline was interrupted by Close, or its
// failure. It runs on the configuration current when it gets its slot.
func (d *Dispatcher) runPipeline(j Job, name string) (bool, *Failure) {
	var stored, into []string
	var output, logged string
	cfg := d.config()
	work := filepath.Join(cfg.WorkDir(), j.Entry.ID, name)
	used := false
	step, err := func() (int, error) {
		if _, ok := Lookup(cfg, name, j.Secret); !ok {
			return 0, errors.New("pipeline not in the config")
		}
		sl := d.slotsOf(name)
		if !sl.acquire(d.stop) {
			return 0, errInterrupted
		}
		defer sl.release()
		cfg = d.config()
		p, ok := Lookup(cfg, name, j.Secret)
		if !ok {
			return 0, errors.New("pipeline not in the config")
		}
		hookRun(j, name)
		set := initialSet(j)
		for i, s := range p.Steps {
			if s.Run != "" || s.Encrypt != nil || s.Relay != "" {
				what := "encrypt"
				switch {
				case s.Run != "":
					what = "run " + s.Run
				case s.Relay != "":
					what = "relay " + s.Relay
				}
				if cfg.WorkDir() == "" {
					return i + 1, fmt.Errorf("%s: no work directory (root is not absolute)", what)
				}
				select {
				case <-d.stop:
					return i + 1, errInterrupted
				default:
				}
				if !used {
					used = true
					if err := os.RemoveAll(work); err != nil {
						return i + 1, fmt.Errorf("%s: %w", what, err)
					}
				}
			}
			if s.Encrypt != nil {
				next, err := d.encryptStep(j, d.resolver(cfg), name, i+1, s.Encrypt, set, stepDir(work, i+1))
				if err != nil {
					if errors.Is(err, errInterrupted) {
						return i + 1, err
					}
					return i + 1, fmt.Errorf("encrypt: %w", err)
				}
				set = next
				continue
			}
			if s.Run != "" {
				next, tail, err := runStep(j, p, i+1, s, set, stepDir(work, i+1), cfg.Root, d.stop)
				if err != nil {
					logged = tail
					var sf stepFailed
					if errors.As(err, &sf) {
						return i + 1, err
					}
					output = tail
					return i + 1, fmt.Errorf("run %s: %w", s.Run, err)
				}
				d.stepOutput(j, name, i+1, tail)
				set = next
				continue
			}
			if s.Relay != "" {
				tail, err := relayStep(j, p, i+1, s, set, stepDir(work, i+1), d.stop)
				if err != nil {
					logged, output = tail, tail
					return i + 1, fmt.Errorf("relay %s: %w", s.Relay, err)
				}
				d.stepOutput(j, name, i+1, tail)
				continue
			}
			for _, sn := range s.Store {
				if j.replaces(sn) && len(set) != 1 {
					return i + 1, fmt.Errorf("store %s: replacing %s needs one file, the set has %d", sn, j.Replace.Name, len(set))
				}
				for _, f := range set {
					res, err := d.store(j, cfg, name, sn, f)
					if err != nil {
						return i + 1, fmt.Errorf("store %s: %w", sn, err)
					}
					if res.Dedup {
						d.log.Info("deduplicated", "id", j.Entry.ID, "pipeline", name, "storage", sn, "path", res.Rel)
						stored = append(stored, sn+":"+res.Rel+" (dedup)")
					} else {
						stored = append(stored, sn+":"+res.Rel)
						into = append(into, sn)
					}
				}
			}
		}
		return 0, nil
	}()
	if errors.Is(err, errInterrupted) {
		d.log.Warn("pipeline interrupted", "id", j.Entry.ID, "pipeline", name, "step", step, "stored", stored)
		return true, nil
	}
	d.report(j, name, step, err, output)
	d.storedInto(into)
	if err != nil {
		args := []any{"id", j.Entry.ID, "pipeline", name, "step", step, "error", err, "stored", stored}
		if used {
			args = append(args, "work", work)
		}
		if logged != "" {
			args = append(args, "output", logged)
		}
		d.log.Error("pipeline failed", args...)
		return false, &Failure{Pipeline: name, Step: step, Error: errorText(err, output), At: time.Now().UTC().Format(time.RFC3339)}
	}
	if used {
		if err := os.RemoveAll(work); err != nil {
			d.log.Warn("work directory not removed", "id", j.Entry.ID, "pipeline", name, "error", err)
		}
	}
	d.log.Info("pipeline done", "id", j.Entry.ID, "pipeline", name, "stored", stored)
	return false, nil
}

// stepOutput logs the output tail of a run or relay step that succeeded at
// debug level.
func (d *Dispatcher) stepOutput(j Job, name string, step int, tail string) {
	if tail != "" {
		d.log.Debug("step output", "id", j.Entry.ID, "pipeline", name, "step", step, "output", tail)
	}
}

// runReplace runs the pipelines of a link replace (names), which hold
// store steps only (see config validation), as one publish: every storage
// they store into gets a staged copy of the content first, then the
// ordinary stores are placed and the replace of the link last. A failure
// anywhere drops the staged copies and removes the names placed so far,
// so the link keeps its old content, the other storages get nothing, and
// every pipeline of the entry fails. It reports whether it was
// interrupted by Close, else the failures.
func (d *Dispatcher) runReplace(j Job, names []string) (bool, []Failure) {
	names = slices.Sorted(slices.Values(names))
	cfg := d.config()
	fail := func(name string, step int, err error) []Failure {
		at := time.Now().UTC().Format(time.RFC3339)
		var out []Failure
		for _, n := range names {
			f := Failure{Pipeline: n, Step: step, Error: errorText(err, ""), At: at}
			if n != name {
				f.Step, f.Error = 0, fmt.Sprintf("replace not published: pipeline %s failed", name)
			}
			d.report(j, n, f.Step, errors.New(f.Error), "")
			out = append(out, f)
		}
		d.log.Error("pipeline failed", "id", j.Entry.ID, "pipeline", name, "step", step, "error", err, "replace", j.Replace.Name)
		return out
	}
	for _, name := range names {
		if _, ok := Lookup(cfg, name, j.Secret); !ok {
			return false, fail(name, 0, errors.New("pipeline not in the config"))
		}
	}
	// Slots in name order: two replaces cannot wait for each other.
	for _, name := range names {
		sl := d.slotsOf(name)
		if !sl.acquire(d.stop) {
			d.log.Warn("pipeline interrupted", "id", j.Entry.ID, "pipeline", name, "step", 0)
			return true, nil
		}
		defer sl.release()
	}
	cfg = d.config()
	type target struct {
		pipeline, storage string
		step              int
		staged            *store.Staged
	}
	var targets []*target
	seen := map[string]bool{}
	for _, name := range names {
		hookRun(j, name)
		p, ok := Lookup(cfg, name, j.Secret)
		if !ok {
			return false, fail(name, 0, errors.New("pipeline not in the config"))
		}
		for i, s := range p.Steps {
			if len(s.Store) == 0 {
				return false, fail(name, i+1, errors.New("a link replace runs pipelines of store steps only"))
			}
			for _, sn := range s.Store {
				if !seen[sn] {
					seen[sn] = true
					targets = append(targets, &target{pipeline: name, storage: sn, step: i + 1})
				}
			}
		}
	}
	defer func() {
		for _, t := range targets {
			t.staged.Drop()
		}
	}()
	f := initialSet(j)[0]
	for _, t := range targets {
		st, err := localStorage(cfg, t.storage)
		if err == nil {
			t.staged, err = store.FromConfig(st).Stage(f.path)
		}
		if err != nil {
			return false, fail(t.pipeline, t.step, fmt.Errorf("store %s: %w", t.storage, err))
		}
	}
	type placed struct {
		l       store.Local
		rel, id string
	}
	var done []placed
	var stored []string
	undo := func() {
		for _, p := range done {
			if err := p.l.RemoveIf(p.rel, p.id); err != nil {
				d.log.Error("stored name of a failed replace not removed", "id", j.Entry.ID, "path", p.rel, "error", err)
			}
		}
	}
	// The ordinary stores first, the replace of the link last.
	for _, last := range []bool{false, true} {
		for _, t := range targets {
			if j.replaces(t.storage) != last {
				continue
			}
			res, err := d.storeStaged(j, cfg, t.pipeline, t.storage, f, t.staged)
			if err != nil {
				undo()
				return false, fail(t.pipeline, t.step, fmt.Errorf("store %s: %w", t.storage, err))
			}
			if !res.Dedup && !last {
				st, _ := localStorage(cfg, t.storage)
				done = append(done, placed{l: store.FromConfig(st), rel: res.Rel, id: j.Sidecar.ID})
			}
			stored = append(stored, t.storage+":"+res.Rel)
		}
	}
	for _, name := range names {
		d.report(j, name, 0, nil, "")
		d.log.Info("pipeline done", "id", j.Entry.ID, "pipeline", name, "stored", stored)
	}
	var into []string
	for _, t := range targets {
		into = append(into, t.storage)
	}
	d.storedInto(into)
	return false, nil
}

// storedInto evaluates the watch rules again when one of the storages
// a pipeline stored into has any.
func (d *Dispatcher) storedInto(storages []string) {
	if watch.Watched(d.config(), storages) {
		d.RefreshWatch(time.Now())
	}
}

// RefreshWatch evaluates the watch rules of every storage at now and
// writes the result to the status.
func (d *Dispatcher) RefreshWatch(now time.Time) {
	if d.status == nil {
		return
	}
	d.watchMu.Lock()
	defer d.watchMu.Unlock()
	ws, err := watch.All(d.config(), now)
	if err != nil {
		d.log.Warn("watch", "error", err)
	}
	if err := d.status.SetWatch(ws); err != nil {
		d.log.Warn("status not written", "error", err)
	}
}

// localStorage is the storage name of cfg, which stores support for local
// storages only.
func localStorage(cfg *config.Config, name string) (*config.Storage, error) {
	st, ok := cfg.Storage[name]
	if !ok {
		return nil, errors.New("storage not in the config")
	}
	if st.Type != "local" {
		return nil, fmt.Errorf("%s storage: %w", st.Type, errNotSupported)
	}
	return st, nil
}

// store writes one file of the set into the storage name for the pipeline
// pipe; a file produced by a run step is stored under its own name with its
// size, sha256 and meta in the sidecar. The sidecar records the pipeline
// and the origin of the upload (its retention series).
func (d *Dispatcher) store(j Job, cfg *config.Config, pipe, name string, f file) (store.Stored, error) {
	return d.storeStaged(j, cfg, pipe, name, f, nil)
}

// storeStaged is store placing the copy of f staged in the storage when
// staged is set.
func (d *Dispatcher) storeStaged(j Job, cfg *config.Config, pipe, name string, f file, staged *store.Staged) (store.Stored, error) {
	st, err := localStorage(cfg, name)
	if err != nil {
		return store.Stored{}, err
	}
	l := store.FromConfig(st)
	if staged == nil {
		if staged, err = l.Stage(f.path); err != nil {
			return store.Stored{}, err
		}
		defer staged.Drop()
	}
	if j.replaces(name) {
		return d.replace(j, l, staged)
	}
	vars, sc := j.Vars.For(name), j.Sidecar
	sc.Pipeline, sc.Origin = pipe, cmp.Or(vars.Hostname, vars.Sender)
	if j.Expires != nil {
		sc.Expires = j.Expires[name]
	}
	if f.produced {
		vars.File = f.name
		sc.Size, sc.SHA256, sc.Produced, sc.Meta = f.size, f.sha256, f.name, f.meta
	}
	rel, err := l.Render(st.PathTemplate(), vars)
	if err != nil {
		return store.Stored{}, err
	}
	return l.StoreStaged(staged, rel, sc)
}

// replaces reports whether a store into storage name replaces a link.
func (j Job) replaces(name string) bool { return j.Replace != nil && j.Replace.Storage == name }

// errLinkGone fails a replace whose link was removed, claimed, expired or
// replaced by another upload since the request.
var errLinkGone = errors.New("link gone")

// replace puts the staged upload in place of the content of the link: the
// sidecar keeps everything of the link (id, sender, owner, expires, the
// client meta of the upload) but the new size and sha256, the file name
// and type of the new content when it names them, and the updated time.
func (d *Dispatcher) replace(j Job, l store.Local, staged *store.Staged) (store.Stored, error) {
	rp, nc := j.Replace, j.Sidecar.Client
	err := l.ReplaceStaged(staged, rp.Name, rp.ID, func(sc *store.Sidecar) error {
		if sc.Expires != "" {
			if t, err := time.Parse(time.RFC3339, sc.Expires); err != nil || !t.After(time.Now()) {
				return errLinkGone
			}
		}
		if !sc.Client.Mutable {
			return errors.New("link is not mutable")
		}
		sc.Size, sc.SHA256, sc.Updated = j.Sidecar.Size, j.Sidecar.SHA256, rp.Updated
		sc.Client.Source, sc.Client.Size, sc.Client.SHA256 = nc.Source, nc.Size, nc.SHA256
		if nc.File != "" || nc.Type != "" {
			sc.Client.File, sc.Client.Type = cmp.Or(nc.File, sc.Client.File), nc.Type
		}
		sc.Produced, sc.Meta = "", nil
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		err = errLinkGone
	}
	if err != nil {
		return store.Stored{}, err
	}
	return store.Stored{Rel: rp.Name}, nil
}

// CleanupQueues removes the half-received entries of every queue directory.
// Call it once at startup, before the listeners open.
func CleanupQueues(cfg *config.Config) error {
	var errs []error
	for _, dir := range QueueDirs(cfg) {
		if err := queue.Cleanup(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Resume submits the accepted entries left from a previous run. It leaves
// half-received entries alone: the receive role may be receiving them (see
// CleanupQueues). An entry with an unreadable meta.json is logged and left
// in place. Call it once at startup.
func (d *Dispatcher) Resume(ctx context.Context) error {
	dirs := d.queueDirs()
	var errs []error
	for di, dir := range dirs {
		if err := ctx.Err(); err != nil {
			return err
		}
		pending, err := queue.Pending(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for i, e := range pending {
			j, err := LoadJob(e)
			if err != nil {
				d.log.Error("queue entry unreadable", "id", e.ID, "dir", e.Dir, "error", err)
				continue
			}
			if err := d.Submit(j); err != nil {
				left := len(pending) - i
				for _, rest := range dirs[di+1:] {
					p, _ := queue.Pending(rest)
					left += len(p)
				}
				d.log.Warn("dispatcher closed, entries left for the next start", "left", left)
				return errors.Join(append(errs, err)...)
			}
		}
	}
	return errors.Join(errs...)
}
