package pipeline

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"luk/internal/queue"
	"luk/internal/status"
)

func (e *env) failedDir(endpoint, id string) string {
	return filepath.Join(FailedDir(e.cfg.Endpoint[endpoint].Path), id)
}

func loadFailed(t *testing.T, dir string) QueueMeta {
	t.Helper()
	j, err := LoadJob(queue.Entry{Dir: dir, ID: filepath.Base(dir)})
	if err != nil {
		t.Fatal(err)
	}
	return QueueMeta{Pipelines: j.Pipelines, Failed: j.Failed}
}

func TestFailedEntryMovesToFailed(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueue(t, "f1", "up", "fail")
	d.Submit(j)
	d.Wait()
	gone(t, j.Entry.Dir)
	dir := e.failedDir("up", "f1")
	if _, err := os.Stat(filepath.Join(dir, "payload")); err != nil {
		t.Fatal(err)
	}
	m := loadFailed(t, dir)
	if strings.Join(m.Pipelines, ",") != "fail" || len(m.Failed) != 1 {
		t.Fatalf("meta %+v", m)
	}
	f := m.Failed[0]
	if f.Pipeline != "fail" || f.Step != 2 || !strings.Contains(f.Error, "exit status 1") {
		t.Fatalf("failure %+v", f)
	}
	if at, err := time.Parse(time.RFC3339, f.At); err != nil || time.Since(at) > time.Minute {
		t.Fatalf("at %q %v", f.At, err)
	}
}

func TestSuccessOnlyRemoved(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueue(t, "s1", "up", "tee")
	d.Submit(j)
	d.Wait()
	gone(t, j.Entry.Dir)
	gone(t, e.failedDir("up", "s1"))
}

func TestMixedKeepsOnlyFailedPipelines(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	d.Submit(e.enqueue(t, "m1", "up", "cloud", "tee", "fail"))
	d.Wait()
	m := loadFailed(t, e.failedDir("up", "m1"))
	if strings.Join(m.Pipelines, ",") != "cloud,fail" || len(m.Failed) != 2 ||
		m.Failed[0].Pipeline != "cloud" || m.Failed[1].Pipeline != "fail" {
		t.Fatalf("meta %+v", m)
	}
	if !strings.Contains(m.Failed[0].Error, "not supported yet") {
		t.Fatalf("error %q", m.Failed[0].Error)
	}
}

func TestFailedErrorCapped(t *testing.T) {
	bad := script(t, `head -c 20000 /dev/zero | tr '\0' x; exit 3`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n", bad))
	e.runOne(t, "c1")
	m := loadFailed(t, e.failedDir("up", "c1"))
	if len(m.Failed) != 1 || len(m.Failed[0].Error) > status.MaxError || !strings.HasSuffix(m.Failed[0].Error, "xxx") {
		t.Fatalf("meta %+v", len(m.Failed[0].Error))
	}
}

func TestPendingAndResumeIgnoreFailed(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	d.Submit(e.enqueue(t, "r1", "up", "fail"))
	d.Wait()
	e.logs.b.Reset()
	d = e.dispatcher()
	if err := d.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	d.Pickup()
	d.Wait()
	if _, err := os.Stat(filepath.Join(e.failedDir("up", "r1"), "meta.json")); err != nil {
		t.Fatal(err)
	}
	if len(e.logs.records(t)) != 0 {
		t.Fatalf("logs %v", e.logs.records(t))
	}
}

func TestStatusFailedCount(t *testing.T) {
	e := newEnv(t, 1)
	st := status.New(status.Path(e.root))
	d := e.dispatcher()
	d.SetStatus(st)
	d.Submit(e.enqueue(t, "n1", "up", "fail"))
	d.Submit(e.enqueue(t, "n2", "up", "fail", "tee"))
	d.Wait()
	counts := map[string]int{}
	for _, x := range st.Entries() {
		counts[x.Pipeline] = x.Failed
	}
	if counts["fail"] != 2 || counts["tee"] != 0 {
		t.Fatalf("counts %v", counts)
	}
	if err := RemoveFailed(e.cfg, "n1"); err != nil {
		t.Fatal(err)
	}
	d.Maintain(time.Now())
	d.Wait()
	for _, x := range st.Entries() {
		if x.Pipeline == "fail" && x.Failed != 1 {
			t.Fatalf("after rm %+v", x)
		}
	}
	if err := RemoveFailed(e.cfg, "n1"); !errors.Is(err, ErrUnknownID) {
		t.Fatalf("second rm: %v", err)
	}
}

func TestRemoveFailedRemovesWork(t *testing.T) {
	bad := script(t, `echo x > "$LUK_OUT/f"; exit 1`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n", bad))
	e.runOne(t, "w1")
	work := filepath.Join(e.cfg.WorkDir(), "w1", "p")
	if !exists(work) {
		t.Fatal("work dir of the failed pipeline removed")
	}
	if err := RemoveFailed(e.cfg, "w1"); err != nil {
		t.Fatal(err)
	}
	gone(t, e.failedDir("up", "w1"))
	gone(t, filepath.Join(e.cfg.WorkDir(), "w1"))
}

func retryEnv(t *testing.T) (*env, string) {
	flag := filepath.Join(t.TempDir(), "ok")
	s := script(t, `test -e "$FLAG" || exit 1
ln "$LUK_FILE" "$LUK_OUT/f"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        env: {FLAG: %s}\n      - store: a\n  q:\n    endpoint: [up]\n    steps:\n      - store: c\n  r:\n    endpoint: [up]\n    steps:\n      - run: %s\n        env: {FLAG: %s}\n      - store: b\n", s, flag, s, flag))
	return e, flag
}

func TestRetryRunsOnlyFailedPipelines(t *testing.T) {
	e, flag := retryEnv(t)
	st := status.New(status.Path(e.root))
	d := e.dispatcher()
	d.SetStatus(st)
	j := e.enqueue(t, "t1", "up", "p", "q")
	d.Submit(j)
	d.Wait()
	if !exists(filepath.Join(e.root, "c/file/t1")) {
		t.Fatal("q not stored")
	}
	if err := os.WriteFile(flag, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := RetryFailed(e.cfg, "t1", nil); err != nil {
		t.Fatal(err)
	}
	gone(t, e.failedDir("up", "t1"))
	got, err := LoadJob(j.Entry)
	if err != nil || strings.Join(got.Pipelines, ",") != "p" || len(got.Failed) != 0 {
		t.Fatalf("queued %+v %v", got, err)
	}
	d.Maintain(time.Now())
	d.Wait()
	gone(t, j.Entry.Dir)
	gone(t, e.failedDir("up", "t1"))
	gone(t, filepath.Join(e.cfg.WorkDir(), "t1"))
	if e.read(t, "a/file/robert.socha/f") != "data-t1" {
		t.Fatal("p not stored")
	}
	ents, _ := os.ReadDir(filepath.Join(e.root, "c", "file"))
	if len(ents) != 1 {
		t.Fatalf("c holds %d entries (q rerun?)", len(ents))
	}
	n := 0
	for _, r := range e.logs.records(t) {
		if r["msg"] == "pipeline done" && r["pipeline"] == "q" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("q ran %d times", n)
	}
	for _, x := range st.Entries() {
		if x.Failed != 0 {
			t.Fatalf("status %+v", x)
		}
	}
}

func TestRetryFailsAgain(t *testing.T) {
	e, _ := retryEnv(t)
	d := e.dispatcher()
	d.Submit(e.enqueue(t, "t2", "up", "p", "r"))
	d.Wait()
	if _, err := RetryFailed(e.cfg, "t2", []string{"x"}); err == nil {
		t.Fatal("unknown pipeline accepted")
	}
	if _, err := RetryFailed(e.cfg, "t2", []string{"r"}); err != nil {
		t.Fatal(err)
	}
	gone(t, filepath.Join(e.cfg.WorkDir(), "t2", "p"))
	d.Maintain(time.Now())
	d.Wait()
	m := loadFailed(t, e.failedDir("up", "t2"))
	if strings.Join(m.Pipelines, ",") != "r" || len(m.Failed) != 1 || m.Failed[0].Pipeline != "r" {
		t.Fatalf("meta %+v", m)
	}
	if _, err := RetryFailed(e.cfg, "nope", nil); !errors.Is(err, ErrUnknownID) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestExpireFailed(t *testing.T) {
	bad := script(t, `echo x > "$LUK_OUT/f"; exit 1`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n", bad))
	st := status.New(status.Path(e.root))
	d := e.dispatcher()
	d.SetStatus(st)
	e.runOne(t, "x1")
	d.RefreshFailed()
	now := time.Now()
	if es := st.Entries(); len(es) != 1 || es[0].Failed != 1 {
		t.Fatalf("status %+v", es)
	}
	ExpireFailed(e.cfg, 0, now.Add(365*24*time.Hour), d.log)
	if !exists(e.failedDir("up", "x1")) {
		t.Fatal("age 0 expired the entry")
	}
	ExpireFailed(e.cfg, 3*24*time.Hour, now.Add(2*24*time.Hour), d.log)
	if !exists(e.failedDir("up", "x1")) {
		t.Fatal("young entry expired")
	}
	e.cfg.Limits.Failed.Age = nil
	d.Maintain(now.Add(4 * 24 * time.Hour))
	d.Wait()
	gone(t, e.failedDir("up", "x1"))
	gone(t, filepath.Join(e.cfg.WorkDir(), "x1"))
	if es := st.Entries(); es[0].Failed != 0 {
		t.Fatalf("status %+v", es)
	}
}

func TestPickupSubmitsCommittedEntries(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueue(t, "p1", "up", "tee")
	half := filepath.Join(e.cfg.Endpoint["up"].Path, "half")
	if err := os.MkdirAll(half, 0o750); err != nil {
		t.Fatal(err)
	}
	d.Pickup()
	d.Wait()
	gone(t, j.Entry.Dir)
	if !exists(half) {
		t.Fatal("pickup removed an upload in progress")
	}
	if e.read(t, "b/file/r-p1") != "data-p1" {
		t.Fatal("not stored")
	}
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	if find(e.logs.records(t), "pipeline failed", "tee") != nil {
		t.Fatal("a finished entry ran again")
	}
}

func TestEntryIDs(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	d.Submit(e.enqueue(t, "i1", "up", "fail"))
	d.Wait()
	e.enqueue(t, "i2", "other", "tee")
	ids := EntryIDs(e.cfg)
	if !ids["i1"] || !ids["i2"] || len(ids) != 2 {
		t.Fatalf("ids %v", ids)
	}
}

// failQueue makes hookQueue fail the ops listed in fail until restored.
func failQueue(t *testing.T, fail map[string]bool) {
	t.Helper()
	old := hookQueue
	hookQueue = func(op string, e queue.Entry) error {
		if fail[op] {
			return fmt.Errorf("simulated %s failure", op)
		}
		return nil
	}
	t.Cleanup(func() { hookQueue = old })
}

// countRuns counts the pipeline runs (hookRun) until the test ends.
func countRuns(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	old := hookRun
	hookRun = func(Job, string) { n.Add(1) }
	t.Cleanup(func() { hookRun = old })
	return &n
}

// A failed entry that cannot be moved to failed/ is parked: Pickup never
// runs its pipelines again, it retries the move after the backoff.
func TestFailedEntryParkedWhenNotMovable(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	defer d.Close()
	clock := time.Now()
	d.now = func() time.Time { return clock }
	runs := countRuns(t)
	fail := map[string]bool{"commit": true, "move": true}
	failQueue(t, fail)
	j := e.enqueue(t, "p1", "up", "fail")
	d.Submit(j)
	d.Wait()
	for range 3 {
		d.Pickup()
		d.Wait()
	}
	if n := runs.Load(); n != 1 {
		t.Fatalf("runs %d", n)
	}
	if _, err := os.Stat(filepath.Join(j.Entry.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.logs.b.String(), "queue entry parked") {
		t.Fatalf("logs %s", e.logs.b.String())
	}
	// Not due yet: still parked when the disk is back.
	fail["commit"], fail["move"] = false, false
	clock = clock.Add(30 * time.Second)
	d.Pickup()
	d.Wait()
	if _, err := os.Stat(j.Entry.Dir); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Minute)
	d.Pickup()
	d.Wait()
	gone(t, j.Entry.Dir)
	m := loadFailed(t, e.failedDir("up", "p1"))
	if len(m.Failed) != 1 || m.Failed[0].Pipeline != "fail" || runs.Load() != 1 {
		t.Fatalf("meta %+v runs %d", m, runs.Load())
	}
	if len(d.parked) != 0 {
		t.Fatalf("parked %v", d.parked)
	}
}

// A meta.json that cannot be written does not stop the move to failed/:
// the entry is there with the meta of its last update.
func TestFailedEntryMovedWithoutMeta(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	defer d.Close()
	runs := countRuns(t)
	failQueue(t, map[string]bool{"commit": true})
	j := e.enqueue(t, "p2", "up", "fail")
	d.Submit(j)
	d.Wait()
	d.Pickup()
	d.Wait()
	gone(t, j.Entry.Dir)
	m := loadFailed(t, e.failedDir("up", "p2"))
	if strings.Join(m.Pipelines, ",") != "fail" || runs.Load() != 1 {
		t.Fatalf("meta %+v runs %d", m, runs.Load())
	}
	if !strings.Contains(e.logs.b.String(), "moved to failed without its failures recorded") {
		t.Fatalf("logs %s", e.logs.b.String())
	}
}

// An entry whose pipelines all succeeded and that cannot be removed is
// parked, not run again.
func TestDoneEntryParkedWhenNotRemovable(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	defer d.Close()
	clock := time.Now()
	d.now = func() time.Time { return clock }
	runs := countRuns(t)
	fail := map[string]bool{"remove": true}
	failQueue(t, fail)
	j := e.enqueue(t, "p3", "up", "tee")
	d.Submit(j)
	d.Wait()
	d.Pickup()
	d.Wait()
	if _, err := os.Stat(filepath.Join(j.Entry.Dir, "meta.json")); err != nil || runs.Load() != 1 {
		t.Fatalf("%v runs %d", err, runs.Load())
	}
	// The second try fails as well: the wait doubles.
	clock = clock.Add(time.Minute)
	d.Pickup()
	if p := d.parked[j.Entry.Dir]; p == nil || p.n != 2 || !p.next.Equal(clock.Add(2*time.Minute)) {
		t.Fatalf("parked %+v", p)
	}
	fail["remove"] = false
	clock = clock.Add(2 * time.Minute)
	d.Pickup()
	d.Wait()
	gone(t, j.Entry.Dir)
	gone(t, e.failedDir("up", "p3"))
	if runs.Load() != 1 {
		t.Fatalf("runs %d", runs.Load())
	}
}
