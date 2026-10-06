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
	"luk/internal/wire"
)

// recordPath is the failure record of id received on endpoint.
func (e *env) recordPath(endpoint, id string) string {
	return filepath.Join(FailedDir(e.cfg.Endpoint[endpoint].Path), id+recordExt)
}

func loadRecord(t *testing.T, path string) Record {
	t.Helper()
	r, err := readRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// outcome is the outcome of pipeline name in r.
func outcome(t *testing.T, r Record, name string) Outcome {
	t.Helper()
	for _, o := range r.Pipelines {
		if o.Pipeline == name {
			return o
		}
	}
	t.Fatalf("no outcome of %s in %+v", name, r.Pipelines)
	return Outcome{}
}

// onlyRecord fails unless the failed/ directory of the queue directory of
// endpoint holds the record of id and nothing else.
func (e *env) onlyRecord(t *testing.T, endpoint, id string) {
	t.Helper()
	ents, err := os.ReadDir(FailedDir(e.cfg.Endpoint[endpoint].Path))
	if err != nil || len(ents) != 1 || ents[0].Name() != id+recordExt || !ents[0].Type().IsRegular() {
		t.Fatalf("failed/ holds %v (%v)", ents, err)
	}
}

func TestFailureKeepsOnlyRecord(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueue(t, "f1", "up", "fail")
	d.Submit(j)
	d.Wait()
	gone(t, j.Entry.Dir)
	e.onlyRecord(t, "up", "f1")
	b, err := os.ReadFile(e.recordPath("up", "f1"))
	if err != nil || strings.Contains(string(b), "data-f1") {
		t.Fatalf("record %s %v", b, err)
	}
	r := loadRecord(t, e.recordPath("up", "f1"))
	if r.ID != "f1" || r.Endpoint != "up" || r.Sender != "robert.socha" || r.Origin != "robert.socha" ||
		r.Size != int64(len("data-f1")) || r.SHA256 != j.Sidecar.SHA256 || len(r.Pipelines) != 1 {
		t.Fatalf("record %+v", r)
	}
	if at, err := time.Parse(time.RFC3339, r.FailedAt); err != nil || time.Since(at) > time.Minute || !r.At().Equal(at) {
		t.Fatalf("failed_at %q %v", r.FailedAt, err)
	}
	o := r.Pipelines[0]
	if o.Pipeline != "fail" || o.State != StateFailed || o.Step != 2 || !strings.Contains(o.Error, "exit status 1") ||
		strings.Join(o.Stored, ",") != "a:robert.socha/f.txt" {
		t.Fatalf("outcome %+v", o)
	}
	if at, err := time.Parse(time.RFC3339, o.At); err != nil || time.Since(at) > time.Minute {
		t.Fatalf("at %q %v", o.At, err)
	}
	// The store of step 1 stays.
	if e.read(t, "a/file/robert.socha/f.txt") != "data-f1" {
		t.Fatal("output of a step that succeeded removed")
	}
}

func TestSuccessOnlyRemoved(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueue(t, "s1", "up", "tee")
	d.Submit(j)
	d.Wait()
	gone(t, j.Entry.Dir)
	gone(t, e.recordPath("up", "s1"))
}

// A partial failure: the pipelines that succeeded keep what they stored
// and the record lists them with it.
func TestPartialFailureRecord(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueueWith(t, "m1", "up", func(j *Job) {
		j.Vars.Hostname = "db1"
		j.Sidecar.Client = wire.Meta{File: "f.txt", Tags: []string{"prod"}}
	}, "cloud", "tee", "fail")
	d.Submit(j)
	d.Wait()
	gone(t, j.Entry.Dir)
	r := loadRecord(t, e.recordPath("up", "m1"))
	if r.Origin != "db1" || r.Client.File != "f.txt" || strings.Join(r.Client.Tags, ",") != "prod" || len(r.Pipelines) != 3 ||
		r.Pipelines[0].Pipeline != "cloud" || r.Pipelines[1].Pipeline != "fail" || r.Pipelines[2].Pipeline != "tee" {
		t.Fatalf("record %+v", r)
	}
	if o := outcome(t, r, "cloud"); o.State != StateFailed || o.Step != 2 || !strings.Contains(o.Error, "not supported yet") ||
		strings.Join(o.Stored, ",") != "a:robert.socha/f.txt" {
		t.Fatalf("cloud %+v", o)
	}
	if o := outcome(t, r, "tee"); o.State != StateOK || o.Step != 0 || o.Error != "" || len(o.Stored) != 2 ||
		!strings.HasPrefix(o.Stored[0], "a:robert.socha/f.txt") || o.Stored[1] != "b:r-m1" {
		t.Fatalf("tee %+v", o)
	}
	if e.read(t, "b/file/r-m1") != "data-m1" {
		t.Fatal("store of a pipeline that succeeded removed")
	}
}

func TestFailedErrorCapped(t *testing.T) {
	bad := script(t, `head -c 20000 /dev/zero | tr '\0' x; exit 3`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n", bad))
	e.runOne(t, "c1")
	r := loadRecord(t, e.recordPath("up", "c1"))
	if len(r.Pipelines) != 1 || len(r.Pipelines[0].Error) > status.MaxError || !strings.HasSuffix(r.Pipelines[0].Error, "xxx") {
		t.Fatalf("record %+v", r.Pipelines)
	}
}

// A failure removes the work directories of every pipeline, also those
// holding a copy of the input, and the payload: nothing of the content
// stays.
func TestFailureRemovesWorkAndPayload(t *testing.T) {
	bad := script(t, `cp "$LUK_FILE" "$LUK_OUT/copy"; echo scratch > "$LUK_WORK/scratch"; echo step output; exit 1`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n", bad))
	j := e.runOne(t, "w1")
	gone(t, j.Entry.Dir)
	gone(t, filepath.Join(e.cfg.WorkDir(), "w1"))
	r := loadRecord(t, e.recordPath("up", "w1"))
	if o := outcome(t, r, "p"); o.State != StateFailed || o.Step != 1 || !strings.Contains(o.Error, "step output") {
		t.Fatalf("outcome %+v", o)
	}
}

// A secret upload that fails leaves nothing of the secret: the entry of
// the secret queue goes, the record names the secret storage.
func TestSecretFailureKeepsNothing(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueueWith(t, "v1", "up", func(j *Job) { j.Secret = "s3" }, SecretPipeline)
	d.Submit(j)
	d.Wait()
	gone(t, j.Entry.Dir)
	e.onlyRecord(t, "up", "v1")
	b, err := os.ReadFile(e.recordPath("up", "v1"))
	if err != nil || strings.Contains(string(b), "data-v1") {
		t.Fatalf("record %s %v", b, err)
	}
	r := loadRecord(t, e.recordPath("up", "v1"))
	if o := outcome(t, r, SecretPipeline); r.Secret != "s3" || o.State != StateFailed || o.Step != 1 || len(o.Stored) != 0 {
		t.Fatalf("record %+v", r)
	}
}

func TestPendingAndResumeIgnoreFailed(t *testing.T) {
	e := newEnv(t, 1)
	runs := countRuns(t)
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
	if !exists(e.recordPath("up", "r1")) || runs.Load() != 1 {
		t.Fatalf("record or runs %d", runs.Load())
	}
	if len(e.logs.records(t)) != 0 {
		t.Fatalf("logs %v", e.logs.records(t))
	}
}

func TestStatusFailedCount(t *testing.T) {
	e := newEnv(t, 1)
	st := status.New(status.Path(e.cfg.DataDir()))
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
	gone(t, e.recordPath("up", "n1"))
	d.Maintain(time.Now())
	d.Wait()
	for _, x := range st.Entries() {
		if x.Pipeline == "fail" && x.Failed != 1 {
			t.Fatalf("after rm %+v", x)
		}
	}
	for _, id := range []string{"n1", "", ".", "..", "../n2", ".n2.json.tmp"} {
		if err := RemoveFailed(e.cfg, id); !errors.Is(err, ErrUnknownID) {
			t.Fatalf("rm %q: %v", id, err)
		}
	}
}

func TestExpireFailed(t *testing.T) {
	bad := script(t, `echo x > "$LUK_OUT/f"; exit 1`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n", bad))
	st := status.New(status.Path(e.cfg.DataDir()))
	d := e.dispatcher()
	d.SetStatus(st)
	e.runOne(t, "x1")
	d.RefreshFailed()
	now := time.Now()
	if es := st.Entries(); len(es) != 1 || es[0].Failed != 1 {
		t.Fatalf("status %+v", es)
	}
	ExpireFailed(e.cfg, 0, now.Add(365*24*time.Hour), d.log)
	if !exists(e.recordPath("up", "x1")) {
		t.Fatal("age 0 expired the record")
	}
	ExpireFailed(e.cfg, 3*24*time.Hour, now.Add(2*24*time.Hour), d.log)
	if !exists(e.recordPath("up", "x1")) {
		t.Fatal("young record expired")
	}
	e.cfg.Limits.Failed.Age = nil
	d.Maintain(now.Add(4 * 24 * time.Hour))
	d.Wait()
	gone(t, e.recordPath("up", "x1"))
	if es := st.Entries(); es[0].Failed != 0 {
		t.Fatalf("status %+v", es)
	}
	for _, r := range e.logs.records(t) {
		if r["msg"] == "failure record expired" && r["id"] == "x1" && r["pipelines"] == "p" {
			return
		}
	}
	t.Fatalf("logs %v", e.logs.records(t))
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
	if !ids["i2"] || len(ids) != 1 {
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

// A record that cannot be written does not keep the upload: the entry and
// its payload go all the same, with an error logged.
func TestRecordFailureStillRemovesPayload(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	defer d.Close()
	runs := countRuns(t)
	failQueue(t, map[string]bool{"record": true})
	j := e.enqueue(t, "p2", "up", "fail")
	d.Submit(j)
	d.Wait()
	d.Pickup()
	d.Wait()
	gone(t, j.Entry.Dir)
	gone(t, e.recordPath("up", "p2"))
	gone(t, filepath.Join(e.cfg.WorkDir(), "p2"))
	if runs.Load() != 1 || len(d.parked) != 0 {
		t.Fatalf("runs %d parked %v", runs.Load(), d.parked)
	}
	var found bool
	for _, r := range e.logs.records(t) {
		if r["msg"] == "failure record not written, the upload is removed all the same" && r["level"] == "ERROR" && r["pipelines"] == "fail" {
			found = true
		}
	}
	if !found {
		t.Fatalf("logs %s", e.logs.b.String())
	}
}

// A failed entry that cannot be removed is parked: Pickup never runs its
// pipelines again, it tries the removal again after the backoff; the
// record is written once.
func TestFailedEntryParkedWhenNotRemovable(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	defer d.Close()
	clock := time.Now()
	d.now = func() time.Time { return clock }
	runs := countRuns(t)
	var records atomic.Int32
	fail := map[string]bool{"remove": true}
	old := hookQueue
	hookQueue = func(op string, en queue.Entry) error {
		if op == "record" {
			records.Add(1)
		}
		if fail[op] {
			return fmt.Errorf("simulated %s failure", op)
		}
		return nil
	}
	t.Cleanup(func() { hookQueue = old })
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
	if !exists(e.recordPath("up", "p1")) {
		t.Fatal("no record while parked")
	}
	if !strings.Contains(e.logs.b.String(), "queue entry parked") {
		t.Fatalf("logs %s", e.logs.b.String())
	}
	// Not due yet: still parked when the disk is back.
	fail["remove"] = false
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
	r := loadRecord(t, e.recordPath("up", "p1"))
	if len(r.Pipelines) != 1 || r.Pipelines[0].Pipeline != "fail" || runs.Load() != 1 || records.Load() != 1 {
		t.Fatalf("record %+v runs %d records %d", r, runs.Load(), records.Load())
	}
	if len(d.parked) != 0 {
		t.Fatalf("parked %v", d.parked)
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
	gone(t, e.recordPath("up", "p3"))
	if runs.Load() != 1 {
		t.Fatalf("runs %d", runs.Load())
	}
}
