package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/queue"
	"luk/internal/status"
	"luk/internal/store"
	"luk/internal/wire"
)

const cfgTmpl = `
root: %s
listen:
  main: {addr: 127.0.0.1:8080}
auth:
  keys:
    - name: robert.socha
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"
endpoint:
  up:
    listen: main
    endpoint: /up
    path: queue/up
    allow: [robert.socha]
  other:
    listen: main
    endpoint: /other
    path: queue/other
    allow: [robert.socha]
pipeline:
  tee:
    endpoint: [up]
    steps:
      - store: [a, b]
  fail:
    endpoint: [up]
    steps:
      - store: a
      - run: /bin/false
      - store: b
  cloud:
    endpoint: [up]
    steps:
      - store: a
      - store: a
  serial:
    endpoint: [up]
    queue: {concurrency: %d}
    steps:
      - store: b
storage:
  a: {type: local, base: a, path: "{{ .Sender }}/{{ .File }}"}
  b: {type: local, base: b, path: "{{ .Random }}"}
  s3: {type: s3, bucket: x}
`

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) records(t *testing.T) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(s.b.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

type env struct {
	root string
	cfg  *config.Config
	q    *queue.Queue
	logs *syncBuf
}

func newEnv(t *testing.T, concurrency int) *env {
	t.Helper()
	root := t.TempDir()
	cfg := parseCfg(t, fmt.Sprintf(cfgTmpl, root, concurrency))
	for _, d := range []string{"queue/up", "queue/other", "a", "b", "status/process"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	free := func(string) (int64, error) { return 1 << 40, nil }
	return &env{root: root, cfg: cfg, q: queue.New(0, free), logs: &syncBuf{}}
}

// parseCfg parses a config of cfgTmpl. The second step of pipeline cloud
// then stores to the s3 storage, which validation refuses and which fails
// at run time.
func parseCfg(t *testing.T, text string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if p := cfg.Pipeline["cloud"]; p != nil {
		p.Steps[1].Store = []string{"s3"}
	}
	return cfg
}

func (e *env) dispatcher() *Dispatcher {
	return NewDispatcher(e.cfg, e.q, slog.New(slog.NewJSONHandler(e.logs, nil)))
}

func (e *env) enqueue(t *testing.T, id, endpoint string, pipelines ...string) Job {
	t.Helper()
	return e.enqueueWith(t, id, endpoint, nil, pipelines...)
}

func (e *env) enqueueWith(t *testing.T, id, endpoint string, mut func(*Job), pipelines ...string) Job {
	t.Helper()
	dir := e.cfg.Endpoint[endpoint].Path
	ent, size, sha, err := e.q.Receive(context.Background(), dir, id, strings.NewReader("data-"+id), 0, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	j := Job{
		Entry:     ent,
		Pipelines: pipelines,
		Vars:      store.Vars{Sender: "robert.socha", Endpoint: endpoint, Time: time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC), Id: id, Random: "r-" + id, File: "f.txt"},
		Sidecar:   store.Sidecar{ID: id, Sender: "robert.socha", Endpoint: endpoint, Size: size, SHA256: sha, Client: wire.Meta{File: "f.txt"}},
	}
	if mut != nil {
		mut(&j)
	}
	if err := e.q.Commit(ent, j.Meta()); err != nil {
		t.Fatal(err)
	}
	return j
}

func (e *env) read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func gone(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("%s still exists (%v)", p, err)
	}
}

func find(recs []map[string]any, msg, pipeline string) map[string]any {
	for _, r := range recs {
		if r["msg"] == msg && r["pipeline"] == pipeline {
			return r
		}
	}
	return nil
}

func TestStoreTee(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueue(t, "id1", "up", "tee")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	if got := e.read(t, "a/file/robert.socha/f.txt"); got != "data-id1" {
		t.Fatalf("a: %q", got)
	}
	if got := e.read(t, "b/file/r-id1"); got != "data-id1" {
		t.Fatalf("b: %q", got)
	}
	var sc store.Sidecar
	if err := json.Unmarshal([]byte(e.read(t, "b/.db/meta/r-id1.json")), &sc); err != nil || sc.ID != "id1" {
		t.Fatalf("sidecar %+v %v", sc, err)
	}
	gone(t, j.Entry.Dir)
	r := find(e.logs.records(t), "pipeline done", "tee")
	if r == nil || r["id"] != "id1" {
		t.Fatalf("no done log: %v", e.logs.records(t))
	}
	if s := fmt.Sprint(r["stored"]); !strings.Contains(s, "a:robert.socha/f.txt") || !strings.Contains(s, "b:r-id1") {
		t.Fatalf("stored %v", r["stored"])
	}
}

func TestRunStepFailsAfterStore(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueue(t, "id2", "up", "fail")
	d.Submit(j)
	d.Wait()
	if got := e.read(t, "a/file/robert.socha/f.txt"); got != "data-id2" {
		t.Fatalf("a: %q", got)
	}
	gone(t, filepath.Join(e.root, "b/file/r-id2"))
	gone(t, j.Entry.Dir)
	r := find(e.logs.records(t), "pipeline failed", "fail")
	if r == nil {
		t.Fatalf("no failed log: %v", e.logs.records(t))
	}
	if r["step"] != float64(2) || !strings.Contains(fmt.Sprint(r["error"]), "exit status 1") || !strings.Contains(fmt.Sprint(r["stored"]), "a:robert.socha/f.txt") {
		t.Fatalf("failed log %v", r)
	}
}

func TestS3StorageFails(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueue(t, "id3", "up", "cloud", "tee")
	d.Submit(j)
	d.Wait()
	recs := e.logs.records(t)
	r := find(recs, "pipeline failed", "cloud")
	if r == nil || r["step"] != float64(2) || !strings.Contains(fmt.Sprint(r["error"]), "not supported yet") {
		t.Fatalf("cloud log %v", recs)
	}
	if find(recs, "pipeline done", "tee") == nil {
		t.Fatalf("tee not done: %v", recs)
	}
	gone(t, j.Entry.Dir)
}

func TestUnknownPipelineFails(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueue(t, "id4", "up", "vanished")
	d.Submit(j)
	d.Wait()
	if find(e.logs.records(t), "pipeline failed", "vanished") == nil {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	gone(t, j.Entry.Dir)
}

func TestNoPipelineRemovesEntry(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	j := e.enqueue(t, "id5", "up")
	d.Submit(j)
	d.Wait()
	gone(t, j.Entry.Dir)
}

func concurrencyPeak(t *testing.T, limit int) int32 {
	e := newEnv(t, limit)
	var cur, peak atomic.Int32
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	hookRun = func(Job, string) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		cur.Add(-1)
	}
	t.Cleanup(func() { hookRun = func(Job, string) {} })
	d := e.dispatcher()
	d.Submit(e.enqueue(t, "s1", "up", "serial"))
	d.Submit(e.enqueue(t, "s2", "up", "serial"))
	<-entered
	if limit > 1 {
		<-entered
	} else {
		select {
		case <-entered:
			t.Fatal("second job entered while first holds the only slot")
		case <-time.After(100 * time.Millisecond):
		}
	}
	close(release)
	d.Wait()
	if e.read(t, "b/file/r-s1") != "data-s1" || e.read(t, "b/file/r-s2") != "data-s2" {
		t.Fatal("not stored")
	}
	return peak.Load()
}

func TestConcurrencyOneSerialises(t *testing.T) {
	if p := concurrencyPeak(t, 1); p != 1 {
		t.Fatalf("peak %d", p)
	}
}

func TestConcurrencyTwoOverlaps(t *testing.T) {
	if p := concurrencyPeak(t, 2); p != 2 {
		t.Fatalf("peak %d", p)
	}
}

func TestResume(t *testing.T) {
	e := newEnv(t, 1)
	j := e.enqueue(t, "r1", "up", "tee")
	o := e.enqueue(t, "r2", "other", "serial")
	half := filepath.Join(e.cfg.Endpoint["up"].Path, "20261004T100000Z-0123abcd")
	if err := os.MkdirAll(half, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(half, ".payload.tmp"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}

	d := e.dispatcher()
	if err := d.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	if _, err := os.Stat(half); err != nil {
		t.Fatalf("half-received entry: %v", err)
	}
	if err := CleanupQueues(e.cfg); err != nil {
		t.Fatal(err)
	}
	gone(t, half)
	gone(t, j.Entry.Dir)
	gone(t, o.Entry.Dir)
	if e.read(t, "b/file/r-r1") != "data-r1" || e.read(t, "a/file/robert.socha/f.txt") != "data-r1" || e.read(t, "b/file/r-r2") != "data-r2" {
		t.Fatal("not stored")
	}

	for range 2 {
		d := e.dispatcher()
		if err := d.Resume(context.Background()); err != nil {
			t.Fatal(err)
		}
		d.Wait()
	}
	ents, err := os.ReadDir(filepath.Join(e.root, "b", "file"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range ents {
		names = append(names, x.Name())
	}
	if strings.Join(names, ",") != "r-r1,r-r2" {
		t.Fatalf("b holds %v", names)
	}
}

func TestResumeKeepsUnreadableMeta(t *testing.T) {
	e := newEnv(t, 1)
	j := e.enqueue(t, "bad", "up", "tee")
	if err := os.WriteFile(filepath.Join(j.Entry.Dir, "meta.json"), []byte("{"), 0o640); err != nil {
		t.Fatal(err)
	}
	d := e.dispatcher()
	if err := d.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	if _, err := os.Stat(filepath.Join(j.Entry.Dir, "payload")); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range e.logs.records(t) {
		if r["id"] == "bad" && r["level"] == "ERROR" {
			found = true
		}
	}
	if !found {
		t.Fatalf("logs %v", e.logs.records(t))
	}
}

func TestResumeMissingQueueDir(t *testing.T) {
	e := newEnv(t, 1)
	if err := os.RemoveAll(e.cfg.Endpoint["other"].Path); err != nil {
		t.Fatal(err)
	}
	d := e.dispatcher()
	if err := d.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.Wait()
}

func TestMetaRoundTrip(t *testing.T) {
	e := newEnv(t, 1)
	j := e.enqueue(t, "m1", "up", "tee", "fail")
	got, err := LoadJob(j.Entry)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(j)
	b, _ := json.Marshal(got)
	if !bytes.Equal(a, b) {
		t.Fatalf("\n%s\n%s", a, b)
	}
}

func TestClose(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	d.Close()
	j := e.enqueue(t, "c1", "up", "tee")
	if err := d.Submit(j); err != ErrClosed {
		t.Fatalf("submit after close: %v", err)
	}
	d.Wait()
	if _, err := os.Stat(filepath.Join(j.Entry.Dir, "meta.json")); err != nil {
		t.Fatal("entry must stay for the next start")
	}
}

func TestSubmitSameEntryOnce(t *testing.T) {
	e := newEnv(t, 2)
	var calls atomic.Int32
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	hookRun = func(Job, string) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
	}
	t.Cleanup(func() { hookRun = func(Job, string) {} })
	d := e.dispatcher()
	j := e.enqueue(t, "dup", "up", "serial")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	if err := d.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	d.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("ran %d times", n)
	}
	gone(t, j.Entry.Dir)
	ents, _ := os.ReadDir(filepath.Join(e.root, "b", "file"))
	if len(ents) != 1 {
		t.Fatalf("b holds %d entries", len(ents))
	}
}

func TestDuplicatePipelineRunsOnce(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	d.Submit(e.enqueue(t, "dp", "up", "serial", "serial"))
	d.Wait()
	n := 0
	for _, r := range e.logs.records(t) {
		if r["msg"] == "pipeline done" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d done logs", n)
	}
	gone(t, filepath.Join(e.root, "b/file/r-dp.1"))
	ents, _ := os.ReadDir(filepath.Join(e.root, "b", "file"))
	if len(ents) != 1 {
		t.Fatalf("b holds %d entries", len(ents))
	}
}

func TestResumeAfterCloseLogsLeft(t *testing.T) {
	e := newEnv(t, 1)
	e.enqueue(t, "l1", "up", "tee")
	e.enqueue(t, "l2", "other", "tee")
	d := e.dispatcher()
	d.Close()
	if err := d.Resume(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("resume: %v", err)
	}
	for _, r := range e.logs.records(t) {
		if r["msg"] == "dispatcher closed, entries left for the next start" && r["left"] == float64(2) {
			return
		}
	}
	t.Fatalf("logs %v", e.logs.records(t))
}

func TestQueueMetaKeepsHostname(t *testing.T) {
	b, err := json.Marshal(Job{Vars: store.Vars{Sender: "s", Hostname: "db1.example.net"}}.Meta())
	if err != nil {
		t.Fatal(err)
	}
	var m QueueMeta
	if err := json.Unmarshal(b, &m); err != nil || m.Vars.Hostname != "db1.example.net" {
		t.Fatalf("%s: %+v %v", b, m.Vars, err)
	}
}

func TestStoreDedupLogged(t *testing.T) {
	e := newEnv(t, 1)
	st, _, err := status.Open(status.Path(e.root))
	if err != nil {
		t.Fatal(err)
	}
	d := e.dispatcher()
	d.SetStatus(st)
	for _, id := range []string{"d1", "d2"} {
		dir := e.cfg.Endpoint["up"].Path
		ent, size, sha, err := e.q.Receive(context.Background(), dir, id, strings.NewReader("same"), 0, nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		j := Job{Entry: ent, Pipelines: []string{"tee"},
			Vars:    store.Vars{Sender: "robert.socha", Endpoint: "up", Id: id, Random: "r-" + id, File: "f.txt"},
			Sidecar: store.Sidecar{ID: id, Sender: "robert.socha", Endpoint: "up", Size: size, SHA256: sha}}
		if err := e.q.Commit(ent, j.Meta()); err != nil {
			t.Fatal(err)
		}
		if err := d.Submit(j); err != nil {
			t.Fatal(err)
		}
		d.Wait()
	}
	var dedup, done map[string]any
	for _, r := range e.logs.records(t) {
		switch {
		case r["msg"] == "deduplicated":
			dedup = r
		case r["msg"] == "pipeline done" && r["id"] == "d2":
			done = r
		}
	}
	if dedup == nil || dedup["id"] != "d2" || dedup["storage"] != "a" || dedup["path"] != "robert.socha/f.txt" {
		t.Fatalf("dedup log %v", dedup)
	}
	if s := fmt.Sprint(done["stored"]); !strings.Contains(s, "a:robert.socha/f.txt (dedup)") || !strings.Contains(s, "b:r-d2") {
		t.Fatalf("stored %v", done["stored"])
	}
	des, _ := os.ReadDir(filepath.Join(e.root, "a/file/robert.socha"))
	if len(des) != 1 {
		t.Fatalf("a holds %d files", len(des))
	}
	es := st.Entries()
	if len(es) != 1 || es[0].LastSuccess == "" || es[0].LastFailure != "" || es[0].LastID != "d2" {
		t.Fatalf("status %+v", es)
	}
}

// replaceOf enqueues a replace of the stored a/robert.socha/f.txt of the
// upload first through the pipelines.
func (e *env) replaceOf(t *testing.T, d *Dispatcher, pipelines ...string) {
	t.Helper()
	first := e.enqueueWith(t, "first", "up", func(j *Job) { j.Sidecar.Client.Mutable = true }, "tee")
	if err := d.Submit(first); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	j := e.enqueueWith(t, "second", "up", func(j *Job) {
		j.Replace = &Replace{Storage: "a", Name: "robert.socha/f.txt", ID: "first", Updated: "2026-10-03T00:00:00Z"}
	}, pipelines...)
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
}

// A replace through a pipeline with a run step after the store fails
// without touching the link: replace runs store steps only.
func TestReplaceWithRunStepKeepsOld(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	defer d.Close()
	e.replaceOf(t, d, "fail")
	failed, err := ListFailed(e.cfg)
	if err != nil || len(failed) != 1 || failed[0].Pipelines[0].Step != 2 ||
		!strings.Contains(failed[0].Pipelines[0].Error, "store steps only") {
		t.Fatalf("%+v %v", failed, err)
	}
	if got := e.read(t, "a/file/robert.socha/f.txt"); got != "data-first" {
		t.Fatalf("link holds %q", got)
	}
}

// A replace stores into every storage of its pipelines and replaces the
// link; every pipeline is done and the entry goes.
func TestReplaceFanOut(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	defer d.Close()
	e.replaceOf(t, d, "tee", "serial")
	if got := e.read(t, "a/file/robert.socha/f.txt"); got != "data-second" {
		t.Fatalf("link holds %q", got)
	}
	if got := e.read(t, "b/file/r-second"); got != "data-second" {
		t.Fatalf("b holds %q", got)
	}
	if failed, err := ListFailed(e.cfg); err != nil || len(failed) != 0 {
		t.Fatalf("%+v %v", failed, err)
	}
	if p, err := queue.Pending(e.cfg.Endpoint["up"].Path); err != nil || len(p) != 0 {
		t.Fatalf("pending %v %v", p, err)
	}
}

func TestStoreRefreshesWatch(t *testing.T) {
	e := newEnv(t, 1)
	every := config.Duration(time.Hour)
	e.cfg.Storage["b"].Watch = []config.Watch{{Origin: config.StringList{"robert.socha"}, Every: &every}, {Origin: config.StringList{"none"}, Every: &every}}
	st, _, err := status.Open(status.Path(e.root))
	if err != nil {
		t.Fatal(err)
	}
	d := e.dispatcher()
	d.SetStatus(st)
	// A store into a storage without watch rules evaluates nothing.
	if err := d.Submit(e.enqueue(t, "w0", "up", "cloud")); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	if ws := st.Watch(); len(ws) != 0 {
		t.Fatalf("watch after a store into a: %+v", ws)
	}
	recv := func(j *Job) {
		j.Sidecar.Received = time.Now().UTC().Format(time.RFC3339)
		j.Sidecar.Client.File = "f.txt"
	}
	if err := d.Submit(e.enqueueWith(t, "w1", "up", recv, "serial")); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	ws := st.Watch()
	if len(ws) != 2 || ws[0].Storage != "b" || ws[0].Pipeline != "serial" || ws[0].Origin != "robert.socha" || ws[0].File != "f.txt" ||
		ws[0].State != "OK" || ws[0].Copies != 1 || ws[1].Rule != 2 || ws[1].State != "WARN" {
		t.Fatalf("watch %+v", ws)
	}
	b, _ := os.ReadFile(status.Path(e.root))
	if !strings.Contains(string(b), `"watch": [`) || !strings.Contains(string(b), `"origin": "robert.socha"`) {
		t.Fatalf("status.json:\n%s", b)
	}
	// The janitor pass evaluates again at its time.
	d.RefreshWatch(time.Now().Add(2 * time.Hour))
	if ws := st.Watch(); ws[0].State != "CRIT" || !strings.Contains(ws[0].Message, "(every 1h)") {
		t.Fatalf("later: %+v", ws)
	}
}

// TestStoreOlderWarned: an upload accepted before the stored file is
// skipped under conflict replace with a warning, and the status counts it.
func TestStoreOlderWarned(t *testing.T) {
	e := newEnv(t, 1)
	e.cfg.Storage["a"].Conflict = "replace"
	st, _, err := status.Open(status.Path(e.root))
	if err != nil {
		t.Fatal(err)
	}
	d := e.dispatcher()
	d.SetStatus(st)
	for _, c := range []struct {
		id string
		ns int64
	}{{"new", 2000}, {"old", 1000}} {
		j := e.enqueueWith(t, c.id, "up", func(j *Job) { j.Sidecar.Accepted = c.ns }, "tee")
		if err := d.Submit(j); err != nil {
			t.Fatal(err)
		}
		d.Wait()
	}
	if got := e.read(t, "a/file/robert.socha/f.txt"); got != "data-new" {
		t.Fatalf("a: %q", got)
	}
	r := find(e.logs.records(t), "store: older upload skipped", "tee")
	if r == nil || r["level"] != "WARN" || r["id"] != "old" || r["stored"] != "new" {
		t.Fatalf("log %v", r)
	}
	es := st.Entries()
	if len(es) != 1 || es[0].OlderSkipped != 1 {
		t.Fatalf("status %+v", es)
	}
}
