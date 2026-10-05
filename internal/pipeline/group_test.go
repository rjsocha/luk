package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/queue"
	"luk/internal/status"
)

// groupTmpl has group g (first and first2 at order 1, second at order 2),
// group h (bad, which runs <root>/step, and hok at order 1, after at 2,
// last at 3) and free without a group. The concurrency of first and second
// is the second argument.
const groupTmpl = `
root: %[1]s
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
pipeline:
  first: {endpoint: [up], queue: {group: g, order: 1, concurrency: %[2]d}, steps: [{store: s}]}
  first2: {endpoint: [up], queue: {group: g, order: 1}, steps: [{store: s}]}
  second: {endpoint: [up], queue: {group: g, order: 2, concurrency: %[2]d}, steps: [{store: s}]}
  free: {endpoint: [up], steps: [{store: s}]}
  bad: {endpoint: [up], queue: {group: h, order: 1}, steps: [{store: s}, {run: %[1]s/step}]}
  hok: {endpoint: [up], queue: {group: h, order: 1}, steps: [{store: s}]}
  after: {endpoint: [up], queue: {group: h, order: 2}, steps: [{store: s}]}
  last: {endpoint: [up], queue: {group: h, order: 3}, steps: [{store: s}]}
storage:
  s: {type: local, base: s, path: "{{ .Random }}"}
`

func groupCfg(t *testing.T, root string, concurrency int, edit func(string) string) *config.Config {
	t.Helper()
	text := fmt.Sprintf(groupTmpl, root, concurrency)
	if edit != nil {
		text = edit(text)
	}
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// newGroupEnv prepares groupTmpl; the step of bad fails until <root>/ok
// exists.
func newGroupEnv(t *testing.T, concurrency int) *env {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	root := t.TempDir()
	for _, d := range []string{"queue/up", "s", "work", "status/process"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	step := "#!/bin/sh\ntest -e " + root + "/ok || exit 1\nln \"$LUK_FILE\" \"$LUK_OUT/x\"\n"
	if err := os.WriteFile(filepath.Join(root, "step"), []byte(step), 0o755); err != nil {
		t.Fatal(err)
	}
	free := func(string) (int64, error) { return 1 << 40, nil }
	return &env{root: root, cfg: groupCfg(t, root, concurrency, nil), q: queue.New(0, free), logs: &syncBuf{}}
}

// enqueueGrouped queues id for pipelines with their stages from the
// configuration, as the receive role does.
func (e *env) enqueueGrouped(t *testing.T, id string, pipelines ...string) Job {
	t.Helper()
	return e.enqueueWith(t, id, "up", func(j *Job) { j.Stages = Stages(e.cfg, pipelines) }, pipelines...)
}

// gates records every pipeline that got its slot ("<id>/<name>") and
// holds those whose name is gated until the gate is opened.
type gates struct {
	entered chan string
	mu      sync.Mutex
	held    map[string]chan struct{}
}

func newGates(t *testing.T, held ...string) *gates {
	g := &gates{entered: make(chan string, 64), held: map[string]chan struct{}{}}
	for _, n := range held {
		g.held[n] = make(chan struct{})
	}
	hookRun = func(j Job, name string) {
		g.entered <- j.Entry.ID + "/" + name
		g.mu.Lock()
		ch := g.held[name]
		g.mu.Unlock()
		if ch != nil {
			<-ch
		}
	}
	t.Cleanup(func() { hookRun = func(Job, string) {} })
	return g
}

func (g *gates) open(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	close(g.held[name])
	delete(g.held, name)
}

// expect waits for the given entries in any order; anything else fails.
func (g *gates) expect(t *testing.T, want ...string) {
	t.Helper()
	var got []string
	for range want {
		select {
		case s := <-g.entered:
			got = append(got, s)
		case <-time.After(5 * time.Second):
			t.Fatalf("entered %v, want %v", got, want)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("entered %v, want %v", got, want)
	}
}

// quiet fails when a pipeline enters within a short while.
func (g *gates) quiet(t *testing.T) {
	t.Helper()
	select {
	case s := <-g.entered:
		t.Fatalf("%s entered", s)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestGroupOrder(t *testing.T) {
	e := newGroupEnv(t, 1)
	g := newGates(t, "first", "free")
	d := e.dispatcher()
	j := e.enqueueGrouped(t, "o1", "first", "first2", "second", "free")
	d.Submit(j)
	// Same order concurrently, the free pipeline beside the group.
	g.expect(t, "o1/first", "o1/first2", "o1/free")
	g.quiet(t)
	g.open("first")
	g.expect(t, "o1/second")
	g.open("free")
	d.Wait()
	gone(t, j.Entry.Dir)
	gone(t, e.recordPath("up", "o1"))
	if e.read(t, "s/file/r-o1") != "data-o1" {
		t.Fatal("not stored")
	}
}

func TestGroupFailureSkipsLaterOrders(t *testing.T) {
	e := newGroupEnv(t, 1)
	g := newGates(t)
	st := status.New(status.Path(e.root))
	d := e.dispatcher()
	d.SetStatus(st)
	j := e.enqueueGrouped(t, "f1", "bad", "hok", "after", "last", "free")
	d.Submit(j)
	d.Wait()
	g.expect(t, "f1/bad", "f1/hok", "f1/free")
	g.quiet(t)
	gone(t, j.Entry.Dir)
	r := loadRecord(t, e.recordPath("up", "f1"))
	var names []string
	for _, x := range r.Pipelines {
		names = append(names, x.Pipeline)
		switch x.Pipeline {
		case "bad":
			if x.State != StateFailed || x.Step != 2 || len(x.Stored) != 1 {
				t.Fatalf("%+v", x)
			}
		case "hok", "free":
			if x.State != StateOK || x.Error != "" || len(x.Stored) != 1 {
				t.Fatalf("%+v", x)
			}
		default:
			if x.State != StateNotRun || x.Step != 0 || x.Error != "not run: bad failed" || len(x.Stored) != 0 {
				t.Fatalf("%+v", x)
			}
		}
	}
	if got := strings.Join(names, ","); got != "after,bad,free,hok,last" {
		t.Fatalf("pipelines %s", got)
	}
	recs := e.logs.records(t)
	for _, n := range []string{"after", "last"} {
		if r := find(recs, "pipeline skipped", n); r == nil || r["reason"] != "not run: bad failed" || r["level"] != "WARN" {
			t.Fatalf("%s: %v", n, r)
		}
	}
	for _, x := range st.Entries() {
		switch x.Pipeline {
		case "after", "last":
			if x.LastFailure == "" || x.FailedStep != 0 || x.Error != "not run: bad failed" {
				t.Fatalf("status %+v", x)
			}
		case "hok", "free":
			if x.LastSuccess == "" || x.LastFailure != "" {
				t.Fatalf("status %+v", x)
			}
		}
	}

}

func TestGroupConcurrencyAcrossUploads(t *testing.T) {
	e := newGroupEnv(t, 1)
	g := newGates(t, "second")
	d := e.dispatcher()
	d.Submit(e.enqueueGrouped(t, "k1", "first", "second"))
	d.Submit(e.enqueueGrouped(t, "k2", "first", "second"))
	var got []string
	for range 3 {
		select {
		case s := <-g.entered:
			got = append(got, s)
		case <-time.After(5 * time.Second):
			t.Fatalf("entered %v", got)
		}
	}
	slices.Sort(got)
	var held string
	switch {
	case slices.Equal(got, []string{"k1/first", "k1/second", "k2/first"}):
		held = "k2/second"
	case slices.Equal(got, []string{"k1/first", "k2/first", "k2/second"}):
		held = "k1/second"
	default:
		t.Fatalf("entered %v", got)
	}
	// One run of second at a time, whichever upload.
	g.quiet(t)
	g.open("second")
	g.expect(t, held)
	d.Wait()
	for _, id := range []string{"k1", "k2"} {
		if e.read(t, "s/file/r-"+id) != "data-"+id {
			t.Fatalf("%s not stored", id)
		}
	}
}

func TestGroupWaitHoldsNoSlot(t *testing.T) {
	e := newGroupEnv(t, 1)
	g := newGates(t, "first")
	d := e.dispatcher()
	d.Submit(e.enqueueGrouped(t, "w1", "first", "second"))
	g.expect(t, "w1/first")
	// w1 waits for first; the only slot of second stays free.
	d.Submit(e.enqueueGrouped(t, "w2", "second"))
	g.expect(t, "w2/second")
	g.open("first")
	g.expect(t, "w1/second")
	d.Wait()
}

func TestGroupNoDeadlock(t *testing.T) {
	e := newGroupEnv(t, 1)
	newGates(t)
	d := e.dispatcher()
	var jobs []Job
	for i := range 4 {
		jobs = append(jobs, e.enqueueGrouped(t, fmt.Sprintf("n%d", i), "first", "second", "free"))
	}
	for _, j := range jobs {
		d.Submit(j)
	}
	done := make(chan struct{})
	go func() { d.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock")
	}
	for _, j := range jobs {
		gone(t, j.Entry.Dir)
	}
}

func TestGroupReloadAppliesToNewUploads(t *testing.T) {
	e := newGroupEnv(t, 1)
	g := newGates(t, "first")
	d := e.dispatcher()
	d.Submit(e.enqueueGrouped(t, "u1", "first", "second"))
	g.expect(t, "u1/first")
	// The reload moves second before first; u1 keeps its snapshot.
	e.cfg = groupCfg(t, e.root, 1, func(s string) string {
		return strings.Replace(s, "{group: g, order: 2, concurrency: 1}", "{group: g, order: 0, concurrency: 1}", 1)
	})
	d.Reload(e.cfg)
	g.quiet(t)
	j := e.enqueueGrouped(t, "u2", "first", "second")
	if j.Stages["second"].Order != 0 {
		t.Fatalf("stages %+v", j.Stages)
	}
	d.Submit(j)
	g.expect(t, "u2/second")
	g.quiet(t)
	g.open("first")
	g.expect(t, "u1/second", "u2/first")
	d.Wait()
}

func TestSchedule(t *testing.T) {
	stages := map[string]Stage{"a": {"x", 2}, "b": {"x", 1}, "c": {"x", 2}, "d": {"w", 5}}
	free, groups := schedule([]string{"a", "b", "c", "d", "e"}, stages)
	if fmt.Sprint(free) != "[e]" || fmt.Sprint(groups) != "[[[d]] [[b] [a c]]]" {
		t.Fatalf("%v %v", free, groups)
	}
}

func TestGroupCloseKeepsLaterOrders(t *testing.T) {
	e := newGroupEnv(t, 1)
	g := newGates(t, "first")
	d := e.dispatcher()
	j := e.enqueueGrouped(t, "x1", "first", "second")
	d.Submit(j)
	g.expect(t, "x1/first")
	d.Close()
	g.open("first")
	d.Wait()
	g.quiet(t)
	left, err := LoadJob(j.Entry)
	if err != nil || strings.Join(left.Pipelines, ",") != "second" || left.Stages["second"].Order != 2 {
		t.Fatalf("%+v %v", left, err)
	}
	d = e.dispatcher()
	if err := d.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.expect(t, "x1/second")
	d.Wait()
	gone(t, j.Entry.Dir)
}
