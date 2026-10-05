package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/config"
	"luk/internal/expose"
	"luk/internal/pipeline"
	"luk/internal/queue"
	"luk/internal/status"
	"luk/internal/store"
	"luk/internal/wire"
)

type roleEnv struct {
	cfg  *config.Config
	dir  string
	root string
	addr string
	user ssh.Signer
}

func newRoleEnv(t *testing.T) *roleEnv {
	t.Helper()
	e := &roleEnv{dir: t.TempDir(), root: t.TempDir(), addr: freePort(t), user: newSigner(t)}
	text := fmt.Sprintf(`
root: %s
listen: {main: {addr: "%s", public: "http://%s"}}
auth:
  keys: [{name: robert.socha, key: "%s"}]
endpoint:
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha], respond: url, storage: drop}
pipeline:
  drop: {endpoint: [drop], steps: [{store: drop}]}
storage:
  drop: {type: local, base: s/drop, path: "{{ .File }}", expose: drop, catalog: true, ttl: {max: 7d}}
expose:
  drop: {listen: main, path: /d/}
`, e.root, e.addr, e.addr, pubLine(e.user.PublicKey()))
	p := filepath.Join(e.dir, "config.yaml")
	if err := os.WriteFile(p, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	writeIdentity(t, p)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	return e
}

func fastPickup(t *testing.T) {
	old := processPickup
	processPickup = 50 * time.Millisecond
	t.Cleanup(func() { processPickup = old })
}

func slowPickup(t *testing.T) {
	old := processPickup
	processPickup = time.Hour
	t.Cleanup(func() { processPickup = old })
}

// start runs a role until the test ends and waits until it is up: the
// listener answers, or the process role logged its start.
func (e *roleEnv) start(t *testing.T, role func(context.Context, *config.Config, *slog.Logger) error, logs *syncBuf) chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- role(ctx, e.cfg, slog.New(slog.NewTextHandler(logs, nil))) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("role did not stop")
		}
	})
	waitFor(t, "start", func() bool {
		if strings.Contains(logs.String(), `msg="process started"`) {
			return true
		}
		c, err := net.Dial("tcp", e.addr)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	return done
}

func (e *roleEnv) upload(t *testing.T, file string, once bool, body string) wire.Created {
	t.Helper()
	m := fileMeta([]byte(body))
	m.File, m.Once = file, once
	rec, _ := chanUpload(t, req{signer: e.user, host: e.addr, path: "/drop", meta: m, body: []byte(body), via: remote{http.DefaultClient, "http://" + e.addr}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload %s: %d %s", file, rec.Code, rec.Body)
	}
	var c wire.Created
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func get(t *testing.T, u string) (int, string) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func (e *roleEnv) catalog(t *testing.T) []string {
	t.Helper()
	code, body := get(t, "http://"+e.addr+"/d/catalog.json")
	if code != http.StatusOK {
		t.Fatalf("catalog %d %s", code, body)
	}
	var c struct {
		Files []struct {
			Name string `json:"name"`
		} `json:"files"`
	}
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatal(err)
	}
	var n []string
	for _, f := range c.Files {
		n = append(n, f.Name)
	}
	return n
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestReceiveQueuesWithoutRunning(t *testing.T) {
	e := newRoleEnv(t)
	var logs syncBuf
	e.start(t, Receive, &logs)
	e.upload(t, "a.txt", false, "hello")
	qdir := filepath.Join(e.root, "q/drop")
	ents := entries(t, qdir)
	if len(ents) != 1 || !exists(filepath.Join(qdir, ents[0], "meta.json")) || !exists(filepath.Join(qdir, ents[0], "payload")) {
		t.Fatalf("queue %v", ents)
	}
	time.Sleep(300 * time.Millisecond)
	if exists(filepath.Join(e.root, "s/drop/file/a.txt")) {
		t.Fatal("receive ran the pipeline")
	}
	if len(entries(t, qdir)) != 1 {
		t.Fatal("queue entry gone")
	}
	if exists(status.Path(e.root)) {
		t.Fatal("receive wrote status.json")
	}
}

// commit puts an accepted entry for the drop pipeline into the queue.
func (e *roleEnv) commit(t *testing.T, id, file, body string) {
	t.Helper()
	qdir := filepath.Join(e.root, "q/drop")
	if err := os.MkdirAll(qdir, 0o750); err != nil {
		t.Fatal(err)
	}
	q := queue.New(0, nil)
	ent, n, sum, err := q.Receive(context.Background(), qdir, id, strings.NewReader(body), 0, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	vars := store.Vars{Sender: "robert.socha", Endpoint: "drop", Id: id, File: file}
	sc := store.Sidecar{ID: id, Sender: "robert.socha", Endpoint: "drop", Received: time.Now().UTC().Format(time.RFC3339), Size: n, SHA256: sum}
	if err := q.Commit(ent, pipeline.QueueMeta{Pipelines: []string{"drop"}, Vars: vars, Sidecar: sc}); err != nil {
		t.Fatal(err)
	}
}

func TestProcessPicksUpCommitted(t *testing.T) {
	fastPickup(t)
	e := newRoleEnv(t)
	half := filepath.Join(e.root, "q/drop/half")
	if err := os.MkdirAll(half, 0o750); err != nil {
		t.Fatal(err)
	}
	var logs syncBuf
	e.start(t, Process, &logs)
	if strings.Contains(logs.String(), "listening") {
		t.Fatal("process opened a listener")
	}
	start := time.Now()
	e.commit(t, "id-1", "kept.txt", "payload")
	waitFor(t, "stored", func() bool {
		b, err := os.ReadFile(filepath.Join(e.root, "s/drop/file/kept.txt"))
		return err == nil && string(b) == "payload"
	})
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("picked up after %s", d)
	}
	waitFor(t, "queue entry removed", func() bool { return !exists(filepath.Join(e.root, "q/drop/id-1")) })
	if !exists(half) {
		t.Fatal("process removed an entry being received")
	}
	waitFor(t, "status", func() bool {
		st, _, err := status.Open(status.Path(e.root))
		if err != nil {
			return false
		}
		es := st.Entries()
		return len(es) == 1 && es[0].Pipeline == "drop" && es[0].LastID == "id-1" && es[0].LastSuccess != ""
	})
}

func TestProcessWokenOnCommit(t *testing.T) {
	slowPickup(t)
	e := newRoleEnv(t)
	var logs syncBuf
	e.start(t, Process, &logs)
	e.commit(t, "id-1", "kept.txt", "payload")
	start := time.Now()
	waitFor(t, "stored", func() bool { return exists(filepath.Join(e.root, "s/drop/file/kept.txt")) })
	if d := time.Since(start); d > time.Second {
		t.Fatalf("picked up after %s", d)
	}
}

func TestProcessWokenOnBurst(t *testing.T) {
	slowPickup(t)
	e := newRoleEnv(t)
	var logs syncBuf
	e.start(t, Process, &logs)
	const n = 20
	for i := range n {
		e.commit(t, fmt.Sprintf("id-%d", i), fmt.Sprintf("f%d.txt", i), "payload")
	}
	waitFor(t, "all stored", func() bool {
		for i := range n {
			if !exists(filepath.Join(e.root, "s/drop/file", fmt.Sprintf("f%d.txt", i))) {
				return false
			}
		}
		return true
	})
}

func TestReceiveAndProcessShareRoot(t *testing.T) {
	fastPickup(t)
	e := newRoleEnv(t)
	var rlogs, plogs syncBuf
	e.start(t, Receive, &rlogs)
	e.start(t, Process, &plogs)
	c := e.upload(t, "a.txt", false, "hello")
	waitFor(t, "download", func() bool {
		code, body := get(t, c.URL)
		return code == http.StatusOK && body == "hello"
	})
	if n := e.catalog(t); fmt.Sprint(n) != "[a.txt]" {
		t.Fatalf("catalog %v", n)
	}
	if code, _ := get(t, c.URL); code != http.StatusOK {
		t.Fatalf("second download %d", code)
	}
}

func TestOnceClaimWhileProcessRebuildsCatalog(t *testing.T) {
	fastPickup(t)
	e := newRoleEnv(t)
	var rlogs, plogs syncBuf
	e.start(t, Receive, &rlogs)
	e.start(t, Process, &plogs)
	const n = 8
	var urls []string
	for i := range n {
		urls = append(urls, e.upload(t, fmt.Sprintf("once%d", i), true, fmt.Sprintf("body%d", i)).URL)
	}
	base := filepath.Join(e.root, "s/drop/file")
	waitFor(t, "stored", func() bool {
		for i := range n {
			if !exists(filepath.Join(base, fmt.Sprintf("once%d", i))) {
				return false
			}
		}
		return true
	})
	st := store.FromConfig(e.cfg.Storage["drop"])
	var fillers []string
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 20 {
			name := fmt.Sprintf("filler%02d", i)
			src := filepath.Join(t.TempDir(), "src")
			if err := os.WriteFile(src, []byte(name), 0o640); err != nil {
				t.Error(err)
				return
			}
			sc := store.Sidecar{ID: name, Sender: "robert.socha", Endpoint: "drop", Received: time.Now().UTC().Format(time.RFC3339), Size: int64(len(name))}
			if _, err := st.Put(src, name, sc); err != nil {
				t.Error(err)
				return
			}
			fillers = append(fillers, name)
			if err := st.Reconcile(); err != nil {
				t.Error(err)
			}
		}
	})
	got := make([][]int, n)
	var mu sync.Mutex
	for i, u := range urls {
		for range 2 {
			wg.Go(func() {
				code, body := get(t, u)
				mu.Lock()
				defer mu.Unlock()
				got[i] = append(got[i], code)
				if code == http.StatusOK && body != fmt.Sprintf("body%d", i) {
					t.Errorf("once%d: %q", i, body)
				}
			})
		}
	}
	wg.Wait()
	for i, codes := range got {
		slices.Sort(codes)
		if fmt.Sprint(codes) != "[200 404]" {
			t.Errorf("once%d: %v", i, codes)
		}
	}
	if err := st.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if c := e.catalog(t); !slices.Equal(c, fillers) {
		t.Fatalf("catalog %v, want %v", c, fillers)
	}
}

func TestProcessReloadsOnHUP(t *testing.T) {
	slowPickup(t)
	e := newRoleEnv(t)
	var logs syncBuf
	done := e.start(t, Process, &logs)
	snippet := `
endpoint:
  extra: {listen: main, endpoint: /extra, path: q/extra, allow: [robert.socha]}
pipeline:
  extra: {endpoint: [extra], steps: [{store: drop}]}
`
	if err := os.MkdirAll(filepath.Join(e.dir, "config.d"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "config.d/extra.yaml"), []byte(snippet), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reload", func() bool { return strings.Contains(logs.String(), `msg="config reloaded"`) })
	select {
	case err := <-done:
		t.Fatalf("process stopped on SIGHUP: %v", err)
	default:
	}
	// The queue directory of the new endpoint is watched: a commit is
	// picked up long before the poll.
	qdir := filepath.Join(e.root, "q/extra")
	q := queue.New(0, nil)
	ent, n, sum, err := q.Receive(context.Background(), qdir, "id-x", strings.NewReader("extra"), 0, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	vars := store.Vars{Sender: "robert.socha", Endpoint: "extra", Id: "id-x", File: "extra.txt"}
	sc := store.Sidecar{ID: "id-x", Sender: "robert.socha", Endpoint: "extra", Received: time.Now().UTC().Format(time.RFC3339), Size: n, SHA256: sum}
	if err := q.Commit(ent, pipeline.QueueMeta{Pipelines: []string{"extra"}, Vars: vars, Sidecar: sc}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "stored", func() bool { return exists(filepath.Join(e.root, "s/drop/file/extra.txt")) })
}

func TestRoleRunsOncePerRoot(t *testing.T) {
	e := newRoleEnv(t)
	var plogs, rlogs syncBuf
	e.start(t, Process, &plogs)
	log := slog.New(slog.DiscardHandler)
	if err := Process(context.Background(), e.cfg, log); err == nil || !strings.Contains(err.Error(), "another lukd runs the process role") {
		t.Fatalf("second process: %v", err)
	}
	e.start(t, Receive, &rlogs)
	if err := Receive(context.Background(), e.cfg, log); err == nil || !strings.Contains(err.Error(), "another lukd runs the receive role") {
		t.Fatalf("second receive: %v", err)
	}
}

func TestProcessResumesQueue(t *testing.T) {
	slowPickup(t)
	e := newRoleEnv(t)
	e.commit(t, "left-over", "kept.txt", "payload")
	half := filepath.Join(e.root, "q/drop/half")
	if err := os.MkdirAll(half, 0o750); err != nil {
		t.Fatal(err)
	}
	old := `[{"pipeline":"gone","sender":"alice","tags":[],"last_id":"x","last_received":"","last_success":"2026-01-01T00:00:00Z","size":1}]`
	writeStatus(t, e.root, []byte(old), 0o640)
	var logs syncBuf
	e.start(t, Process, &logs)
	waitFor(t, "stored", func() bool {
		b, err := os.ReadFile(filepath.Join(e.root, "s/drop/file/kept.txt"))
		return err == nil && string(b) == "payload"
	})
	waitFor(t, "queue entry removed", func() bool { return !exists(filepath.Join(e.root, "q/drop/left-over")) })
	if !exists(half) {
		t.Fatal("process removed an entry being received")
	}
	waitFor(t, "status", func() bool {
		st, _, err := status.Open(status.Path(e.root))
		if err != nil {
			return false
		}
		es := st.Entries()
		return len(es) == 2 && es[0].Pipeline == "drop" && es[0].LastSuccess != "" && es[0].LastID == "left-over" && es[1].Pipeline == "gone"
	})
}

func TestReceiveRemovesHalfReceived(t *testing.T) {
	e := newRoleEnv(t)
	e.commit(t, "committed", "kept.txt", "payload")
	half := filepath.Join(e.root, "q/drop/20261004T100000Z-0123abcd")
	if err := os.MkdirAll(half, 0o750); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(e.root, "q/drop/inner/20261004T100000Z-0123abcd")
	if err := os.MkdirAll(other, 0o750); err != nil {
		t.Fatal(err)
	}
	var logs syncBuf
	e.start(t, Receive, &logs)
	if exists(half) {
		t.Fatal("half-received entry kept")
	}
	if !exists(other) {
		t.Fatal("a directory not named like an entry removed")
	}
	if !exists(filepath.Join(e.root, "q/drop/committed/meta.json")) {
		t.Fatal("committed entry removed")
	}
}

func TestRolesCancelledBeforeStart(t *testing.T) {
	for name, fn := range map[string]func(context.Context, *config.Config, *slog.Logger) error{"receive": Receive, "process": Process} {
		e := newRoleEnv(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := fn(ctx, e.cfg, slog.New(slog.DiscardHandler)); err != nil {
			t.Fatalf("%s: cancelled start: %v", name, err)
		}
	}
}

func TestProcessStatusCorruptMovedAside(t *testing.T) {
	e := newRoleEnv(t)
	writeStatus(t, e.root, []byte("not json"), 0o640)
	var logs strings.Builder
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Process(ctx, e.cfg, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatalf("process: %v", err)
	}
	ms, _ := filepath.Glob(status.Path(e.root) + ".corrupt-*")
	if len(ms) != 1 || !strings.Contains(logs.String(), ms[0]) || !strings.Contains(logs.String(), status.Path(e.root)) {
		t.Fatalf("aside %v, logs %s", ms, logs.String())
	}
}

func TestProcessStatusUnreadableFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	e := newRoleEnv(t)
	writeStatus(t, e.root, []byte("[]"), 0o000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Process(ctx, e.cfg, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("process: %v", err)
	}
}

// writeStatus writes a status file the process role finds at start.
func writeStatus(t *testing.T, root string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(status.Path(root)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(status.Path(root), data, perm); err != nil {
		t.Fatal(err)
	}
}

// TestRolesAlive: each role writes its liveness file at start and its
// janitor loop touches it, rewriting it when deleted.
func TestRolesAlive(t *testing.T) {
	old := expose.BeatEvery
	expose.BeatEvery = 20 * time.Millisecond
	t.Cleanup(func() { expose.BeatEvery = old })
	slowPickup(t)
	for _, c := range []struct {
		name string
		role func(context.Context, *config.Config, *slog.Logger) error
	}{{"receive", Receive}, {"process", Process}} {
		t.Run(c.name, func(t *testing.T) {
			e := newRoleEnv(t)
			var logs syncBuf
			e.start(t, c.role, &logs)
			p := status.AlivePath(e.root, c.name)
			for _, d := range []string{status.Dir(e.root), status.RoleDir(e.root, c.name)} {
				if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o750 {
					t.Fatalf("%s: %v %v", d, fi, err)
				}
			}
			waitFor(t, "alive.json", func() bool { return exists(p) })
			b, _ := os.ReadFile(p)
			var info status.AliveInfo
			if err := json.Unmarshal(b, &info); err != nil || info.Role != c.name || info.Version != Version {
				t.Fatalf("%s: %+v %v", b, info, err)
			}
			if _, err := time.Parse(time.RFC3339, info.Started); err != nil {
				t.Fatal(err)
			}
			past := time.Now().Add(-time.Hour)
			if err := os.Chtimes(p, past, past); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "heartbeat", func() bool {
				fi, err := os.Stat(p)
				return err == nil && time.Since(fi.ModTime()) < time.Minute
			})
			if after, _ := os.ReadFile(p); string(after) != string(b) {
				t.Fatalf("content rewritten: %s", after)
			}
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "alive.json rewritten", func() bool {
				after, err := os.ReadFile(p)
				return err == nil && string(after) == string(b)
			})
			other := map[string]string{"receive": "process", "process": "receive"}[c.name]
			if exists(status.RoleDir(e.root, other)) {
				t.Fatalf("%s created the status directory of %s", c.name, other)
			}
		})
	}
}

// TestReceiveAcceptedAfterMark: the receive role continues the acceptance
// order after the mark under the root, even with the wall clock behind
// it, and moves the mark past the order it hands out.
func TestReceiveAcceptedAfterMark(t *testing.T) {
	e := newRoleEnv(t)
	mark := time.Now().Add(time.Hour).UnixNano()
	if err := os.WriteFile(queue.MarkPath(e.root), []byte(fmt.Sprintf(`{"mark":%d}`, mark)), 0o640); err != nil {
		t.Fatal(err)
	}
	var logs syncBuf
	e.start(t, Receive, &logs)
	e.upload(t, "a.txt", false, "hello")
	qdir := filepath.Join(e.root, "q/drop")
	ents := entries(t, qdir)
	if len(ents) != 1 {
		t.Fatalf("queue %v", ents)
	}
	b, err := os.ReadFile(filepath.Join(qdir, ents[0], "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m pipeline.QueueMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Sidecar.Accepted <= mark {
		t.Fatalf("accepted %d, not after the mark %d", m.Sidecar.Accepted, mark)
	}
	b, err = os.ReadFile(queue.MarkPath(e.root))
	if err != nil {
		t.Fatal(err)
	}
	var now struct{ Mark int64 }
	if err := json.Unmarshal(b, &now); err != nil || now.Mark < m.Sidecar.Accepted {
		t.Fatalf("mark %s after accepted %d: %v", b, m.Sidecar.Accepted, err)
	}
}
