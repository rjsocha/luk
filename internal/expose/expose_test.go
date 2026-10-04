package expose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"luk/internal/config"
	"luk/internal/store"
	"luk/internal/wire"
)

var t0 = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

type env struct {
	cfg  *config.Config
	base string
	st   store.Local
	h    http.Handler
	now  time.Time
	logs *bytes.Buffer
}

// sweep runs both parts of a janitor pass.
func sweep(cfg *config.Config, log *slog.Logger, now time.Time) {
	expire(cfg, log, now)
	maintain(cfg, log, now)
}

func newEnv(t *testing.T, mod func(x *config.Expose)) *env {
	t.Helper()
	base := t.TempDir()
	x := &config.Expose{Listen: config.StringList{"l"}, Path: "/d/"}
	if mod != nil {
		mod(x)
	}
	cfg := &config.Config{
		Storage: map[string]*config.Storage{"drop": {Type: "local", Base: base, Expose: "pub", Conflict: "version"}},
		Expose:  map[string]*config.Expose{"pub": x},
	}
	e := &env{cfg: cfg, base: base, st: store.Local{Base: base, Conflict: "version"}, now: t0, logs: &bytes.Buffer{}}
	e.h = New(cfg, e.log(), func() time.Time { return e.now }, "l", nil)
	return e
}

func (e *env) log() *slog.Logger {
	return slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func (e *env) put(t *testing.T, rel, content string, sc store.Sidecar) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	sc.SHA256 = hex.EncodeToString(sum[:])
	sc.Size = int64(len(content))
	if sc.ID == "" {
		sc.ID = "id-" + rel
	}
	if sc.Received == "" {
		sc.Received = t0.Format(time.RFC3339)
	}
	if sc.Client.Portal == "" {
		sc.Client.Portal = wire.PortalDirect
	}
	got, err := e.st.Put(src, rel, sc)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (e *env) do(t *testing.T, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func TestDownloadHeaders(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "a/meta.bin", "hello", store.Sidecar{Client: wire.Meta{File: "report.pdf", Type: "text/x-custom"}})
	e.put(t, "a/ext", "hello", store.Sidecar{Client: wire.Meta{File: "notes.txt"}})
	e.put(t, "a/none", "hello", store.Sidecar{})
	e.put(t, "a/utf", "hello", store.Sidecar{Client: wire.Meta{File: "zażółć.txt"}})

	w := e.do(t, "GET", "/d/a/meta.bin", nil)
	if w.Code != 200 || w.Body.String() != "hello" {
		t.Fatalf("code %d body %q", w.Code, w.Body.String())
	}
	h := w.Header()
	sum := sha256.Sum256([]byte("hello"))
	want := map[string]string{
		"Content-Type":            "text/x-custom",
		"Content-Disposition":     `attachment; filename="report.pdf"`,
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "sandbox",
		"Etag":                    `"` + hex.EncodeToString(sum[:]) + `"`,
		"Content-Length":          "5",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if h.Get("Cache-Control") == "no-store" {
		t.Error("no-store on non-once")
	}

	if got := e.do(t, "GET", "/d/a/ext", nil).Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("ext type %q", got)
	}
	w = e.do(t, "GET", "/d/a/none", nil)
	if got := w.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("default type %q", got)
	}
	if got := w.Header().Get("Content-Disposition"); got != `attachment; filename="none"` {
		t.Errorf("stored name disposition %q", got)
	}
	got := e.do(t, "GET", "/d/a/utf", nil).Header().Get("Content-Disposition")
	if got != `attachment; filename="za____.txt"; filename*=UTF-8''za%C5%BC%C3%B3%C5%82%C4%87.txt` {
		t.Errorf("utf disposition %q", got)
	}
	if got := disposition("a\xffb"); got != `attachment; filename="a_b"; filename*=UTF-8''a_b` {
		t.Errorf("invalid utf-8 disposition %q", got)
	}
}

func TestRangeHeadETag(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "f", "0123456789", store.Sidecar{})
	w := e.do(t, "GET", "/d/f", map[string]string{"Range": "bytes=2-4"})
	if w.Code != http.StatusPartialContent || w.Body.String() != "234" {
		t.Fatalf("range: %d %q", w.Code, w.Body.String())
	}
	w = e.do(t, "HEAD", "/d/f", nil)
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "10" {
		t.Fatalf("head: %d %d %q", w.Code, w.Body.Len(), w.Header().Get("Content-Length"))
	}
	etag := w.Header().Get("Etag")
	if w = e.do(t, "GET", "/d/f", map[string]string{"If-None-Match": etag}); w.Code != http.StatusNotModified {
		t.Fatalf("if-none-match: %d", w.Code)
	}
}

func TestNotFoundAndMethods(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "ok", "x", store.Sidecar{})
	e.put(t, "dir/in", "x", store.Sidecar{})
	if err := os.WriteFile(filepath.Join(e.base, store.DataDir, ".hidden"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e.base, store.DataDir, "ok"), filepath.Join(e.base, store.DataDir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e.base, ".db", "meta", "ok.json"), filepath.Join(e.base, ".db", "meta", "link.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e.base, store.DataDir, "dir"), filepath.Join(e.base, store.DataDir, "ldir")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"/d/missing", "/d/", "/d/../d/ok", "/d/dir/../ok", "/d/.hidden", "/d/.luk/ok.json", "/d/.db/lock", "/d/.db/meta/ok.json", "/d/file/ok",
		"/d/dir", "/d/dir/", "/d//ok", "/d/link", "/d/ldir/in", "/other/ok", "/", "/dok", "/d/ok/x",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
		if strings.Contains(w.Body.String(), e.base) {
			t.Errorf("%s: body leaks path: %q", p, w.Body.String())
		}
	}
	if e.logs.Len() != 0 {
		t.Errorf("warnings for plain misses: %s", e.logs)
	}
	w := e.do(t, "PUT", "/d/ok", nil)
	if w.Code != http.StatusMethodNotAllowed || !strings.Contains(w.Header().Get("Allow"), "GET") {
		t.Errorf("PUT: %d allow %q", w.Code, w.Header().Get("Allow"))
	}
	if w := e.do(t, "GET", "/d/ok", nil); w.Code != 200 {
		t.Errorf("ok: %d", w.Code)
	}
}

func TestExpired(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "old", "x", store.Sidecar{Expires: t0.Add(-time.Second).Format(time.RFC3339)})
	e.put(t, "new", "x", store.Sidecar{Expires: t0.Add(time.Hour).Format(time.RFC3339)})
	if w := e.do(t, "GET", "/d/old", nil); w.Code != 404 {
		t.Errorf("expired: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/new", nil); w.Code != 200 {
		t.Errorf("valid: %d", w.Code)
	}
	e.put(t, "garbled", "x", store.Sidecar{Expires: "tomorrow"})
	if w := e.do(t, "GET", "/d/garbled", nil); w.Code != 404 {
		t.Errorf("unparseable expires served: %d", w.Code)
	}
	sweep(e.cfg, e.log(), t0)
	if !exists(filepath.Join(e.base, store.DataDir, "garbled")) || !strings.Contains(e.logs.String(), "garbled") {
		t.Errorf("unparseable expires: removed or not logged: %s", e.logs)
	}
	if exists(filepath.Join(e.base, store.DataDir, "old")) || exists(e.st.SidecarPath("old")) {
		t.Error("janitor kept expired file")
	}
	if !exists(filepath.Join(e.base, store.DataDir, "new")) || !exists(e.st.SidecarPath("new")) {
		t.Error("janitor removed valid file")
	}
}

func TestOnce(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "o", "secret", store.Sidecar{Client: wire.Meta{Once: true}})
	w := e.do(t, "HEAD", "/d/o", nil)
	if w.Code != 200 || w.Header().Get("Content-Length") != "6" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("head: %d %v", w.Code, w.Header())
	}
	if !exists(filepath.Join(e.base, store.DataDir, "o")) {
		t.Fatal("HEAD consumed once")
	}
	w = e.do(t, "GET", "/d/o", map[string]string{"Range": "bytes=0-1"})
	if w.Code != 200 || w.Body.String() != "secret" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Accept-Ranges") == "bytes" {
		t.Fatalf("get: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	if w := e.do(t, "GET", "/d/o", nil); w.Code != 404 {
		t.Fatalf("second get: %d", w.Code)
	}
	if exists(filepath.Join(e.base, store.DataDir, "o")) || exists(e.st.SidecarPath("o")) {
		t.Error("once file or sidecar left")
	}
	ents, _ := os.ReadDir(filepath.Join(e.base, store.ClaimedDir))
	if len(ents) != 0 {
		t.Errorf("claimed left: %v", ents)
	}
}

func TestOnceConcurrent(t *testing.T) {
	for i := 0; i < 20; i++ {
		e := newEnv(t, nil)
		e.put(t, "o", "secret", store.Sidecar{Client: wire.Meta{Once: true}})
		var wg sync.WaitGroup
		codes := make([]int, 8)
		for j := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[j] = e.do(t, "GET", "/d/o", nil).Code
			}()
		}
		wg.Wait()
		ok := 0
		for _, c := range codes {
			switch c {
			case 200:
				ok++
			case 404:
			default:
				t.Fatalf("code %d", c)
			}
		}
		if ok != 1 {
			t.Fatalf("%d successful downloads: %v", ok, codes)
		}
	}
}

func TestOnceKeepsNewUploadAtSameName(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "o", "first", store.Sidecar{Client: wire.Meta{Once: true}})
	orig := claimHook
	defer func() { claimHook = orig }()
	claimHook = func() {
		claimHook = func() {}
		e.put(t, "o", "second", store.Sidecar{ID: "second"})
	}
	if w := e.do(t, "GET", "/d/o", nil); w.Code != 200 || w.Body.String() != "first" {
		t.Fatalf("get: %d %q", w.Code, w.Body.String())
	}
	if w := e.do(t, "GET", "/d/o", nil); w.Code != 200 || w.Body.String() != "second" {
		t.Fatalf("new upload: %d %q", w.Code, w.Body.String())
	}
}

func TestOnceReplacedBeforeClaim(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "o", "first", store.Sidecar{Client: wire.Meta{Once: true}})
	orig := beforeClaim
	defer func() { beforeClaim = orig }()
	beforeClaim = func() {
		beforeClaim = func() {}
		st := store.Local{Base: e.base, Conflict: "replace"}
		src := filepath.Join(t.TempDir(), "src")
		os.WriteFile(src, []byte("second"), 0o640)
		if _, err := st.Put(src, "o", store.Sidecar{ID: "second", Client: wire.Meta{Portal: wire.PortalDirect}}); err != nil {
			t.Fatal(err)
		}
	}
	w := e.do(t, "GET", "/d/o", nil)
	if w.Code != 404 {
		t.Fatalf("replaced: %d %q", w.Code, w.Body.String())
	}
	for _, k := range []string{"Content-Disposition", "Etag", "Cache-Control", "Content-Security-Policy"} {
		if v := w.Header().Get(k); v != "" {
			t.Errorf("404 carries %s: %q", k, v)
		}
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("404 content type %q", ct)
	}
	if w := e.do(t, "GET", "/d/o", nil); w.Code != 200 || w.Body.String() != "second" {
		t.Fatalf("new upload: %d %q", w.Code, w.Body.String())
	}
	ents, _ := os.ReadDir(filepath.Join(e.base, store.ClaimedDir))
	if len(ents) != 0 {
		t.Errorf("claimed left: %v", ents)
	}
}

func TestBasicAuth(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	h2y := "$2y$" + string(hash[4:])
	e := newEnv(t, func(x *config.Expose) { x.Auth.Basic = []string{"alice:" + string(hash), "bob:" + h2y} })
	e.put(t, "f", "x", store.Sidecar{})
	for _, c := range []struct {
		user, pass string
		auth       bool
		code       int
	}{
		{"", "", false, 401},
		{"alice", "bad", true, 401},
		{"carol", "pw", true, 401},
		{"alice", "pw", true, 200},
		{"bob", "pw", true, 200},
	} {
		r := httptest.NewRequest("GET", "/d/f", nil)
		if c.auth {
			r.SetBasicAuth(c.user, c.pass)
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		if w.Code != c.code {
			t.Errorf("%s:%s: %d, want %d", c.user, c.pass, w.Code, c.code)
		}
		if c.code == 401 && w.Header().Get("WWW-Authenticate") != `Basic realm="luk"` {
			t.Errorf("%s: WWW-Authenticate %q", c.user, w.Header().Get("WWW-Authenticate"))
		}
	}
	r := httptest.NewRequest("GET", "/d/missing", nil)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("missing without auth: %d", w.Code)
	}
}

func TestCleanupAgeAndClaimed(t *testing.T) {
	e := newEnv(t, nil)
	e.cfg.Storage["drop"].Cleanup.Age = config.Duration(24 * time.Hour)
	now := time.Now()
	e.put(t, "old", "x", store.Sidecar{Received: now.Add(-25 * time.Hour).UTC().Format(time.RFC3339)})
	e.put(t, "young", "x", store.Sidecar{Received: now.Add(-time.Hour).UTC().Format(time.RFC3339)})
	e.put(t, "garbled", "x", store.Sidecar{Received: "yesterday"})
	claimed := filepath.Join(e.base, store.ClaimedDir)
	if err := os.MkdirAll(claimed, 0o750); err != nil {
		t.Fatal(err)
	}
	stale, fresh := filepath.Join(claimed, "aaaa"), filepath.Join(claimed, "bbbb")
	for _, p := range []string{stale, fresh} {
		if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(stale, now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartJanitor(ctx, func() *config.Config { return e.cfg }, slog.New(slog.DiscardHandler), 0, Expire, nil, nil)
	deadline := time.Now().Add(5 * time.Second)
	for exists(filepath.Join(e.base, store.DataDir, "old")) || exists(stale) {
		if time.Now().After(deadline) {
			t.Fatal("janitor did not remove old files")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if exists(e.st.SidecarPath("old")) {
		t.Error("old sidecar left")
	}
	if !exists(filepath.Join(e.base, store.DataDir, "young")) || !exists(filepath.Join(e.base, store.DataDir, "garbled")) || !exists(fresh) {
		t.Error("janitor removed young files")
	}
}

func TestCleanupAgeWithoutExpose(t *testing.T) {
	base := t.TempDir()
	cfg := &config.Config{Storage: map[string]*config.Storage{"archive": {Type: "local", Base: base, Conflict: "version"}}}
	cfg.Storage["archive"].Cleanup.Age = config.Duration(24 * time.Hour)
	e := &env{cfg: cfg, base: base, st: store.Local{Base: base, Conflict: "version"}, now: t0, logs: &bytes.Buffer{}}
	old := t0.Add(-25 * time.Hour).Format(time.RFC3339)
	e.put(t, "old", "x", store.Sidecar{Received: old})
	e.put(t, "young", "x", store.Sidecar{Received: t0.Add(-time.Hour).Format(time.RFC3339)})
	e.put(t, "expiring", "x", store.Sidecar{Received: old, Expires: t0.Add(time.Hour).Format(time.RFC3339)})
	e.put(t, "expired", "x", store.Sidecar{Received: t0.Format(time.RFC3339), Expires: t0.Add(-time.Second).Format(time.RFC3339)})
	expire(cfg, e.log(), t0)
	for name, want := range map[string]bool{"old": false, "young": true, "expiring": true, "expired": false} {
		if exists(filepath.Join(base, store.DataDir, name)) != want {
			t.Errorf("%s: present %v, want %v", name, !want, want)
		}
	}
}

func TestSkipsNonLocal(t *testing.T) {
	cfg := &config.Config{
		Storage: map[string]*config.Storage{"s": {Type: "s3", Expose: "pub"}},
		Expose:  map[string]*config.Expose{"pub": {Listen: config.StringList{"l"}, Path: "/d/"}},
	}
	h := New(cfg, slog.New(slog.DiscardHandler), time.Now, "l", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/d/f", nil))
	if w.Code != 404 {
		t.Errorf("s3: %d", w.Code)
	}
	sweep(cfg, slog.New(slog.DiscardHandler), time.Now())
}

func TestJanitorKeepsReplacedFile(t *testing.T) {
	e := newEnv(t, nil)
	e.st.Conflict = "replace"
	e.put(t, "x", "old", store.Sidecar{ID: "id1", Expires: t0.Add(-time.Second).Format(time.RFC3339)})
	old := beforeRemove
	beforeRemove = func() {
		e.put(t, "x", "new", store.Sidecar{ID: "id2", Expires: t0.Add(time.Hour).Format(time.RFC3339)})
	}
	t.Cleanup(func() { beforeRemove = old })
	sweep(e.cfg, e.log(), t0)
	b, err := os.ReadFile(filepath.Join(e.base, store.DataDir, "x"))
	if err != nil || string(b) != "new" || !exists(e.st.SidecarPath("x")) {
		t.Fatalf("replacement removed: %q %v", b, err)
	}
}

func TestSweepUnexposedStorage(t *testing.T) {
	e := newEnv(t, nil)
	other := t.TempDir()
	e.cfg.Storage["archive"] = &config.Storage{Type: "local", Base: other}
	tmp, orphan := filepath.Join(other, ".db", "tmp", "0123"), filepath.Join(other, store.DataDir, ".lost")
	for _, p := range []string{tmp, orphan} {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, t0.Add(-2*time.Hour), t0.Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	sweep(e.cfg, e.log(), t0)
	if exists(tmp) {
		t.Error("staging leftover kept")
	}
	if !exists(orphan) || !strings.Contains(e.logs.String(), ".lost") {
		t.Errorf("orphan removed or not logged: %s", e.logs)
	}
}

func TestJanitorRemovesOldWorkDirs(t *testing.T) {
	e := newEnv(t, nil)
	e.cfg.Root = t.TempDir()
	work := e.cfg.WorkDir()
	old, young := filepath.Join(work, "old", "p"), filepath.Join(work, "young", "p")
	for _, d := range []string{old, young} {
		if err := os.MkdirAll(filepath.Join(d, "1", "out"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "1", "out", "f"), []byte("x"), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(old, t0.Add(-8*24*time.Hour), t0.Add(-8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(young, t0.Add(-6*24*time.Hour), t0.Add(-6*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	sweep(e.cfg, e.log(), t0)
	if exists(filepath.Join(work, "old")) {
		t.Error("old work dir kept")
	}
	if !exists(filepath.Join(young, "1", "out", "f")) {
		t.Error("young work dir removed")
	}
}

func TestShardedDownload(t *testing.T) {
	e := newEnv(t, nil)
	e.cfg.Storage["drop"].Shard = 2
	e.st.Shard = 2
	e.h = New(e.cfg, e.log(), func() time.Time { return e.now }, "l", nil)
	e.put(t, "Rnd0", "hello", store.Sidecar{Client: wire.Meta{File: "a.txt"}})
	e.put(t, "o", "secret", store.Sidecar{Client: wire.Meta{Once: true}})
	sum := sha256.Sum256([]byte("Rnd0"))
	x := hex.EncodeToString(sum[:2])
	if !exists(filepath.Join(e.base, store.DataDir, x[:2], x[2:], "Rnd0")) || exists(filepath.Join(e.base, store.DataDir, "Rnd0")) {
		t.Fatal("not sharded on disk")
	}
	w := e.do(t, "GET", "/d/Rnd0", nil)
	if w.Code != 200 || w.Body.String() != "hello" || w.Header().Get("Content-Disposition") != `attachment; filename="a.txt"` {
		t.Fatalf("get: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	if w := e.do(t, "GET", "/d/"+x[:2]+"/"+x[2:]+"/Rnd0", nil); w.Code != 404 {
		t.Fatalf("physical path served: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/o", nil); w.Code != 200 || w.Body.String() != "secret" {
		t.Fatalf("once: %d %q", w.Code, w.Body.String())
	}
	if w := e.do(t, "GET", "/d/o", nil); w.Code != 404 {
		t.Fatalf("second once: %d", w.Code)
	}
}

func TestListenerRoutes(t *testing.T) {
	root, dir := t.TempDir(), t.TempDir()
	cfg := &config.Config{
		Storage: map[string]*config.Storage{
			"a": {Type: "local", Base: root, Expose: "root", Conflict: "version"},
			"b": {Type: "local", Base: dir, Expose: "dir", Conflict: "version"},
		},
		Expose: map[string]*config.Expose{
			"root": {Listen: config.StringList{"dl"}, Path: "/"},
			"dir":  {Listen: config.StringList{"dl2", "intake"}, Path: "/d/"},
		},
	}
	for _, e := range []*env{{base: root, st: store.Local{Base: root, Conflict: "version"}}, {base: dir, st: store.Local{Base: dir, Conflict: "version"}}} {
		e.put(t, "f", filepath.Base(e.base), store.Sidecar{})
	}
	for _, c := range []struct {
		listen, path string
		code         int
		body         string
	}{
		{"dl", "/f", 200, filepath.Base(root)},
		{"dl", "/d/f", 404, ""},
		{"dl2", "/d/f", 200, filepath.Base(dir)},
		{"intake", "/d/f", 200, filepath.Base(dir)},
		{"intake", "/f", 404, ""},
		{"other", "/f", 404, ""},
	} {
		w := httptest.NewRecorder()
		New(cfg, slog.New(slog.DiscardHandler), time.Now, c.listen, nil).ServeHTTP(w, httptest.NewRequest("GET", c.path, nil))
		if w.Code != c.code || (c.body != "" && w.Body.String() != c.body) {
			t.Errorf("%s %s: %d %q", c.listen, c.path, w.Code, w.Body.String())
		}
	}
}

func TestJanitorKeepsWorkOfFailedEntry(t *testing.T) {
	e := newEnv(t, nil)
	e.cfg.Root = t.TempDir()
	q := filepath.Join(e.cfg.Root, "queue", "up")
	e.cfg.Endpoint = map[string]*config.Endpoint{"up": {Path: q}}
	work := e.cfg.WorkDir()
	old := t0.Add(-30 * 24 * time.Hour)
	for _, id := range []string{"failed1", "orphan"} {
		d := filepath.Join(work, id, "p")
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(d, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(q, "failed", "failed1"), 0o750); err != nil {
		t.Fatal(err)
	}
	sweep(e.cfg, e.log(), t0)
	if !exists(filepath.Join(work, "failed1", "p")) {
		t.Error("work dir of a failed entry removed")
	}
	if exists(filepath.Join(work, "orphan")) {
		t.Error("orphan work dir kept")
	}
}

func TestExpiryPrunesEmptyDirs(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r4nd/f", "x", store.Sidecar{Expires: t0.Add(-time.Second).Format(time.RFC3339)})
	e.put(t, "keep/a/f", "x", store.Sidecar{Expires: t0.Add(-time.Second).Format(time.RFC3339)})
	e.put(t, "keep/b", "x", store.Sidecar{Expires: t0.Add(time.Hour).Format(time.RFC3339)})
	expire(e.cfg, e.log(), t0)
	for _, p := range []string{"file/r4nd", ".db/meta/r4nd", "file/keep/a", ".db/meta/keep/a"} {
		if exists(filepath.Join(e.base, p)) {
			t.Errorf("%s left", p)
		}
	}
	for _, p := range []string{"file/keep/b", ".db/meta/keep/b.json", ".db/meta", store.DataDir, store.LockName} {
		if !exists(filepath.Join(e.base, p)) {
			t.Errorf("%s removed", p)
		}
	}
}

func TestOncePrunesEmptyDirs(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r4nd/o", "secret", store.Sidecar{Client: wire.Meta{Once: true}})
	if w := e.do(t, "GET", "/d/r4nd/o", nil); w.Code != 200 || w.Body.String() != "secret" {
		t.Fatalf("get: %d %q", w.Code, w.Body.String())
	}
	if exists(filepath.Join(e.base, store.DataDir, "r4nd")) || exists(filepath.Join(e.base, ".db", "meta", "r4nd")) {
		t.Error("claimed file left its directories")
	}
	if !exists(filepath.Join(e.base, ".db", "meta")) {
		t.Error(".db/meta removed")
	}
}

// TestNestedExposes: on one listener the longest expose path wins, the
// nested path without its slash is the nested expose's, and the outer
// storage never serves a name under the nested path, also on a listener
// without the nested expose.
func TestNestedExposes(t *testing.T) {
	outer, inner := t.TempDir(), t.TempDir()
	cfg, err := config.Parse([]byte(`
root: ` + t.TempDir() + `
listen:
  l: {addr: "127.0.0.1:1", public: "http://l.vm"}
  m: {addr: "127.0.0.1:2", public: "http://m.vm"}
storage:
  outer: {type: local, base: ` + outer + `, path: x, expose: outer}
  inner: {type: local, base: ` + inner + `, path: x, expose: inner}
expose:
  outer: {listen: [l, m], path: /}
  inner: {listen: l, path: /v/}
`))
	if err != nil {
		t.Fatal(err)
	}
	put := func(base, rel, content string) {
		src := filepath.Join(t.TempDir(), "src")
		if err := os.WriteFile(src, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
		sc := store.Sidecar{ID: rel, Size: int64(len(content)), Client: wire.Meta{Portal: wire.PortalDirect}}
		if _, err := (store.Local{Base: base, Conflict: "version"}).Put(src, rel, sc); err != nil {
			t.Fatal(err)
		}
	}
	put(outer, "a", "outer a")
	put(outer, "v/b", "outer v/b")
	put(inner, "b", "inner b")
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	for _, c := range []struct {
		listen, path string
		code         int
		body         string
	}{
		{"l", "/a", 200, "outer a"},
		{"l", "/v/b", 200, "inner b"},
		{"l", "/v", 404, ""},
		{"l", "/v/a", 404, ""},
		{"m", "/a", 200, "outer a"},
		{"m", "/v/b", 404, ""},
		{"m", "/v", 404, ""},
	} {
		w := httptest.NewRecorder()
		New(cfg, log, time.Now, c.listen, nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.path, nil))
		if w.Code != c.code || (c.code == 200 && w.Body.String() != c.body) {
			t.Errorf("%s %s: %d %q", c.listen, c.path, w.Code, w.Body)
		}
	}
}

func TestJanitorBeforeAndAfter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan string, 4)
	cfg := &config.Config{Storage: map[string]*config.Storage{}}
	StartJanitor(ctx, func() *config.Config { return cfg }, slog.New(slog.DiscardHandler), time.Hour, Maintain,
		func(time.Time) { calls <- "before" }, func(time.Time) { calls <- "after" })
	for _, want := range []string{"before", "after"} {
		select {
		case got := <-calls:
			if got != want {
				t.Fatalf("%s, want %s", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s", want)
		}
	}
}
