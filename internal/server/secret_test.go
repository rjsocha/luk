package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"luk/internal/queue"
	"luk/internal/rund/rundtest"
	"luk/internal/runproto"
	"luk/internal/store"
	"luk/internal/wire"
)

// secretFixture is the fixture with the reveal uploads of /drop going to
// the queue and the storage under vol (a tmpfs on a real host), exposed
// at /d/volatile/, every link action on /drop, and a pipeline mark whose
// run step appends to the file marker for every upload it runs for.
type secretFixture struct {
	*fixture
	vol, marker string
}

func newSecretFixture(t *testing.T, mod func(string) string) *secretFixture {
	t.Helper()
	vol, tmp := filepath.Join(t.TempDir(), "volatile"), t.TempDir()
	marker, prog := filepath.Join(tmp, "marker"), filepath.Join(tmp, "mark")
	script := "#!/bin/sh\necho run >> " + marker + "\ncp \"$LUK_FILE\" \"$LUK_OUT/out\"\n"
	if err := os.WriteFile(prog, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(tmp, "run.sock")
	rundtest.Start(t, &rundtest.Server{Socket: sock, Resolve: func(r runproto.StepRequest) (rundtest.Unit, error) {
		if r.Pipeline != "mark" || r.Step != 1 || r.Job != "" {
			return rundtest.Unit{}, fmt.Errorf("pipeline %s step %d: not a run or relay step", r.Pipeline, r.Step)
		}
		return rundtest.Unit{Argv: []string{prog}, Env: []string{"PATH=" + os.Getenv("PATH")}}, nil
	}})
	f := newFixtureWith(t, func(s string) string {
		s = strings.NewReplacer(
			`respond: url, storage: drop}`,
			`respond: url, storage: drop, secret: {allow: ['*'], path: `+vol+`/queue, storage: volatile}, link: {remove: ['*'], ttl: ['*'], list: ['*']}}`,
			"  drop: {endpoint: [drop], steps: [{store: drop}]}\n",
			"  drop: {endpoint: [drop], steps: [{store: drop}]}\n  mark: {endpoint: [drop], steps: [{run: "+prog+"}]}\n",
			"storage:\n",
			"storage:\n  volatile: {type: local, base: "+vol+"/storage, path: \"{{ .Random }}\", expose: volatile, ttl: {user: true}}\n",
			"  drop: {listen: main, path: /d/}\n",
			"  drop: {listen: main, path: /d/}\n  volatile: {listen: main, path: /d/volatile/}\n",
		).Replace(s)
		if mod != nil {
			s = mod(s)
		}
		return s
	})
	f.runSocket = sock
	return &secretFixture{fixture: f, vol: vol, marker: marker}
}

// visible lists the names under dir that are not dot entries (the data of
// a storage, the entries of a queue).
func visible(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, n := range entries(t, dir) {
		if !strings.HasPrefix(n, ".") {
			out = append(out, n)
		}
	}
	return out
}

// runs is how many times the run step of pipeline mark ran.
func (f *secretFixture) runs(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile(f.marker)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "run\n")
}

// wantEmpty fails unless the endpoint queue and the drop storage hold
// nothing.
func (f *secretFixture) wantEmpty(t *testing.T, when string) {
	t.Helper()
	for _, d := range []string{filepath.Join(f.root, "data", "q/drop"), filepath.Join(f.root, "data", "s/drop/file")} {
		if v := visible(t, d); len(v) != 0 {
			t.Fatalf("%s: %s holds %v", when, d, v)
		}
	}
}

func secretMeta(body string) wire.Meta {
	n := int64(len(body))
	sum := sha256.Sum256([]byte(body))
	return wire.Meta{Portal: wire.PortalReveal, Source: wire.SourceTerminal, Type: "text/plain; charset=utf-8", Size: &n, SHA256: hex.EncodeToString(sum[:])}
}

// get sends method to the path of link plus suffix, with the Accept header
// accept when set.
func (f *fixture) get(t *testing.T, method, link, suffix, accept string) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	hr := httptest.NewRequest(method, "http://lukd.vm:8443"+u.Path+suffix, nil)
	if accept != "" {
		hr.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	f.handler().ServeHTTP(rec, hr)
	return rec
}

func TestSecretUpload(t *testing.T) {
	f := newSecretFixture(t, nil)
	m := secretMeta("s3cr3t")
	m.TTL = "1h"
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: m, body: []byte("s3cr3t")})
	out := receipt(t, rec, http.StatusCreated)
	if !strings.HasPrefix(out.URL, "https://lukd.vm:8443/d/volatile/") || out.TTL != "1h" || out.Expires == "" || out.Size != 6 {
		t.Fatalf("%+v", out)
	}
	name := path.Base(out.URL)
	if q := visible(t, filepath.Join(f.vol, "queue")); len(q) != 1 || q[0] != out.ID {
		t.Fatalf("secret queue %v", q)
	}
	f.wantEmpty(t, "queued")
	f.settle(t)
	f.wantEmpty(t, "stored")
	if q := visible(t, filepath.Join(f.vol, "queue")); len(q) != 0 {
		t.Fatalf("secret queue left %v", q)
	}
	if got, err := os.ReadFile(filepath.Join(f.vol, "storage", "file", name)); err != nil || string(got) != "s3cr3t" {
		t.Fatalf("stored %q %v", got, err)
	}
	sc := sidecarOf(t, filepath.Join(f.vol, "storage"), name)
	if sc.Endpoint != "drop" || sc.ID != out.ID || sc.Expires != out.Expires || sc.OwnerKey != "key:robert.socha" {
		t.Fatalf("sidecar %+v", sc)
	}
	if n := f.runs(t); n != 0 {
		t.Fatalf("the run step ran %d times for a secret", n)
	}
	if rec := f.get(t, http.MethodGet, out.URL, "", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "text/html") || strings.Contains(rec.Body.String(), "s3cr3t") {
		t.Fatalf("landing %d %s", rec.Code, rec.Body)
	}
	if rec := f.get(t, http.MethodPost, out.URL, "/reveal", "text/plain"); rec.Code != http.StatusOK || rec.Body.String() != "s3cr3t" {
		t.Fatalf("reveal %d %q", rec.Code, rec.Body)
	}
	if rec := f.get(t, http.MethodGet, out.URL, "/get", ""); rec.Code != http.StatusOK || rec.Body.String() != "s3cr3t" {
		t.Fatalf("get %d %q", rec.Code, rec.Body)
	}
	// Under the outer expose the name is not served.
	if rec := f.get(t, http.MethodGet, "https://lukd.vm:8443/d/"+name, "/get", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("outer expose %d", rec.Code)
	}
}

func TestSecretOnce(t *testing.T) {
	f := newSecretFixture(t, nil)
	m := secretMeta("once")
	m.Once = true
	out := receipt(t, mustDo(t, f.fixture, m, "once"), http.StatusCreated)
	f.settle(t)
	if rec := f.get(t, http.MethodGet, out.URL, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("landing %d", rec.Code)
	}
	if rec := f.get(t, http.MethodGet, out.URL, "/get", ""); rec.Code != http.StatusOK || rec.Body.String() != "once" {
		t.Fatalf("first %d %q", rec.Code, rec.Body)
	}
	if rec := f.get(t, http.MethodGet, out.URL, "/get", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("second %d", rec.Code)
	}
	if v := visible(t, filepath.Join(f.vol, "storage", "file")); len(v) != 0 {
		t.Fatalf("claimed left %v", v)
	}
}

func mustDo(t *testing.T, f *fixture, m wire.Meta, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: m, body: []byte(body)})
	return rec
}

// TestSecretOthersUnchanged: uploads with another portal go through the
// queue and the pipelines of the endpoint as before.
func TestSecretOthersUnchanged(t *testing.T) {
	f := newSecretFixture(t, nil)
	for i, portal := range []string{wire.PortalDirect, wire.PortalDownload} {
		m := fileMeta([]byte("plain"))
		m.Portal = portal
		out := receipt(t, mustDo(t, f.fixture, m, "plain"), http.StatusCreated)
		if !strings.HasPrefix(out.URL, "https://lukd.vm:8443/d/") || strings.HasPrefix(out.URL, "https://lukd.vm:8443/d/volatile/") {
			t.Fatalf("url %s", out.URL)
		}
		if q := visible(t, filepath.Join(f.root, "data", "q/drop")); len(q) != 1 {
			t.Fatalf("endpoint queue %v", q)
		}
		f.settle(t)
		if got, err := os.ReadFile(filepath.Join(f.root, "data", "s/drop/file", path.Base(out.URL))); err != nil || string(got) != "plain" {
			t.Fatalf("stored %q %v", got, err)
		}
		if n := f.runs(t); n != i+1 {
			t.Fatalf("run step ran %d times", n)
		}
	}
	for _, d := range []string{"queue", "storage/file"} {
		if v := visible(t, filepath.Join(f.vol, d)); len(v) != 0 {
			t.Fatalf("%s holds %v", d, v)
		}
	}
}

// TestSecretAnyTags: a secret needs no pipeline of its tags.
func TestSecretAnyTags(t *testing.T) {
	f := newSecretFixture(t, func(s string) string {
		return strings.NewReplacer("drop: {endpoint: [drop], steps", "drop: {endpoint: [drop], tags: [x], steps",
			"mark: {endpoint: [drop], steps", "mark: {endpoint: [drop], tags: [x], steps").Replace(s)
	})
	receipt(t, mustDo(t, f.fixture, secretMeta("t"), "t"), http.StatusCreated)
	rec := mustDo(t, f.fixture, fileMeta([]byte("t")), "t")
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "no pipeline") {
		t.Fatalf("direct without tags: %d %s", rec.Code, rec.Body)
	}
}

func TestSecretDedup(t *testing.T) {
	f := newSecretFixture(t, nil)
	first := receipt(t, mustDo(t, f.fixture, secretMeta("same"), "same"), http.StatusCreated)
	n := 0
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: secretMeta("same"), body: []byte("same"), tamper: countBody(&n)})
	second := receipt(t, rec, http.StatusCreated)
	if !second.Deduplicated || n != 0 || second.URL == first.URL || !strings.HasPrefix(second.URL, "https://lukd.vm:8443/d/volatile/") {
		t.Fatalf("%+v, %d body bytes", second, n)
	}
	f.settle(t)
	f.wantEmpty(t, "stored")
	a := filepath.Join(f.vol, "storage", "file", path.Base(first.URL))
	if !shared(t, a, filepath.Join(f.vol, "storage", "file", path.Base(second.URL))) {
		t.Fatal("not one copy")
	}
}

func TestSecretLinks(t *testing.T) {
	// A replace needs pipelines of store steps only: no mark pipeline.
	f := newSecretFixture(t, func(s string) string {
		s = strings.Replace(s, "link: {remove: ['*'], ttl: ['*'], list: ['*']}", "link: {remove: ['*'], ttl: ['*'], replace: ['*'], list: ['*']}", 1)
		start := strings.Index(s, "  mark: ")
		end := start + strings.Index(s[start:], "\n") + 1
		return s[:start] + s[end:]
	})
	direct := f.drop(t, f.user, wire.Meta{File: "a.txt"}, "direct")
	m := secretMeta("old")
	m.Mutable = true
	sec := receipt(t, mustDo(t, f.fixture, m, "old"), http.StatusCreated).URL
	f.settle(t)
	a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList}))
	got := map[string]wire.LinkEntry{}
	for _, l := range a.Links {
		got[l.URL] = l
	}
	if l := got[sec]; len(a.Links) != 2 || l.Portal != wire.PortalReveal || !l.Mutable || got[direct].Portal != wire.PortalDirect {
		t.Fatalf("list %+v", a.Links)
	}

	n := int64(3)
	sum := sha256.Sum256([]byte("new"))
	nm := wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceFile, Size: &n, SHA256: hex.EncodeToString(sum[:])}
	ans := linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: sec, meta: &nm, body: []byte("new")}), http.StatusAccepted)
	if q := visible(t, filepath.Join(f.vol, "queue")); len(q) != 1 || q[0] != ans.ID {
		t.Fatalf("replace queue %v", q)
	}
	if q := visible(t, filepath.Join(f.root, "data", "q/drop")); len(q) != 0 {
		t.Fatalf("endpoint queue %v", q)
	}
	f.settle(t)
	if rec := f.get(t, http.MethodGet, sec, "/get", ""); rec.Code != http.StatusOK || rec.Body.String() != "new" {
		t.Fatalf("replaced %d %q", rec.Code, rec.Body)
	}

	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: sec}), http.StatusOK)
	if rec := f.get(t, http.MethodGet, sec, "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("removed: %d", rec.Code)
	}
	if v := visible(t, filepath.Join(f.vol, "storage", "file")); len(v) != 0 {
		t.Fatalf("storage left %v", v)
	}
	if a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList})); len(a.Links) != 1 || a.Links[0].URL != direct {
		t.Fatalf("list after remove %+v", a.Links)
	}
}

// TestNestedExposeReserved: a name of the outer storage under the nested
// expose path cannot be stored (422 before the body), and a request for it
// goes to the nested expose even when such a file exists.
func TestNestedExposeReserved(t *testing.T) {
	f := newSecretFixture(t, func(s string) string {
		return strings.Replace(s, `base: s/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}"`, `base: s/drop, ttl: {user: true, max: 7d}, path: "{{ .File }}"`, 1)
	})
	for _, name := range []string{"volatile"} {
		m := fileMeta([]byte("x"))
		m.File = name
		rec := mustDo(t, f.fixture, m, "x")
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "storage drop") || !strings.Contains(rec.Body.String(), "reserved") {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	f.wantEmpty(t, "refused")
	// A file left from before the nested expose existed.
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc := store.Sidecar{ID: "old", Endpoint: "drop", Size: 3, Client: wire.Meta{Portal: wire.PortalDirect}}
	if _, err := (store.Local{Base: filepath.Join(f.root, "data", "s/drop"), Conflict: "version"}).Store(src, "volatile", sc); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/d/volatile", "/d/volatile/"} {
		if rec := f.get(t, http.MethodGet, "https://lukd.vm:8443"+p, "", ""); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d %q", p, rec.Code, rec.Body)
		}
	}
	m := fileMeta([]byte("x"))
	m.File = "volatilex"
	out := receipt(t, mustDo(t, f.fixture, m, "x"), http.StatusCreated)
	f.settle(t)
	if code, body := f.fetch(t, out.URL); code != http.StatusOK || body != "x" {
		t.Fatalf("volatilex: %d %q", code, body)
	}
}

func TestSecretDirsCreated(t *testing.T) {
	f := newSecretFixture(t, nil)
	for _, d := range []string{"queue", "storage/file"} {
		fi, err := os.Stat(filepath.Join(f.vol, d))
		if err != nil || !fi.IsDir() {
			t.Fatalf("%s: %v", d, err)
		}
		if d == "queue" && fi.Mode().Perm() != 0o700 {
			t.Fatalf("queue mode %v", fi.Mode())
		}
	}
	// Emptied (a reboot), then prepared again as at start.
	if err := os.RemoveAll(f.vol); err != nil {
		t.Fatal(err)
	}
	if err := prepareDirs(f.srv.config(), "receive"); err != nil {
		t.Fatal(err)
	}
	out := receipt(t, mustDo(t, f.fixture, secretMeta("again"), "again"), http.StatusCreated)
	f.settle(t)
	if rec := f.get(t, http.MethodGet, out.URL, "/get", ""); rec.Code != http.StatusOK || rec.Body.String() != "again" {
		t.Fatalf("after a reboot %d %q", rec.Code, rec.Body)
	}
}

// TestSecretReserve: the secret queue keeps secret.reserve free, not
// limits.queue.reserve, which still holds for the endpoint queue.
func TestSecretReserve(t *testing.T) {
	f := newSecretFixture(t, func(s string) string {
		s = strings.Replace(s, "storage: volatile}", "storage: volatile, reserve: 1M}", 1)
		return strings.Replace(s, "listen: {main:", "limits: {queue: {reserve: 1G}}\nlisten: {main:", 1)
	})
	cfg := f.srv.config()
	if r := cfg.Endpoint["drop"].Secret.Reserve; r != 1<<20 {
		t.Fatalf("reserve %d", r)
	}
	free := int64(100 << 20)
	f.srv.queue = queue.New(int64(cfg.Limits.Queue.Reserve), func(string) (int64, error) { return free, nil })
	f.srv.queue.SetDirReserves(cfg.SecretReserves())
	receipt(t, mustDo(t, f.fixture, secretMeta("tmpfs"), "tmpfs"), http.StatusCreated)
	if rec := mustDo(t, f.fixture, fileMeta([]byte("disk")), "disk"); rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("endpoint queue: %d %s", rec.Code, rec.Body)
	}
	free = 512 << 10
	if rec := mustDo(t, f.fixture, secretMeta("full"), "full"); rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("under secret.reserve: %d %s", rec.Code, rec.Body)
	}
}

// A rejected secret upload logs and answers nothing derived from the
// secret: a body of the signed length that differs keeps the signed
// sha256 out of the 422 and of the log line.
func TestSecretMismatchHidesHash(t *testing.T) {
	f := newSecretFixture(t, nil)
	var logs bytes.Buffer
	f.srv.log = slog.New(slog.NewTextHandler(&logs, nil))
	sum := sha256.Sum256([]byte("hunter2"))
	hash := hex.EncodeToString(sum[:])
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: secretMeta("hunter2"), body: []byte("hunter3")})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), hash) || strings.Contains(logs.String(), hash) {
		t.Fatalf("the secret hash leaks:\n%s\n%s", rec.Body, logs.String())
	}
}
