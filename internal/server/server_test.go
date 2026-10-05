package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/config"
	"luk/internal/expose"
	"luk/internal/pipeline"
	"luk/internal/queue"
	"luk/internal/sshsig"
	"luk/internal/store"
	"luk/internal/wire"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func pubLine(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

type fixture struct {
	srv    *Server
	user   ssh.Signer
	hostCA ssh.Signer
	root   string
}

func newFixture(t *testing.T) *fixture { return newFixtureWith(t, nil) }

// newFixtureWith lets mod rewrite the config text before it is parsed.
func newFixtureWith(t *testing.T, mod func(string) string) *fixture {
	return newFixtureDir(t, mod, nil)
}

// newFixtureDir is newFixtureWith that, with dir set, writes the config
// into a directory dir prepares (ssh.d, config.d; user is the fixture key)
// and loads it from there.
func newFixtureDir(t *testing.T, mod func(string) string, dir func(dir string, user ssh.Signer)) *fixture {
	t.Helper()
	user, hostCA := newSigner(t), newSigner(t)
	root := t.TempDir()
	cfgText := `
root: ` + root + `
listen: {main: {addr: "127.0.0.1:0", public: "https://lukd.vm:8443"}}
auth:
  keys: [{name: robert.socha, key: "` + pubLine(user.PublicKey()) + `"}]
  ca: [{name: hosts, type: host, key: "` + pubLine(hostCA.PublicKey()) + `"}]
endpoint:
  backup: {listen: main, endpoint: /backup, path: q/backup, allow: [robert.socha, "hosts:*"], limits: {body: {size: 1K}}}
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha], respond: url, storage: drop}
pipeline:
  archive: {endpoint: [backup], tags: [prod], steps: [{store: archive}]}
  devdb: {endpoint: [backup], tags: [prod, devdump], steps: [{store: archive}]}
  drop: {endpoint: [drop], steps: [{store: drop}]}
storage:
  archive: {type: local, base: s/archive, path: "{{ .File }}"}
  drop: {type: local, base: s/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop}
expose:
  drop: {listen: main, path: /d/}
`
	if mod != nil {
		cfgText = mod(cfgText)
	}
	var cfg *config.Config
	var err error
	if dir == nil {
		cfg, err = config.Parse([]byte(cfgText))
	} else {
		d := t.TempDir()
		dir(d, user)
		p := filepath.Join(d, "config.yaml")
		if err = os.WriteFile(p, []byte(cfgText), 0o600); err == nil {
			cfg, err = config.Load(p)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareDirs(cfg, "receive"); err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &fixture{srv: srv, user: user, hostCA: hostCA, root: root}
}

// handler serves the only address of the fixture.
func (f *fixture) handler() http.Handler { return f.srv.Handler(f.srv.config().Addrs()[0].Addr) }

// settle runs the pipelines of the committed queue entries to the end, as
// the process role does on its start.
func (f *fixture) settle(t *testing.T) {
	t.Helper()
	d := pipeline.NewDispatcher(f.srv.config(), queue.New(0, nil), slog.New(slog.DiscardHandler))
	if err := d.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	d.Close()
}

func receipt(t *testing.T, rec *httptest.ResponseRecorder, code int) wire.Receipt {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("%d, want %d: %s", rec.Code, code, rec.Body)
	}
	var out wire.Receipt
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode: %v: %s", err, rec.Body)
	}
	return out
}

// entries lists the names under dir, hidden ones included.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range des {
		out = append(out, d.Name())
	}
	return out
}

type req struct {
	signer  ssh.Signer
	path    string
	meta    wire.Meta
	body    []byte
	chunked bool
	ts      time.Time
	nonce   string
	host    string
	tamper  func(*http.Request)
	// rd is the body sent instead of body, which is still what is signed.
	rd io.Reader
	// via serves the request instead of the fixture handler.
	via http.Handler
}

func (f *fixture) do(t *testing.T, r req) (*httptest.ResponseRecorder, wire.Response) {
	t.Helper()
	if r.host == "" {
		r.host = "lukd.test"
	}
	if r.ts.IsZero() {
		r.ts = time.Now()
	}
	if r.nonce == "" {
		r.nonce = wire.NewNonce()
	}
	if err := r.meta.Normalize(); err != nil {
		t.Fatal(err)
	}
	metaS, err := wire.EncodeMeta(r.meta)
	if err != nil {
		t.Fatal(err)
	}
	ts := r.ts.UTC().Format(time.RFC3339)
	sig, err := sshsig.Sign(r.signer, wire.Namespace, wire.CanonicalText(r.host, r.path, ts, r.nonce, metaS))
	if err != nil {
		t.Fatal(err)
	}
	var rd io.Reader = bytes.NewReader(r.body)
	if r.rd != nil {
		rd = r.rd
	}
	hr := httptest.NewRequest(http.MethodPut, "http://"+r.host+r.path, rd)
	hr.Host = r.host
	if r.chunked {
		hr.ContentLength = -1
	}
	hr.Header.Set(wire.HeaderMeta, metaS)
	hr.Header.Set(wire.HeaderTimestamp, ts)
	hr.Header.Set(wire.HeaderNonce, r.nonce)
	hr.Header.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
	if r.tamper != nil {
		r.tamper(hr)
	}
	rec := httptest.NewRecorder()
	h := r.via
	if h == nil {
		h = f.handler()
	}
	h.ServeHTTP(rec, hr)
	var out wire.Response
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v: %s", err, rec.Body.String())
		}
	}
	return rec, out
}

func fileMeta(body []byte, tags ...string) wire.Meta {
	n := int64(len(body))
	sum := sha256.Sum256(body)
	return wire.Meta{Portal: wire.PortalDirect, File: "f", Source: wire.SourceFile, Size: &n, SHA256: hex.EncodeToString(sum[:]), Tags: tags}
}

func TestAcceptKey(t *testing.T) {
	f := newFixture(t)
	body := []byte("dump")
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "devdump", "prod"), body: body})
	out := receipt(t, rec, http.StatusAccepted)
	if out.ID == "" || out.Size != 4 || out.SHA256 != fileMeta(body).SHA256 || out.URL != "" || out.Expires != "" {
		t.Fatalf("%+v", out)
	}
	f.settle(t)
	got, err := os.ReadFile(filepath.Join(f.root, "s/archive/file/f"))
	if err != nil || string(got) != "dump" {
		t.Fatalf("stored %q %v", got, err)
	}
	var sc struct {
		ID, Sender, Endpoint, Expires string
	}
	b, err := os.ReadFile(filepath.Join(f.root, "s/archive/.db/meta/f.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &sc); err != nil || sc.ID != out.ID || sc.Sender != "robert.socha" || sc.Endpoint != "backup" || sc.Expires != "" {
		t.Fatalf("sidecar %s", b)
	}
	if e := entries(t, filepath.Join(f.root, "q/backup")); len(e) != 0 {
		t.Fatalf("queue left %v", e)
	}
}

func TestAcceptHostCertificate(t *testing.T) {
	f := newFixture(t)
	host := newSigner(t)
	c := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, KeyId: "luk.vm", Serial: 9, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, f.hostCA); err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(c, host)
	if err != nil {
		t.Fatal(err)
	}
	rec, out := f.do(t, req{signer: cs, path: "/backup", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Tags: []string{"prod"}, DryRun: true}, body: []byte("x"), chunked: true})
	if rec.Code != 200 || out.Identity.Name != "hosts:luk.vm" || out.Identity.Serial != 9 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// a host certificate is not allowed on /drop
	rec, _ = f.do(t, req{signer: cs, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, body: []byte("x"), chunked: true})
	if rec.Code != 403 {
		t.Fatalf("drop: %d", rec.Code)
	}
}

func TestRespondURL(t *testing.T) {
	f := newFixture(t)
	const prefix = "https://lukd.vm:8443/d/"
	before := time.Now()
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, body: []byte("x"), chunked: true})
	out := receipt(t, rec, http.StatusCreated)
	name := strings.TrimPrefix(out.URL, prefix)
	if !strings.HasPrefix(out.URL, prefix) || len(name) != 32 || out.Size != 1 || out.ID == "" {
		t.Fatalf("%+v", out)
	}
	exp, err := time.Parse(time.RFC3339, out.Expires)
	if err != nil || exp.Before(before.Add(7*24*time.Hour-time.Second)) || exp.After(time.Now().Add(7*24*time.Hour)) {
		t.Fatalf("expires %q: %v", out.Expires, err)
	}
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, File: "notes.txt", Source: wire.SourceStdin}, body: []byte("y"), chunked: true})
	out2 := receipt(t, rec, http.StatusCreated)
	if strings.HasSuffix(out2.URL, "notes.txt") || len(strings.TrimPrefix(out2.URL, prefix)) != 32 || out2.URL == out.URL {
		t.Fatalf("%+v", out2)
	}
	f.settle(t)
	got, err := os.ReadFile(filepath.Join(f.root, "s/drop/file", name))
	if err != nil || string(got) != "x" {
		t.Fatalf("stored %q %v", got, err)
	}
	b, err := os.ReadFile(filepath.Join(f.root, "s/drop/.db/meta", name+".json"))
	if err != nil || !strings.Contains(string(b), `"expires":"`+out.Expires+`"`) {
		t.Fatalf("sidecar %s %v", b, err)
	}
}

func TestDropDownload(t *testing.T) {
	f := newFixture(t)
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, File: "a.txt", Source: wire.SourceStdin}, body: []byte("hello"), chunked: true})
	out := receipt(t, rec, http.StatusCreated)
	f.settle(t)
	u, err := url.Parse(out.URL)
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443"+u.Path, nil))
	if rec.Code != 200 || rec.Body.String() != "hello" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestDropRandomAlphabet(t *testing.T) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	f := newFixtureWith(t, func(s string) string {
		return strings.Replace(s, `expose: drop}`, `expose: drop, random: {alphabet: "`+alphabet+`"}}`, 1)
	})
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, File: "a.txt", Source: wire.SourceStdin}, body: []byte("hello"), chunked: true})
	out := receipt(t, rec, http.StatusCreated)
	name := strings.TrimPrefix(out.URL, "https://lukd.vm:8443/d/")
	if len(name) != 26 || strings.Trim(name, alphabet) != "" {
		t.Fatalf("name %q", name)
	}
	f.settle(t)
	rec = httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443/d/"+name, nil))
	if rec.Code != 200 || rec.Body.String() != "hello" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

var proquintRe = regexp.MustCompile(`^[bdfghjklmnprstvz][aiou][bdfghjklmnprstvz][aiou][bdfghjklmnprstvz](-[bdfghjklmnprstvz][aiou][bdfghjklmnprstvz][aiou][bdfghjklmnprstvz])*$`)

func TestDropPrettyURL(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, `respond: url, storage: drop}`, `respond: url, storage: drop, pretty: {bits: 128, allow: ['*']}}`, 1)
		s = strings.Replace(s, `steps: [{store: drop}]`, `steps: [{store: [drop, archive]}]`, 1)
		s = strings.Replace(s, `path: "{{ .File }}"}`, `path: "{{ .Random }}", random: {alphabet: "01"}}`, 1)
		return strings.Replace(s, `expose: drop}`, `expose: drop, random: {alphabet: "abc"}}`, 1)
	})
	meta := wire.Meta{Portal: wire.PortalDirect, File: "a.txt", Source: wire.SourceStdin, PrettyURL: true, DryRun: true}
	rec, out := f.do(t, req{signer: f.user, path: "/drop", meta: meta, body: []byte("hello"), chunked: true})
	name := strings.TrimPrefix(out.Respond.URL, "https://lukd.vm:8443/d/")
	if rec.Code != 200 || !out.Client.PrettyURL || !proquintRe.MatchString(name) || strings.Count(name, "-") != 7 {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body)
	}
	meta.DryRun = false
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: meta, body: []byte("hello"), chunked: true})
	name = strings.TrimPrefix(receipt(t, rec, http.StatusCreated).URL, "https://lukd.vm:8443/d/")
	if !proquintRe.MatchString(name) || strings.Count(name, "-") != 7 {
		t.Fatalf("name %q", name)
	}
	f.settle(t)
	rec = httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443/d/"+name, nil))
	if rec.Code != 200 || rec.Body.String() != "hello" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got, err := os.ReadFile(filepath.Join(f.root, "s/archive/file", name)); err != nil || string(got) != "hello" {
		t.Fatalf("archive: %q %v", got, err)
	}
}

func TestPrettyURLNotOfferedBeforeBody(t *testing.T) {
	f := newFixture(t)
	body := []byte("dump")
	for path, tags := range map[string][]string{"/drop": nil, "/backup": {"prod"}} {
		m := fileMeta(body, tags...)
		m.PrettyURL = true
		var read int
		rec, _ := f.do(t, req{signer: f.user, path: path, meta: m, body: body, tamper: countBody(&read)})
		want := "endpoint " + strings.TrimPrefix(path, "/") + " does not offer pretty URLs"
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		if read != 0 {
			t.Fatalf("%s: body read %d bytes", path, read)
		}
	}
}

func TestURLStorageNotLocal(t *testing.T) {
	f := newFixture(t)
	f.srv.config().Storage["drop"] = &config.Storage{Type: "s3", Bucket: "b", Expose: "drop"}
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, body: []byte("x"), chunked: true})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "storage drop is not a local storage") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestInternalErrorIsGeneric(t *testing.T) {
	f := newFixture(t)
	var logs bytes.Buffer
	f.srv.log = slog.New(slog.NewTextHandler(&logs, nil))
	if err := os.RemoveAll(filepath.Join(f.root, "q/backup")); err != nil {
		t.Fatal(err)
	}
	body := []byte("x")
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body})
	if rec.Code != 500 || strings.TrimSpace(rec.Body.String()) != "{\n  \"error\": \"internal error\"\n}" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(logs.String(), "q/backup") {
		t.Fatalf("detail not logged: %s", logs.String())
	}
}

func TestAuthBeforeSpace(t *testing.T) {
	f := newFixture(t)
	f.srv.queue = queue.New(0, func(string) (int64, error) { return 0, nil })
	body := []byte("x")
	rec, _ := f.do(t, req{signer: newSigner(t), path: "/backup", meta: fileMeta(body, "prod"), body: body})
	if rec.Code != 401 {
		t.Fatalf("stranger: %d %s", rec.Code, rec.Body)
	}
	rec, _ = f.do(t, req{signer: f.hostCert(t), path: "/drop", meta: fileMeta(body), body: body})
	if rec.Code != 403 {
		t.Fatalf("host on drop: %d %s", rec.Code, rec.Body)
	}
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body})
	if rec.Code != 507 {
		t.Fatalf("allowed: %d %s", rec.Code, rec.Body)
	}
}

func (f *fixture) hostCert(t *testing.T) ssh.Signer {
	t.Helper()
	host := newSigner(t)
	c := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, KeyId: "luk.vm", Serial: 9, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, f.hostCA); err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(c, host)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestIngestHostCertificate(t *testing.T) {
	f := newFixture(t)
	rec, _ := f.do(t, req{signer: f.hostCert(t), path: "/backup", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Tags: []string{"prod"}}, body: []byte("host data"), chunked: true})
	out := receipt(t, rec, http.StatusAccepted)
	f.settle(t)
	got, err := os.ReadFile(filepath.Join(f.root, "s/archive/file", out.ID))
	if err != nil || string(got) != "host data" {
		t.Fatalf("stored %q %v", got, err)
	}
	b, err := os.ReadFile(filepath.Join(f.root, "s/archive/.db/meta", out.ID+".json"))
	if err != nil || !strings.Contains(string(b), `"sender":"hosts:luk.vm"`) {
		t.Fatalf("sidecar %s %v", b, err)
	}
}

// expiresAbout fails unless the RFC 3339 expiry s is about d after before.
func expiresAbout(t *testing.T, what, s string, before time.Time, d time.Duration) {
	t.Helper()
	exp, err := time.Parse(time.RFC3339, s)
	if err != nil || exp.Before(before.Add(d-time.Second)) || exp.After(time.Now().Add(d)) {
		t.Errorf("%s: expires %q, want about %v", what, s, d)
	}
}

func TestExpiresFromClientTTL(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		return strings.Replace(s, "ttl: {user: true, max: 7d}", "ttl: {user: true, min: 3h, max: 7d}", 1)
	})
	for _, tc := range []struct {
		ttl, want, note string
		d               time.Duration
	}{
		{"2d", "2d", "", 48 * time.Hour},
		{"30d", "7d", wire.TTLCapped, 7 * 24 * time.Hour},
		{"1h", "3h", wire.TTLRaised, 3 * time.Hour},
		{"", "7d", "", 7 * 24 * time.Hour},
		{wire.TTLMax, "7d", "", 7 * 24 * time.Hour},
	} {
		before := time.Now()
		rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, TTL: tc.ttl}, body: []byte("x"), chunked: true})
		out := receipt(t, rec, http.StatusCreated)
		expiresAbout(t, "ttl "+tc.ttl, out.Expires, before, tc.d)
		if out.TTL != tc.want || out.TTLNote != tc.note || out.TTLMin != "3h" || out.TTLMax != "7d" {
			t.Errorf("ttl %q: answer %+v, want ttl %q note %q", tc.ttl, out, tc.want, tc.note)
		}
	}
	f.srv.config().Storage["drop"].TTL.Max = 0
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, TTL: "1h"}, body: []byte("x"), chunked: true})
	if out := receipt(t, rec, http.StatusCreated); out.TTL != "3h" || out.TTLNote != wire.TTLRaised || out.TTLMin != "3h" || out.TTLMax != "" {
		t.Fatalf("only min: %+v", out)
	}
	f.srv.config().Storage["drop"].TTL.Min = 0
	for _, ttl := range []string{"", wire.TTLMax} {
		rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, TTL: ttl}, body: []byte("x"), chunked: true})
		if out := receipt(t, rec, http.StatusCreated); out.Expires != "" || out.TTL != "" || out.TTLNote != "" || out.TTLMin != "" || out.TTLMax != "" {
			t.Fatalf("no ttl anywhere, ttl %q: %+v", ttl, out)
		}
	}
}

func TestExpiresOnceClamped(t *testing.T) {
	f := newFixture(t)
	before := time.Now()
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, TTL: "30d", Once: true}, body: []byte("x"), chunked: true})
	out := receipt(t, rec, http.StatusCreated)
	if out.TTL != "7d" || out.TTLNote != wire.TTLCapped {
		t.Errorf("once: %+v", out)
	}
	expiresAbout(t, "once answer", out.Expires, before, 7*24*time.Hour)
	f.settle(t)
	sc := sidecarOf(t, filepath.Join(f.root, "s/drop"), path.Base(out.URL))
	if !sc.Client.Once {
		t.Errorf("once lost: %+v", sc)
	}
	expiresAbout(t, "once sidecar", sc.Expires, before, 7*24*time.Hour)
}

func TestExpiresUserFalse(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		return strings.Replace(s, "ttl: {user: true, max: 7d}", "ttl: {max: 21d}", 1)
	})
	before := time.Now()
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, TTL: "1h"}, body: []byte("x"), chunked: true})
	out := receipt(t, rec, http.StatusCreated)
	expiresAbout(t, "fixed", out.Expires, before, 21*24*time.Hour)
	if out.TTL != "21d" || out.TTLNote != wire.TTLIgnored || out.TTLMin != "" || out.TTLMax != "21d" {
		t.Errorf("fixed: %+v", out)
	}
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, body: []byte("x"), chunked: true})
	if out := receipt(t, rec, http.StatusCreated); out.TTL != "21d" || out.TTLNote != "" {
		t.Errorf("fixed without ttl: %+v", out)
	}
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, TTL: wire.TTLMax}, body: []byte("x"), chunked: true})
	if out := receipt(t, rec, http.StatusCreated); out.TTL != "21d" || out.TTLNote != wire.TTLIgnored {
		t.Errorf("fixed with ttl max: %+v", out)
	}
	f.srv.config().Storage["drop"].TTL.Max = 0
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, TTL: "1h"}, body: []byte("x"), chunked: true})
	if out := receipt(t, rec, http.StatusCreated); out.Expires != "" || out.TTL != "" || out.TTLNote != wire.TTLIgnored {
		t.Errorf("no max: %+v", out)
	}
}

// sidecarOf reads the sidecar of the stored name rel under the storage base.
func sidecarOf(t *testing.T, base, rel string) store.Sidecar {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(base, ".db", "meta", rel+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var sc store.Sidecar
	if err := json.Unmarshal(b, &sc); err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestExpiresPerStorage(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, "steps: [{store: drop}]", "steps: [{store: [drop, archive]}]", 1)
		return strings.Replace(s, `base: s/archive, path: "{{ .File }}"}`, `base: s/archive, path: "{{ .File }}", ttl: {max: 1h}}`, 1)
	})
	before := time.Now()
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, File: "a.txt", TTL: "2d"}, body: []byte("x"), chunked: true})
	out := receipt(t, rec, http.StatusCreated)
	f.settle(t)
	if out.TTL != "2d" || out.TTLNote != "" {
		t.Errorf("answer of the respond storage: %+v", out)
	}
	expiresAbout(t, "answer", out.Expires, before, 48*time.Hour)
	expiresAbout(t, "drop", sidecarOf(t, filepath.Join(f.root, "s/drop"), path.Base(out.URL)).Expires, before, 48*time.Hour)
	expiresAbout(t, "archive", sidecarOf(t, filepath.Join(f.root, "s/archive"), "a.txt").Expires, before, time.Hour)
}

func TestExpiresRespondAccept(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		return strings.Replace(s, `base: s/archive, path: "{{ .File }}"}`, `base: s/archive, path: "{{ .File }}", ttl: {user: true, max: 2h}}`, 1)
	})
	body := []byte("data")
	before := time.Now()
	for name, want := range map[string][3]string{"plain": {"", "2h", ""}, "short": {"30m", "30m", ""}, "long": {"5h", "2h", wire.TTLCapped}} {
		m := fileMeta(body, "prod")
		m.File, m.TTL = name, want[0]
		rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: body})
		if out := receipt(t, rec, http.StatusAccepted); out.TTL != want[1] || out.TTLNote != want[2] || out.TTLMin != "" || out.TTLMax != "2h" {
			t.Errorf("%s: answer %+v", name, out)
		}
	}
	f.settle(t)
	for name, want := range map[string]time.Duration{"plain": 2 * time.Hour, "short": 30 * time.Minute, "long": 2 * time.Hour} {
		s := sidecarOf(t, filepath.Join(f.root, "s/archive"), name).Expires
		exp, err := time.Parse(time.RFC3339, s)
		if err != nil || exp.Before(before.Add(want-time.Second)) || exp.After(time.Now().Add(want)) {
			t.Errorf("%s: expires %q, want about %v", name, s, want)
		}
	}
}

func TestExpiresAcceptFanOut(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, "tags: [prod], steps: [{store: archive}]", "tags: [prod], steps: [{store: [archive, keep]}]", 1)
		s = strings.Replace(s, `base: s/archive, path: "{{ .File }}"}`, `base: s/archive, path: "{{ .File }}", ttl: {user: true, max: 2h}}`, 1)
		return strings.Replace(s, "storage:\n", "storage:\n  keep: {type: local, base: s/keep, path: \"{{ .File }}\", ttl: {max: 21d}}\n", 1)
	})
	body := []byte("data")
	m := fileMeta(body, "prod")
	m.File, m.TTL = "a", "1h"
	before := time.Now()
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: body})
	if out := receipt(t, rec, http.StatusAccepted); out.TTL != "" || out.TTLNote != "" || out.TTLMin != "" || out.TTLMax != "" {
		t.Errorf("storages differ, the answer names none: %+v", out)
	}
	f.settle(t)
	expiresAbout(t, "archive", sidecarOf(t, filepath.Join(f.root, "s/archive"), "a").Expires, before, time.Hour)
	expiresAbout(t, "keep", sidecarOf(t, filepath.Join(f.root, "s/keep"), "a").Expires, before, 21*24*time.Hour)
}

func TestNoSpaceBeforeBody(t *testing.T) {
	f := newFixture(t)
	f.srv.queue = queue.New(0, func(string) (int64, error) { return 3, nil })
	ts := httptest.NewServer(f.handler())
	defer ts.Close()
	body := []byte("abcd")
	var read int
	rd := readFunc(func(p []byte) (int, error) {
		read++
		return 0, io.EOF
	})
	hr := f.signed(t, "/drop", body, rd)
	hr.URL.Host = ts.Listener.Addr().String()
	hr.ContentLength = int64(len(body))
	hr.Header.Set("Expect", "100-continue")
	hr.Proto, hr.ProtoMajor, hr.ProtoMinor = "HTTP/1.1", 1, 1
	c := &http.Client{Transport: &http.Transport{ExpectContinueTimeout: 5 * time.Second}}
	resp, err := c.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInsufficientStorage || strings.TrimSpace(string(b)) != "{\n  \"error\": \"not enough space\"\n}" {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if read != 0 {
		t.Fatalf("body read %d times", read)
	}
	if e := entries(t, filepath.Join(f.root, "q/drop")); len(e) != 0 {
		t.Fatalf("queue %v", e)
	}
}

type readFunc func([]byte) (int, error)

func (r readFunc) Read(p []byte) (int, error) { return r(p) }

func TestReservationReleased(t *testing.T) {
	f := newFixture(t)
	f.srv.queue = queue.New(0, func(string) (int64, error) { return 4, nil })
	m := fileMeta([]byte("abcd"), "prod")
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: []byte("abc"), chunked: true})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("short body: %d %s", rec.Code, rec.Body)
	}
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: m, body: []byte("abcd")})
	receipt(t, rec, http.StatusAccepted)
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: m, body: []byte("abcd")})
	receipt(t, rec, http.StatusAccepted)
}

func TestDryRunNeedsNoSpace(t *testing.T) {
	f := newFixture(t)
	f.srv.queue = queue.New(0, func(string) (int64, error) { return 0, nil })
	m := fileMeta([]byte("abcd"), "prod")
	m.DryRun = true
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: []byte("abcd")})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestRouting(t *testing.T) {
	f := newFixture(t)
	f.srv.cur().listeners["main"].expose = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	for _, c := range []struct {
		method, path string
		code         int
	}{
		{http.MethodGet, "/d/abc", http.StatusTeapot},
		{http.MethodHead, "/d/abc", http.StatusTeapot},
		{http.MethodPut, "/d/abc", http.StatusNotFound},
		{http.MethodPost, "/d/abc/reveal", http.StatusTeapot},
		{http.MethodPost, "/nope", http.StatusTeapot},
		{http.MethodGet, "/backup", http.StatusMethodNotAllowed},
	} {
		rec := httptest.NewRecorder()
		f.handler().ServeHTTP(rec, httptest.NewRequest(c.method, "http://lukd.test"+c.path, nil))
		if rec.Code != c.code {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, rec.Code, c.code)
		}
	}
	f.srv.cur().listeners["main"].expose = nil
	rec := httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.test/d/abc", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("default expose: %d", rec.Code)
	}
}

func TestRejections(t *testing.T) {
	f := newFixture(t)
	body := []byte("x")
	stranger := newSigner(t)
	cases := map[string]struct {
		r    req
		code int
	}{
		"unknown key":      {req{signer: stranger, path: "/backup", meta: fileMeta(body, "prod"), body: body}, 401},
		"no pipeline":      {req{signer: f.user, path: "/backup", meta: fileMeta(body, "other"), body: body}, 422},
		"old timestamp":    {req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, ts: time.Now().Add(-10 * time.Minute)}, 401},
		"future timestamp": {req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, ts: time.Now().Add(10 * time.Minute)}, 401},
		"bad nonce":        {req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, nonce: "abc"}, 401},
		"unknown path":     {req{signer: f.user, path: "/nope", meta: fileMeta(body), body: body}, 404},
		"signed size too big": {req{signer: f.user, path: "/backup", meta: func() wire.Meta {
			m := fileMeta(body, "prod")
			n := int64(2048)
			m.Size = &n
			return m
		}(), body: body}, 413},
		"tampered meta": {req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, tamper: func(h *http.Request) {
			m := fileMeta(body, "prod", "devdump")
			s, _ := wire.EncodeMeta(m)
			h.Header.Set(wire.HeaderMeta, s)
		}}, 401},
		"other host":        {req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, tamper: func(h *http.Request) { h.Host = "evil.test" }}, 401},
		"missing signature": {req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, tamper: func(h *http.Request) { h.Header.Del(wire.HeaderSignature) }}, 401},
		"wrong method":      {req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, tamper: func(h *http.Request) { h.Method = http.MethodPost }}, 405},
	}
	for name, c := range cases {
		rec, _ := f.do(t, c.r)
		if rec.Code != c.code {
			t.Errorf("%s: %d, want %d (%s)", name, rec.Code, c.code, rec.Body)
		}
		if rec.Code >= 400 {
			var e wire.ErrorResponse
			if json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.Error == "" {
				t.Errorf("%s: no JSON error: %s", name, rec.Body)
			}
		}
	}
}

func TestReplay(t *testing.T) {
	f := newFixture(t)
	body := []byte("x")
	nonce := wire.NewNonce()
	r := req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, nonce: nonce}
	if rec, _ := f.do(t, r); rec.Code != http.StatusAccepted {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec, _ := f.do(t, r); rec.Code != 401 {
		t.Fatalf("replay: %d", rec.Code)
	}
}

func TestSignedHashMismatch(t *testing.T) {
	f := newFixture(t)
	m := fileMeta([]byte("abcd"), "prod")
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: []byte("abce")})
	if rec.Code != 422 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: m, body: []byte("abc"), chunked: true})
	if rec.Code != 422 {
		t.Fatalf("short body: %d %s", rec.Code, rec.Body)
	}
	if e := entries(t, filepath.Join(f.root, "q/backup")); len(e) != 0 {
		t.Fatalf("queue left %v", e)
	}
}

func TestBodyOverMaxSizeChunked(t *testing.T) {
	f := newFixture(t)
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Tags: []string{"prod"}}, body: bytes.Repeat([]byte("x"), 2000), chunked: true})
	if rec.Code != 413 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if e := entries(t, filepath.Join(f.root, "q/backup")); len(e) != 0 {
		t.Fatalf("queue left %v", e)
	}
}

func TestEmptyBody(t *testing.T) {
	f := newFixture(t)
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(nil, "prod")})
	if out := receipt(t, rec, http.StatusAccepted); out.Size != 0 {
		t.Fatalf("%+v", out)
	}
}

func TestTrailingSlash(t *testing.T) {
	f := newFixture(t)
	body := []byte("x")
	rec, _ := f.do(t, req{signer: f.user, path: "/backup/", meta: fileMeta(body, "prod"), body: body})
	receipt(t, rec, http.StatusAccepted)
}

func TestMatch(t *testing.T) {
	f := newFixture(t)
	if got, _, _ := Match(f.srv.config(), "backup", []string{"prod", "devdump", "extra"}); strings.Join(got, ",") != "archive,devdb" {
		t.Fatalf("%v", got)
	}
	if got, _, _ := Match(f.srv.config(), "backup", nil); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if got, _, _ := Match(f.srv.config(), "drop", []string{"anything"}); strings.Join(got, ",") != "drop" {
		t.Fatalf("%v", got)
	}
}

func TestMatchClaim(t *testing.T) {
	f := newFixture(t)
	cfg := f.srv.config()
	cfg.Pipeline["devdb"].Claim = true
	if got, skipped, err := Match(cfg, "backup", []string{"prod", "devdump"}); err != nil || strings.Join(got, ",") != "devdb" || strings.Join(skipped, ",") != "archive" {
		t.Fatalf("%v %v %v", got, skipped, err)
	}
	if got, skipped, _ := Match(cfg, "backup", []string{"prod"}); skipped != nil || strings.Join(got, ",") != "archive" {
		t.Fatalf("unclaimed %v %v", got, skipped)
	}
	cfg.Pipeline["archive"].Claim = true
	if _, _, err := Match(cfg, "backup", []string{"prod", "devdump"}); err == nil || !strings.Contains(err.Error(), "upload claimed by archive and devdb") {
		t.Fatalf("two claims: %v", err)
	}
}

func TestTimestampBeforeStart(t *testing.T) {
	f := newFixture(t)
	body := []byte("x")
	f.srv.start = time.Now().Truncate(time.Second)
	r := req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, ts: f.srv.start.Add(-30 * time.Second)}
	rec, _ := f.do(t, r)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "timestamp before server start") {
		t.Fatalf("before start: %d %s", rec.Code, rec.Body)
	}
	r.ts = f.srv.start.Add(500 * time.Millisecond)
	if rec, _ := f.do(t, r); rec.Code != http.StatusAccepted {
		t.Fatalf("start second: %d %s", rec.Code, rec.Body)
	}
}

func TestDryRunScheduleAndStages(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, "tags: [prod], steps:", "tags: [prod], queue: {group: backup, order: 1}, steps:", 1)
		s = strings.Replace(s, "tags: [prod, devdump], steps:", "tags: [prod, devdump], queue: {group: backup, order: 2}, steps:", 1)
		return strings.Replace(s, "  drop: {endpoint: [drop]", "  plain: {endpoint: [backup], steps: [{store: archive}]}\n  drop: {endpoint: [drop]", 1)
	})
	body := []byte("dump")
	m := fileMeta(body, "devdump", "prod")
	m.DryRun = true
	rec, out := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: body})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	want := []wire.Scheduled{{Pipeline: "plain"}, {Pipeline: "archive", Group: "backup", Order: 1}, {Pipeline: "devdb", Group: "backup", Order: 2}}
	if !slices.Equal(out.Schedule, want) || strings.Join(out.Pipelines, ",") != "archive,devdb,plain" {
		t.Fatalf("%+v %v", out.Schedule, out.Pipelines)
	}
	m.DryRun = false
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: m, body: body})
	receipt(t, rec, http.StatusAccepted)
	pending, err := queue.Pending(filepath.Join(f.root, "q/backup"))
	if err != nil || len(pending) != 1 {
		t.Fatalf("%v %v", pending, err)
	}
	j, err := pipeline.LoadJob(pending[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Stages) != 2 || j.Stages["archive"] != (pipeline.Stage{Group: "backup", Order: 1}) || j.Stages["devdb"] != (pipeline.Stage{Group: "backup", Order: 2}) {
		t.Fatalf("stages %+v", j.Stages)
	}
}

func TestDryRunEchoedAndVerified(t *testing.T) {
	f := newFixture(t)
	body := []byte("dump")
	m := fileMeta(body, "devdump", "prod")
	m.DryRun = true
	rec, out := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: body})
	if rec.Code != 200 || !out.Client.DryRun {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if out.Identity.Name != "robert.socha" || out.Endpoint != "backup" || strings.Join(out.Pipelines, ",") != "archive,devdb" {
		t.Fatalf("%+v", out)
	}
	var raw struct{ Server map[string]any }
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil || len(raw.Server) != 1 || out.Server.Received == "" {
		t.Fatalf("server meta %v %v", raw.Server, err)
	}
	if out.Respond.Mode != "accept" || out.ID == "" {
		t.Fatalf("%+v", out)
	}
	var read int
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: m, body: body, tamper: countBody(&read)})
	if rec.Code != 200 || read != 0 || rec.Header().Get("Connection") != "close" {
		t.Fatalf("dry run read %d body bytes: %d %s", read, rec.Code, rec.Body)
	}
	big := make([]byte, 2048)
	bm := fileMeta(big, "prod")
	bm.DryRun = true
	if rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: bm, body: big}); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("dry run over the size limit: %d %s", rec.Code, rec.Body)
	}
	dm := wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, DryRun: true}
	rec, out = f.do(t, req{signer: f.user, path: "/drop", meta: dm, body: []byte("x"), chunked: true})
	if rec.Code != 200 || out.Respond.Mode != "url" || len(strings.TrimPrefix(out.Respond.URL, "https://lukd.vm:8443/d/")) != 32 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	f.settle(t)
	for _, d := range []string{"q/backup", "q/drop", "s/archive/file", "s/drop/file"} {
		if e := entries(t, filepath.Join(f.root, d)); len(e) != 0 {
			t.Fatalf("%s: %v", d, e)
		}
	}
}

// countBody replaces the request body with one that counts the bytes read.
func countBody(n *int) func(*http.Request) {
	return func(hr *http.Request) {
		b := hr.Body
		hr.Body = io.NopCloser(readFunc(func(p []byte) (int, error) {
			k, err := b.Read(p)
			*n += k
			return k, err
		}))
	}
}

func TestUnstorableNameBeforeBody(t *testing.T) {
	f := newFixture(t)
	body := []byte("dump")
	m := fileMeta(body, "prod")
	m.File = ".."
	var read int
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: body, tamper: countBody(&read)})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "storage archive") || !strings.Contains(rec.Body.String(), `element \"..\" is not a name`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if read != 0 {
		t.Fatalf("body read %d bytes", read)
	}
	if e := entries(t, filepath.Join(f.root, "q/backup")); len(e) != 0 {
		t.Fatalf("queue %v", e)
	}
}

func TestUnstorableNameSecondStorage(t *testing.T) {
	f := newFixture(t)
	p := f.srv.config().Pipeline["drop"]
	p.Steps = append(p.Steps, config.Step{Store: config.StringList{"archive"}})
	body := []byte("x")
	m := fileMeta(body)
	m.File = ".."
	var read int
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: m, body: body, tamper: countBody(&read)})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "storage archive") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if read != 0 {
		t.Fatalf("body read %d bytes", read)
	}
	m.File = "env"
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: m, body: body})
	receipt(t, rec, http.StatusCreated)
}

func TestDotFileStored(t *testing.T) {
	f := newFixture(t)
	body := []byte("rc")
	m := fileMeta(body, "prod")
	m.File = ".bashrc"
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: body})
	receipt(t, rec, http.StatusAccepted)
	f.settle(t)
	if got, err := os.ReadFile(filepath.Join(f.root, "s/archive/file/.bashrc")); err != nil || string(got) != "rc" {
		t.Fatalf("stored %q %v", got, err)
	}
	if sc := sidecarOf(t, filepath.Join(f.root, "s/archive"), ".bashrc"); sc.Client.File != ".bashrc" {
		t.Fatalf("sidecar %+v", sc)
	}
}

func TestCreatedAlwaysHasExpires(t *testing.T) {
	f := newFixture(t)
	f.srv.config().Storage["drop"].TTL.Max = 0
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, body: []byte("x"), chunked: true})
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if v, ok := raw["expires"]; rec.Code != http.StatusCreated || !ok || v != "" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestRevealOverLimitBeforeBody(t *testing.T) {
	f := newFixture(t)
	body := bytes.Repeat([]byte("s"), expose.MaxReveal+1)
	m := fileMeta(body)
	m.Portal = wire.PortalReveal
	var read int
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: m, body: body, tamper: countBody(&read)})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "reveal") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if read != 0 {
		t.Fatalf("body read %d bytes", read)
	}
	m = fileMeta(body[:expose.MaxReveal])
	m.Portal = wire.PortalReveal
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: m, body: body[:expose.MaxReveal]})
	receipt(t, rec, http.StatusCreated)
	m = fileMeta(body)
	m.Portal = wire.PortalDownload
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: m, body: body})
	receipt(t, rec, http.StatusCreated)
}

func TestRevealPortalEndToEnd(t *testing.T) {
	f := newFixture(t)
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalReveal, Once: true, Source: wire.SourceStdin}, body: []byte("pw<b>"), chunked: true})
	out := receipt(t, rec, http.StatusCreated)
	f.settle(t)
	u, err := url.Parse(out.URL)
	if err != nil {
		t.Fatal(err)
	}
	get := func(method, p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		f.handler().ServeHTTP(rec, httptest.NewRequest(method, "http://lukd.vm:8443"+p, nil))
		return rec
	}
	if rec := get(http.MethodGet, u.Path); rec.Code != 200 || strings.Contains(rec.Body.String(), "pw&lt;b&gt;") {
		t.Fatalf("landing %d %s", rec.Code, rec.Body)
	}
	if rec := get(http.MethodPost, u.Path+"/reveal"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "pw&lt;b&gt;") {
		t.Fatalf("reveal %d %s", rec.Code, rec.Body)
	}
	if rec := get(http.MethodPost, u.Path+"/reveal"); rec.Code != 404 {
		t.Fatalf("second reveal %d", rec.Code)
	}
}

func TestCatalogEndToEnd(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		old := `drop: {type: local, base: s/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop}`
		if !strings.Contains(s, old) {
			t.Fatal("drop storage line not found")
		}
		return strings.Replace(s, old, `drop: {type: local, base: s/drop, ttl: {user: true, max: 7d}, path: "{{ .File }}", expose: drop, catalog: true}`, 1)
	})
	body := []byte("report")
	m := fileMeta(body)
	m.File = "catalog.json"
	var read int
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: m, body: body, tamper: countBody(&read)})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "reserved") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if read != 0 {
		t.Fatalf("body read %d bytes", read)
	}
	m.File = "report.txt"
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: m, body: body})
	receipt(t, rec, http.StatusCreated)
	f.settle(t)
	get := httptest.NewRecorder()
	f.handler().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443/d/catalog.json", nil))
	var c struct {
		Files []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if get.Code != 200 || get.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %s", get.Code, get.Body)
	}
	if err := json.Unmarshal(get.Body.Bytes(), &c); err != nil || len(c.Files) != 1 || c.Files[0].Name != "report.txt" || c.Files[0].SHA256 != m.SHA256 {
		t.Fatalf("%s %v", get.Body, err)
	}
}

func TestRevealUnsizedOverLimit(t *testing.T) {
	f := newFixture(t)
	body := bytes.Repeat([]byte("s"), expose.MaxReveal+1)
	m := wire.Meta{Portal: wire.PortalReveal, Source: wire.SourceStdin}
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: m, body: body, chunked: true})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "reveal") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Without a signed size a dry run has nothing to check: no body is read.
	m.DryRun = true
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: m, body: body, chunked: true})
	if rec.Code != http.StatusOK {
		t.Fatalf("dry run %d %s", rec.Code, rec.Body)
	}
	m.DryRun = false
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: m, body: body[:expose.MaxReveal], chunked: true})
	receipt(t, rec, http.StatusCreated)
}

func TestHostnameAndOriginPaths(t *testing.T) {
	withPath := func(p string) *fixture {
		return newFixtureWith(t, func(s string) string {
			return strings.Replace(s, `archive: {type: local, base: s/archive, path: "{{ .File }}"}`, `archive: {type: local, base: s/archive, path: "`+p+`"}`, 1)
		})
	}
	body := []byte("dump")
	backup := func() wire.Meta {
		m := fileMeta(body, "prod")
		m.Backup = &wire.Backup{Hostname: "db1.example.net", Path: "/var/backups/f"}
		return m
	}

	f := withPath("{{ .Hostname }}/{{ .File }}")
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: backup(), body: body})
	receipt(t, rec, http.StatusAccepted)
	var read int
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, tamper: countBody(&read)})
	if rec.Code != http.StatusUnprocessableEntity || read != 0 || !strings.Contains(rec.Body.String(), "storage archive") || !strings.Contains(rec.Body.String(), "hostname") {
		t.Fatalf("without --backup: %d read %d %s", rec.Code, read, rec.Body)
	}
	f.settle(t)
	if b, err := os.ReadFile(filepath.Join(f.root, "s/archive/file/db1.example.net/f")); err != nil || string(b) != "dump" {
		t.Fatalf("stored under the hostname: %q %v", b, err)
	}

	f = withPath("{{ .Origin }}/{{ .File }}")
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body})
	receipt(t, rec, http.StatusAccepted)
	f.settle(t)
	if _, err := os.Stat(filepath.Join(f.root, "s/archive/file/robert.socha/f")); err != nil {
		t.Fatalf("origin falls back to the sender: %v", err)
	}
}

// debugLogs makes the server log everything into the returned buffer.
func (f *fixture) debugLogs() *bytes.Buffer {
	var logs bytes.Buffer
	f.srv.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.srv.apply(f.srv.config())
	return &logs
}

func TestDownloadListenerMethods(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, `listen: {main: {addr: "127.0.0.1:0", public: "https://lukd.vm:8443"}}`,
			`listen: {main: {addr: "127.0.0.1:0", public: "https://lukd.vm:8443"}, dl: {addr: "127.0.0.1:1", public: "https://dl.vm"}}`, 1)
		return strings.Replace(s, `drop: {listen: main, path: /d/}`, `drop: {listen: dl, path: /}`, 1)
	})
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDownload, Source: wire.SourceStdin}, body: []byte("hello"), chunked: true, via: f.srv.Handler("127.0.0.1:0")})
	out := receipt(t, rec, http.StatusCreated)
	f.settle(t)
	name, ok := strings.CutPrefix(out.URL, "https://dl.vm/")
	if !ok {
		t.Fatalf("url %q", out.URL)
	}
	logs := f.debugLogs()
	dl := f.srv.Handler("127.0.0.1:1")
	do := func(method, p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		dl.ServeHTTP(rec, httptest.NewRequest(method, "http://dl.vm"+p, nil))
		return rec
	}
	for _, p := range []string{"/", "/" + name, "/nope"} {
		for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodDelete} {
			if rec := do(m, p); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("%s %s: %d allow %q", m, p, rec.Code, rec.Header().Get("Allow"))
			}
		}
	}
	for _, m := range []string{http.MethodPut, http.MethodDelete} {
		if rec := do(m, "/"+name+"/download"); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD, POST" {
			t.Errorf("%s action: %d allow %q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
	if rec := do(http.MethodPost, "/"+name+"/download"); rec.Code != 200 || rec.Body.String() != "hello" {
		t.Errorf("download action: %d %q", rec.Code, rec.Body)
	}
	if strings.Contains(logs.String(), "upload rejected") {
		t.Errorf("upload rejected logged on a download listener: %s", logs)
	}
	if !strings.Contains(logs.String(), `level=DEBUG msg="method not allowed"`) || !strings.Contains(logs.String(), "method=DELETE path=/"+name) {
		t.Errorf("405 not logged at debug: %s", logs)
	}
}

func TestRejectedLogLevel(t *testing.T) {
	f := newFixture(t)
	logs := f.debugLogs()
	rec := httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "http://lukd.test/junk", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(logs.String(), `level=DEBUG msg="upload rejected"`) || strings.Contains(logs.String(), "level=INFO") {
		t.Errorf("unsigned junk: %d %s", rec.Code, logs)
	}
	logs.Reset()
	body := []byte("x")
	if rec, _ := f.do(t, req{signer: f.user, path: "/nope", meta: fileMeta(body), body: body}); rec.Code != http.StatusNotFound {
		t.Fatalf("signed: %d", rec.Code)
	}
	if !strings.Contains(logs.String(), `level=INFO msg="upload rejected"`) {
		t.Errorf("signed request not logged at info: %s", logs)
	}
	logs.Reset()
	rec = httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "http://lukd.test/backup", nil))
	if rec.Code != http.StatusMethodNotAllowed || !strings.Contains(logs.String(), `level=INFO msg="upload rejected"`) {
		t.Errorf("unsigned request to an endpoint: %d %s", rec.Code, logs)
	}
}

func TestACMEUnknownHostLogLevel(t *testing.T) {
	for _, level := range []string{"info", "debug"} {
		cfg := acmeTestConfig(t, t.TempDir(), "https://ca.example.com/dir", "0.0.0.0:8443", "127.0.0.1:8080")
		cfg.Log.Level = level
		var logs bytes.Buffer
		log := NewLogger(&logs, cfg)
		s := New(cfg, log)
		s.acme = newACME(cfg, log, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = "other.example.com"
		s.Handler("127.0.0.1:8080").ServeHTTP(w, r)
		shown := strings.Contains(logs.String(), `level=DEBUG msg="request for an unknown host"`) && strings.Contains(logs.String(), "acme=true")
		if w.Code != http.StatusMisdirectedRequest || shown != (level == "debug") {
			t.Errorf("%s: %d %q", level, w.Code, logs.String())
		}
	}
}

func TestPortalOwner(t *testing.T) {
	userCA := newSigner(t)
	f := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, `ca: [{name: hosts, type: host, key: "`, `ca: [{name: users, type: user, key: "`+pubLine(userCA.PublicKey())+`"}, {name: hosts, type: host, key: "`, 1)
		return strings.Replace(s, `allow: [robert.socha], respond: url`, `allow: [robert.socha, "hosts:*", "users:*"], respond: url`, 1)
	})
	user := newSigner(t)
	c := &ssh.Certificate{Key: user.PublicKey(), CertType: ssh.UserCert, KeyId: "alice", ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, userCA); err != nil {
		t.Fatal(err)
	}
	userCert, err := ssh.NewCertSigner(c, user)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		signer ssh.Signer
		portal string
		hide   bool
		want   string
	}{
		{"key", f.user, wire.PortalDownload, false, "robert.socha"},
		{"key reveal", f.user, wire.PortalReveal, false, "robert.socha"},
		{"host cert", f.hostCert(t), wire.PortalDownload, false, "host"},
		{"user cert", userCert, wire.PortalReveal, false, "user"},
		{"no_owner", f.user, wire.PortalDownload, true, ""},
		{"no_owner reveal", userCert, wire.PortalReveal, true, ""},
	} {
		meta := wire.Meta{Portal: tc.portal, Source: wire.SourceStdin, NoOwner: tc.hide}
		rec, _ := f.do(t, req{signer: tc.signer, path: "/drop", meta: meta, body: []byte("x"), chunked: true})
		out := receipt(t, rec, http.StatusCreated)
		f.settle(t)
		u, err := url.Parse(out.URL)
		if err != nil {
			t.Fatal(err)
		}
		rec = httptest.NewRecorder()
		f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443"+u.Path, nil))
		page := rec.Body.String()
		sc := sidecarOf(t, filepath.Join(f.root, "s/drop"), path.Base(u.Path))
		if tc.want == "" {
			if rec.Code != 200 || strings.Contains(page, "<dt>Sent by</dt>") || strings.Contains(page, "robert.socha") || sc.Owner != "" || !sc.Client.NoOwner {
				t.Errorf("%s: owner shown, sidecar %q: %d %s", tc.name, sc.Owner, rec.Code, page)
			}
			continue
		}
		if rec.Code != 200 || !strings.Contains(page, "<dt>Sent by</dt><dd>"+tc.want+"</dd>") || sc.Owner != tc.want {
			t.Errorf("%s: want owner %q, sidecar %q: %d %s", tc.name, tc.want, sc.Owner, rec.Code, page)
		}
	}
}

func TestRevealSecretType(t *testing.T) {
	f := newFixture(t)
	meta := wire.Meta{Portal: wire.PortalReveal, Source: wire.SourceStdin, Type: "text/plain; charset=utf-8"}
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: meta, body: []byte("pw"), chunked: true})
	out := receipt(t, rec, http.StatusCreated)
	f.settle(t)
	u, err := url.Parse(out.URL)
	if err != nil {
		t.Fatal(err)
	}
	if sc := sidecarOf(t, filepath.Join(f.root, "s/drop"), path.Base(u.Path)); sc.Client.Type != meta.Type {
		t.Fatalf("sidecar type %q", sc.Client.Type)
	}
	rec = httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443"+u.Path, nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<dt>Type</dt><dd>secret</dd>") || strings.Contains(rec.Body.String(), "SHA-256") {
		t.Fatalf("landing %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443"+u.Path+"/get", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" || rec.Body.String() != "pw" {
		t.Fatalf("get %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	// The download keeps the full type too.
	dl := newFixture(t)
	meta = wire.Meta{Portal: wire.PortalDownload, Source: wire.SourceStdin, Type: "text/csv; charset=utf-8; header=present"}
	rec, _ = dl.do(t, req{signer: dl.user, path: "/drop", meta: meta, body: []byte("a,b"), chunked: true})
	out = receipt(t, rec, http.StatusCreated)
	dl.settle(t)
	u, _ = url.Parse(out.URL)
	rec = httptest.NewRecorder()
	dl.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443"+u.Path, nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<dt>Type</dt><dd>text/csv</dd>") {
		t.Fatalf("download landing %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	dl.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://lukd.vm:8443"+u.Path+"/download", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != meta.Type {
		t.Fatalf("download %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

// A request signed ahead of the server clock and replayed after a restart
// within the window is refused by the persisted nonce cache; a reload
// keeps the cache too.
func TestReplayAfterRestartRefused(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	f.srv.start = now.Add(-time.Minute)
	f.srv.SetClock(func() time.Time { return now })
	if err := f.srv.persistNonces(dir); err != nil {
		t.Fatal(err)
	}
	var captured *http.Request
	r, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, ts: now.Add(30 * time.Second),
		tamper: func(r *http.Request) { captured = r.Clone(context.Background()) }})
	if r.Code != http.StatusCreated {
		t.Fatalf("first %d %s", r.Code, r.Body)
	}
	replay := func(s *Server) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Handler(s.config().Addrs()[0].Addr).ServeHTTP(rec, captured.Clone(context.Background()))
		return rec
	}
	f.srv.apply(f.srv.config())
	if rec := replay(f.srv); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "replayed nonce") {
		t.Fatalf("after a reload %d %s", rec.Code, rec.Body)
	}
	fresh := New(f.srv.config(), f.srv.log)
	fresh.start = now.Add(time.Second)
	fresh.SetClock(func() time.Time { return now.Add(time.Second) })
	if err := fresh.persistNonces(dir); err != nil {
		t.Fatal(err)
	}
	if rec := replay(fresh); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "replayed nonce") {
		t.Fatalf("after a restart %d %s", rec.Code, rec.Body)
	}
}

// A missing nonce directory leaves the cache in memory only.
func TestPersistNoncesMissingDir(t *testing.T) {
	f := newFixture(t)
	if err := f.srv.persistNonces(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.persistNonces(filepath.Join(f.root)); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	if err := f.srv.persistNonces(file); err == nil {
		t.Fatal("a file accepted as the nonce directory")
	}
}
