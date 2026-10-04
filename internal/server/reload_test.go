package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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
	"luk/internal/tlsself"
	"luk/internal/wire"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newPair writes a new certificate and key for host and moves them over
// cert and key, as an external tool renewing them would.
func newPair(t *testing.T, cert, key, host string) string {
	t.Helper()
	dir := t.TempDir()
	pin, err := tlsself.Generate(filepath.Join(dir, "c"), filepath.Join(dir, "k"), host, tlsself.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	for src, dst := range map[string]string{"c": cert, "k": key} {
		if err := os.Rename(filepath.Join(dir, src), dst); err != nil {
			t.Fatal(err)
		}
	}
	return pin
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTLSReloadOnHUP(t *testing.T) {
	root, ext := t.TempDir(), t.TempDir()
	self, files := freePort(t), freePort(t)
	cert, key := filepath.Join(ext, "fullchain.pem"), filepath.Join(ext, "key.pem")
	pin1 := newPair(t, cert, key, "f.vm")
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
root: %s
listen:
  own:
    addr: %s
    host: [a.vm]
    tls: {mode: self, cert: tls/a.crt, key: tls/a.key, host: a.vm}
  ext:
    addr: %s
    host: [f.vm]
    tls: {mode: files, cert: %s, key: %s}
auth:
  keys: [{name: robert.socha, key: "%s"}]
endpoint:
  up: {listen: [own, ext], endpoint: /up, path: q/up, allow: [robert.socha]}
pipeline:
  p: {endpoint: [up], steps: [{run: /bin/true}]}
`, root, self, files, cert, key, pubLine(newSigner(t).PublicKey()))))
	if err != nil {
		t.Fatal(err)
	}
	own := cfg.Listen["own"].TLS
	selfPin, err := tlsself.Generate(own.Cert, own.Key, own.Host, own.Algorithm)
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Receive(ctx, cfg, slog.New(slog.NewTextHandler(&logs, nil))) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	waitFor(t, "listeners", func() bool {
		for _, a := range []string{self, files} {
			c, err := net.Dial("tcp", a)
			if err != nil {
				return false
			}
			c.Close()
		}
		return true
	})
	if got := peerPin(t, files, "f.vm"); got != pin1 {
		t.Fatalf("files pin %s, want %s", got, pin1)
	}
	if got := peerPin(t, self, "a.vm"); got != selfPin {
		t.Fatalf("self pin %s, want %s", got, selfPin)
	}

	pin2 := newPair(t, cert, key, "f.vm")
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "new certificate", func() bool { return peerPin(t, files, "f.vm") == pin2 })
	if !strings.Contains(logs.String(), `msg="tls reloaded" listen=ext pin="`+pin2+`"`) {
		t.Fatalf("log:\n%s", logs.String())
	}
	if got := peerPin(t, self, "a.vm"); got != selfPin {
		t.Fatalf("self pin after reload %s, want %s", got, selfPin)
	}

	if err := os.WriteFile(cert, []byte("broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reload failure", func() bool { return strings.Contains(logs.String(), "tls reload failed") })
	const failed = `msg="tls reload failed, keeping the current certificate" listen=`
	if !strings.Contains(logs.String(), failed+"ext") || strings.Contains(logs.String(), failed+"own") {
		t.Fatalf("log:\n%s", logs.String())
	}
	if got := peerPin(t, files, "f.vm"); got != pin2 {
		t.Fatalf("pin after broken reload %s, want %s", got, pin2)
	}
}

const reloadBase = `
root: %s
listen: {main: {addr: "127.0.0.1:0", public: "https://lukd.vm:8443"}}
endpoint:
  backup: {listen: main, endpoint: /backup, path: q/backup, allow: [robert.socha], limits: {body: {size: %s}}}
pipeline:
  archive: {endpoint: [backup], tags: [prod], steps: [{store: archive}]}
storage:
  archive: {type: local, base: s/archive, path: "{{ .Id }}"}
`

// reloadEnv is a fixture whose configuration comes from files: config.yaml
// and ssh.d/robert.socha.pub in dir.
type reloadEnv struct {
	*fixture
	dir  string
	logs *syncBuf
}

func newReloadEnv(t *testing.T) *reloadEnv {
	t.Helper()
	e := &reloadEnv{dir: t.TempDir(), logs: &syncBuf{}}
	root := t.TempDir()
	e.write(t, "config.yaml", fmt.Sprintf(reloadBase, root, "1K"))
	user := newSigner(t)
	e.write(t, "ssh.d/robert.socha.pub", pubLine(user.PublicKey())+"\n")
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareDirs(cfg, true); err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, slog.New(slog.NewTextHandler(e.logs, nil)))
	e.fixture = &fixture{srv: srv, user: user, root: root}
	return e
}

func (e *reloadEnv) write(t *testing.T, rel, text string) {
	t.Helper()
	p := filepath.Join(e.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
}

func (e *reloadEnv) upload(t *testing.T, signer ssh.Signer, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec, _ := e.do(t, req{signer: signer, path: path, meta: fileMeta([]byte(body), "prod"), body: []byte(body)})
	return rec
}

func wantCode(t *testing.T, what string, rec *httptest.ResponseRecorder, code int, text string) {
	t.Helper()
	if rec.Code != code || !strings.Contains(rec.Body.String(), text) {
		t.Fatalf("%s: %d %s, want %d with %q", what, rec.Code, rec.Body, code, text)
	}
}

func TestReloadKeys(t *testing.T) {
	e := newReloadEnv(t)
	second := newSigner(t)
	wantCode(t, "unknown key", e.upload(t, second, "/backup", "ok"), http.StatusUnauthorized, "unknown key")

	// An upload past its checks when the reload happens keeps its key and
	// its body limit.
	started, resume := make(chan struct{}), make(chan struct{})
	body := []byte("dump")
	first := readFunc(func([]byte) (int, error) {
		close(started)
		<-resume
		return 0, io.EOF
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec, _ := e.do(t, req{signer: e.user, path: "/backup", meta: fileMeta(body, "prod"), body: body,
			rd: io.MultiReader(first, bytes.NewReader(body))})
		done <- rec
	}()
	<-started
	e.write(t, "ssh.d/robert.socha.pub", pubLine(second.PublicKey())+"\n")
	e.write(t, "config.yaml", fmt.Sprintf(reloadBase, e.root, "2"))
	if e.srv.reload() == nil {
		t.Fatalf("reload failed:\n%s", e.logs)
	}
	close(resume)
	wantCode(t, "in flight", <-done, http.StatusAccepted, `"size": 4`)

	wantCode(t, "removed key", e.upload(t, e.user, "/backup", "ok"), http.StatusUnauthorized, "unknown key")
	wantCode(t, "added key", e.upload(t, second, "/backup", "ok"), http.StatusAccepted, `"size": 2`)
	wantCode(t, "new limit", e.upload(t, second, "/backup", "dump"), http.StatusRequestEntityTooLarge, "limit 2")
	e.settle(t)
	var stored []string
	for _, n := range entries(t, filepath.Join(e.root, "s/archive/file")) {
		if !strings.HasPrefix(n, ".") {
			stored = append(stored, n)
		}
	}
	if len(stored) != 2 {
		t.Fatalf("stored %v, want 2 files", stored)
	}
	want := `msg="config reloaded" keys=1 ca=0 endpoints=1 pipelines=1 storages=1 files=` +
		filepath.Join(e.dir, "config.yaml") + "," + filepath.Join(e.dir, "ssh.d/robert.socha.pub")
	if !strings.Contains(e.logs.String(), want) {
		t.Fatalf("log:\n%s", e.logs)
	}
}

func TestReloadAddsCAFile(t *testing.T) {
	e := newReloadEnv(t)
	ca, host := newSigner(t), newSigner(t)
	c := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, KeyId: "luk.vm", ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(c, host)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, "before", e.upload(t, cs, "/backup", "ok"), http.StatusUnauthorized, "unknown CA")
	e.write(t, "ssh.d/ca/host/hosts.pub", pubLine(ca.PublicKey())+"\n")
	e.write(t, "config.yaml", strings.Replace(fmt.Sprintf(reloadBase, e.root, "1K"), "allow: [robert.socha]", `allow: [robert.socha, "hosts:*"]`, 1))
	if e.srv.reload() == nil {
		t.Fatalf("reload failed:\n%s", e.logs)
	}
	wantCode(t, "after", e.upload(t, cs, "/backup", "ok"), http.StatusAccepted, `"size": 2`)
	want := `msg="config reloaded" keys=1 ca=1 endpoints=1 pipelines=1 storages=1 files=` + filepath.Join(e.dir, "config.yaml") + "," +
		filepath.Join(e.dir, "ssh.d/robert.socha.pub") + "," + filepath.Join(e.dir, "ssh.d/ca/host/hosts.pub")
	if !strings.Contains(e.logs.String(), want) {
		t.Fatalf("log:\n%s", e.logs)
	}
	e.settle(t)
}

func TestReloadAddsEndpoint(t *testing.T) {
	e := newReloadEnv(t)
	wantCode(t, "before", e.upload(t, e.user, "/extra", "x"), http.StatusNotFound, "no endpoint")
	e.write(t, "config.d/extra.yaml", `
endpoint:
  extra: {listen: main, endpoint: /extra, path: q/extra, allow: [robert.socha], respond: url, storage: extra}
pipeline:
  extra: {endpoint: [extra], steps: [{store: extra}]}
storage:
  extra: {type: local, base: s/extra, path: "{{ .Random }}", expose: extra}
expose:
  extra: {listen: main, path: /x/}
`)
	if e.srv.reload() == nil {
		t.Fatalf("reload failed:\n%s", e.logs)
	}
	rec := e.upload(t, e.user, "/extra", "new")
	wantCode(t, "after", rec, http.StatusCreated, "https://lukd.vm:8443/x/")
	var c wire.Created
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	dl := httptest.NewRecorder()
	e.handler().ServeHTTP(dl, httptest.NewRequest(http.MethodGet, strings.TrimPrefix(c.URL, "https://lukd.vm:8443"), nil))
	if dl.Code != http.StatusOK || dl.Body.String() != "new" {
		t.Fatalf("download %d %q", dl.Code, dl.Body)
	}
}

func TestReloadRandomAlphabet(t *testing.T) {
	e := newReloadEnv(t)
	base := strings.Replace(fmt.Sprintf(reloadBase, e.root, "1K"), `path: "{{ .Id }}"}`, `path: "{{ .Random }}"%s}`, 1)
	e.write(t, "config.yaml", fmt.Sprintf(base, ""))
	if e.srv.reload() == nil {
		t.Fatalf("reload failed:\n%s", e.logs)
	}
	wantCode(t, "before", e.upload(t, e.user, "/backup", "a"), http.StatusAccepted, `"size": 1`)
	e.write(t, "config.yaml", fmt.Sprintf(base, `, random: {alphabet: "01"}`))
	if e.srv.reload() == nil {
		t.Fatalf("reload failed:\n%s", e.logs)
	}
	wantCode(t, "after", e.upload(t, e.user, "/backup", "b"), http.StatusAccepted, `"size": 1`)
	e.settle(t)
	var names []string
	for _, n := range entries(t, filepath.Join(e.root, "s/archive/file")) {
		if !strings.HasPrefix(n, ".") {
			names = append(names, n)
		}
	}
	slices.SortFunc(names, func(a, b string) int { return len(a) - len(b) })
	if len(names) != 2 || len(names[0]) != 32 || len(names[1]) != 128 || strings.Trim(names[1], "01") != "" {
		t.Fatalf("stored %v", names)
	}
}

func TestReloadInvalidKeepsCurrent(t *testing.T) {
	e := newReloadEnv(t)
	cur := e.srv.cur()
	e.write(t, "ssh.d/robert.socha.pub", pubLine(newSigner(t).PublicKey())+"\n")
	e.write(t, "config.d/bad.yaml", "pipeline:\n  bad: {endpoint: [backup], steps: [{store: nowhere}]}\n")
	if e.srv.reload() != nil || e.srv.cur() != cur {
		t.Fatal("invalid configuration applied")
	}
	if !strings.Contains(e.logs.String(), `msg="reload failed, keeping the current configuration"`) ||
		!strings.Contains(e.logs.String(), "nowhere") {
		t.Fatalf("log:\n%s", e.logs)
	}
	wantCode(t, "old key", e.upload(t, e.user, "/backup", "ok"), http.StatusAccepted, `"size": 2`)
}

func TestReloadRefusedOnRestartSetting(t *testing.T) {
	for _, c := range []struct{ name, from, to string }{
		{"root", "root: ", "root: /var/lib/luk-other\n#"},
		{"listen.main.addr", `addr: "127.0.0.1:0"`, `addr: "127.0.0.1:1"`},
		{"listen.main.public", `public: "https://lukd.vm:8443"`, `public: "https://other.vm"`},
		{"limits.header.timeout", "listen:", "limits: {header: {timeout: 3s}}\nlisten:"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newReloadEnv(t)
			cur := e.srv.cur()
			if err := writeRunning(cur.cfg, "receive"); err != nil {
				t.Fatal(err)
			}
			lock, err := lockRole(e.root, "receive")
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			second := newSigner(t)
			e.write(t, "ssh.d/robert.socha.pub", pubLine(e.user.PublicKey())+"\n"+pubLine(second.PublicKey())+"\n")
			e.write(t, "config.yaml", strings.Replace(fmt.Sprintf(reloadBase, e.root, "1K"), c.from, c.to, 1))
			if e.srv.reload() != nil || e.srv.cur() != cur {
				t.Fatal("reload applied")
			}
			if want := `msg="reload refused: ` + c.name + ` changed, restart required"`; !strings.Contains(e.logs.String(), want) {
				t.Fatalf("log:\n%s", e.logs)
			}
			// lukd check reports the same change; a changed root points it
			// to another root, where no role runs.
			next, err := config.Load(filepath.Join(e.dir, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			changes, notes, err := RunningChanges(next)
			switch {
			case err != nil:
				t.Fatal(err)
			case c.name == "root":
				if len(changes) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "a changed root") {
					t.Fatalf("check: %v %v", changes, notes)
				}
			case !slices.Equal(changes, []string{c.name}):
				t.Fatalf("check: %v %v", changes, notes)
			}
			wantCode(t, "key of the refused reload", e.upload(t, second, "/backup", "ok"), http.StatusUnauthorized, "unknown key")
		})
	}
}

func TestReloadKeepsNonces(t *testing.T) {
	e := newReloadEnv(t)
	body := []byte("once")
	r := req{signer: e.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, ts: time.Now(), nonce: wire.NewNonce()}
	rec, _ := e.do(t, r)
	wantCode(t, "first", rec, http.StatusAccepted, `"size": 4`)
	e.write(t, "config.yaml", fmt.Sprintf(reloadBase, e.root, "2K"))
	if e.srv.reload() == nil {
		t.Fatalf("reload failed:\n%s", e.logs)
	}
	rec, _ = e.do(t, r)
	wantCode(t, "replay", rec, http.StatusUnauthorized, "replayed nonce")
}

func TestConfigReloadOnHUP(t *testing.T) {
	root, dir := t.TempDir(), t.TempDir()
	plain, files := freePort(t), freePort(t)
	cert, key := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "key.pem")
	pin1 := newPair(t, cert, key, "f.vm")
	user, second := newSigner(t), newSigner(t)
	text := fmt.Sprintf(`
root: %s
listen:
  plain: {addr: "%s"}
  ext:
    addr: %s
    host: [f.vm]
    tls: {mode: files, cert: %s, key: %s}
endpoint:
  up: {listen: plain, endpoint: /up, path: q/up, allow: [robert.socha]}
pipeline:
  p: {endpoint: [up], steps: [{store: s}]}
storage:
  s: {type: local, base: s, path: "{{ .Id }}"}
`, root, plain, files, cert, key)
	e := &reloadEnv{dir: dir}
	e.write(t, "config.yaml", text)
	e.write(t, "ssh.d/robert.socha.pub", pubLine(user.PublicKey())+"\n")
	cfg, err := config.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Receive(ctx, cfg, slog.New(slog.NewTextHandler(&logs, nil))) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	waitFor(t, "listeners", func() bool {
		c, err := net.Dial("tcp", files)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	if got := peerPin(t, files, "f.vm"); got != pin1 {
		t.Fatalf("pin %s, want %s", got, pin1)
	}
	put := func(signer ssh.Signer) int {
		t.Helper()
		resp, err := http.DefaultClient.Do(signedPut(t, signer, "http://"+plain, plain, "/up", []byte("x")))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	hup := func() {
		t.Helper()
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
	}

	// A refused reload still re-reads the certificates.
	e.write(t, "ssh.d/robert.socha.pub", pubLine(user.PublicKey())+"\n"+pubLine(second.PublicKey())+"\n")
	e.write(t, "config.yaml", strings.Replace(text, "host: [f.vm]", "host: [f.vm, g.vm]", 1))
	pin2 := newPair(t, cert, key, "f.vm")
	hup()
	waitFor(t, "refusal", func() bool {
		return strings.Contains(logs.String(), `msg="reload refused: listen.ext.host changed, restart required"`)
	})
	waitFor(t, "new certificate", func() bool { return peerPin(t, files, "f.vm") == pin2 })
	if code := put(second); code != http.StatusUnauthorized {
		t.Fatalf("key of the refused reload: %d", code)
	}

	e.write(t, "config.yaml", text)
	hup()
	waitFor(t, "reload", func() bool { return strings.Contains(logs.String(), `msg="config reloaded"`) })
	if code := put(second); code != http.StatusAccepted {
		t.Fatalf("added key: %d", code)
	}
	if code := put(user); code != http.StatusAccepted {
		t.Fatalf("kept key: %d", code)
	}
}

func TestReloadPrettyBits(t *testing.T) {
	e := newReloadEnv(t)
	const cfg = `
root: %s
listen: {main: {addr: "127.0.0.1:0", public: "https://lukd.vm:8443"}}
endpoint:
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha], respond: url, storage: drop%s}
pipeline:
  drop: {endpoint: [drop], steps: [{store: drop}]}
storage:
  drop: {type: local, base: s/drop, path: "{{ .Random }}", expose: drop}
expose:
  drop: {listen: main, path: /d/}
`
	meta := wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, PrettyURL: true}
	for _, c := range []struct {
		pretty string
		code   int
		dashes int
	}{
		{", pretty: {allow: ['*']}", http.StatusCreated, 3},
		{", pretty: {bits: 128, allow: ['*']}", http.StatusCreated, 7},
		{"", http.StatusUnprocessableEntity, 0},
	} {
		e.write(t, "config.yaml", fmt.Sprintf(cfg, e.root, c.pretty))
		if e.srv.reload() == nil {
			t.Fatalf("reload failed:\n%s", e.logs)
		}
		rec, _ := e.do(t, req{signer: e.user, path: "/drop", meta: meta, body: []byte("x"), chunked: true})
		if c.code != http.StatusCreated {
			wantCode(t, c.pretty, rec, c.code, "does not offer pretty URLs")
			continue
		}
		name := strings.TrimPrefix(receipt(t, rec, c.code).URL, "https://lukd.vm:8443/d/")
		if !proquintRe.MatchString(name) || strings.Count(name, "-") != c.dashes {
			t.Fatalf("%s: name %q", c.pretty, name)
		}
	}
}

func TestReloadTTLMax(t *testing.T) {
	e := newReloadEnv(t)
	const cfg = `
root: %s
listen: {main: {addr: "127.0.0.1:0", public: "https://lukd.vm:8443"}}
endpoint:
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha], respond: url, storage: drop}
pipeline:
  drop: {endpoint: [drop], steps: [{store: drop}]}
storage:
  drop: {type: local, base: s/drop, path: "{{ .Random }}", expose: drop, ttl: {max: %s}}
expose:
  drop: {listen: main, path: /d/}
`
	meta := wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}
	for _, want := range []time.Duration{time.Hour, 3 * time.Hour} {
		e.write(t, "config.yaml", fmt.Sprintf(cfg, e.root, want))
		if e.srv.reload() == nil {
			t.Fatalf("reload failed:\n%s", e.logs)
		}
		before := time.Now()
		rec, _ := e.do(t, req{signer: e.user, path: "/drop", meta: meta, body: []byte("x"), chunked: true})
		exp, err := time.Parse(time.RFC3339, receipt(t, rec, http.StatusCreated).Expires)
		if err != nil || exp.Before(before.Add(want-time.Second)) || exp.After(time.Now().Add(want)) {
			t.Fatalf("ttl.max %v: expires %v %v", want, exp, err)
		}
	}
}

func TestReloadLogLevel(t *testing.T) {
	e := newReloadEnv(t)
	withHost := strings.Replace(fmt.Sprintf(reloadBase, e.root, "1K"), `addr: "127.0.0.1:0",`, `addr: "127.0.0.1:0", host: [lukd.test],`, 1)
	e.write(t, "config.yaml", withHost)
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	e.srv = New(cfg, NewLogger(e.logs, cfg))
	unknown := func() {
		rec := httptest.NewRecorder()
		e.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://other.test/x", nil))
		if rec.Code != http.StatusMisdirectedRequest {
			t.Fatalf("unknown host: %d", rec.Code)
		}
	}
	unknown()
	if strings.Contains(e.logs.String(), "unknown host") {
		t.Fatalf("unknown host logged at info:\n%s", e.logs)
	}
	e.write(t, "config.yaml", withHost+"log: {level: debug}\n")
	if e.srv.reload() == nil {
		t.Fatalf("reload failed:\n%s", e.logs)
	}
	unknown()
	if !strings.Contains(e.logs.String(), `level=DEBUG msg="request for an unknown host" remote=192.0.2.1:1234 host=other.test addr=127.0.0.1:0`) {
		t.Fatalf("unknown host not logged at debug:\n%s", e.logs)
	}
	e.write(t, "config.yaml", withHost+"log: {level: error}\n")
	if e.srv.reload() == nil {
		t.Fatalf("reload failed:\n%s", e.logs)
	}
	n := len(e.logs.String())
	unknown()
	e.upload(t, e.user, "/nope", "x")
	if got := e.logs.String()[n:]; got != "" {
		t.Fatalf("logged below error:\n%s", got)
	}
}

// A reload that raises auth.clock_skew widens the timestamp window back
// past what the nonce cache remembers: a request captured 10 minutes
// before, whose nonce the cache dropped under the old 1m skew, stays
// refused, while timestamps within the old skew pass.
func TestReloadSkewRaiseNoReplay(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	f.srv.start = now.Add(-time.Minute)
	f.srv.SetClock(func() time.Time { return clock })
	stream := wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}
	var captured *http.Request
	r, _ := f.do(t, req{signer: f.user, path: "/drop", meta: stream, ts: now,
		tamper: func(r *http.Request) { captured = r.Clone(context.Background()) }})
	if r.Code != http.StatusCreated {
		t.Fatalf("first %d %s", r.Code, r.Body)
	}
	replay := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		f.handler().ServeHTTP(rec, captured.Clone(context.Background()))
		return rec
	}
	// 10 minutes later other traffic sweeps the nonce out of the cache.
	clock = now.Add(10 * time.Minute)
	if r, _ := f.do(t, req{signer: f.user, path: "/drop", meta: stream, ts: clock}); r.Code != http.StatusCreated {
		t.Fatalf("traffic %d %s", r.Code, r.Body)
	}
	raise := func(skew time.Duration) {
		next := *f.srv.config()
		next.Auth.ClockSkew = config.Duration(skew)
		f.srv.apply(&next)
	}
	raise(time.Hour)
	if rec := replay(); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay after the skew raise: %d %s", rec.Code, rec.Body)
	}
	if r, _ := f.do(t, req{signer: f.user, path: "/drop", meta: stream, ts: clock.Add(-30 * time.Second)}); r.Code != http.StatusCreated {
		t.Fatalf("timestamp within the old skew: %d %s", r.Code, r.Body)
	}
	if r, _ := f.do(t, req{signer: f.user, path: "/drop", meta: stream, ts: clock.Add(-5 * time.Minute)}); r.Code != http.StatusUnauthorized {
		t.Fatalf("timestamp before the raise window: %d %s", r.Code, r.Body)
	}
	// The cache remembers 2h now: lowering and raising again moves nothing.
	floor := f.srv.floor.Load()
	raise(time.Minute)
	clock = clock.Add(time.Hour)
	raise(time.Hour)
	if f.srv.floor.Load() != floor {
		t.Fatal("floor moved without a TTL raise")
	}
	if r, _ := f.do(t, req{signer: f.user, path: "/drop", meta: stream, ts: clock.Add(-30 * time.Minute)}); r.Code != http.StatusCreated {
		t.Fatalf("timestamp within the remembered window: %d %s", r.Code, r.Body)
	}
}
