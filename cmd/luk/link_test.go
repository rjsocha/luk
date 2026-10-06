package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/channel/chantest"
	"luk/internal/client"
	"luk/internal/config"
	"luk/internal/server"
	"luk/internal/wire"
)

// newKeyFile writes a new ed25519 private key and returns its path and
// the authorized_keys line of its public key.
func newKeyFile(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return p, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

// lukdEnv runs both lukd roles on a free port with a drop endpoint that
// allows every link action; the luk config has the endpoint drop. The
// drop storage has the ttl policy {user: true, min: 1h, max: 7d} unless
// newLukdEnvTTL gives another.
type lukdEnv struct {
	base       string // http://addr
	key, other string // key files of robert.socha and of other
	logs       *logBuf
}

func newLukdEnv(t *testing.T) *lukdEnv {
	t.Helper()
	return newLukdEnvTTL(t, "{user: true, min: 1h, max: 7d}")
}

func newLukdEnvTTL(t *testing.T, ttl string) *lukdEnv {
	t.Helper()
	tempConfig(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	e := &lukdEnv{base: "http://" + addr}
	var pub, otherPub string
	e.key, pub = newKeyFile(t)
	e.other, otherPub = newKeyFile(t)
	dir := t.TempDir()
	text := fmt.Sprintf(`
root: %s
listen: {main: {addr: "%s", public: "http://%s"}}
auth:
  keys: [{name: robert.socha, key: "%s"}, {name: other, key: "%s"}]
endpoint:
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha, other], respond: url, storage: drop, link: {remove: ['*'], ttl: ['*'], replace: ['*'], list: ['*']}}
pipeline:
  drop: {endpoint: [drop], steps: [{store: drop}]}
storage:
  drop: {type: local, base: s/drop, path: "{{ .Random }}", expose: drop, ttl: %s}
expose:
  drop: {listen: main, path: /d/}
`, t.TempDir(), addr, addr, pub, otherPub, ttl)
	e.logs = startLukd(t, filepath.Join(dir, "config.yaml"), text, addr)
	mustRun(t, "config", "endpoint", "add", "-e", "drop", "--url", e.base+"/drop#"+lukdPin(t, filepath.Join(dir, "config.yaml")))
	mustRun(t, "config", "link", "add", "--url", e.base+"/d/", "--endpoint", "drop")
	return e
}

// logBuf collects the log lines of lukd.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// count is the number of log lines with the message msg.
func (l *logBuf) count(msg string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.b.String(), "msg=\""+msg+"\"")
}

// startLukd writes the config text to p (and an identity key next to it
// when there is none) and runs both lukd roles on it until the test ends,
// logging into the returned buffer; addr is an address it listens on.
func startLukd(t *testing.T, p, text, addr string) *logBuf {
	t.Helper()
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.IdentityPath(p)); err != nil {
		k, err := channel.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := channel.WriteKey(config.IdentityPath(p), k); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	logs := &logBuf{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	var done []chan error
	for _, role := range []func(context.Context, *config.Config, *slog.Logger) error{server.Receive, server.Process} {
		c := make(chan error, 1)
		go func() { c <- role(ctx, cfg, log) }()
		done = append(done, c)
	}
	t.Cleanup(func() {
		cancel()
		for _, c := range done {
			if err := <-c; err != nil {
				t.Error(err)
			}
		}
	})
	waitUntil(t, "lukd listens", func() bool {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	return logs
}

// lukdPin is the words pin of the identity key of the lukd whose config
// file is p.
func lukdPin(t *testing.T, p string) string {
	t.Helper()
	k, err := channel.LoadKey(config.IdentityPath(p))
	if err != nil {
		t.Fatal(err)
	}
	return channel.Words(k.Public)
}

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting: %s", what)
}

func httpGet(t *testing.T, u string) (int, string) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// waitContent waits until the link serves want.
func waitContent(t *testing.T, link, want string) {
	t.Helper()
	waitUntil(t, link+" serves "+want, func() bool {
		code, body := httpGet(t, link)
		return code == 200 && body == want
	})
}

func namedFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLinkEndToEnd(t *testing.T) {
	e := newLukdEnv(t)
	link := strings.TrimSpace(mustRun(t, "send", "-e", "drop", "-k", e.key, "--mutable", "--file", namedFile(t, "a.txt", "hello")))
	if !strings.HasPrefix(link, e.base+"/d/") {
		t.Fatalf("link %q", link)
	}
	waitContent(t, link, "hello")

	code, out, errs := runLuk(t, "link", link, "--ttl", "30d", "-k", e.key)
	if code != 0 || errs != "luk: ttl 30d capped to 7d by the server (allowed 1h to 7d)\n" {
		t.Fatalf("ttl: exit %d %q", code, errs)
	}
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(out))
	if err != nil || exp.Before(time.Now().Add(7*24*time.Hour-time.Minute)) {
		t.Fatalf("ttl out %q: %v", out, err)
	}

	code, out, errs = runLuk(t, "link", link, "--file", namedFile(t, "b.txt", "new content"), "-k", e.key)
	if code != 0 || out != link+"\n" {
		t.Fatalf("replace: exit %d %q %q", code, out, errs)
	}
	waitContent(t, link, "new content")

	defer stdinFrom(t, "from stdin")()
	code, out, errs = runLuk(t, "link", link, "--stdin", "-k", e.key, "--json")
	if code != 0 || !strings.Contains(out, `"url": "`+link+`"`) || !strings.Contains(out, `"id": "`) {
		t.Fatalf("replace --stdin --json: exit %d %q %q", code, out, errs)
	}
	waitContent(t, link, "from stdin")

	// Another identity allowed on the endpoint is not the owner.
	code, _, errs = runLuk(t, "link", link, "--rm", "-k", e.other)
	if code != 2 || !strings.Contains(errs, "404") || !strings.Contains(errs, "link not found") {
		t.Fatalf("other: exit %d %q", code, errs)
	}

	code, out, errs = runLuk(t, "link", link, "--rm", "-k", e.key)
	if code != 0 || out != "" {
		t.Fatalf("rm: exit %d %q %q", code, out, errs)
	}
	if code, _ := httpGet(t, link); code != 404 {
		t.Fatalf("after rm: %d", code)
	}
}

func TestLinkNotMutable(t *testing.T) {
	e := newLukdEnv(t)
	link := strings.TrimSpace(mustRun(t, "send", "-e", "drop", "-k", e.key, "--file", namedFile(t, "a.txt", "hello")))
	waitContent(t, link, "hello")
	code, _, errs := runLuk(t, "link", link, "--file", namedFile(t, "b.txt", "x"), "-k", e.key)
	if code != 2 || !strings.Contains(errs, "link is not mutable") {
		t.Fatalf("exit %d %q", code, errs)
	}
}

func TestLinkUsageErrors(t *testing.T) {
	tempConfig(t)
	for _, args := range [][]string{
		{"link"},
		{"link", "https://d.example/d/x"},
		{"link", "https://d.example/d/x", "--rm", "--ttl", "1d"},
		{"link", "https://d.example/d/x", "--rm", "--stdin"},
		{"link", "https://d.example/d/x", "--file", "a", "--stdin"},
		{"link", "https://d.example/d/x", "--ttl", "soon"},
		{"link", "https://d.example/d/x", "--rm", "--progress"},
		{"link", "ftp://d.example/d/x", "--rm"},
		{"link", "https://d.example/d/x", "--rm", "x"},
	} {
		if code, _, _ := runLuk(t, args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
	code, _, errs := runLuk(t, "link", "https://d.example/d/x", "--rm")
	if code != 1 || !strings.Contains(errs, "no endpoint for host d.example; add one with luk config link add --url LINK -e NAME") {
		t.Errorf("no endpoint: exit %d %q", code, errs)
	}
}

func TestLinkEndpointOrder(t *testing.T) {
	tempConfig(t)
	var hits []string
	srv := func(name string) {
		s := chantest.New(t)
		s.Op = func(req channel.Request, _ []byte) *chantest.Answer {
			hits = append(hits, name+" "+req.Method+" "+req.Target)
			return &chantest.Answer{Status: http.StatusOK, Body: wire.LinkAnswer{URL: "x", Removed: true}}
		}
		mustRun(t, "config", "endpoint", "add", "-e", name, "--url", s.URL+"/"+name+"#"+s.Pin())
	}
	srv("byhost")
	srv("def")
	srv("flag")
	key, _ := newKeyFile(t)
	const link = "https://Drop.Example:8443/d/x"
	rm := func(extra ...string) {
		t.Helper()
		if code, _, errs := runLuk(t, append([]string{"link", link, "--rm", "-k", key}, extra...)...); code != 0 {
			t.Fatalf("exit %d %s", code, errs)
		}
	}
	mustRun(t, "config", "default", "-e", "def")
	rm()
	mustRun(t, "config", "link", "add", "--url", "https://drop.example/", "--endpoint", "byhost")
	rm()
	rm("-e", "flag")
	want := []string{"def DELETE /def", "byhost DELETE /byhost", "flag DELETE /flag"}
	if strings.Join(hits, ",") != strings.Join(want, ",") {
		t.Fatalf("hits %v, want %v", hits, want)
	}
}

func TestConfigLinkLayers(t *testing.T) {
	user := tempConfig(t)
	global := globalConfig(t)
	writeCfg(t, global, "endpoint:\n  drop: {url: https://lukd.vm/drop}\n  other: {url: https://other.vm/drop}\nlink:\n  drop.example: drop\n  g.example: other\n")
	mustRun(t, "config", "link", "add", "--url", "https://DROP.example:8443/d/x", "--endpoint", "other")
	c, err := client.LoadConfig(user)
	if err != nil || c.Link["drop.example"] != "other" || len(c.Link) != 1 {
		t.Fatalf("user layer %+v %v", c, err)
	}
	out := mustRun(t, "config", "link", "ls")
	for _, want := range []string{"drop.example  other  user\n", "g.example     other  global\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls lacks %q:\n%s", want, out)
		}
	}
	if out := mustRun(t, "config", "show"); !strings.Contains(out, "link:\n  drop.example: other  # user\n  g.example: other  # global\n") {
		t.Errorf("show:\n%s", out)
	}
	if code, _, errs := runLuk(t, "config", "link", "rm", "--host", "g.example"); code != 1 || !strings.Contains(errs, "use --global") {
		t.Errorf("rm global-only: exit %d %q", code, errs)
	}
	for _, args := range [][]string{
		{"config", "link", "add", "--url", "ftp://x.example/", "--endpoint", "drop"},
		{"config", "link", "add", "--url", "https://x.example/", "--endpoint", "nope"},
		{"config", "link", "add", "--url", "https://x.example/"},
		{"config", "link", "rm", "--host", "nope.example"},
		{"config", "link", "rm"},
	} {
		if code, _, _ := runLuk(t, args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
	mustRun(t, "config", "link", "rm", "--host", "drop.example")
	if out := mustRun(t, "config", "link", "ls"); !strings.Contains(out, "drop.example  drop") {
		t.Errorf("global back after the user rm:\n%s", out)
	}
	mustRun(t, "config", "check")
	writeCfg(t, user, "link:\n  x.example: gone\n")
	if code, _, errs := runLuk(t, "config", "check"); code != 1 || !strings.Contains(errs, `link x.example: endpoint "gone" is not a defined endpoint`) {
		t.Errorf("check: exit %d %q", code, errs)
	}
	f := namedFile(t, "c.yaml", "endpoint:\n  drop: {url: https://lukd.vm/drop}\nlink:\n  Bad.Example: drop\n  ok.example: nope\n")
	if code, _, errs := runLuk(t, "config", "check", "--file", f); code != 1 || !strings.Contains(errs, "not a lowercase host name") || !strings.Contains(errs, `"nope" is not a defined endpoint`) {
		t.Errorf("check --file: exit %d %q", code, errs)
	}
}

func TestLinkCompletion(t *testing.T) {
	tempConfig(t)
	mustRun(t, "config", "endpoint", "add", "-e", "drop", "--url", "https://u.example/drop")
	mustRun(t, "config", "link", "add", "--url", "https://d.example/d/", "--endpoint", "drop")
	wantCompletion(t, []string{"config", "link", "rm", "--host", ""}, []string{"d.example\tdrop"}, ":4")
	wantCompletion(t, []string{"config", "link", "add", "--endpoint", ""}, []string{"drop\thttps://u.example/drop"}, ":4")
	wantCompletion(t, []string{"link", "--endpoint", ""}, []string{"drop\thttps://u.example/drop"}, ":4")
	wantCompletion(t, []string{"link", "--ttl", ""}, []string{"max", "1h", "1d", "7d"}, ":4")
	wantCompletion(t, []string{"link", ""}, []string{"ls\tList your links on an endpoint"}, ":4")
	wantCompletion(t, []string{"link", "https://d.example/d/x", ""}, nil, ":4")
	wantCompletion(t, []string{"get", ""}, nil, ":4")
	wantCompletion(t, []string{"get", "-o", ""}, nil, ":0")
	mustRun(t, "alias", "add", "--alias", "lrm", "--", "link", "--rm", "-e", "drop")
	wantCompletion(t, []string{"lrm", "-e", ""}, []string{"drop\thttps://u.example/drop"}, ":4")
}

func TestLinkAlias(t *testing.T) {
	tempConfig(t)
	var got string
	s := chantest.New(t)
	s.Op = func(req channel.Request, _ []byte) *chantest.Answer {
		got = req.Method + " " + req.Header.Get(wire.HeaderLinkAction) + " " + req.Header.Get(wire.HeaderLink)
		return &chantest.Answer{Status: http.StatusOK, Body: wire.LinkAnswer{URL: "x", Expires: "2026-10-09T00:00:00Z", TTL: "7d"}}
	}
	mustRun(t, "config", "endpoint", "add", "-e", "drop", "--url", s.URL+"/drop#"+s.Pin())
	key, _ := newKeyFile(t)
	mustRun(t, "alias", "add", "--alias", "keep", "--", "link", "--ttl", "7d", "-e", "drop", "-k", key)
	code, out, errs := runLuk(t, "keep", "https://d.example/d/x")
	if code != 0 || out != "2026-10-09T00:00:00Z\n" || got != "PATCH ttl https://d.example/d/x" {
		t.Fatalf("exit %d %q %q, request %q", code, out, errs, got)
	}
}

func TestSendMutable(t *testing.T) {
	e := newLukdEnv(t)
	out := mustRun(t, "send", "-e", "drop", "-k", e.key, "--mutable", "--dry-run", "--file", namedFile(t, "a.txt", "x"))
	if !strings.Contains(out, `"mutable": true`) {
		t.Fatalf("dry run:\n%s", out)
	}
	out = mustRun(t, "send", "-e", "drop", "-k", e.key, "--dry-run", "--file", namedFile(t, "a.txt", "x"))
	if strings.Contains(out, `"mutable"`) {
		t.Fatalf("dry run without --mutable:\n%s", out)
	}
}

// expiresIn fails unless the RFC 3339 expiry s is about d from now.
func expiresIn(t *testing.T, what, s string, d time.Duration) {
	t.Helper()
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil || exp.Before(time.Now().Add(d-time.Minute)) || exp.After(time.Now().Add(d)) {
		t.Fatalf("%s: expires %q, want about %v", what, s, d)
	}
}

func TestTTLMaxWithMax(t *testing.T) {
	e := newLukdEnv(t)
	code, out, errs := runLuk(t, "send", "-e", "drop", "-k", e.key, "--ttl", "max", "--json", "--file", namedFile(t, "a.txt", "a"))
	if code != 0 || errs != "" || !strings.Contains(out, `"ttl": "7d"`) || !strings.Contains(out, `"ttl_min": "1h"`) || !strings.Contains(out, `"ttl_max": "7d"`) {
		t.Fatalf("send: exit %d %q %s", code, errs, out)
	}

	mustRun(t, "alias", "add", "--alias", "keep", "--", "send", "-e", "drop", "-k", e.key, "--ttl", "2d")
	link := strings.TrimSpace(mustRun(t, "keep", "--file", namedFile(t, "b.txt", "b")))
	code, out, errs = runLuk(t, "keep", "--file", namedFile(t, "c.txt", "c"), "--ttl", "max", "--json")
	if code != 0 || errs != "" || !strings.Contains(out, `"ttl": "7d"`) {
		t.Fatalf("alias override: exit %d %q %s", code, errs, out)
	}

	waitContent(t, link, "b")
	code, out, errs = runLuk(t, "link", link, "--ttl", "max", "-k", e.key)
	if code != 0 || errs != "" {
		t.Fatalf("link --ttl max: exit %d %q", code, errs)
	}
	expiresIn(t, "link --ttl max", out, 7*24*time.Hour)
}

func TestTTLMaxWithoutMax(t *testing.T) {
	e := newLukdEnvTTL(t, "{user: true, min: 1h}")
	code, out, errs := runLuk(t, "send", "-e", "drop", "-k", e.key, "--ttl", "max", "--json", "--file", namedFile(t, "a.txt", "a"))
	if code != 0 || errs != "" || strings.Contains(out, `"expires"`) || strings.Contains(out, `"ttl":`) || !strings.Contains(out, `"ttl_min": "1h"`) || strings.Contains(out, `"ttl_max"`) {
		t.Fatalf("send: exit %d %q %s", code, errs, out)
	}

	link := strings.TrimSpace(mustRun(t, "send", "-e", "drop", "-k", e.key, "--ttl", "1d", "--file", namedFile(t, "b.txt", "b")))
	waitContent(t, link, "b")
	code, out, errs = runLuk(t, "link", link, "--ttl", "max", "-k", e.key)
	if code != 0 || out != "" || errs != "" {
		t.Fatalf("link --ttl max: exit %d %q %q", code, out, errs)
	}
	code, out, errs = runLuk(t, "link", link, "--ttl", "10m", "-k", e.key)
	if code != 0 || errs != "luk: ttl 10m raised to 1h by the server (allowed from 1h)\n" {
		t.Fatalf("link --ttl 10m: exit %d %q", code, errs)
	}
	expiresIn(t, "link --ttl 10m", out, time.Hour)
}

func TestTTLMaxUserFalse(t *testing.T) {
	e := newLukdEnvTTL(t, "{max: 7d}")
	code, out, errs := runLuk(t, "send", "-e", "drop", "-k", e.key, "--ttl", "max", "--json", "--file", namedFile(t, "a.txt", "a"))
	if code != 0 || errs != "luk: ttl ignored by the server\n" || !strings.Contains(out, `"ttl": "7d"`) || !strings.Contains(out, `"ttl_max": "7d"`) {
		t.Fatalf("send: exit %d %q %s", code, errs, out)
	}
}

func TestLinkLs(t *testing.T) {
	e := newLukdEnv(t)
	if code, _, errs := runLuk(t, "link", "ls", "-k", e.key); code != 1 || !strings.Contains(errs, "no endpoint") {
		t.Fatalf("no default: exit %d %q", code, errs)
	}
	if out := mustRun(t, "link", "ls", "-e", "drop", "-k", e.key); out != "" {
		t.Fatalf("empty: %q", out)
	}
	a := strings.TrimSpace(mustRun(t, "send", "-e", "drop", "-k", e.key, "--mutable", "--file", namedFile(t, "a.txt", "hello")))
	waitContent(t, a, "hello")
	b := strings.TrimSpace(mustRun(t, "send", "-e", "drop", "-k", e.key, "--once", "--file", namedFile(t, "b.txt", "x")))
	mustRun(t, "send", "-e", "drop", "-k", e.other, "--file", namedFile(t, "c.txt", "other"))
	waitUntil(t, "two links listed", func() bool {
		return strings.Count(mustRun(t, "link", "ls", "-e", "drop", "-k", e.key), "\n") == 3
	})
	mustRun(t, "config", "default", "-e", "drop")
	out := mustRun(t, "link", "ls", "-k", e.key)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if !strings.HasPrefix(lines[0], "NAME") || !strings.Contains(lines[0], "SIZE") || !strings.Contains(lines[0], "SENT") ||
		!strings.Contains(lines[0], "EXPIRES") || !strings.Contains(lines[0], "FLAGS") || !strings.HasSuffix(lines[0], "URL") {
		t.Fatalf("header %q", lines[0])
	}
	got := map[string]string{}
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		got[f[len(f)-1]] = f[len(f)-2]
		if f[1]+" "+f[2] != "5 B" && f[1]+" "+f[2] != "1 B" {
			t.Errorf("size in %q", l)
		}
	}
	if got[a] != "mutable" || got[b] != "once" || len(got) != 2 {
		t.Fatalf("links:\n%s", out)
	}
	out = mustRun(t, "link", "ls", "-k", e.key, "--json")
	var ans linkList
	if err := json.Unmarshal([]byte(out), &ans); err != nil || len(ans.Links) != 2 || ans.Permanent == nil || len(ans.Permanent) != 0 || ans.Next != "" {
		t.Fatalf("json %q %v", out, err)
	}
	if !strings.Contains(out, `"permanent": []`) {
		t.Fatalf("json without an empty permanent array: %s", out)
	}
	if code, _, _ := runLuk(t, "link", "ls", "extra"); code != 1 {
		t.Fatalf("positional: exit %d", code)
	}
}

// TestLinkLsPages: --limit asks for a page, --after for the page after a
// cursor, --all for every page; the text output hints the next page on
// stderr, --cursor adds the cursor column, --json carries cursor and next.
func TestLinkLsPages(t *testing.T) {
	e := newLukdEnv(t)
	for i := range 5 {
		mustRun(t, "send", "-e", "drop", "-k", e.key, "--file", namedFile(t, fmt.Sprintf("f%d.txt", i), fmt.Sprint(i)))
	}
	ls := func(args ...string) linkList {
		t.Helper()
		var l linkList
		if err := json.Unmarshal([]byte(mustRun(t, append([]string{"link", "ls", "-e", "drop", "-k", e.key, "--json"}, args...)...)), &l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	waitUntil(t, "five links listed", func() bool { return len(ls().Links) == 5 })
	full := ls()
	if full.Next != "" {
		t.Fatalf("full: %+v", full)
	}
	urls := func(items []linkItem) string {
		var u []string
		for _, l := range items {
			if l.Cursor == "" {
				t.Errorf("no cursor: %+v", l)
			}
			u = append(u, l.URL)
		}
		return strings.Join(u, " ")
	}
	want := urls(full.Links)

	page := ls("--limit", "2")
	if len(page.Links) != 2 || page.Next != page.Links[1].Cursor || urls(page.Links) != urls(full.Links[:2]) {
		t.Fatalf("page: %+v", page)
	}
	next := ls("--limit", "2", "--after", page.Next)
	if urls(next.Links) != urls(full.Links[2:4]) || next.Next != next.Links[1].Cursor {
		t.Fatalf("next: %+v", next)
	}
	if last := ls("--limit", "2", "--after", next.Next); urls(last.Links) != urls(full.Links[4:]) || last.Next != "" {
		t.Fatalf("last: %+v", last)
	}
	raw := mustRun(t, "link", "ls", "-e", "drop", "-k", e.key, "--json", "--limit", "1")
	if !strings.Contains(raw, `"next": "`+full.Links[0].Cursor+`"`) || !strings.Contains(raw, `"cursor": "`) {
		t.Fatalf("json: %s", raw)
	}
	if all := ls("--all", "--limit", "2"); urls(all.Links) != want || all.Next != "" {
		t.Fatalf("all: %+v", all)
	}
	if all := ls("--all", "--limit", "2", "--after", page.Next); urls(all.Links) != urls(full.Links[2:]) {
		t.Fatalf("all after: %+v", all)
	}

	// Text: the hint of the next page on stderr, unless --quiet or --all.
	code, out, errs := runLuk(t, "link", "ls", "-e", "drop", "-k", e.key, "--limit", "2")
	if code != 0 || strings.Count(out, "\n") != 3 || errs != "more: luk link ls --after "+page.Next+"\n" {
		t.Fatalf("text: exit %d %q %q", code, out, errs)
	}
	if code, out, errs := runLuk(t, "link", "ls", "-e", "drop", "-k", e.key, "--limit", "2", "-q"); code != 0 || strings.Count(out, "\n") != 3 || errs != "" {
		t.Fatalf("quiet: exit %d %q %q", code, out, errs)
	}
	if code, out, errs := runLuk(t, "link", "ls", "-e", "drop", "-k", e.key, "--limit", "2", "--all"); code != 0 || strings.Count(out, "\n") != 6 || errs != "" {
		t.Fatalf("all: exit %d %q %q", code, out, errs)
	}
	out = mustRun(t, "link", "ls", "-e", "drop", "-k", e.key, "--cursor", "--limit", "1", "-q")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 2 || !strings.HasSuffix(strings.Join(strings.Fields(lines[0]), " "), "URL CURSOR") ||
		!strings.HasSuffix(strings.Join(strings.Fields(lines[1]), " "), full.Links[0].URL+" "+full.Links[0].Cursor) {
		t.Fatalf("cursor column:\n%s", out)
	}

	// --any asks for the shared entries; without it lukd is not asked.
	if n := strings.Count(e.logs.String(), "any=true"); n != 0 {
		t.Fatalf("any before --any: %d", n)
	}
	mustRun(t, "link", "ls", "-e", "drop", "-k", e.key, "--any")
	if n := strings.Count(e.logs.String(), "any=true"); n != 1 {
		t.Fatalf("any after --any: %d", n)
	}

	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--limit", "0"}, "--limit: want 1 to 1000"},
		{[]string{"--limit", "1001"}, "--limit: want 1 to 1000"},
		{[]string{"--after", "not a cursor"}, `bad cursor`},
	} {
		if code, _, errs := runLuk(t, append([]string{"link", "ls", "-e", "drop", "-k", e.key}, c.args...)...); code == 0 || !strings.Contains(errs, c.want) {
			t.Errorf("%v: exit %d %q", c.args, code, errs)
		}
	}
}

func TestPrintLinks(t *testing.T) {
	cest := time.FixedZone("CEST", 2*3600)
	var b strings.Builder
	if err := printLinks(&b, newLinkList(&wire.LinkListAnswer{}), cest, false); err != nil || b.String() != "" {
		t.Fatalf("empty: %q %v", b.String(), err)
	}
	err := printLinks(&b, newLinkList(&wire.LinkListAnswer{Links: []wire.LinkEntry{
		{URL: "https://d.example/d/long-name", File: "notes.txt", Size: 1536, Received: "2026-10-01T10:00:00Z", Expires: "2026-10-08T10:00:00Z", Once: true, Mutable: true, Portal: wire.PortalReveal},
		{URL: "https://d.example/d/b", Size: 7, Received: "2026-09-30T22:30:00Z", Portal: wire.PortalDirect},
	}}), cest, false)
	want := "NAME       SIZE     SENT              EXPIRES           FLAGS                URL\n" +
		"notes.txt  1.5 KiB  2026-10-01 12:00  2026-10-08 12:00  once,mutable,reveal  https://d.example/d/long-name\n" +
		"-          7 B      2026-10-01 00:30  never             -                    https://d.example/d/b\n"
	if err != nil || b.String() != want {
		t.Fatalf("%v\n%s", err, b.String())
	}
}

// A shared link (private.list) is marked by the flag shared and, in the
// JSON, "shared": true; an own link has no shared key.
func TestPrintLinksShared(t *testing.T) {
	ls := newLinkList(&wire.LinkListAnswer{Links: []wire.LinkEntry{
		{URL: "luk://s.example/a", File: "a", Size: 1, Received: "2026-10-01T10:00:00Z", Access: wire.AccessAny, Shared: true},
		{URL: "luk://s.example/b", File: "b", Size: 1, Received: "2026-10-01T09:00:00Z", Access: wire.AccessAny},
	}})
	var b strings.Builder
	err := printLinks(&b, ls, time.UTC, false)
	want := "NAME  SIZE  SENT              EXPIRES  FLAGS       URL\n" +
		"a     1 B   2026-10-01 10:00  never    any,shared  luk://s.example/a\n" +
		"b     1 B   2026-10-01 09:00  never    any         luk://s.example/b\n"
	if err != nil || b.String() != want {
		t.Fatalf("%v\n%s", err, b.String())
	}
	j, err := json.Marshal(ls)
	want = `{"links":[{"name":"a","size":1,"sent":"2026-10-01T10:00:00Z","flags":["any","shared"],"url":"luk://s.example/a","shared":true,"cursor":""},` +
		`{"name":"b","size":1,"sent":"2026-10-01T09:00:00Z","flags":["any"],"url":"luk://s.example/b","cursor":""}],"permanent":[]}`
	if err != nil || string(j) != want {
		t.Fatalf("%v\n%s", err, j)
	}
}

// --cursor adds the CURSOR column after URL; --json always has the cursor
// of each link and the next of the page.
func TestPrintLinksCursor(t *testing.T) {
	ls := newLinkList(&wire.LinkListAnswer{Links: []wire.LinkEntry{
		{URL: "https://d.example/d/a", File: "a", Size: 1, Received: "2026-10-01T10:00:00Z", Cursor: "MS4wLmE"},
		{URL: "https://d.example/d/b", File: "b", Size: 1, Received: "2026-10-01T09:00:00Z", Cursor: "Yy\x1b"},
	}, Next: "Yy\x1b"})
	var b strings.Builder
	err := printLinks(&b, ls, time.UTC, true)
	want := "NAME  SIZE  SENT              EXPIRES  FLAGS  URL                    CURSOR\n" +
		"a     1 B   2026-10-01 10:00  never    -      https://d.example/d/a  MS4wLmE\n" +
		"b     1 B   2026-10-01 09:00  never    -      https://d.example/d/b  " + `Yy\x1b` + "\n"
	if err != nil || b.String() != want {
		t.Fatalf("%v\n%q\nwant %q", err, b.String(), want)
	}
	j, err := json.Marshal(ls)
	wantJSON := `{"links":[{"name":"a","size":1,"sent":"2026-10-01T10:00:00Z","flags":[],"url":"https://d.example/d/a","cursor":"MS4wLmE"},` +
		`{"name":"b","size":1,"sent":"2026-10-01T09:00:00Z","flags":[],"url":"https://d.example/d/b","cursor":"Yy\u001b"}],"permanent":[],"next":"Yy\u001b"}`
	if err != nil || string(j) != wantJSON {
		t.Fatalf("%v\n%s\nwant\n%s", err, j, wantJSON)
	}
}

// The columns of luk link ls escape the control characters a server sends.
func TestPrintLinksEscapes(t *testing.T) {
	var b strings.Builder
	err := printLinks(&b, newLinkList(&wire.LinkListAnswer{Links: []wire.LinkEntry{
		{URL: "https://d.example/d/a\x1b[2J", File: "a\tb\nc", Size: 1, Received: "now\r", Expires: "x\x07"},
	}}), time.UTC, false)
	want := "NAME     SIZE  SENT   EXPIRES  FLAGS  URL\n" +
		`a\tb\nc` + "  1 B   " + `now\r` + "  " + `x\a` + "      -      " + `https://d.example/d/a\x1b[2J` + "\n"
	if err != nil || b.String() != want {
		t.Fatalf("%v\n%q\nwant %q", err, b.String(), want)
	}
}

// Remove, ttl and list go through the channel: they need the lukd key of
// the endpoint and fail against a pin of another key.
func TestLinkThroughChannel(t *testing.T) {
	e := newLukdEnv(t)
	link := strings.TrimSpace(mustRun(t, "send", "-e", "drop", "-k", e.key, "--file", namedFile(t, "a.txt", "hello")))
	waitContent(t, link, "hello")
	other, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	wrong := e.base + "/drop#" + channel.Words(other.Public)
	for _, args := range [][]string{
		{"link", "ls", "-e", wrong},
		{"link", link, "--ttl", "1d", "-e", wrong},
		{"link", link, "--rm", "-e", wrong},
	} {
		code, _, errs := runLuk(t, append(args, "-k", e.key)...)
		if code != 3 || !strings.Contains(errs, "matches no pin of this endpoint") {
			t.Fatalf("%v: exit %d %q", args, code, errs)
		}
	}
	if out := mustRun(t, "link", "ls", "-e", "drop", "-k", e.key); !strings.Contains(out, link) {
		t.Fatalf("ls: %q", out)
	}
	if code, out, errs := runLuk(t, "link", link, "--ttl", "1d", "-k", e.key); code != 0 || strings.TrimSpace(out) == "" {
		t.Fatalf("ttl: exit %d %q %q", code, out, errs)
	}
	if code, out, errs := runLuk(t, "link", link, "--rm", "-k", e.key); code != 0 || out != "" {
		t.Fatalf("rm: exit %d %q %q", code, out, errs)
	}
	if code, _ := httpGet(t, link); code != 404 {
		t.Fatalf("after rm: %d", code)
	}
}
