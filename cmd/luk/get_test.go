package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"luk/internal/tlsself"
)

// privateEnv runs lukd with the plain listener main (endpoint /drop,
// public expose /d/) and the tls mode self listener secure, whose expose
// at / is the protect expose of the drop storage with auth.ssh allow
// ["*"]; /drop accepts both private modes and the link remove and list.
// The luk config has the endpoint drop and maps the host of the secure
// listener to it.
type privateEnv struct {
	*lukdEnv
	root   string
	secure string // https://127.0.0.1:port
	pin    string
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func newPrivateEnv(t *testing.T) *privateEnv {
	t.Helper()
	tempConfig(t)
	addr, saddr := freeAddr(t), freeAddr(t)
	e := &privateEnv{lukdEnv: &lukdEnv{base: "http://" + addr}, root: t.TempDir(), secure: "https://" + saddr}
	var pub, otherPub string
	e.key, pub = newKeyFile(t)
	e.other, otherPub = newKeyFile(t)
	crt, key := filepath.Join(e.root, "tls/s.crt"), filepath.Join(e.root, "tls/s.key")
	var err error
	if e.pin, err = tlsself.Generate(crt, key, "luk.test", tlsself.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf(`
root: %s
listen:
  main: {addr: "%s", public: "http://%s"}
  secure: {addr: "%s", public: "https://%s", tls: {mode: self, cert: tls/s.crt, key: tls/s.key, host: luk.test}}
auth:
  keys: [{name: robert.socha, key: "%s"}, {name: other, key: "%s"}]
endpoint:
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha, other], respond: url, storage: drop, private: {owner: true, any: true}, link: {remove: true, list: true}}
pipeline:
  drop: {endpoint: [drop], steps: [{store: drop}]}
storage:
  drop: {type: local, base: s/drop, ttl: {user: true}, path: "{{ .Random }}", expose: drop, protect: secure}
expose:
  drop: {listen: main, path: /d/}
  secure: {listen: secure, path: /, auth: {ssh: {allow: ["*"]}}}
`, e.root, addr, addr, saddr, saddr, pub, otherPub)
	startLukd(t, filepath.Join(t.TempDir(), "config.yaml"), text, saddr)
	mustRun(t, "config", "endpoint", "add", "-e", "drop", "--url", e.base+"/drop")
	mustRun(t, "config", "link", "add", "--url", "luk://"+saddr+"/", "--endpoint", "drop")
	return e
}

// send uploads a file of content named name with the extra send flags and
// waits until it is stored; it returns the URL.
func (e *privateEnv) send(t *testing.T, name, content string, flags ...string) string {
	t.Helper()
	args := append([]string{"send", "-e", "drop", "-k", e.key, "--file", namedFile(t, name, content)}, flags...)
	link := strings.TrimSpace(mustRun(t, args...))
	waitUntil(t, link+" stored", func() bool {
		_, err := os.Stat(e.sidecar(t, link))
		return err == nil
	})
	return link
}

// sidecar is the sidecar path of the drop file of link.
func (e *privateEnv) sidecar(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(e.root, "s/drop/.db/meta", path.Base(u.Path)+".json")
}

func TestGetPrivate(t *testing.T) {
	e := newPrivateEnv(t)
	link := e.send(t, "a.txt", "secret", "--private")
	if want := "luk://" + strings.TrimPrefix(e.secure, "https://") + "/"; !strings.HasPrefix(link, want) || !strings.HasSuffix(link, "#"+e.pin) {
		t.Fatalf("link %q, want %s<name>#%s", link, want, e.pin)
	}
	if code, _ := httpGet(t, e.base+"/d/"+path.Base(strings.TrimSuffix(link, "#"+e.pin))); code != 404 {
		t.Fatalf("public expose: %d", code)
	}

	dir := t.TempDir()
	t.Chdir(dir)
	code, out, errs := runLuk(t, "get", link, "-k", e.key)
	if code != 1 || !strings.Contains(errs, "luk get needs -o FILE (or -o - for stdout), or --head") {
		t.Fatalf("no -o: exit %d %q %q", code, out, errs)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("no -o wrote %v", left)
	}
	if code, out, errs = runLuk(t, "get", link, "-k", e.key, "-o", "a.txt"); code != 0 || out != "a.txt\n" {
		t.Fatalf("get: exit %d %q %q", code, out, errs)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "a.txt")); err != nil || string(b) != "secret" {
		t.Fatalf("a.txt %q %v", b, err)
	}
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("old"), 0o600)
	if code, _, errs = runLuk(t, "get", link, "-k", e.key, "-o", "a.txt", "--force"); code != 0 {
		t.Fatalf("force: exit %d %q", code, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(b) != "secret" {
		t.Fatalf("forced %q", b)
	}
	code, out, errs = runLuk(t, "get", link, "-k", e.key, "-o", "-")
	if code != 0 || out != "secret" {
		t.Fatalf("stdout: exit %d %q %q", code, out, errs)
	}
	o := filepath.Join(t.TempDir(), "b.bin")
	if code, out, errs = runLuk(t, "get", link, "-k", e.key, "-o", o); code != 0 || out != o+"\n" {
		t.Fatalf("-o: exit %d %q %q", code, out, errs)
	}
	if code, _, errs = runLuk(t, "get", link, "-k", e.key, "-o", o); code != 1 || !strings.Contains(errs, "exists") {
		t.Fatalf("-o existing: exit %d %q", code, errs)
	}
	// The https URL of the expose works as well.
	if code, out, errs = runLuk(t, "get", strings.Replace(link, "luk://", "https://", 1), "-k", e.key, "-o", "-"); code != 0 || out != "secret" {
		t.Fatalf("https: exit %d %q %q", code, out, errs)
	}

	code, _, errs = runLuk(t, "get", link, "-k", e.other, "-o", "-")
	if code != 2 || !strings.Contains(errs, "404") {
		t.Fatalf("other: exit %d %q", code, errs)
	}
	unknown, _ := newKeyFile(t)
	code, _, errs = runLuk(t, "get", link, "-k", unknown, "-o", "-")
	if code != 2 || !strings.Contains(errs, "401") || !strings.Contains(errs, "unknown key") {
		t.Fatalf("unknown key: exit %d %q", code, errs)
	}
	// Without the pin the self-signed certificate fails the system CAs.
	code, _, _ = runLuk(t, "get", strings.TrimSuffix(link, "#"+e.pin), "-k", e.key, "-o", "-")
	if code != 3 {
		t.Fatalf("no pin: exit %d", code)
	}
}

func TestGetAny(t *testing.T) {
	e := newPrivateEnv(t)
	link := e.send(t, "n.txt", "shared", "--private", "--any")
	code, out, errs := runLuk(t, "get", link, "-k", e.other, "-o", "-")
	if code != 0 || out != "shared" {
		t.Fatalf("other: exit %d %q %q", code, out, errs)
	}
	unknown, _ := newKeyFile(t)
	if code, _, errs = runLuk(t, "get", link, "-k", unknown, "-o", "-"); code != 2 || !strings.Contains(errs, "401") {
		t.Fatalf("unknown key: exit %d %q", code, errs)
	}
	// The key of the endpoint the host of the URL maps to, before the
	// config key.
	mustRun(t, "config", "key", "-k", e.key)
	mustRun(t, "config", "endpoint", "add", "-e", "sec", "--url", e.base+"/drop", "--key", unknown)
	mustRun(t, "config", "link", "add", "--url", link, "--endpoint", "sec")
	if code, _, errs = runLuk(t, "get", link, "-o", "-"); code != 2 || !strings.Contains(errs, "401") {
		t.Fatalf("mapped endpoint key: exit %d %q", code, errs)
	}
	mustRun(t, "config", "link", "rm", "--host", "127.0.0.1")
	if code, out, errs = runLuk(t, "get", link, "-o", "-"); code != 0 || out != "shared" {
		t.Fatalf("config key: exit %d %q %q", code, out, errs)
	}
}

func TestGetOnceAndFailure(t *testing.T) {
	e := newPrivateEnv(t)
	link := e.send(t, "o.txt", "once", "--private", "--once")
	dir := t.TempDir()
	o := filepath.Join(dir, "o.txt")
	// A usage error sends nothing: the once file is still there.
	if code, _, errs := runLuk(t, "get", link, "-k", e.key); code != 1 || !strings.Contains(errs, "needs -o FILE") {
		t.Fatalf("no -o: exit %d %q", code, errs)
	}
	os.WriteFile(o, []byte("old"), 0o600)
	if code, _, errs := runLuk(t, "get", link, "-k", e.key, "-o", o); code != 1 || !strings.Contains(errs, o+" exists; pass --force") {
		t.Fatalf("existing: exit %d %q", code, errs)
	}
	os.Remove(o)
	// HEAD never claims it.
	for range 2 {
		code, out, errs := runLuk(t, "get", link, "-k", e.key, "--head")
		if code != 0 || !strings.Contains(out, "name: o.txt\n") || !strings.Contains(out, "size: 4\n") {
			t.Fatalf("head: exit %d %q %q", code, out, errs)
		}
	}
	if code, _, errs := runLuk(t, "get", link, "-k", e.key, "-o", o); code != 0 {
		t.Fatalf("first: exit %d %q", code, errs)
	}
	if code, _, errs := runLuk(t, "get", link, "-k", e.key, "-o", filepath.Join(dir, "again")); code != 2 || !strings.Contains(errs, "404") {
		t.Fatalf("second: exit %d %q", code, errs)
	}

	// Content that differs from the announced sha256 fails the download
	// and leaves nothing behind.
	link = e.send(t, "c.txt", "content", "--private")
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(e.root, "s/drop/file", path.Base(u.Path))
	if err := os.Chmod(data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(data, []byte("tampere"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := runLuk(t, "get", link, "-k", e.key, "-o", "-")
	if code != 4 || !strings.Contains(errs, "sha256 mismatch, the output is not the announced content") {
		t.Fatalf("stdout mismatch: exit %d %q", code, errs)
	}
	empty := t.TempDir()
	code, _, errs = runLuk(t, "get", link, "-k", e.key, "-o", filepath.Join(empty, "c.txt"))
	if code != 4 || !strings.Contains(errs, "sha256 mismatch") {
		t.Fatalf("mismatch: exit %d %q", code, errs)
	}
	if left, _ := os.ReadDir(empty); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
}

func TestGetLinks(t *testing.T) {
	e := newPrivateEnv(t)
	link := e.send(t, "a.txt", "secret", "--private")
	e.send(t, "b.txt", "open")
	out := mustRun(t, "link", "ls", "-e", "drop", "-k", e.key)
	if !strings.Contains(out, link) || !strings.Contains(out, "private") || !strings.Contains(out, e.base+"/d/") {
		t.Fatalf("ls:\n%s", out)
	}
	// The link host of a luk:// URL maps to the endpoint drop.
	if code, out, errs := runLuk(t, "link", link, "--rm", "-k", e.key); code != 0 || out != "" {
		t.Fatalf("rm: exit %d %q %q", code, out, errs)
	}
	if code, _, errs := runLuk(t, "get", link, "-k", e.key, "-o", "-"); code != 2 || !strings.Contains(errs, "404") {
		t.Fatalf("removed: exit %d %q", code, errs)
	}
}

func TestSendPrivateUsage(t *testing.T) {
	tempConfig(t)
	f := namedFile(t, "a.txt", "x")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--any"}, "--any needs --private"},
		{[]string{"--private", "--secret"}, "--private takes no --secret or --portal"},
		{[]string{"--private", "--portal"}, "--private takes no --secret or --portal"},
	} {
		code, _, errs := runLuk(t, append([]string{"send", "--file", f}, c.args...)...)
		if code != 1 || !strings.Contains(errs, c.want) {
			t.Errorf("%v: exit %d %q", c.args, code, errs)
		}
	}
	for _, c := range []struct{ url, want string }{
		{"http://h/x", "invalid URL"}, {"luk://h/x#nopin", "fragment must be a pin"}, {"ftp://h/x", "invalid URL"},
	} {
		if code, _, errs := runLuk(t, "get", c.url); code != 1 || !strings.Contains(errs, c.want) {
			t.Errorf("get %s: exit %d %q", c.url, code, errs)
		}
	}
}

func TestGetLinkURLArgument(t *testing.T) {
	tempConfig(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"get"}, "luk get needs one link URL"},
		{[]string{"get", "-o", "-"}, "luk get needs one link URL"},
		{[]string{"get", "luk://h/a", "luk://h/b", "-o", "-"}, "luk get needs one link URL"},
		{[]string{"get", "--url", "luk://h/a", "-o", "-"}, "unknown flag: --url"},
		{[]string{"link", "--rm"}, "luk link needs one link URL"},
		{[]string{"link", "https://d.example/d/a", "https://d.example/d/b", "--rm"}, "luk link needs one link URL"},
		{[]string{"link", "--url", "https://d.example/d/a", "--rm"}, "unknown flag: --url"},
		{[]string{"link", "ls", "https://d.example/d/a"}, `unexpected argument "https://d.example/d/a"`},
	} {
		if code, _, errs := runLuk(t, c.args...); code != 1 || !strings.Contains(errs, c.want) {
			t.Errorf("%v: exit %d %q, want %q", c.args, code, errs, c.want)
		}
	}
}

func TestGetAliasAndArgumentOrder(t *testing.T) {
	e := newPrivateEnv(t)
	link := e.send(t, "a.txt", "secret", "--private")
	t.Chdir(t.TempDir())
	// The URL may come after the flags.
	if code, out, errs := runLuk(t, "get", "-k", e.key, "-o", "-", link); code != 0 || out != "secret" {
		t.Fatalf("URL last: exit %d %q %q", code, out, errs)
	}
	// Words of the expansion stay, the URL of the call is appended.
	mustRun(t, "alias", "add", "--alias", "pget", "--", "get", "-o", "out.bin", "-k", e.key)
	if code, out, errs := runLuk(t, "pget", link); code != 0 || out != "out.bin\n" {
		t.Fatalf("alias: exit %d %q %q", code, out, errs)
	}
	if b, err := os.ReadFile("out.bin"); err != nil || string(b) != "secret" {
		t.Fatalf("out.bin %q %v", b, err)
	}
	if code, out, errs := runLuk(t, "pget", link, "-o", "-"); code != 0 || out != "secret" {
		t.Fatalf("alias -o override: exit %d %q %q", code, out, errs)
	}
	if code, _, errs := runLuk(t, "pget"); code != 1 || !strings.Contains(errs, "luk get needs one link URL") {
		t.Fatalf("alias without URL: exit %d %q", code, errs)
	}
}

func TestSendPrivateDryRun(t *testing.T) {
	e := newPrivateEnv(t)
	out := mustRun(t, "send", "-e", "drop", "-k", e.key, "--file", namedFile(t, "a.txt", "x"), "--private", "--any", "--dry-run")
	if !strings.Contains(out, `"access": "any"`) || !strings.Contains(out, `"url": "luk://`) {
		t.Fatalf("dry run:\n%s", out)
	}
}

func TestGetHead(t *testing.T) {
	e := newPrivateEnv(t)
	link := e.send(t, "h.txt", "hello", "--private")
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte("hello")))
	code, out, errs := runLuk(t, "get", link, "-k", e.key, "--head")
	want := "name: h.txt\nsize: 5\ncontent_type: text/plain; charset=utf-8\nsha256: " + sum + "\n"
	if code != 0 || out != want {
		t.Fatalf("head: exit %d %q %q, want %q", code, out, errs, want)
	}
	code, out, errs = runLuk(t, "get", link, "-k", e.key, "--head", "--json")
	var got struct {
		Name        string `json:"name"`
		Size        int64  `json:"size"`
		ContentType string `json:"content_type"`
		SHA256      string `json:"sha256"`
	}
	if err := json.Unmarshal([]byte(out), &got); code != 0 || err != nil || got.Name != "h.txt" || got.Size != 5 || got.SHA256 != sum || got.ContentType == "" {
		t.Fatalf("head --json: exit %d %q %q %v", code, out, errs, err)
	}
	if strings.Contains(out, "expires") || strings.Contains(out, "once") {
		t.Fatalf("head --json without expiry and once: %s", out)
	}

	// Luk-Expires and Luk-Once on the protect expose (GET and HEAD) only.
	link = e.send(t, "x.txt", "bye", "--private", "--once", "--ttl", "1h")
	code, out, errs = runLuk(t, "get", link, "-k", e.key, "--head")
	m := regexp.MustCompile(`(?m)^expires: (\S+)$`).FindStringSubmatch(out)
	if code != 0 || m == nil || !strings.HasSuffix(out, "once: true\n") {
		t.Fatalf("head once ttl: exit %d %q %q", code, out, errs)
	}
	if exp, err := time.Parse(time.RFC3339, m[1]); err != nil || !strings.HasSuffix(m[1], "Z") || time.Until(exp) < 50*time.Minute {
		t.Fatalf("expires %q %v", m[1], err)
	}
	code, out, errs = runLuk(t, "get", link, "-k", e.key, "--head", "--json")
	if code != 0 || !strings.Contains(out, `"expires": "`+m[1]+`"`) || !strings.Contains(out, `"once": true`) {
		t.Fatalf("head once ttl --json: exit %d %q %q", code, out, errs)
	}
	pub := e.send(t, "p.txt", "open", "--once", "--ttl", "1h")
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, _ := http.NewRequest(method, pub, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Luk-Expires") != "" || resp.Header.Get("Luk-Once") != "" {
			t.Fatalf("public %s: %d %v", method, resp.StatusCode, resp.Header)
		}
	}

	if code, _, errs = runLuk(t, "get", link, "-k", e.other, "--head"); code != 2 || !strings.Contains(errs, "404") {
		t.Fatalf("head other: exit %d %q", code, errs)
	}
	for _, args := range [][]string{{"--head", "-o", "x"}, {"--head", "-o", "-"}} {
		if code, _, errs = runLuk(t, append([]string{"get", link, "-k", e.key}, args...)...); code != 1 || !strings.Contains(errs, "--head takes no --output") {
			t.Errorf("%v: exit %d %q", args, code, errs)
		}
	}
	if code, _, errs = runLuk(t, "get", link, "-k", e.key, "-o", "-", "--json"); code != 1 || !strings.Contains(errs, "--json needs --head") {
		t.Errorf("--json without --head: exit %d %q", code, errs)
	}
}

// contentServer answers every GET with body and ETag (the sha256 of
// sum); it counts the requests.
func contentServer(t *testing.T, body, sum string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, sha256.Sum256([]byte(sum))))
		w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts, &n
}

func TestGetInplace(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	ts, n := contentServer(t, "new", "new")
	u := ts.URL + "/x#" + tlsself.Pin(ts.Certificate())
	dir := t.TempDir()
	o := filepath.Join(dir, "a.txt")

	if code, out, errs := runLuk(t, "get", u, "-k", key, "-o", o, "--inplace"); code != 0 || out != o+"\n" {
		t.Fatalf("new: exit %d %q %q", code, out, errs)
	}
	if fi, err := os.Stat(o); err != nil || fi.Mode().Perm() != 0o666&^umask(t) {
		t.Fatalf("new mode %v %v", fi, err)
	}
	os.WriteFile(o, []byte("old content"), 0o600)
	os.Chmod(o, 0o640)
	link := filepath.Join(dir, "hard")
	if err := os.Link(o, link); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(o)
	n.Store(0)
	if code, _, errs := runLuk(t, "get", u, "-k", key, "-o", o, "--inplace"); code != 1 || !strings.Contains(errs, o+" exists; pass --force") || n.Load() != 0 {
		t.Fatalf("existing: exit %d %q, %d requests", code, errs, n.Load())
	}
	if code, _, errs := runLuk(t, "get", u, "-k", key, "-o", o, "--inplace", "--clobber"); code != 1 || !strings.Contains(errs, "unknown flag: --clobber") {
		t.Fatalf("--clobber: exit %d %q", code, errs)
	}
	if code, _, errs := runLuk(t, "get", u, "-k", key, "-o", o, "--inplace", "-f"); code != 1 || !strings.Contains(errs, "unknown shorthand flag: 'f'") {
		t.Fatalf("-f: exit %d %q", code, errs)
	}
	if code, _, errs := runLuk(t, "get", u, "-k", key, "-o", o, "--inplace", "--force"); code != 0 {
		t.Fatalf("force: exit %d %q", code, errs)
	}
	after, _ := os.Stat(o)
	if !os.SameFile(before, after) || after.Mode().Perm() != 0o640 {
		t.Fatalf("inode or mode not kept: %v %v", before, after)
	}
	if b, _ := os.ReadFile(link); string(b) != "new" {
		t.Fatalf("hard link %q", b)
	}

	// A 404 leaves the file untouched.
	nf := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(nf.Close)
	code, _, errs := runLuk(t, "get", nf.URL+"/x#"+tlsself.Pin(nf.Certificate()), "-k", key, "-o", o, "--inplace", "--force")
	if b, _ := os.ReadFile(o); code != 2 || string(b) != "new" {
		t.Fatalf("404: exit %d %q, file %q", code, errs, b)
	}

	// A device needs no --force.
	if code, _, errs := runLuk(t, "get", u, "-k", key, "-o", os.DevNull, "--inplace"); code != 0 {
		t.Fatalf("device: exit %d %q", code, errs)
	}

	for _, args := range [][]string{{"-o", "-"}, {"--head"}, {"--head", "-o", "x"}} {
		code, _, errs := runLuk(t, append([]string{"get", u, "-k", key, "--inplace"}, args...)...)
		if code != 1 || !strings.Contains(errs, "--inplace takes no --head or -o -") {
			t.Errorf("%v: exit %d %q", args, code, errs)
		}
	}
}

func umask(t *testing.T) os.FileMode {
	t.Helper()
	p := filepath.Join(t.TempDir(), "m")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o777)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, _ := os.Stat(p)
	return 0o777 &^ fi.Mode().Perm()
}

func TestGetInplaceFIFO(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	ts, _ := contentServer(t, "through the pipe", "through the pipe")
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() {
		b, _ := os.ReadFile(fifo)
		got <- string(b)
	}()
	if code, _, errs := runLuk(t, "get", ts.URL+"/x#"+tlsself.Pin(ts.Certificate()), "-k", key, "-o", fifo, "--inplace"); code != 0 {
		t.Fatalf("fifo: exit %d %q", code, errs)
	}
	if s := <-got; s != "through the pipe" {
		t.Fatalf("read %q", s)
	}
}

func TestGetMismatchInplaceAndDefault(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	ts, _ := contentServer(t, "tampered", "content")
	u := ts.URL + "/x#" + tlsself.Pin(ts.Certificate())
	got, want := fmt.Sprintf("%x", sha256.Sum256([]byte("tampered"))), fmt.Sprintf("%x", sha256.Sum256([]byte("content")))

	o := filepath.Join(t.TempDir(), "c.txt")
	code, _, errs := runLuk(t, "get", u, "-k", key, "-o", o, "--inplace")
	if wantErr := "luk: sha256 mismatch, " + o + " kept as written (got " + got + ", want " + want + ")\n"; code != 4 || errs != wantErr {
		t.Fatalf("inplace: exit %d %q, want %q", code, errs, wantErr)
	}
	if b, _ := os.ReadFile(o); string(b) != "tampered" {
		t.Fatalf("kept %q", b)
	}

	empty := t.TempDir()
	code, _, errs = runLuk(t, "get", u, "-k", key, "-o", filepath.Join(empty, "c.txt"))
	if wantErr := "luk: sha256 mismatch, nothing written (got " + got + ", want " + want + ")\n"; code != 4 || errs != wantErr {
		t.Fatalf("default: exit %d %q, want %q", code, errs, wantErr)
	}
	if left, _ := os.ReadDir(empty); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
}

func TestGetDefaultMode(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	ts, _ := contentServer(t, "x", "x")
	u := ts.URL + "/x#" + tlsself.Pin(ts.Certificate())
	o := filepath.Join(t.TempDir(), "m.txt")
	if code, _, errs := runLuk(t, "get", u, "-k", key, "-o", o); code != 0 {
		t.Fatalf("get: exit %d %q", code, errs)
	}
	if fi, err := os.Stat(o); err != nil || fi.Mode().Perm() != 0o666&^umask(t) {
		t.Fatalf("mode %v %v, want %v", fi.Mode(), err, 0o666&^umask(t))
	}
	os.Chmod(o, 0o600)
	if code, _, errs := runLuk(t, "get", u, "-k", key, "-o", o, "--force"); code != 0 {
		t.Fatalf("force: exit %d %q", code, errs)
	}
	if fi, _ := os.Stat(o); fi.Mode().Perm() != 0o666&^umask(t) {
		t.Fatalf("force mode %v", fi.Mode())
	}
}

// The text of --head escapes the control characters of what the server
// announces: a file name chosen by another identity can neither add a
// sha256 line nor drive the terminal; --json keeps it raw.
func TestGetHeadControlCharacters(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	evil := "report.pdf\nsha256: " + strings.Repeat("0", 64) + "\nonce: true\x1b]0;owned\x07\x1b[2K"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": evil}))
		w.Header().Set("Content-Type", "text/plain\u2028x")
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, sha256.Sum256([]byte("hello"))))
		w.Write([]byte("hello"))
	}))
	defer ts.Close()
	u := ts.URL + "/x#" + tlsself.Pin(ts.Certificate())
	code, out, errs := runLuk(t, "get", u, "-k", key, "--head")
	want := "name: report.pdf\\nsha256: " + strings.Repeat("0", 64) + "\\nonce: true\\x1b]0;owned\\a\\x1b[2K\n" +
		"size: 5\ncontent_type: text/plain\\u2028x\nsha256: " + fmt.Sprintf("%x", sha256.Sum256([]byte("hello"))) + "\n"
	if code != 0 || out != want {
		t.Fatalf("exit %d %q %q\nwant %q", code, out, errs, want)
	}
	code, out, _ = runLuk(t, "get", u, "-k", key, "--head", "--json")
	var got struct{ Name string }
	if err := json.Unmarshal([]byte(out), &got); code != 0 || err != nil || got.Name != evil {
		t.Fatalf("--json: exit %d %q %v", code, out, err)
	}
}

// The error text of a server is printed escaped and cut: it cannot add a
// line that looks like one of luk.
func TestRejectedMessageEscaped(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"error":"no\u001b[2J\u001b]0;owned\u0007\nluk: uploaded ok` + strings.Repeat("x", 1000) + `"}`))
	}))
	defer ts.Close()
	code, _, errs := runLuk(t, "send", "-e", ts.URL+"/drop", "-k", key, "--file", namedFile(t, "a", "x"))
	want := `luk: rejected (403 Forbidden): no\x1b[2J\x1b]0;owned\a\nluk: uploaded ok` + strings.Repeat("x", 256-3-41) + "...\n"
	if code != 2 || errs != want {
		t.Fatalf("exit %d %q\nwant %q", code, errs, want)
	}
}
