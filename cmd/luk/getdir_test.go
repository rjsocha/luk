package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"luk/internal/store"
	"luk/internal/tlsself"
	"luk/internal/wire"
)

// vaultEnv is the private env with the storage vault (path {{ .File }})
// exposed by vault, an auth.ssh expose at /v/ on the secure listener that
// allows robert.socha; files are put into the storage directly.
type vaultEnv struct {
	*privateEnv
	st  store.Local
	url string // luk://host:port/v/#pin
}

func newVaultEnv(t *testing.T) *vaultEnv {
	t.Helper()
	return newVaultEnvAuth(t, "{ssh: {allow: [robert.socha]}}")
}

// newVaultEnvAuth is the vault env with auth as the auth of the expose.
func newVaultEnvAuth(t *testing.T, auth string) *vaultEnv {
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
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha], respond: url, storage: vault}
pipeline:
  drop: {endpoint: [drop], steps: [{store: vault}]}
storage:
  vault: {type: local, base: s/vault, path: "{{ .File }}", expose: vault}
expose:
  vault: {listen: secure, path: /v/, index: %t, auth: %s}
`, e.root, addr, addr, saddr, saddr, pub, otherPub, strings.Contains(auth, "basic"), auth)
	startLukd(t, filepath.Join(t.TempDir(), "config.yaml"), text, saddr)
	return &vaultEnv{privateEnv: e, st: store.Local{Base: filepath.Join(e.root, "s/vault"), Conflict: "replace"},
		url: "luk://" + saddr + "/v/#" + e.pin}
}

// put stores content as rel, received at the given time.
func (v *vaultEnv) put(t *testing.T, rel, content, received string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	sc := store.Sidecar{ID: "id-" + rel, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(content)), Received: received,
		Client: wire.Meta{Portal: wire.PortalDirect}}
	if _, err := v.st.Put(src, rel, sc); err != nil {
		t.Fatal(err)
	}
}

// in is the URL of the directory dir (ending with a slash) of vault.
func (v *vaultEnv) in(dir string) string {
	return strings.Replace(v.url, "/v/#", "/v/"+dir+"#", 1)
}

func sumOf(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

func TestGetDirListing(t *testing.T) {
	v := newVaultEnv(t)
	v.put(t, "db.sql.gz", "dump", "2026-10-03T10:00:00Z")
	v.put(t, "2026/10/a.txt", "a", "2026-10-02T09:30:00Z")
	v.put(t, "2026/b.txt", "bb", "2026-10-01T08:00:00Z")
	v.put(t, "Notes", strings.Repeat("x", 2048), "2026-10-04T12:00:00Z")
	once := filepath.Join(t.TempDir(), "o")
	os.WriteFile(once, []byte("o"), 0o600)
	if _, err := v.st.Put(once, "once", store.Sidecar{ID: "o", SHA256: sumOf("o"), Size: 1, Client: wire.Meta{Once: true, Portal: wire.PortalDirect}}); err != nil {
		t.Fatal(err)
	}

	out := mustRun(t, "get", v.url, "-k", v.key)
	at := func(s string) string { return localTime(s, time.Local) }
	want := "NAME       SIZE     RECEIVED          SHA256\n" +
		"2026/      -        -                 -\n" +
		"db.sql.gz  4 B      " + at("2026-10-03T10:00:00Z") + "  " + sumOf("dump")[:12] + "\n" +
		"Notes      2.0 KiB  " + at("2026-10-04T12:00:00Z") + "  " + sumOf(strings.Repeat("x", 2048))[:12] + "\n"
	if out != want {
		t.Fatalf("listing:\n%s\nwant:\n%s", out, want)
	}
	out = mustRun(t, "get", v.in("2026/"), "-k", v.key, "-r")
	if !regexp.MustCompile(`(?m)^10/a\.txt\s+1 B\s+`+at("2026-10-02T09:30:00Z")+`\s+`+sumOf("a")[:12]+`$`).MatchString(out) || !strings.Contains(out, "\nb.txt ") {
		t.Fatalf("recursive:\n%s", out)
	}
	out = mustRun(t, "get", v.url, "-k", v.key, "-r", "--json")
	var ents []wire.ListEntry
	if err := json.Unmarshal([]byte(out), &ents); err != nil || len(ents) != 4 || ents[0].Name != "2026/10/a.txt" || ents[0].SHA256 != sumOf("a") ||
		*ents[0].Size != 1 || ents[0].Received != "2026-10-02T09:30:00Z" || ents[1].Name != "2026/b.txt" || ents[3].Name != "Notes" {
		t.Fatalf("json:\n%s %v", out, err)
	}
	out = mustRun(t, "get", v.url, "-k", v.key, "--json")
	if !strings.Contains(out, `"name": "2026/",`+"\n    \"dir\": true") {
		t.Fatalf("json one level:\n%s", out)
	}
	// Not allowed and missing directories are not found.
	if code, _, errs := runLuk(t, "get", v.url, "-k", v.other); code != 2 || !strings.Contains(errs, "404") {
		t.Fatalf("other: exit %d %q", code, errs)
	}
	if code, _, errs := runLuk(t, "get", v.in("nope/"), "-k", v.key); code != 2 || !strings.Contains(errs, "404") {
		t.Fatalf("missing: exit %d %q", code, errs)
	}
	// A file URL works as before.
	if code, out, errs := runLuk(t, "get", strings.Replace(v.url, "/v/#", "/v/db.sql.gz#", 1), "-k", v.key, "-c"); code != 0 || out != "dump" {
		t.Fatalf("file: exit %d %q %q", code, out, errs)
	}
}

var (
	durRE  = regexp.MustCompile(`\b[0-9m]*[0-9]+\.[0-9]s\b`)
	rateRE = regexp.MustCompile(`\b[0-9.]+ (B|[KMGT]iB)/s\b`)
)

// untimed replaces the durations of a directory download output with T
// and the rates with R.
func untimed(s string) string {
	return rateRE.ReplaceAllString(durRE.ReplaceAllString(s, "T"), "R")
}

func TestGetDirDownload(t *testing.T) {
	v := newVaultEnv(t)
	v.put(t, "db.sql.gz", "dump", "2026-10-03T10:00:00Z")
	v.put(t, "2026/10/a.txt", "a", "2026-10-02T09:30:00Z")
	v.put(t, "2026/b.txt", "bb", "2026-10-01T08:00:00Z")
	dest := filepath.Join(t.TempDir(), "backups") + "/"
	code, out, errs := runLuk(t, "get", v.url, "-k", v.key, "-o", dest)
	if want := "get 2026/10/a.txt  1 B  T\nget 2026/b.txt  2 B  T\nget db.sql.gz  4 B  T\n3 downloaded, 0 skipped, 7 B in T, R\n"; code != 0 || untimed(out) != want {
		t.Fatalf("fresh: exit %d %q %q", code, out, errs)
	}
	for rel, content := range map[string]string{"db.sql.gz": "dump", "2026/10/a.txt": "a", "2026/b.txt": "bb"} {
		if b, err := os.ReadFile(filepath.Join(dest, rel)); err != nil || string(b) != content {
			t.Errorf("%s: %q %v", rel, b, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dest, "2026", ".*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
	if code, out, errs = runLuk(t, "get", v.url, "-k", v.key, "-o", dest); code != 0 || untimed(out) != "skip 2026/10/a.txt\nskip 2026/b.txt\nskip db.sql.gz\n0 downloaded, 3 skipped, 0 B in T, R\n" {
		t.Fatalf("second: exit %d %q %q", code, out, errs)
	}
	// A subdirectory into an existing directory, quiet.
	sub := t.TempDir()
	if code, out, errs = runLuk(t, "get", v.in("2026/"), "-k", v.key, "-o", sub, "-q"); code != 0 || out != "" {
		t.Fatalf("sub: exit %d %q %q", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(sub, "10/a.txt")); string(b) != "a" {
		t.Fatalf("sub a.txt %q", b)
	}

	// A changed remote file is refused without --force, the others skipped.
	v.put(t, "2026/b.txt", "changed", "2026-10-04T08:00:00Z")
	code, out, errs = runLuk(t, "get", v.url, "-k", v.key, "-o", dest)
	if code != 1 || errs != "luk: 2026/b.txt: exists and differs; pass --force to overwrite it\nluk: 1 of 3 files failed\n" ||
		untimed(out) != "skip 2026/10/a.txt\nskip db.sql.gz\n0 downloaded, 2 skipped, 1 failed, 0 B in T, R\n" {
		t.Fatalf("changed: exit %d %q %q", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "2026/b.txt")); string(b) != "bb" {
		t.Fatalf("overwritten without --force: %q", b)
	}
	if code, out, errs = runLuk(t, "get", v.url, "-k", v.key, "-o", dest, "--force"); code != 0 || !strings.Contains(untimed(out), "get 2026/b.txt  7 B  T\n") || !strings.HasSuffix(untimed(out), "1 downloaded, 2 skipped, 7 B in T, R\n") {
		t.Fatalf("force: exit %d %q %q", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "2026/b.txt")); string(b) != "changed" {
		t.Fatalf("forced %q", b)
	}

	// A symlink in DIR is never followed, even with --force.
	outside := t.TempDir()
	link := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(link, "2026")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "x"), filepath.Join(link, "db.sql.gz")); err != nil {
		t.Fatal(err)
	}
	code, out, errs = runLuk(t, "get", v.url, "-k", v.key, "-o", link, "--force")
	if code != 1 || !strings.Contains(errs, "luk: 2026/10/a.txt: 2026 exists and is not a directory\n") || !strings.Contains(errs, "luk: db.sql.gz: exists and is not a regular file\n") ||
		!strings.Contains(errs, "3 of 3 files failed") {
		t.Fatalf("symlinks: exit %d %q %q", code, out, errs)
	}
	if left, _ := os.ReadDir(outside); len(left) != 0 {
		t.Fatalf("written through a symlink: %v", left)
	}

	// Usage.
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-c"}, "-c/--stdout and -o - take no directory URL"},
		{[]string{"-o", "-"}, "-c/--stdout and -o - take no directory URL"},
		{[]string{"-o", dest, "--inplace"}, "--inplace and --head take no directory URL"},
		{[]string{"--head"}, "--inplace and --head take no directory URL"},
		{[]string{"-o", file}, "is not a directory"},
		{[]string{"-o", filepath.Join(t.TempDir(), "new")}, "does not exist; a directory URL needs -o DIR/"},
		{[]string{"-o", dest, "--json"}, "--json takes no -o"},
		{[]string{"--force"}, "need -o DIR/"},
	} {
		if code, _, errs := runLuk(t, append([]string{"get", v.url, "-k", v.key}, c.args...)...); code != 1 || !strings.Contains(errs, c.want) {
			t.Errorf("%v: exit %d %q", c.args, code, errs)
		}
	}
	if code, _, errs := runLuk(t, "get", strings.Replace(v.url, "/v/#", "/v/db.sql.gz#", 1), "-k", v.key, "-r", "-c"); code != 1 || !strings.Contains(errs, "-r needs a directory URL") {
		t.Errorf("-r on a file: exit %d %q", code, errs)
	}
}

// fakeDir is a TLS server answering the signed listing of /v/ with
// listing and every file with its name as content (404 for names in
// missing); it ignores the signature.
func fakeDir(t *testing.T, listing string, missing ...string) string {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v/" {
			w.Write([]byte(listing))
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v/")
		for _, m := range missing {
			if m == name {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("ETag", `"`+sumOf(name)+`"`)
		w.Write([]byte(name))
	}))
	t.Cleanup(ts.Close)
	return ts.URL + "/v/#" + tlsself.Pin(ts.Certificate())
}

func TestGetDirHostileListing(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	for _, name := range []string{"../evil", "/etc/evil", "a/../../evil", "a//b", "./x", "x\x1b[2J", "x\ny", ""} {
		dest := t.TempDir()
		listing, _ := json.Marshal([]wire.ListEntry{{Name: "ok"}, {Name: name}})
		code, out, errs := runLuk(t, "get", fakeDir(t, string(listing)), "-k", key, "-o", dest)
		if code != 3 || !strings.Contains(errs, "unsafe name") || !strings.Contains(errs, "nothing downloaded") || out != "" {
			t.Errorf("%q: exit %d %q %q", name, code, out, errs)
		}
		if left, _ := os.ReadDir(dest); len(left) != 0 {
			t.Errorf("%q: wrote %v", name, left)
		}
	}
	dest := t.TempDir()
	code, _, errs := runLuk(t, "get", fakeDir(t, `[{"name":"a"},{"name":"a"}]`), "-k", key, "-o", dest)
	if code != 3 || !strings.Contains(errs, "twice") {
		t.Errorf("duplicate: exit %d %q", code, errs)
	}
	code, _, errs = runLuk(t, "get", fakeDir(t, `{"not": "a list"}`), "-k", key)
	if code != 3 || !strings.Contains(errs, "not a JSON array") {
		t.Errorf("not a list: exit %d %q", code, errs)
	}
	// The table escapes what it prints.
	code, out, _ := runLuk(t, "get", fakeDir(t, `[{"name":"x\u001b[2J\ny","size":1}]`), "-k", key)
	if code != 0 || !strings.Contains(out, `x\x1b[2J\ny`) {
		t.Errorf("table: exit %d %q", code, out)
	}
}

func TestGetDirPartialFailure(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	dest := t.TempDir()
	listing := `[{"name":"a","sha256":"` + sumOf("a") + `"},{"name":"gone"},{"name":"d/c"}]`
	code, out, errs := runLuk(t, "get", fakeDir(t, listing, "gone"), "-k", key, "-o", dest)
	if code != 2 || !strings.Contains(errs, "luk: gone: ") || !strings.Contains(errs, "404") || !strings.HasSuffix(errs, "luk: 1 of 3 files failed\n") ||
		untimed(out) != "get a  1 B  T\nget d/c  3 B  T\n2 downloaded, 0 skipped, 1 failed, 4 B in T, R\n" {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "d/c")); string(b) != "d/c" {
		t.Fatalf("d/c %q", b)
	}
	if _, err := os.Lstat(filepath.Join(dest, "gone")); err == nil {
		t.Fatal("gone written")
	}
}
