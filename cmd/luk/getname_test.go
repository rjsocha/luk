package main

import (
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"luk/internal/tlsself"
)

// nameServer answers every GET and HEAD with content "x", announcing
// name in Content-Disposition (none when empty); it counts the GETs.
func nameServer(t *testing.T, name string) (string, *atomic.Int32) {
	t.Helper()
	var gets atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
		}
		if name != "" {
			w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		}
		w.Header().Set("ETag", `"`+sumOf("x")+`"`)
		w.Write([]byte("x"))
	}))
	t.Cleanup(ts.Close)
	return ts.URL + "#" + tlsself.Pin(ts.Certificate()), &gets
}

// atPath puts p as the path of the URL u (with its pin fragment).
func atPath(u, p string) string {
	base, pin, _ := strings.Cut(u, "#")
	return base + p + "#" + pin
}

func TestGetRemoteName(t *testing.T) {
	e := newPrivateEnv(t)
	link := e.send(t, "a.txt", "secret", "--private")
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	random := path.Base(u.Path)
	dir := t.TempDir()
	t.Chdir(dir)

	// -O: the last segment of the URL.
	if code, out, errs := runLuk(t, "get", link, "-k", e.key, "-O"); code != 0 || out != random+"\n" {
		t.Fatalf("-O: exit %d %q %q", code, out, errs)
	}
	if b, err := os.ReadFile(filepath.Join(dir, random)); err != nil || string(b) != "secret" {
		t.Fatalf("%s %q %v", random, b, err)
	}
	if code, _, errs := runLuk(t, "get", link, "-k", e.key, "--remote-name"); code != 1 || !strings.Contains(errs, random+" exists; pass --force") {
		t.Fatalf("-O existing: exit %d %q", code, errs)
	}
	os.WriteFile(filepath.Join(dir, random), []byte("old"), 0o600)
	if code, _, errs := runLuk(t, "get", link, "-k", e.key, "-O", "--force", "-q"); code != 0 {
		t.Fatalf("-O --force: exit %d %q", code, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, random)); string(b) != "secret" {
		t.Fatalf("forced %q", b)
	}

	// -J: the name the server announces, which differs from the random
	// name of the drop link.
	if code, out, errs := runLuk(t, "get", link, "-k", e.key, "-O", "-J"); code != 0 || out != "a.txt\n" {
		t.Fatalf("-O -J: exit %d %q %q", code, out, errs)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "a.txt")); err != nil || string(b) != "secret" {
		t.Fatalf("a.txt %q %v", b, err)
	}

	// An existing file is refused before the download: a once file stays
	// there for the run with --force.
	once := e.send(t, "a.txt", "once", "--private", "--once")
	if code, _, errs := runLuk(t, "get", once, "-k", e.key, "-OJ"); code != 1 || !strings.Contains(errs, "a.txt exists; pass --force") {
		t.Fatalf("-J existing: exit %d %q", code, errs)
	}
	if code, _, errs := runLuk(t, "get", once, "-k", e.key, "--remote-name", "--remote-header-name", "--force"); code != 0 {
		t.Fatalf("-J --force: exit %d %q", code, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(b) != "once" {
		t.Fatalf("-J forced %q", b)
	}
}

func TestGetRemoteNameUsage(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	srv, gets := nameServer(t, "")
	file := atPath(srv, "/x")
	dir := t.TempDir()
	t.Chdir(dir)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{file, "-O", "-o", "y"}, "-O excludes -o and -c"},
		{[]string{file, "-O", "-o", "-"}, "-O excludes -o and -c"},
		{[]string{file, "-O", "-c"}, "-O excludes -o and -c"},
		{[]string{file, "-O", "--head"}, "--head takes no -O"},
		{[]string{file, "-J"}, "-J needs -O"},
		{[]string{file, "-J", "-o", "y"}, "-J needs -O"},
		{[]string{atPath(srv, "/v/"), "-O"}, "-O takes no directory URL; use -o DIR/"},
		{[]string{atPath(srv, "/v/"), "-O", "-J"}, "-O takes no directory URL; use -o DIR/"},
		{[]string{atPath(srv, "/"), "-O"}, "-O takes no directory URL; use -o DIR/"},
		{[]string{atPath(srv, "/a%2Fb"), "-O"}, `unsafe file name "a/b" in the URL: a path separator; pass -o FILE`},
		{[]string{atPath(srv, `/a%5Cb`), "-O"}, `unsafe file name "a\\b" in the URL: a path separator; pass -o FILE`},
		{[]string{atPath(srv, "/v/%2e%2e"), "-O"}, `unsafe file name ".." in the URL`},
		{[]string{atPath(srv, "/v/."), "-O"}, `unsafe file name "." in the URL`},
		{[]string{atPath(srv, "/x%00"), "-O"}, `unsafe file name "x\x00" in the URL: control or formatting characters`},
		{[]string{atPath(srv, "/x%1b%5b2J"), "-O"}, `unsafe file name "x\x1b[2J" in the URL`},
		{[]string{atPath(srv, "/x%ff"), "-O"}, `unsafe file name "x\xff" in the URL: not UTF-8`},
	} {
		if code, _, errs := runLuk(t, append([]string{"get", "-k", key}, c.args...)...); code != 1 || !strings.Contains(errs, c.want) {
			t.Errorf("%v: exit %d %q, want %q", c.args, code, errs, c.want)
		}
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 || gets.Load() != 0 {
		t.Fatalf("usage errors wrote %v, %d GETs", left, gets.Load())
	}

	// -J without an announced name falls back to the URL; percent-encoded
	// segments are decoded.
	if code, out, errs := runLuk(t, "get", "-k", key, atPath(srv, "/d/my%20file.txt"), "-O", "-J"); code != 0 || out != "my file.txt\n" {
		t.Fatalf("-J fallback: exit %d %q %q", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "my file.txt")); string(b) != "x" {
		t.Fatalf("my file.txt %q", b)
	}
	// -O with --force over an existing file.
	if code, _, errs := runLuk(t, "get", "-k", key, atPath(srv, "/d/my%20file.txt"), "-O", "--force"); code != 0 {
		t.Fatalf("-O --force: exit %d %q", code, errs)
	}
}

// A name the server announces is only ever a file in the current
// directory: anything else fails before the download.
func TestGetRemoteHeaderNameHostile(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "cwd")
	os.Mkdir(dir, 0o777)
	t.Chdir(dir)
	for _, name := range []string{"../x", "a/b", "/etc/x", `..\x`, "..", ".", "x\x01y", "x\ny", "x\x1b[2J", "x‮y"} {
		srv, gets := nameServer(t, name)
		code, out, errs := runLuk(t, "get", "-k", key, atPath(srv, "/safe"), "-O", "-J", "--force")
		if code != 3 || !strings.Contains(errs, "unsafe file name") || !strings.Contains(errs, "announced by the server: ") || !strings.HasSuffix(errs, "; nothing downloaded\n") || out != "" {
			t.Errorf("%q: exit %d %q %q", name, code, out, errs)
		}
		if gets.Load() != 0 {
			t.Errorf("%q: %d GETs", name, gets.Load())
		}
	}
	for _, d := range []string{dir, parent} {
		if left, _ := os.ReadDir(d); len(left) != map[string]int{dir: 0, parent: 1}[d] {
			t.Fatalf("%s: written %v", d, left)
		}
	}
	// The escaping of the error keeps it on one line.
	srv, _ := nameServer(t, "x\ny")
	if _, _, errs := runLuk(t, "get", "-k", key, atPath(srv, "/safe"), "-OJ"); strings.Count(errs, "\n") != 1 {
		t.Fatalf("not one line: %q", errs)
	}
}

// A symlink at the name -O or -J picks is never written through: --inplace
// takes no -O, and the default path replaces the link itself (--force) or
// refuses it.
func TestGetRemoteNameSymlink(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	srv, _ := nameServer(t, "a.txt")
	plain, _ := nameServer(t, "")
	dir, outside := t.TempDir(), t.TempDir()
	t.Chdir(dir)
	target := filepath.Join(outside, "target")
	for _, c := range []struct {
		url  string
		args []string
		code int
	}{
		{atPath(plain, "/a.txt"), []string{"-O"}, 1},
		{atPath(plain, "/a.txt"), []string{"-O", "-J"}, 1},
		{atPath(srv, "/other"), []string{"-O", "-J"}, 1},
		{atPath(plain, "/a.txt"), []string{"-O", "--force"}, 0},
		{atPath(srv, "/other"), []string{"-O", "-J", "--force"}, 0},
		{atPath(plain, "/a.txt"), []string{"-O", "--inplace"}, 1},
		{atPath(plain, "/a.txt"), []string{"-O", "--inplace", "--force"}, 1},
		{atPath(srv, "/other"), []string{"-O", "-J", "--inplace"}, 1},
		{atPath(srv, "/other"), []string{"-O", "-J", "--inplace", "--force"}, 1},
	} {
		os.Remove("a.txt")
		if err := os.Symlink(target, "a.txt"); err != nil {
			t.Fatal(err)
		}
		code, _, errs := runLuk(t, append([]string{"get", "-k", key, c.url}, c.args...)...)
		if code != c.code {
			t.Errorf("%v: exit %d %q, want %d", c.args, code, errs, c.code)
		}
		if strings.Contains(strings.Join(c.args, " "), "--inplace") && !strings.Contains(errs, "--inplace takes no -O") {
			t.Errorf("%v: %q", c.args, errs)
		}
		if left, _ := os.ReadDir(outside); len(left) != 0 {
			t.Fatalf("%v: written through the symlink: %v", c.args, left)
		}
	}
}

// A name whose temporary file would not fit in a directory entry is
// refused before the download.
func TestGetRemoteNameLength(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	t.Chdir(t.TempDir())
	plain, gets := nameServer(t, "")
	long := strings.Repeat("n", 237)
	if code, _, errs := runLuk(t, "get", "-k", key, atPath(plain, "/"+long), "-O"); code != 1 || !strings.Contains(errs, "longer than 236 bytes") {
		t.Fatalf("237: exit %d %q", code, errs)
	}
	if code, _, errs := runLuk(t, "get", "-k", key, atPath(plain, "/"+long[1:]), "-O"); code != 0 {
		t.Fatalf("236: exit %d %q", code, errs)
	}
	srv, sgets := nameServer(t, strings.Repeat("ż", 119))
	if code, _, errs := runLuk(t, "get", "-k", key, atPath(srv, "/x"), "-OJ"); code != 3 || !strings.Contains(errs, "longer than 236 bytes") || sgets.Load() != 0 {
		t.Fatalf("announced: exit %d %q, %d GETs", code, errs, sgets.Load())
	}
	if gets.Load() != 1 {
		t.Fatalf("%d GETs", gets.Load())
	}
}
