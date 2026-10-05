package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"text/template"
	"time"

	"luk/internal/wire"
)

func TestTemplateData(t *testing.T) {
	d := Vars{Id: "abc", Tags: []string{"a", "b"}}.TemplateData()
	if d["File"] != "abc" || d["Tags"] != "a-b" || d["Id"] != "abc" {
		t.Fatalf("data %v", d)
	}
	if d := (Vars{Id: "abc", File: "f.txt"}).TemplateData(); d["File"] != "f.txt" {
		t.Fatalf("file %v", d["File"])
	}
	if d := (Vars{Sender: "s"}).TemplateData(); d["Hostname"] != "" || d["Origin"] != "s" {
		t.Fatalf("origin without hostname %v", d)
	}
	if d := (Vars{Sender: "s", Hostname: "h"}).TemplateData(); d["Hostname"] != "h" || d["Origin"] != "h" {
		t.Fatalf("origin with hostname %v", d)
	}
}

func TestRenderHostname(t *testing.T) {
	tm := func(s string) *template.Template { return template.Must(template.New("").Parse(s)) }
	v := Vars{Sender: "hosts:db1", Time: time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC), File: "d.sql", Hostname: "db1.example.net"}
	for src, want := range map[string]string{
		"{{.Hostname}}/{{.File}}":                           "db1.example.net/d.sql",
		"{{.Origin}}/{{.Year}}{{.Month}}{{.Day}}/{{.File}}": "db1.example.net/20260930/d.sql",
	} {
		if got, err := Render(tm(src), v); err != nil || got != want {
			t.Errorf("%q: %q %v", src, got, err)
		}
	}
	v.Hostname = ""
	if got, err := Render(tm("{{.Origin}}/{{.File}}"), v); err != nil || got != "hosts:db1/d.sql" {
		t.Errorf("origin fallback: %q %v", got, err)
	}
	for _, src := range []string{"{{.Hostname}}/{{.File}}", "{{.Year}}{{.Month}}{{.Day}}/{{.Hostname}}/{{.File}}", "{{.File}}/{{.Hostname}}"} {
		if _, err := Render(tm(src), v); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "needs a hostname") {
			t.Errorf("%q without hostname: %v", src, err)
		}
	}
	if got, err := Render(tm("{{with .Hostname}}{{.}}/{{end}}{{.File}}"), v); err != nil || got != "d.sql" {
		t.Errorf("optional hostname: %q %v", got, err)
	}
}

func TestRandomName(t *testing.T) {
	const alphabet = "abc~-"
	seen := map[rune]int{}
	for range 2000 {
		s := RandomName(alphabet, 10)
		if len(s) != 10 {
			t.Fatalf("length %d", len(s))
		}
		for _, c := range s {
			if !strings.ContainsRune(alphabet, c) {
				t.Fatalf("%q outside the alphabet", c)
			}
			seen[c]++
		}
	}
	// 20000 draws over 5 characters: each near 4000.
	for _, c := range alphabet {
		if n := seen[c]; n < 3500 || n > 4500 {
			t.Errorf("%q drawn %d times", c, n)
		}
	}
}

func TestVarsFor(t *testing.T) {
	v := Vars{Random: "default", Randoms: map[string]string{"drop": "custom"}}
	if v.For("drop").Random != "custom" || v.For("other").Random != "default" || v.Random != "default" {
		t.Fatal(v.For("drop"), v.For("other"))
	}
}

func TestRender(t *testing.T) {
	v := Vars{Sender: "alice", Endpoint: "up", Time: time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC), Id: "id1", Random: "R", File: "x.txt", Tags: []string{"t1", "t2"}}
	ok := map[string]string{
		"{{.Sender}}/{{.Year}}{{.Month}}{{.Day}}/{{.File}}": "alice/20260930/x.txt",
		"{{.Tags}}/{{.Id}}": "t1-t2/id1",
		"a//{{.Random}}":    "a/R",
		"x/.luk/{{.File}}":  "x/.luk/x.txt",
		".db/{{.File}}":     ".db/x.txt",
	}
	for src, want := range ok {
		got, err := Render(template.Must(template.New("").Parse(src)), v)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", src, got, err, want)
		}
	}
	bad := []struct {
		src string
		v   Vars
	}{
		{"{{.File}}", Vars{File: ".."}},
		{"a/{{.File}}/b", Vars{File: ".."}},
		{"a/../b", v},
		{"/{{.File}}", v},
		{"{{.File}}", Vars{File: "."}},
		{"", v},
		{"{{.Tags}}", Vars{Id: "i"}},
		{"./a", v},
		{"a\x00b", v},
	}
	for _, b := range bad {
		if got, err := Render(template.Must(template.New("").Parse(b.src)), b.v); err == nil {
			t.Errorf("%q with %+v: accepted %q", b.src, b.v, got)
		}
	}
	if got, err := Render(template.Must(template.New("").Parse("{{.File}}")), Vars{File: ".bashrc"}); err != nil || got != ".bashrc" {
		t.Errorf("dotfile: got %q, %v", got, err)
	}
	_, err := Render(template.Must(template.New("").Parse("a/{{.File}}")), Vars{File: ".."})
	if err == nil || !strings.Contains(err.Error(), `element ".." is not a name`) {
		t.Errorf("error does not name the element: %v", err)
	}
}

func TestValidName(t *testing.T) {
	for _, rel := range []string{"x", ".bashrc", "a/.env", ".luk/x", ".db", "file/.db/lock", "a.b/..c"} {
		if err := ValidName(rel); err != nil {
			t.Errorf("%q refused: %v", rel, err)
		}
	}
	for rel, why := range map[string]string{
		"":       "empty name",
		"/x":     "is absolute",
		"a\x00b": "NUL byte",
		"a//b":   "empty element",
		"a/":     "empty element",
		"a/./b":  `element "." is not a name`,
		"../x":   `element ".." is not a name`,
	} {
		err := ValidName(rel)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: %v, want %q", rel, err, why)
		}
	}
}

func TestSafeJoin(t *testing.T) {
	base := t.TempDir()
	if p, err := SafeJoin(base, "a/b"); err != nil || p != filepath.Join(base, DataDir, "a/b") {
		t.Fatalf("got %q, %v", p, err)
	}
	if p, err := SafeJoin(base, "a/.b"); err != nil || p != filepath.Join(base, DataDir, "a/.b") {
		t.Fatalf("dot name: got %q, %v", p, err)
	}
	for _, rel := range []string{"", "..", "../x", "a/../../x", "/etc/passwd", ".", "a//b", "a/"} {
		if _, err := SafeJoin(base, rel); err == nil {
			t.Errorf("%q accepted", rel)
		}
	}
	outside := t.TempDir()
	mkdirAll(t, filepath.Join(base, DataDir))
	if err := os.Symlink(outside, filepath.Join(base, DataDir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := SafeJoin(base, "link/x"); err == nil {
		t.Error("symlink dir accepted")
	}
	if _, err := SafeJoin(base, "link"); err == nil {
		t.Error("symlink leaf accepted")
	}
}

func srcFile(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, "src")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func sidecar(id string) Sidecar {
	sz := int64(5)
	return Sidecar{ID: id, Sender: "alice", Endpoint: "up", Received: "2026-09-30T10:00:00Z", Size: 5, SHA256: "00",
		Client: wire.Meta{File: "x.txt", Source: wire.SourceFile, Size: &sz, Portal: wire.PortalDirect, Tags: []string{"t"}}}
}

func fixedNow(t *testing.T, ts int64) {
	t.Helper()
	old := now
	now = func() time.Time { return time.Unix(ts, 0) }
	t.Cleanup(func() { now = old })
}

func readAll(t *testing.T, l Local, rel string) (string, Sidecar) {
	t.Helper()
	f, sc, err := l.Open(rel)
	if err != nil {
		t.Fatalf("open %s: %v", rel, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), sc
}

// recvTS is the unix time of the received time of sidecar.
var recvTS = strconv.FormatInt(time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC).Unix(), 10)

func TestPutVersion(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "version"}
	src := srcFile(t, t.TempDir(), "hello")
	for i := range 4 {
		got, err := l.Put(src, "a/x.txt", sidecar("id"+strconv.Itoa(i)))
		if err != nil || got != "a/x.txt" {
			t.Fatalf("put %d: got %q, %v", i, got, err)
		}
	}
	want := map[string]string{"a/x.txt": "id3", "a/x.txt." + recvTS: "id0", "a/x.txt." + recvTS + ".000001": "id1", "a/x.txt." + recvTS + ".000002": "id2"}
	for rel, id := range want {
		body, sc := readAll(t, l, rel)
		if body != "hello" || sc.ID != id || sc.Client.File != "x.txt" {
			t.Fatalf("%s: %q %+v", rel, body, sc)
		}
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("source removed: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(l.Base, DataDir, "a"))
	if len(entries) != len(want) {
		t.Fatalf("leftovers in dir: %v", entries)
	}
}

func TestPutDefaultConflictIsVersion(t *testing.T) {
	l := Local{Base: t.TempDir()}
	src := srcFile(t, t.TempDir(), "hello")
	if _, err := l.Put(src, "x", sidecar("1")); err != nil {
		t.Fatal(err)
	}
	if got, err := l.Put(src, "x", sidecar("2")); err != nil || got != "x" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, sc := readAll(t, l, "x."+recvTS); sc.ID != "1" {
		t.Fatalf("version %+v", sc)
	}
}

func TestPutReject(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "reject"}
	src := srcFile(t, t.TempDir(), "hello")
	if _, err := l.Put(src, "x", sidecar("1")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(src, "x", sidecar("2")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want exists", err)
	}
	if _, sc := readAll(t, l, "x"); sc.ID != "1" {
		t.Fatalf("sidecar overwritten: %+v", sc)
	}
	if e := dirNames(t, filepath.Join(l.Base, DataDir)); fmt.Sprint(e) != "[x]" {
		t.Fatalf("data tree %v", e)
	}
	if e := dirNames(t, filepath.Join(l.Base, tmpDir)); len(e) != 0 {
		t.Fatalf("leftover %v", e)
	}
}

func TestPutReplace(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "replace"}
	d := t.TempDir()
	if _, err := l.Put(srcFile(t, d, "one"), "x", sidecar("1")); err != nil {
		t.Fatal(err)
	}
	got, err := l.Put(srcFile(t, d, "two"), "x", sidecar("2"))
	if err != nil || got != "x" {
		t.Fatalf("got %q, %v", got, err)
	}
	if body, sc := readAll(t, l, "x"); body != "two" || sc.ID != "2" {
		t.Fatalf("%q %+v", body, sc)
	}
}

func TestPutHardlink(t *testing.T) {
	l := Local{Base: t.TempDir()}
	d := t.TempDir()
	src := srcFile(t, d, "hello")
	got, err := l.Put(src, "x", sidecar("1"))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := os.Stat(src)
	b, _ := os.Stat(filepath.Join(l.Base, DataDir, got))
	if !os.SameFile(a, b) {
		t.Fatal("not hardlinked")
	}
	if n := a.Sys().(*syscall.Stat_t).Nlink; n != 2 {
		t.Fatalf("nlink %d", n)
	}
}

func TestPutCopy(t *testing.T) {
	old := link
	link = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EXDEV} }
	t.Cleanup(func() { link = old })
	l := Local{Base: t.TempDir()}
	src := srcFile(t, t.TempDir(), "hello")
	got, err := l.Put(src, "d/x", sidecar("1"))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := os.Stat(src)
	b, _ := os.Stat(filepath.Join(l.Base, DataDir, got))
	if os.SameFile(a, b) {
		t.Fatal("hardlinked, want copy")
	}
	if body, _ := readAll(t, l, got); body != "hello" {
		t.Fatalf("body %q", body)
	}
}

func TestPutRefusesSymlinkDir(t *testing.T) {
	l := Local{Base: t.TempDir()}
	outside := t.TempDir()
	mkdirAll(t, filepath.Join(l.Base, DataDir))
	if err := os.Symlink(outside, filepath.Join(l.Base, DataDir, "d")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(srcFile(t, t.TempDir(), "x"), "d/x", sidecar("1")); err == nil {
		t.Fatal("put through symlink accepted")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote outside: %v", entries)
	}
}

func TestPutRefusesSymlinkedSidecarTree(t *testing.T) {
	l := Local{Base: t.TempDir()}
	outside := t.TempDir()
	mkdirAll(t, filepath.Join(l.Base, DBDir))
	if err := os.Symlink(outside, filepath.Join(l.Base, metaDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(srcFile(t, t.TempDir(), "x"), "x", sidecar("1")); err == nil {
		t.Fatal("sidecar through symlink accepted")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote outside: %v", entries)
	}
	if _, err := os.Lstat(filepath.Join(l.Base, DataDir, "x")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("data file left without sidecar: %v", err)
	}
}

func TestSidecarPath(t *testing.T) {
	l := Local{Base: "/srv/b"}
	if p := l.SidecarPath("a/x.txt"); p != "/srv/b/.db/meta/a/x.txt.json" {
		t.Fatal(p)
	}
}

func TestOpenRefuses(t *testing.T) {
	l := Local{Base: t.TempDir()}
	if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "x", sidecar("1")); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(l.Base, DataDir, "evil")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(l.Base, DataDir, "evildir")); err != nil {
		t.Fatal(err)
	}
	sc, err := os.ReadFile(l.SidecarPath("x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"evil", "evildir/secret"} {
		if err := os.MkdirAll(filepath.Dir(l.SidecarPath(rel)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(l.SidecarPath(rel), sc, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{"../.db/meta/x.json", "../x", "/etc/passwd", "evil", "evildir/secret", "missing"} {
		if f, _, err := l.Open(rel); err == nil {
			f.Close()
			t.Errorf("%q opened", rel)
		}
	}
}

func TestOpenMissingSidecar(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mkdirAll(t, filepath.Join(l.Base, DataDir))
	if err := os.WriteFile(filepath.Join(l.Base, DataDir, "orphan"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Open("orphan"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want not found", err)
	}
}

func TestRemove(t *testing.T) {
	l := Local{Base: t.TempDir()}
	got, err := l.Put(srcFile(t, t.TempDir(), "hello"), "a/x", sidecar("1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Remove(got); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(l.Base, DataDir, got), l.SidecarPath(got)} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s still there: %v", p, err)
		}
	}
	if err := l.Remove("../x"); err == nil {
		t.Error("escape accepted")
	}
}

func TestWalk(t *testing.T) {
	l := Local{Base: t.TempDir()}
	src := srcFile(t, t.TempDir(), "hello")
	for _, rel := range []string{"a/x", "b/c/y", "z"} {
		if _, err := l.Put(src, rel, sidecar(rel)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(l.Base, DataDir, "orphan"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(src, filepath.Join(l.Base, DataDir, "sl")); err != nil {
		t.Fatal(err)
	}
	var got []string
	err := l.Walk(func(rel string, sc Sidecar) error {
		if sc.ID != rel {
			t.Errorf("%s: sidecar %s", rel, sc.ID)
		}
		got = append(got, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	if want := []string{"a/x", "b/c/y", "z"}; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("walk %v", got)
	}
	if err := (Local{Base: filepath.Join(l.Base, "nope")}).Walk(func(string, Sidecar) error { return nil }); err != nil {
		t.Fatalf("missing base: %v", err)
	}
}

func shaOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func putContent(t *testing.T, l Local, dir, rel, content string) (string, error) {
	t.Helper()
	src := filepath.Join(dir, shaOf(content))
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	sc := sidecar(content)
	sc.SHA256 = shaOf(content)
	return l.Put(src, rel, sc)
}

func TestPutConcurrentVersion(t *testing.T) {
	l := Local{Base: t.TempDir()}
	dir := t.TempDir()
	const n = 20
	var wg sync.WaitGroup
	stored := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stored[i], errs[i] = putContent(t, l, dir, "x", fmt.Sprint("content ", i))
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil || stored[i] != "x" {
			t.Fatal(stored[i], errs[i])
		}
	}
	ids := map[string]bool{}
	if err := l.Walk(func(rel string, _ Sidecar) error {
		body, sc := readAll(t, l, rel)
		if shaOf(body) != sc.SHA256 || sc.ID != body || ids[sc.ID] {
			t.Fatalf("%s: body %q sidecar %+v", rel, body, sc)
		}
		ids[sc.ID] = true
		return nil
	}); err != nil || len(ids) != n {
		t.Fatalf("%d files, %v", len(ids), err)
	}
}

func TestPutConcurrentReplace(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "replace"}
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := putContent(t, l, dir, "x", fmt.Sprint("content ", i)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	body, sc := readAll(t, l, "x")
	if shaOf(body) != sc.SHA256 {
		t.Fatalf("body %q sidecar %+v", body, sc)
	}
}

func TestPutReplaceSidecarFailureKeepsOld(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "replace"}
	dir := t.TempDir()
	if _, err := putContent(t, l, dir, "d/x", "one"); err != nil {
		t.Fatal(err)
	}
	sdir := filepath.Dir(l.SidecarPath("d/x"))
	if err := os.Chmod(sdir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(sdir, 0o700) })
	if _, err := putContent(t, l, dir, "d/x", "two"); err == nil {
		t.Skip("directory permissions not enforced (root?)")
	}
	os.Chmod(sdir, 0o700)
	body, sc := readAll(t, l, "d/x")
	if body != "one" || sc.SHA256 != shaOf("one") {
		t.Fatalf("body %q sidecar %+v", body, sc)
	}
}

func TestPutDirSwappedForSymlink(t *testing.T) {
	l := Local{Base: t.TempDir()}
	outside := t.TempDir()
	old := hookAfterCheck
	hookAfterCheck = func() {
		d := filepath.Join(l.Base, DataDir, "d")
		if err := os.Remove(d); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(outside, d); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { hookAfterCheck = old })
	if _, err := l.Put(srcFile(t, t.TempDir(), "x"), "d/x", sidecar("1")); err == nil {
		t.Fatal("put through swapped symlink accepted")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote outside: %v", entries)
	}
}

func TestErrInvalid(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mkdirAll(t, filepath.Join(l.Base, DataDir))
	if err := os.Symlink(t.TempDir(), filepath.Join(l.Base, DataDir, "sl")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"../x", "/x", "a/./b", "a/../b", "a//b", "sl/x", ""} {
		if _, err := SafeJoin(l.Base, rel); !errors.Is(err, ErrInvalid) {
			t.Errorf("SafeJoin %q: %v", rel, err)
		}
		if _, _, err := l.Open(rel); !errors.Is(err, ErrInvalid) {
			t.Errorf("Open %q: %v", rel, err)
		}
		if err := l.Remove(rel); !errors.Is(err, ErrInvalid) {
			t.Errorf("Remove %q: %v", rel, err)
		}
	}
	if _, err := Render(template.Must(template.New("").Parse("../x")), Vars{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("Render: %v", err)
	}
}

func TestWalkCollectsErrors(t *testing.T) {
	l := Local{Base: t.TempDir()}
	src := srcFile(t, t.TempDir(), "hello")
	for _, rel := range []string{"a", "b", "c"} {
		if _, err := l.Put(src, rel, sidecar(rel)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(l.SidecarPath("b"), []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	err := l.Walk(func(rel string, sc Sidecar) error {
		got = append(got, rel)
		return nil
	})
	if err == nil || len(got) != 2 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestSweep(t *testing.T) {
	l := Local{Base: t.TempDir()}
	src := srcFile(t, t.TempDir(), "hello")
	if _, err := l.Put(src, "keep/x", sidecar("1")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(src, "gone", sidecar("2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(l.Base, DataDir, "gone")); err != nil {
		t.Fatal(err)
	}
	write := func(rel string) {
		p := filepath.Join(l.Base, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Dot names in the data tree are stored names: without a sidecar
	// they are orphans, never temporary files.
	for _, rel := range []string{"file/orphan", "file/d/young", "file/.luk-tmp-a", ".db/tmp/a", ".db/tmp/b", ".db/meta/d/not-a-sidecar"} {
		write(rel)
	}
	t0 := time.Now()
	old := t0.Add(-2 * time.Hour)
	for _, rel := range []string{"file/orphan", "file/.luk-tmp-a", ".db/tmp/a", ".db/meta/d/not-a-sidecar", ".db/meta/gone.json", "file/keep/x", ".db/meta/keep/x.json"} {
		if err := os.Chtimes(filepath.Join(l.Base, rel), old, old); err != nil {
			t.Fatal(err)
		}
	}
	sw, err := l.Sweep(time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(sw.Removed)
	want := []string{".db/meta/gone.json", ".db/tmp/a"}
	if fmt.Sprint(sw.Removed) != fmt.Sprint(want) {
		t.Fatalf("removed %v, want %v", sw.Removed, want)
	}
	sort.Strings(sw.Orphans)
	if fmt.Sprint(sw.Orphans) != "[.luk-tmp-a orphan]" {
		t.Fatalf("orphans %v", sw.Orphans)
	}
	for _, rel := range []string{"file/keep/x", ".db/meta/keep/x.json", "file/d/young", "file/orphan", "file/.luk-tmp-a", ".db/tmp/b", ".db/meta/d/not-a-sidecar"} {
		if _, err := os.Lstat(filepath.Join(l.Base, rel)); err != nil {
			t.Errorf("%s: %v", rel, err)
		}
	}
}

func TestClaim(t *testing.T) {
	base := t.TempDir()
	l := Local{Base: base}
	if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "a/x", sidecar("id1")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Claim("a/x", "other", nil); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("wrong id: %v", err)
	}
	c, err := l.Claim("a/x", "id1", nil)
	if err != nil {
		t.Fatal(err)
	}
	dir, name := filepath.Split(filepath.FromSlash(c))
	if filepath.Clean(dir) != ClaimedDir || name == "" {
		t.Fatalf("claimed at %q", c)
	}
	if b, err := os.ReadFile(filepath.Join(base, c)); err != nil || string(b) != "hello" {
		t.Fatalf("claimed content %q %v", b, err)
	}
	for _, p := range []string{filepath.Join(base, DataDir, "a", "x"), l.SidecarPath("a/x")} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left: %v", p, err)
		}
	}
	if _, err := l.Claim("a/x", "id1", nil); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("second claim: %v", err)
	}
	if _, err := l.Claim("../x", "id1", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("escape: %v", err)
	}
	sw, err := l.Sweep(-time.Hour, time.Now())
	if err != nil || len(sw.Removed)+len(sw.Orphans) != 0 {
		t.Fatalf("sweep touched claimed: %+v %v", sw, err)
	}
}

func TestClaimConcurrent(t *testing.T) {
	l := Local{Base: t.TempDir()}
	if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "x", sidecar("id1")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := l.Claim("x", "id1", nil)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Error(err)
			}
			mu.Lock()
			if err == nil {
				won++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d claims won", won)
	}
}

func TestClaimRefreshesMtime(t *testing.T) {
	base := t.TempDir()
	l := Local{Base: base}
	src := srcFile(t, t.TempDir(), "hello")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(src, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(src, "x", sidecar("id1")); err != nil {
		t.Fatal(err)
	}
	c, err := l.Claim("x", "id1", nil)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(base, c))
	if err != nil || time.Since(fi.ModTime()) > time.Minute {
		t.Fatalf("claimed mtime %v %v", fi.ModTime(), err)
	}
}

func TestRemoveIf(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "replace"}
	if _, err := l.Put(srcFile(t, t.TempDir(), "old"), "x", sidecar("id1")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(srcFile(t, t.TempDir(), "new"), "x", sidecar("id2")); err != nil {
		t.Fatal(err)
	}
	if err := l.RemoveIf("x", "id1"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stale id: %v", err)
	}
	if got, sc := readAll(t, l, "x"); got != "new" || sc.ID != "id2" {
		t.Fatalf("%q %+v", got, sc)
	}
	if err := l.RemoveIf("x", "id2"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(l.Base, DataDir, "x"), l.SidecarPath("x")} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s still there: %v", p, err)
		}
	}
	if err := l.RemoveIf("../x", "id2"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("escape: %v", err)
	}
}

func TestPutIdempotentAfterCrash(t *testing.T) {
	fixedNow(t, 1790000000)
	l := Local{Base: t.TempDir(), Conflict: "version"}
	src := srcFile(t, t.TempDir(), "hello")
	if _, err := l.Put(srcFile(t, t.TempDir(), "older"), "x", sidecar("id0")); err != nil {
		t.Fatal(err)
	}
	got, err := l.Put(src, "a/x", sidecar("id1"))
	if err != nil || got != "a/x" {
		t.Fatalf("%q %v", got, err)
	}
	// Data placed, sidecar never renamed.
	if err := os.Remove(l.SidecarPath("a/x")); err != nil {
		t.Fatal(err)
	}
	got, err = l.Put(src, "a/x", sidecar("id1"))
	if err != nil || got != "a/x" {
		t.Fatalf("retry: %q %v", got, err)
	}
	if c, sc := readAll(t, l, "a/x"); c != "hello" || sc.ID != "id1" {
		t.Fatalf("%q %+v", c, sc)
	}
	// Both placed: a retry by copy recognises the sidecar id.
	old := link
	link = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EXDEV} }
	t.Cleanup(func() { link = old })
	got, err = l.Put(srcFile(t, t.TempDir(), "hello"), "a/x", sidecar("id1"))
	if err != nil || got != "a/x" {
		t.Fatalf("copy retry: %q %v", got, err)
	}
	if e := dirNames(t, filepath.Join(l.Base, DataDir, "a")); len(e) != 1 {
		t.Fatalf("versions %v", e)
	}
	// Another upload still gets a version.
	got, err = l.Put(srcFile(t, t.TempDir(), "other"), "a/x", sidecar("id2"))
	if err != nil || got != "a/x" {
		t.Fatalf("other: %q %v", got, err)
	}
	if c, sc := readAll(t, l, "a/x."+recvTS); c != "hello" || sc.ID != "id1" {
		t.Fatalf("version %q %+v", c, sc)
	}
}

func dirNames(t *testing.T, dir string) []string {
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

func TestSidecarMeta(t *testing.T) {
	l := Local{Base: t.TempDir()}
	src := srcFile(t, t.TempDir(), "hello")
	sc := sidecar("m1")
	sc.Meta = []byte(`{"kind": "dump", "n": 2}`)
	got, err := l.Put(src, "m.txt", sc)
	if err != nil {
		t.Fatal(err)
	}
	_, rsc := readAll(t, l, got)
	if string(rsc.Meta) != `{"kind":"dump","n":2}` {
		t.Fatalf("meta %s", rsc.Meta)
	}
	plain, err := l.Put(src, "p.txt", sidecar("p1"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(l.SidecarPath(plain))
	if err != nil || strings.Contains(string(b), `"meta"`) {
		t.Fatalf("sidecar without meta: %s %v", b, err)
	}
	old := `{"id":"o1","sender":"s","endpoint":"e","received":"","size":5,"sha256":"","client":{"portal":"direct"}}`
	if err := os.WriteFile(l.SidecarPath(plain), []byte(old), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, rsc := readAll(t, l, plain); rsc.ID != "o1" || rsc.Meta != nil {
		t.Fatalf("old sidecar %+v", rsc)
	}
}

func TestPutSameIDOtherContentVersions(t *testing.T) {
	fixedNow(t, 1790000000)
	l := Local{Base: t.TempDir()}
	a, b := sidecar("id1"), sidecar("id1")
	a.SHA256, b.SHA256 = "aa", "bb"
	if got, err := l.Put(srcFile(t, t.TempDir(), "one"), "x", a); err != nil || got != "x" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := l.Put(srcFile(t, t.TempDir(), "two"), "x", b); err != nil || got != "x" {
		t.Fatalf("second file of the upload: %q %v", got, err)
	}
	if got, err := l.Put(srcFile(t, t.TempDir(), "one"), "x", a); err != nil || got != "x."+recvTS {
		t.Fatalf("retry: %q %v", got, err)
	}
}

func TestPutRefusesNonRegularSource(t *testing.T) {
	l := Local{Base: t.TempDir()}
	dir := t.TempDir()
	target := srcFile(t, dir, "hello")
	lnk := filepath.Join(dir, "lnk")
	if err := os.Symlink(target, lnk); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(lnk, "x", sidecar("s1")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink source by link: %v", err)
	}
	old := link
	link = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EXDEV} }
	t.Cleanup(func() { link = old })
	if _, err := l.Put(lnk, "y", sidecar("s2")); err == nil {
		t.Fatal("symlink source by copy accepted")
	}
	if e := dirNames(t, filepath.Join(l.Base, tmpDir)); len(e) != 0 {
		t.Fatalf("leftovers %v", e)
	}
	if _, err := os.Lstat(filepath.Join(l.Base, DataDir)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("data tree: %v", err)
	}
}

func TestPutProducedInIdempotencyKey(t *testing.T) {
	fixedNow(t, 1790000000)
	l := Local{Base: t.TempDir()}
	a, b := sidecar("id1"), sidecar("id1")
	a.Produced, b.Produced = "a.txt", "b.txt"
	if got, err := l.Put(srcFile(t, t.TempDir(), "same"), "x", a); err != nil || got != "x" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := l.Put(srcFile(t, t.TempDir(), "same"), "x", b); err != nil || got != "x" {
		t.Fatalf("other produced file, same content: %q %v", got, err)
	}
	if got, err := l.Put(srcFile(t, t.TempDir(), "same"), "x", a); err != nil || got != "x."+recvTS {
		t.Fatalf("retry: %q %v", got, err)
	}
	if _, sc := readAll(t, l, "x."+recvTS); sc.Produced != "a.txt" {
		t.Fatalf("sidecar %+v", sc)
	}
}

func realSidecar(id, content string) Sidecar {
	sc := sidecar(id)
	sc.SHA256, sc.Size = shaOf(content), int64(len(content))
	return sc
}

func noLink(t *testing.T) {
	t.Helper()
	old := link
	link = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EXDEV} }
	t.Cleanup(func() { link = old })
}

func TestPutResumeCopyWithoutSidecar(t *testing.T) {
	fixedNow(t, 1790000000)
	noLink(t)
	l := Local{Base: t.TempDir()}
	sc := realSidecar("id1", "hello")
	if got, err := l.Put(srcFile(t, t.TempDir(), "hello"), "x", sc); err != nil || got != "x" {
		t.Fatalf("%q %v", got, err)
	}
	if err := os.Remove(l.SidecarPath("x")); err != nil {
		t.Fatal(err)
	}
	if got, err := l.Put(srcFile(t, t.TempDir(), "hello"), "x", sc); err != nil || got != "x" {
		t.Fatalf("retry: %q %v", got, err)
	}
	if c, rsc := readAll(t, l, "x"); c != "hello" || rsc.ID != "id1" {
		t.Fatalf("%q %+v", c, rsc)
	}
	if e := dirNames(t, filepath.Join(l.Base, DataDir)); fmt.Sprint(e) != "[x]" {
		t.Fatalf("names %v", e)
	}
	if e := dirNames(t, filepath.Join(l.Base, tmpDir)); len(e) != 0 {
		t.Fatalf("leftovers %v", e)
	}
	if err := os.Remove(l.SidecarPath("x")); err != nil {
		t.Fatal(err)
	}
	if got, err := l.Put(srcFile(t, t.TempDir(), "hellO"), "x", realSidecar("id2", "hellO")); err != nil || got != "x" {
		t.Fatalf("same size, other content: %q %v", got, err)
	}
}

func TestPutResumeFindsVersion(t *testing.T) {
	l := Local{Base: t.TempDir()}
	put := func(content, id string) string {
		t.Helper()
		got, err := l.Put(srcFile(t, t.TempDir(), content), "d/x", realSidecar(id, content))
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	put("one", "id0")
	put("two", "id1")
	if got := put("three", "id2"); got != "d/x" {
		t.Fatal(got)
	}
	if got := put("two", "id1"); got != "d/x."+recvTS+".000001" {
		t.Fatalf("retry of a version: %s", got)
	}
	if got := put("one", "id0"); got != "d/x."+recvTS {
		t.Fatalf("retry of the first version: %s", got)
	}
	if got := put("three", "id2"); got != "d/x" {
		t.Fatalf("retry of the newest: %s", got)
	}
	if e := dirNames(t, filepath.Join(l.Base, DataDir, "d")); len(e) != 3 {
		t.Fatalf("versions %v", e)
	}
	if got := put("four", "id3"); got != "d/x" {
		t.Fatalf("new upload: %s", got)
	}
	if c, sc := readAll(t, l, "d/x."+recvTS+".000002"); c != "three" || sc.ID != "id2" {
		t.Fatalf("%q %+v", c, sc)
	}
}

func TestSlowStagingDoesNotBlockDownloads(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPut(t, l, "x", "one", 1, "")
	noLink(t)
	entered, release := make(chan struct{}), make(chan struct{})
	old := hookCopy
	hookCopy = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { hookCopy = old })
	done := make(chan error, 1)
	go func() {
		_, err := l.Put(srcFile(t, t.TempDir(), "slow"), "y", realSidecar("id-y", "slow"))
		done <- err
	}()
	<-entered
	ok := make(chan error, 1)
	go func() {
		f, sc, err := l.Open("x")
		if err == nil {
			var b []byte
			b, err = io.ReadAll(f)
			f.Close()
			if err == nil && (string(b) != "one" || sc.ID != "id-one") {
				err = fmt.Errorf("%q %+v", b, sc)
			}
		}
		if err == nil {
			_, err = l.Sweep(0, time.Now().Add(time.Hour))
		}
		ok <- err
	}()
	select {
	case err := <-ok:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("download waited for the staging copy")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("put after sweep: %v", err)
	}
	if got, sc := readAll(t, l, "y"); got != "slow" || sc.ID != "id-y" {
		t.Fatalf("%q %+v", got, sc)
	}
}

func dedupSidecar(id, content string) Sidecar {
	sc := sidecar(id)
	sum := sha256.Sum256([]byte(content))
	sc.Size, sc.SHA256 = int64(len(content)), hex.EncodeToString(sum[:])
	return sc
}

func TestPutDedup(t *testing.T) {
	fixedNow(t, 1790000000)
	d := t.TempDir()
	store := func(l Local, rel, content, id string) Stored {
		t.Helper()
		res, err := l.Store(srcFile(t, d, content), rel, dedupSidecar(id, content))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	names := func(l Local) []string {
		var out []string
		if err := l.Walk(func(rel string, _ Sidecar) error { out = append(out, rel); return nil }); err != nil {
			t.Fatal(err)
		}
		sort.Strings(out)
		return out
	}

	l := Local{Base: t.TempDir(), Conflict: "version", Dedup: true}
	if res := store(l, "x", "same", "1"); !reflect.DeepEqual(res, Stored{Rel: "x"}) {
		t.Fatalf("first %+v", res)
	}
	if res := store(l, "x", "same", "2"); !reflect.DeepEqual(res, Stored{Rel: "x", Dedup: true}) {
		t.Fatalf("second %+v", res)
	}
	if got := names(l); strings.Join(got, ",") != "x" {
		t.Fatalf("files %v", got)
	}
	if _, sc := readAll(t, l, "x"); sc.ID != "1" {
		t.Fatalf("sidecar changed: %+v", sc)
	}

	// A, B, A: only the newest version is compared.
	l = Local{Base: t.TempDir(), Conflict: "version", Dedup: true}
	store(l, "x", "aaaa", "1")
	if res := store(l, "x", "bbbb", "2"); res.Dedup || res.Rel != "x" {
		t.Fatalf("B %+v", res)
	}
	if res := store(l, "x", "aaaa", "3"); res.Dedup || res.Rel != "x" {
		t.Fatalf("third A %+v", res)
	}
	if res := store(l, "x", "aaaa", "4"); !res.Dedup || res.Rel != "x" {
		t.Fatalf("fourth A %+v", res)
	}
	if got := names(l); len(got) != 3 {
		t.Fatalf("files %v", got)
	}

	// Same name, different size: a version.
	l = Local{Base: t.TempDir(), Conflict: "version", Dedup: true}
	store(l, "x", "aaaa", "1")
	if res := store(l, "x", "aaaaa", "2"); res.Dedup || res.Rel != "x" {
		t.Fatalf("other size %+v", res)
	}

	// Dedup off: a version.
	l = Local{Base: t.TempDir(), Conflict: "version"}
	store(l, "x", "aaaa", "1")
	if res := store(l, "x", "aaaa", "2"); res.Dedup || res.Rel != "x" {
		t.Fatalf("dedup off %+v", res)
	}

	// Sharded.
	l = Local{Base: t.TempDir(), Conflict: "version", Dedup: true, Shard: 2}
	store(l, "d/x", "aaaa", "1")
	store(l, "d/x", "bbbb", "2")
	if res := store(l, "d/x", "bbbb", "3"); !res.Dedup || res.Rel != "d/x" {
		t.Fatalf("sharded %+v", res)
	}
	if got := names(l); len(got) != 2 {
		t.Fatalf("sharded files %v", got)
	}

	// Once uploads are never shared.
	l = Local{Base: t.TempDir(), Conflict: "version", Dedup: true}
	store(l, "x", "aaaa", "1")
	sc := dedupSidecar("2", "aaaa")
	sc.Client.Once = true
	if res, err := l.Store(srcFile(t, d, "aaaa"), "x", sc); err != nil || res.Dedup {
		t.Fatalf("once %+v %v", res, err)
	}
}

// putAt stores content at rel with a real sidecar received at unix second
// sec; the id is the content.
func putAt(t *testing.T, l Local, rel, content string, sec int64) (Stored, error) {
	t.Helper()
	sc := realSidecar(fmt.Sprint(content, "@", sec), content)
	sc.Received = time.Unix(sec, 0).UTC().Format(time.RFC3339)
	return l.Store(srcFile(t, t.TempDir(), content), rel, sc)
}

func mustPutAt(t *testing.T, l Local, rel, content string, sec int64) Stored {
	t.Helper()
	res, err := putAt(t, l, rel, content, sec)
	if err != nil {
		t.Fatalf("put %s %q: %v", rel, content, err)
	}
	return res
}

func storedNames(t *testing.T, l Local) []string {
	t.Helper()
	var out []string
	if err := l.Walk(func(rel string, _ Sidecar) error { out = append(out, rel); return nil }); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func checkBody(t *testing.T, l Local, rel, content string) {
	t.Helper()
	got, sc := readAll(t, l, rel)
	if got != content || !strings.HasPrefix(sc.ID, content+"@") || sc.SHA256 != shaOf(content) {
		t.Fatalf("%s: %q %+v, want %q", rel, got, sc, content)
	}
}

func TestVersionRotation(t *testing.T) {
	for _, shard := range []int{0, 2} {
		t.Run(fmt.Sprint("shard", shard), func(t *testing.T) {
			l := Local{Base: t.TempDir(), Conflict: "version", Shard: shard}
			if res := mustPutAt(t, l, "d/abc", "v1", 1000); !reflect.DeepEqual(res, Stored{Rel: "d/abc"}) {
				t.Fatalf("v1 %+v", res)
			}
			before, err := os.ReadFile(l.SidecarPath("d/abc"))
			if err != nil {
				t.Fatal(err)
			}
			if res := mustPutAt(t, l, "d/abc", "v2", 2000); !reflect.DeepEqual(res, Stored{Rel: "d/abc"}) {
				t.Fatalf("v2 %+v", res)
			}
			checkBody(t, l, "d/abc", "v2")
			checkBody(t, l, "d/abc.1000", "v1")
			if after, err := os.ReadFile(l.SidecarPath("d/abc.1000")); err != nil || string(after) != string(before) {
				t.Fatalf("versioned sidecar %s %v, want %s", after, err, before)
			}
			mustPutAt(t, l, "d/abc", "v3", 3000)
			checkBody(t, l, "d/abc", "v3")
			checkBody(t, l, "d/abc.1000", "v1")
			checkBody(t, l, "d/abc.2000", "v2")
			if got := storedNames(t, l); fmt.Sprint(got) != "[d/abc d/abc.1000 d/abc.2000]" {
				t.Fatalf("names %v", got)
			}
			if shard > 0 {
				for _, rel := range []string{"d/abc", "d/abc.1000", "d/abc.2000"} {
					mustExist(t, filepath.Join(l.Base, DataDir, physOf(rel, shard)))
				}
			}
		})
	}
}

func TestVersionRotationSameSecond(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPutAt(t, l, "abc", "v1", 1000)
	mustPutAt(t, l, "abc", "v2", 1000)
	mustPutAt(t, l, "abc", "v3", 1000)
	checkBody(t, l, "abc", "v3")
	checkBody(t, l, "abc.1000", "v1")
	checkBody(t, l, "abc.1000.000001", "v2")
}

func TestVersionRotationMtimeFallback(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPutAt(t, l, "abc", "v1", 1000)
	if err := os.Remove(l.SidecarPath("abc")); err != nil {
		t.Fatal(err)
	}
	mt := time.Unix(1500, 0)
	if err := os.Chtimes(filepath.Join(l.Base, DataDir, "abc"), mt, mt); err != nil {
		t.Fatal(err)
	}
	mustPutAt(t, l, "abc", "v2", 2000)
	checkBody(t, l, "abc", "v2")
	if b, err := os.ReadFile(filepath.Join(l.Base, DataDir, "abc.1500")); err != nil || string(b) != "v1" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestVersionRotationDedup(t *testing.T) {
	l := Local{Base: t.TempDir(), Dedup: true}
	mustPutAt(t, l, "abc", "A", 1000)
	if res := mustPutAt(t, l, "abc", "A", 2000); !reflect.DeepEqual(res, Stored{Rel: "abc", Dedup: true}) {
		t.Fatalf("identical %+v", res)
	}
	if got := storedNames(t, l); fmt.Sprint(got) != "[abc]" {
		t.Fatalf("names %v", got)
	}
	mustPutAt(t, l, "abc", "B", 3000)
	if res := mustPutAt(t, l, "abc", "A", 4000); !reflect.DeepEqual(res, Stored{Rel: "abc"}) {
		t.Fatalf("A after B %+v", res)
	}
	checkBody(t, l, "abc", "A")
	checkBody(t, l, "abc.1000", "A")
	checkBody(t, l, "abc.3000", "B")
	if got := storedNames(t, l); len(got) != 3 {
		t.Fatalf("names %v", got)
	}
}

func crashAt(t *testing.T, at int) {
	t.Helper()
	old := hookRotate
	hookRotate = func(step int) {
		if step == at {
			panic("crash")
		}
	}
	t.Cleanup(func() { hookRotate = old })
}

func TestVersionRotationCrash(t *testing.T) {
	for _, shard := range []int{0, 1} {
		for _, step := range []int{1, 2} {
			t.Run(fmt.Sprint("shard", shard, "step", step), func(t *testing.T) {
				l := Local{Base: t.TempDir(), Shard: shard}
				mustPutAt(t, l, "abc", "v1", 1000)
				mustPutAt(t, l, "abc", "v2", 2000)
				func() {
					crashAt(t, step)
					defer func() {
						if recover() == nil {
							t.Fatal("no crash")
						}
					}()
					putAt(t, l, "abc", "v3", 3000)
				}()
				hookRotate = func(int) {}
				if step == 1 {
					// Also a crash between the version's data and sidecar.
					if err := os.Remove(l.SidecarPath("abc.2000")); err != nil {
						t.Fatal(err)
					}
				}
				if res := mustPutAt(t, l, "abc", "v3", 3000); !reflect.DeepEqual(res, Stored{Rel: "abc"}) {
					t.Fatalf("retry %+v", res)
				}
				checkBody(t, l, "abc", "v3")
				checkBody(t, l, "abc.1000", "v1")
				checkBody(t, l, "abc.2000", "v2")
				if got := storedNames(t, l); fmt.Sprint(got) != "[abc abc.1000 abc.2000]" {
					t.Fatalf("names %v", got)
				}
				if res := mustPutAt(t, l, "abc", "v3", 3000); !reflect.DeepEqual(res, Stored{Rel: "abc"}) {
					t.Fatalf("second retry %+v", res)
				}
				if got := storedNames(t, l); len(got) != 3 {
					t.Fatalf("names %v", got)
				}
			})
		}
	}
}

func TestVersionRotationSidecarFailureRestores(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPutAt(t, l, "d/abc", "v1", 1000)
	old := hookRotate
	hookRotate = func(step int) {
		if step == 2 {
			os.Chmod(filepath.Dir(l.SidecarPath("d/abc")), 0o500)
		}
	}
	t.Cleanup(func() {
		hookRotate = old
		os.Chmod(filepath.Dir(l.SidecarPath("d/abc")), 0o700)
	})
	if _, err := putAt(t, l, "d/abc", "v2", 2000); err == nil {
		t.Skip("directory permissions not enforced (root?)")
	}
	os.Chmod(filepath.Dir(l.SidecarPath("d/abc")), 0o700)
	checkBody(t, l, "d/abc", "v1")
	if got := storedNames(t, l); fmt.Sprint(got) != "[d/abc]" {
		t.Fatalf("names %v", got)
	}
}

func TestVersionRotationAlias(t *testing.T) {
	at := func(m int) string {
		return strconv.FormatInt(time.Date(2026, 9, 30, 10, m, 0, 0, time.UTC).Unix(), 10)
	}
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "abc", "one", 1, "cur")
	mustPut(t, l, "abc", "two", 2, "cur")
	checkAlias(t, l, "cur", "abc", "two")
	mustPut(t, l, "abc", "three", 3, "")
	checkAlias(t, l, "cur", "abc."+at(2), "two")
	if c := readCatalog(t, l); fmt.Sprint(catalogNames(c)) != fmt.Sprint([]string{"abc", "abc." + at(1), "abc." + at(2)}) {
		t.Fatalf("catalog %v", catalogNames(c))
	}
	mustPut(t, l, "abc", "four", 4, "cur")
	checkAlias(t, l, "cur", "abc", "four")
	// An older upload does not take the alias from a newer version.
	l = Local{Base: t.TempDir()}
	mustPut(t, l, "abc", "new", 5, "cur")
	mustPut(t, l, "abc", "old", 4, "cur")
	checkAlias(t, l, "cur", "abc."+at(5), "new")
}

func TestVersionRotationConcurrentOpenClaim(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPutAt(t, l, "abc", "v0", 1000)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	errc := make(chan error, 8)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				f, sc, err := l.Open("abc")
				if err != nil {
					continue
				}
				b, _ := io.ReadAll(f)
				fi, _ := f.Stat()
				f.Close()
				if shaOf(string(b)) != sc.SHA256 || !strings.HasPrefix(sc.ID, string(b)+"@") {
					errc <- fmt.Errorf("open: %q with %+v", b, sc)
					return
				}
				if len(b)%3 == 0 {
					if claimed, err := l.Claim("abc", sc.ID, fi); err == nil {
						c, _ := os.ReadFile(filepath.Join(l.Base, claimed))
						if string(c) != string(b) {
							errc <- fmt.Errorf("claimed %q, opened %q", c, b)
							return
						}
					}
				}
			}
		}()
	}
	for i := 1; i <= 60; i++ {
		if _, err := putAt(t, l, "abc", fmt.Sprint("content-", i), int64(1000+i)); err != nil {
			t.Error(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-errc:
		t.Fatal(err)
	default:
	}
}

func TestProquint(t *testing.T) {
	for in, want := range map[string]string{
		"\x7f\x00\x00\x01": "lusab-babad",
		"\x3f\x54\xdc\xc1": "gutih-tugad",
		"\xd4\x3a\xfd\x44": "tibup-zujah",
		"\x0c\x6e\x6e\xcc": "budov-kuras",
		"\x00\x00":         "babab",
		"\xff\xff":         "zuzuz",
	} {
		if got := Proquint([]byte(in)); got != want {
			t.Errorf("% x: %q, want %q", in, got, want)
		}
	}
}

func TestPrettyName(t *testing.T) {
	for bits, groups := range map[int]int{64: 4, 80: 5, 128: 8} {
		re := regexp.MustCompile(`^[bdfghjklmnprstvz][aiou][bdfghjklmnprstvz][aiou][bdfghjklmnprstvz](-[bdfghjklmnprstvz][aiou][bdfghjklmnprstvz][aiou][bdfghjklmnprstvz]){` + strconv.Itoa(groups-1) + `}$`)
		a, b := PrettyName(bits), PrettyName(bits)
		if !re.MatchString(a) || a == b {
			t.Errorf("%d bits: %q %q", bits, a, b)
		}
	}
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
}
