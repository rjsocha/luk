package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"luk/internal/tlsself"
	"luk/internal/wire"
)

// tree maps every regular file below dir to its content.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		rel, _ := filepath.Rel(dir, p)
		m[filepath.ToSlash(rel)] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// sortedLines sorts the lines of s but the last (the summary).
func sortedLines(s string) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	slices.Sort(lines[:len(lines)-1])
	return strings.Join(lines, "\n") + "\n"
}

func TestGetDirParallel(t *testing.T) {
	v := newVaultEnv(t)
	for i := range 12 {
		v.put(t, fmt.Sprintf("%d/f%02d.bin", i%3, i), strings.Repeat(fmt.Sprint(i), 1000*(i+1)), "2026-10-03T10:00:00Z")
	}
	seq, par := filepath.Join(t.TempDir(), "seq")+"/", filepath.Join(t.TempDir(), "par")+"/"
	code, seqOut, errs := runLuk(t, "get", v.url, "-k", v.key, "-o", seq)
	if code != 0 {
		t.Fatalf("sequential: exit %d %q", code, errs)
	}
	code, parOut, errs := runLuk(t, "get", v.url, "-k", v.key, "-o", par, "--parallel", "4")
	if code != 0 {
		t.Fatalf("parallel: exit %d %q", code, errs)
	}
	if s, p := tree(t, seq), tree(t, par); len(s) != 12 || !maps.Equal(s, p) {
		t.Fatalf("trees differ:\n%v\n%v", s, p)
	}
	if s, p := sortedLines(untimed(seqOut)), sortedLines(untimed(parOut)); s != p {
		t.Fatalf("outputs differ:\n%s\n%s", s, p)
	}
	// Same sha: all skipped; a changed file needs --force, as without.
	if code, out, errs := runLuk(t, "get", v.url, "-k", v.key, "-o", par, "--parallel", "4"); code != 0 || !strings.HasSuffix(untimed(out), "0 downloaded, 12 skipped, 0 B in T, R\n") {
		t.Fatalf("again: exit %d %q %q", code, out, errs)
	}
	v.put(t, "1/f04.bin", "changed", "2026-10-04T10:00:00Z")
	code, out, errs := runLuk(t, "get", v.url, "-k", v.key, "-o", par, "--parallel", "4")
	if code != 1 || errs != "luk: 1/f04.bin: exists and differs; pass --force to overwrite it\nluk: 1 of 12 files failed\n" ||
		!strings.HasSuffix(untimed(out), "0 downloaded, 11 skipped, 1 failed, 0 B in T, R\n") {
		t.Fatalf("changed: exit %d %q %q", code, out, errs)
	}
	if code, _, errs := runLuk(t, "get", v.url, "-k", v.key, "-o", par, "--parallel", "4", "--force"); code != 0 {
		t.Fatalf("force: exit %d %q", code, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(par, "1/f04.bin")); string(b) != "changed" {
		t.Fatalf("forced %q", b)
	}

	file := strings.Replace(v.url, "/v/#", "/v/0/f00.bin#", 1)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{file, "-o", filepath.Join(t.TempDir(), "x"), "--parallel", "2"}, "--parallel needs a directory URL"},
		{[]string{file, "-c", "--parallel", "1"}, "--parallel needs a directory URL"},
		{[]string{v.url, "--parallel", "2"}, "--force, --progress, --bwlimit and --parallel need -o DIR/"},
		{[]string{v.url, "-o", par, "--parallel", "0"}, "--parallel must be 1 to 32"},
		{[]string{v.url, "-o", par, "--parallel", "33"}, "--parallel must be 1 to 32"},
	} {
		if code, _, errs := runLuk(t, append([]string{"get", "-k", v.key}, c.args...)...); code != 1 || !strings.Contains(errs, c.want) {
			t.Errorf("%v: exit %d %q, want %q", c.args, code, errs, c.want)
		}
	}
}

func TestGetDirParallelPartialFailure(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	dest := t.TempDir()
	listing := `[{"name":"a","sha256":"` + sumOf("a") + `"},{"name":"gone"},{"name":"d/c"},{"name":"d/e"}]`
	code, out, errs := runLuk(t, "get", fakeDir(t, listing, "gone"), "-k", key, "-o", dest, "--parallel", "3")
	if code != 2 || !strings.Contains(errs, "luk: gone: ") || !strings.Contains(errs, "404") || !strings.HasSuffix(errs, "luk: 1 of 4 files failed\n") ||
		sortedLines(untimed(out)) != "get a  1 B  T\nget d/c  3 B  T\nget d/e  3 B  T\n3 downloaded, 0 skipped, 1 failed, 7 B in T, R\n" {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
	if got := tree(t, dest); !maps.Equal(got, map[string]string{"a": "a", "d/c": "d/c", "d/e": "d/e"}) {
		t.Fatalf("tree %v", got)
	}
}

// Ctrl-C ends every download in flight and starts no other.
func TestGetDirParallelInterrupted(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	var ents []wire.ListEntry
	for i := range 10 {
		ents = append(ents, wire.ListEntry{Name: fmt.Sprintf("f%d", i)})
	}
	listing, _ := json.Marshal(ents)
	var started, active atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v/" {
			w.Write(listing)
			return
		}
		started.Add(1)
		active.Add(1)
		defer active.Add(-1)
		w.Header().Set("Content-Length", "1000")
		w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(ts.Close)
	cancel := fakeInterrupt(t)
	go func() {
		for started.Load() < 4 {
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
	}()
	dest := t.TempDir()
	done := make(chan struct{})
	var code int
	var errs string
	go func() {
		code, _, errs = runLuk(t, "get", ts.URL+"/v/#"+tlsself.Pin(ts.Certificate()), "-k", key, "-o", dest, "--parallel", "4")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("not ended by Ctrl-C")
	}
	if code != 130 || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, "interrupted") {
		t.Fatalf("exit %d %q", code, errs)
	}
	if n := started.Load(); n != 4 {
		t.Fatalf("%d downloads started", n)
	}
	waitUntil(t, "server handlers ended", func() bool { return active.Load() == 0 })
	if left, _ := os.ReadDir(dest); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
}

// With several failures the exit code is that of the first in the order
// of the listing, as without --parallel, whichever ends first.
func TestGetDirParallelFirstFailure(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	listing := `[{"name":"slow404"},{"name":"bad"}]`
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v/":
			w.Write([]byte(listing))
		case "/v/slow404":
			time.Sleep(300 * time.Millisecond)
			http.NotFound(w, r)
		default:
			w.Header().Set("ETag", `"`+sumOf("other")+`"`)
			w.Write([]byte("bad"))
		}
	}))
	t.Cleanup(ts.Close)
	u := ts.URL + "/v/#" + tlsself.Pin(ts.Certificate())
	for _, args := range [][]string{nil, {"--parallel", "2"}} {
		code, _, errs := runLuk(t, append([]string{"get", u, "-k", key, "-o", t.TempDir()}, args...)...)
		if code != 2 || !strings.HasSuffix(errs, "luk: 2 of 2 files failed\n") {
			t.Errorf("%v: exit %d %q", args, code, errs)
		}
	}
}
