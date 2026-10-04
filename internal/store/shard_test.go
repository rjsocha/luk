package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// physOf is where a stored name lies on disk with n shard levels.
func physOf(rel string, n int) string {
	h := sha256.Sum256([]byte(rel))
	x := hex.EncodeToString(h[:])
	p := ""
	for i := 0; i < n; i++ {
		p += x[2*i:2*i+2] + "/"
	}
	return p + rel
}

func mustExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
}

func mustNotExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s: %v", p, err)
	}
}

func TestShardLayout(t *testing.T) {
	l := Local{Base: t.TempDir(), Shard: 2}
	for _, rel := range []string{"x", "a/b/c"} {
		got, err := l.Put(srcFile(t, t.TempDir(), "hello"), rel, sidecar("id-"+rel))
		if err != nil || got != rel {
			t.Fatalf("%s: %q %v", rel, got, err)
		}
		p := physOf(rel, 2)
		mustExist(t, filepath.Join(l.Base, DataDir, p))
		mustExist(t, filepath.Join(l.Base, metaDir, p+".json"))
		if l.SidecarPath(rel) != filepath.Join(l.Base, metaDir, p+".json") {
			t.Fatalf("sidecar path %s", l.SidecarPath(rel))
		}
		if c, sc := readAll(t, l, rel); c != "hello" || sc.ID != "id-"+rel {
			t.Fatalf("%s: %q %+v", rel, c, sc)
		}
		mustNotExist(t, filepath.Join(l.Base, DataDir, rel))
	}
	if _, _, err := l.Open(physOf("x", 2)); err == nil {
		t.Fatal("physical path opened as a name")
	}

	flat := Local{Base: t.TempDir()}
	if _, err := flat.Put(srcFile(t, t.TempDir(), "hello"), "x", sidecar("1")); err != nil {
		t.Fatal(err)
	}
	if e := dirNames(t, flat.Base); fmt.Sprint(e) != "[.db file]" {
		t.Fatalf("shard 0 layout %v", e)
	}
	if e := dirNames(t, filepath.Join(flat.Base, DataDir)); fmt.Sprint(e) != "[x]" {
		t.Fatalf("shard 0 data tree %v", e)
	}
}

func TestShardRemoveClaimWalk(t *testing.T) {
	l := Local{Base: t.TempDir(), Shard: 2}
	for _, rel := range []string{"x", "y", "d/z"} {
		if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), rel, sidecar("id-"+rel)); err != nil {
			t.Fatal(err)
		}
	}
	// Foreign files outside the shard layout are ignored.
	for _, p := range []string{"zz/qq/f", "ab/f", "top", physOf("x", 1)} {
		full := filepath.Join(l.Base, DataDir, p)
		os.MkdirAll(filepath.Dir(full), 0o750)
		if err := os.WriteFile(full, []byte("f"), 0o640); err != nil {
			t.Fatal(err)
		}
		sp := filepath.Join(l.Base, metaDir, p+".json")
		os.MkdirAll(filepath.Dir(sp), 0o750)
		b, _ := os.ReadFile(l.SidecarPath("x"))
		os.WriteFile(sp, b, 0o640)
	}
	var names []string
	if err := l.Walk(func(rel string, sc Sidecar) error {
		names = append(names, rel)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	if fmt.Sprint(names) != "[d/z x y]" {
		t.Fatalf("walk %v", names)
	}
	if err := l.Remove("x"); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, filepath.Join(l.Base, DataDir, physOf("x", 2)))
	mustNotExist(t, l.SidecarPath("x"))
	if err := l.RemoveIf("d/z", "other"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("remove if: %v", err)
	}
	if err := l.RemoveIf("d/z", "id-d/z"); err != nil {
		t.Fatal(err)
	}
	claimed, err := l.Claim("y", "id-y", nil)
	if err != nil || claimed == "" {
		t.Fatalf("claim %q %v", claimed, err)
	}
	mustNotExist(t, filepath.Join(l.Base, DataDir, physOf("y", 2)))
	mustNotExist(t, l.SidecarPath("y"))
	mustExist(t, filepath.Join(l.Base, claimed))
}

func TestShardSweep(t *testing.T) {
	l := Local{Base: t.TempDir(), Shard: 2}
	src := srcFile(t, t.TempDir(), "hello")
	for _, rel := range []string{"keep", "gone", "orphan"} {
		if _, err := l.Put(src, rel, sidecar("id-"+rel)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(l.Base, DataDir, physOf("gone", 2))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(l.SidecarPath("orphan")); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	old := t0.Add(-2 * time.Hour)
	for _, p := range []string{"file/" + physOf("keep", 2), "file/" + physOf("orphan", 2), ".db/meta/" + physOf("gone", 2) + ".json", ".db/meta/" + physOf("keep", 2) + ".json"} {
		if err := os.Chtimes(filepath.Join(l.Base, p), old, old); err != nil {
			t.Fatal(err)
		}
	}
	sw, err := l.Sweep(time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sw.Orphans) != "[orphan]" {
		t.Fatalf("orphans %v", sw.Orphans)
	}
	if want := ".db/meta/" + physOf("gone", 2) + ".json"; fmt.Sprint(sw.Removed) != "["+want+"]" {
		t.Fatalf("removed %v, want %s", sw.Removed, want)
	}
	mustExist(t, filepath.Join(l.Base, DataDir, physOf("keep", 2)))
	mustExist(t, l.SidecarPath("keep"))
}

func TestShardCatalogAndAlias(t *testing.T) {
	l := Local{Base: t.TempDir(), Shard: 2, Catalog: true}
	mustPut(t, l, "a/one", "first", 1, "cur")
	mustPut(t, l, "two", "second", 2, "cur")
	checkAlias(t, l, "cur", "two", "second")
	mustExist(t, filepath.Join(l.Base, DataDir, physOf("cur", 2)))
	mustExist(t, filepath.Join(l.Base, metaDir, physOf("cur", 2)+".json"))
	mustNotExist(t, filepath.Join(l.Base, DataDir, "cur"))
	if c := readCatalog(t, l); fmt.Sprint(catalogNames(c)) != "[a/one two]" {
		t.Fatalf("catalog %v", catalogNames(c))
	}
	if err := os.Remove(filepath.Join(l.Base, DataDir, physOf("cur", 2))); err != nil {
		t.Fatal(err)
	}
	catalogFresh.Delete(l.key())
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	checkAlias(t, l, "cur", "two", "second")
	if err := l.Remove("two"); err != nil {
		t.Fatal(err)
	}
	checkAlias(t, l, "cur", "a/one", "first")
	if claimed, err := l.Claim("cur", "id-first", nil); err != nil || claimed == "" {
		t.Fatalf("claim through alias: %q %v", claimed, err)
	}
	checkNoAlias(t, l, "cur")
	mustNotExist(t, filepath.Join(l.Base, DataDir, physOf("cur", 2)))
	if c := readCatalog(t, l); len(c.Files) != 0 {
		t.Fatalf("catalog %v", catalogNames(c))
	}
}

func TestShardVersions(t *testing.T) {
	l := Local{Base: t.TempDir(), Shard: 2}
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
	v1, v2 := "d/x."+recvTS, "d/x."+recvTS+".000001"
	for _, rel := range []string{"d/x", v1, v2} {
		mustExist(t, filepath.Join(l.Base, DataDir, physOf(rel, 2)))
		mustExist(t, l.SidecarPath(rel))
	}
	if got := put("two", "id1"); got != v2 {
		t.Fatalf("retry of a version: %s", got)
	}
	if got := put("three", "id2"); got != "d/x" {
		t.Fatalf("retry of the newest: %s", got)
	}
	if _, sc := readAll(t, l, v1); sc.ID != "id0" {
		t.Fatalf("%+v", sc)
	}
	if got := put("four", "id3"); got != "d/x" {
		t.Fatalf("new upload: %s", got)
	}
	if c, _ := readAll(t, l, "d/x"); c != "four" {
		t.Fatal(c)
	}
}

func TestShardRefusesSymlink(t *testing.T) {
	l := Local{Base: t.TempDir(), Shard: 1}
	p := physOf("x", 1)
	if err := os.MkdirAll(filepath.Join(l.Base, DataDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(l.Base, DataDir, filepath.Dir(p))); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "x", sidecar("1")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("put through a symlinked shard dir: %v", err)
	}
}
