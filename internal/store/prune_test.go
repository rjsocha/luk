package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestRemovePrunesEmptyDirs(t *testing.T) {
	l := Local{Base: t.TempDir()}
	src := srcFile(t, t.TempDir(), "hello")
	for _, rel := range []string{"a/b/c/one", "a/two"} {
		if _, err := l.Put(src, rel, sidecar("id-"+rel)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Remove("a/b/c/one"); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, filepath.Join(l.Base, DataDir, "a/b"))
	mustNotExist(t, filepath.Join(l.Base, metaDir, "a/b"))
	mustExist(t, filepath.Join(l.Base, DataDir, "a/two"))
	mustExist(t, filepath.Join(l.Base, metaDir, "a/two.json"))
	if err := l.RemoveIf("a/two", "id-a/two"); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, filepath.Join(l.Base, DataDir, "a"))
	mustNotExist(t, filepath.Join(l.Base, metaDir, "a"))
	mustExist(t, l.Base)
	mustExist(t, filepath.Join(l.Base, metaDir))
	mustExist(t, filepath.Join(l.Base, LockName))
}

func TestRemoveKeepsSymlinkedDir(t *testing.T) {
	l := Local{Base: t.TempDir()}
	src := srcFile(t, t.TempDir(), "hello")
	if _, err := l.Put(src, "a/b/f", sidecar("id")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(l.Base, DataDir, "a/link")); err != nil {
		t.Fatal(err)
	}
	if err := l.Remove("a/b/f"); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, filepath.Join(l.Base, DataDir, "a/b"))
	mustExist(t, filepath.Join(l.Base, DataDir, "a/link"))
}

func TestClaimPrunesEmptyDirs(t *testing.T) {
	l := Local{Base: t.TempDir(), Shard: 2}
	src := srcFile(t, t.TempDir(), "hello")
	if _, err := l.Put(src, "r/o", sidecar("id")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Claim("r/o", "id", nil); err != nil {
		t.Fatal(err)
	}
	top := physOf("r/o", 2)[:2]
	mustNotExist(t, filepath.Join(l.Base, DataDir, top))
	mustNotExist(t, filepath.Join(l.Base, metaDir, top))
	mustExist(t, filepath.Join(l.Base, ClaimedDir))
}

func TestFailedPutPrunesDirs(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "reject"}
	src := srcFile(t, t.TempDir(), "hello")
	if err := os.MkdirAll(filepath.Join(l.Base, metaDir, "new/dir"), 0o750); err != nil {
		t.Fatal(err)
	}
	// A directory at the sidecar path makes the sidecar rename fail.
	if err := os.Mkdir(filepath.Join(l.Base, metaDir, "new/dir/f.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.Base, metaDir, "new/dir/f.json/x"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(src, "new/dir/f", sidecar("id")); err == nil {
		t.Fatal("put succeeded")
	}
	mustNotExist(t, filepath.Join(l.Base, DataDir, "new"))
}

func TestPutConcurrentWithRemoveInSameDir(t *testing.T) {
	l := Local{Base: t.TempDir()}
	dir := t.TempDir()
	for i := range 200 {
		a, b := fmt.Sprintf("d/x%d", i), fmt.Sprintf("d/y%d", i)
		if _, err := l.Put(srcFile(t, dir, "a"), a, sidecar("id-a")); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs <- l.Remove(a)
		}()
		go func() {
			defer wg.Done()
			_, err := l.Put(srcFile(t, t.TempDir(), "b"), b, sidecar("id-b"))
			errs <- err
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("iteration %d: %v", i, err)
			}
		}
		if err := l.Remove(b); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		mustNotExist(t, filepath.Join(l.Base, DataDir, "d"))
	}
}

func TestSweepPrunesEmptyDirs(t *testing.T) {
	l := Local{Base: t.TempDir()}
	src := srcFile(t, t.TempDir(), "hello")
	if _, err := l.Put(src, "full/f", sidecar("id")); err != nil {
		t.Fatal(err)
	}
	// Dot names in the data tree are names like any other; the top of
	// each tree and the other directories of .db stay.
	for _, d := range []string{"file/e1/e2/e3", "file/full/e4", ".db/meta/e5/e6", ".db/meta/full/e7", "file/.dot/empty",
		"file/.luk-claimed", "file/x/.hidden/d", ".db/claimed", ".db/objects/ab"} {
		if err := os.MkdirAll(filepath.Join(l.Base, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(l.Base, "file/x/.hidden/d/f"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(l.Base, DataDir, "lnk/in"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(l.Base, DataDir, "lnk/in/s")); err != nil {
		t.Fatal(err)
	}
	sw, err := l.Sweep(time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(sw.Dirs)
	want := "[.db/meta/e5 .db/meta/e5/e6 .db/meta/full/e7 file/.dot file/.dot/empty file/.luk-claimed file/e1 file/e1/e2 file/e1/e2/e3 file/full/e4]"
	if fmt.Sprint(sw.Dirs) != want {
		t.Fatalf("pruned %v, want %s", sw.Dirs, want)
	}
	for _, p := range []string{"file/full/f", ".db/meta/full/f.json", ".db/meta", "file", "file/x/.hidden/d/f", "file/lnk/in/s", ".db/claimed", ".db/objects/ab"} {
		mustExist(t, filepath.Join(l.Base, p))
	}
	for _, p := range []string{"file/e1", "file/full/e4", "file/.dot", ".db/meta/e5", ".db/meta/full/e7"} {
		mustNotExist(t, filepath.Join(l.Base, p))
	}
}
