package store

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdate(t *testing.T) {
	l := Local{Base: t.TempDir(), Shard: 1}
	if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "f", sidecar("id")); err != nil {
		t.Fatal(err)
	}
	sc, err := l.Update("f", "id", func(sc *Sidecar) error {
		sc.Expires = "2026-12-01T00:00:00Z"
		sc.ID = "other"
		return nil
	})
	if err != nil || sc.Expires != "2026-12-01T00:00:00Z" || sc.ID != "id" {
		t.Fatalf("%+v %v", sc, err)
	}
	f, got, err := l.Open("f")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got.Expires != sc.Expires || got.ID != "id" || got.Sender != "alice" {
		t.Fatalf("stored %+v", got)
	}
	if _, err := l.Update("f", "wrong", func(*Sidecar) error { return nil }); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("wrong id: %v", err)
	}
	if _, err := l.Update("nope", "id", func(*Sidecar) error { return nil }); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	boom := errors.New("boom")
	if _, err := l.Update("f", "id", func(sc *Sidecar) error { sc.Expires = ""; return boom }); err != boom {
		t.Fatalf("fn error: %v", err)
	}
	if _, got, _ = l.Open("f"); got.Expires != sc.Expires {
		t.Fatal("a failed update changed the sidecar")
	}
}

func TestRemoveExpired(t *testing.T) {
	l := Local{Base: t.TempDir()}
	sc := sidecar("id")
	sc.Expires = "2026-10-01T00:00:00Z"
	if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "f", sc); err != nil {
		t.Fatal(err)
	}
	if err := l.RemoveExpired("f", "id", "2026-09-01T00:00:00Z"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("other expiry removed: %v", err)
	}
	mustExist(t, filepath.Join(l.Base, DataDir, "f"))
	if err := l.RemoveExpired("f", "id", sc.Expires); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, filepath.Join(l.Base, DataDir, "f"))
}

func TestReplace(t *testing.T) {
	for _, shard := range []int{0, 2} {
		l := Local{Base: t.TempDir(), Shard: shard, Catalog: true}
		if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "d/f", sidecar("id")); err != nil {
			t.Fatal(err)
		}
		err := l.Replace(srcFile(t, t.TempDir(), "new content"), "d/f", "id", func(sc *Sidecar) error {
			sc.Size, sc.SHA256, sc.Updated = 11, "11", "2026-10-02T00:00:00Z"
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		f, sc, err := l.Open("d/f")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(f)
		f.Close()
		if string(b) != "new content" || sc.ID != "id" || sc.Size != 11 || sc.Updated == "" || sc.Sender != "alice" {
			t.Fatalf("shard %d: %q %+v", shard, b, sc)
		}
		cat, err := l.OpenCatalog()
		if err != nil {
			t.Fatal(err)
		}
		var c struct{ Files []struct{ Size int64 } }
		err = json.NewDecoder(cat).Decode(&c)
		cat.Close()
		if err != nil || len(c.Files) != 1 || c.Files[0].Size != 11 {
			t.Fatalf("catalog %+v %v", c, err)
		}
		// A failure before the data is placed keeps the old content.
		boom := errors.New("boom")
		if err := l.Replace(srcFile(t, t.TempDir(), "third"), "d/f", "id", func(*Sidecar) error { return boom }); err != boom {
			t.Fatalf("fn error: %v", err)
		}
		if err := l.Replace(srcFile(t, t.TempDir(), "third"), "d/f", "other", func(*Sidecar) error { return nil }); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("wrong id: %v", err)
		}
		f, _, _ = l.Open("d/f")
		b, _ = io.ReadAll(f)
		f.Close()
		if string(b) != "new content" {
			t.Fatalf("after failures: %q", b)
		}
		if sw, err := l.Sweep(-1, now()); err != nil || len(sw.Removed) != 0 || len(sw.Orphans) != 0 {
			t.Fatalf("leftovers %+v %v", sw, err)
		}
	}
}

func TestReplaceAlias(t *testing.T) {
	l := Local{Base: t.TempDir()}
	sc := sidecar("id")
	sc.Meta = json.RawMessage(`{"alias":"latest"}`)
	if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "f", sc); err != nil {
		t.Fatal(err)
	}
	if err := l.Replace(srcFile(t, t.TempDir(), "x"), "f", "id", func(*Sidecar) error { return nil }); !errors.Is(err, ErrAliased) {
		t.Fatalf("%v", err)
	}
	if _, err := l.Update("f", "id", func(*Sidecar) error { return nil }); !errors.Is(err, ErrAliased) {
		t.Fatalf("update: %v", err)
	}
}

// A failure after the data or the sidecar was renamed puts the old ones
// back: the name keeps its old content with its old sidecar.
func TestReplaceFailureAfterRenameKeepsOld(t *testing.T) {
	for _, step := range []int{1, 2} {
		l := Local{Base: t.TempDir(), Hardlink: true}
		putOwned(t, l, "f", "old", "key:alice")
		old := hookReplace
		hookReplace = func(s int) error {
			if s == step {
				return errors.New("boom")
			}
			return nil
		}
		err := l.Replace(srcFile(t, t.TempDir(), "new"), "f", "f", func(sc *Sidecar) error {
			sc.Size, sc.SHA256 = 3, shaOf("new")
			return nil
		})
		hookReplace = old
		if err == nil {
			t.Fatalf("step %d: no error", step)
		}
		checkContent(t, l, "f", "old")
		if _, sc, err := l.Open("f"); err != nil || sc.SHA256 != shaOf("old") {
			t.Fatalf("step %d: sidecar %+v %v", step, sc, err)
		}
		if got := indexNames(t, l, "old"); len(got) != 1 {
			t.Fatalf("step %d: index %v", step, got)
		}
		if sw, err := l.Sweep(-1, now()); err != nil || len(sw.Removed) != 0 || len(sw.Orphans) != 0 {
			t.Fatalf("step %d: leftovers %+v %v", step, sw, err)
		}
	}
}

// A crash after the data rename (1) or the sidecar rename (2) of Replace,
// taken as a copy of the base at that moment, is rolled back by the next
// taker of the base lock: the name keeps its old content with its old
// sidecar, the index and the generation agree, nothing is left over.
func TestReplaceCrashRolledBack(t *testing.T) {
	for _, step := range []int{1, 2} {
		l := Local{Base: filepath.Join(t.TempDir(), "base"), Hardlink: true}
		if err := os.Mkdir(l.Base, 0o750); err != nil {
			t.Fatal(err)
		}
		putOwned(t, l, "f", "old", "key:alice")
		snap := filepath.Join(t.TempDir(), "snap")
		old := hookReplace
		hookReplace = func(s int) error {
			if s == step {
				if out, err := exec.Command("cp", "-a", l.Base, snap).CombinedOutput(); err != nil {
					t.Fatalf("%s %v", out, err)
				}
			}
			return nil
		}
		err := l.Replace(srcFile(t, t.TempDir(), "NEW"), "f", "f", func(sc *Sidecar) error {
			sc.Size, sc.SHA256 = 3, shaOf("NEW")
			return nil
		})
		hookReplace = old
		if err != nil {
			t.Fatal(err)
		}
		checkContent(t, l, "f", "NEW")
		if _, err := os.Lstat(filepath.Join(l.Base, intentName)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("step %d: record left after the replace: %v", step, err)
		}

		c := Local{Base: snap, Hardlink: true}
		if g := lockSize(t, snap); g%2 == 0 {
			t.Fatalf("step %d: generation %d of the crash is even", step, g)
		}
		checkContent(t, c, "f", "old")
		if _, err := os.Lstat(filepath.Join(snap, intentName)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("step %d: record left after the roll back: %v", step, err)
		}
		if g := lockSize(t, snap); g%2 != 0 {
			t.Fatalf("step %d: generation %d odd after the roll back", step, g)
		}
		if _, err := c.MaintainObjects(); err != nil {
			t.Fatal(err)
		}
		if got := indexNames(t, c, "old"); len(got) != 1 {
			t.Fatalf("step %d: index of old %v", step, got)
		}
		if got := indexNames(t, c, "NEW"); len(got) != 0 {
			t.Fatalf("step %d: index of NEW %v", step, got)
		}
		// Only the temporary files of the crashed process are left, for the
		// sweep of crash leftovers.
		sw, err := c.Sweep(-1, now().Add(2*time.Hour))
		if err != nil || len(sw.Orphans) != 0 {
			t.Fatalf("step %d: leftovers %+v %v", step, sw, err)
		}
		for _, p := range sw.Removed {
			if !strings.HasPrefix(p, tmpDir+"/") {
				t.Fatalf("step %d: removed %s", step, p)
			}
		}
		checkContent(t, c, "f", "old")
	}
}

// A record of a Replace that names anything but second names in the
// temporary directory and a stored name is refused, and the lock with it.
func TestReplaceRecordRefused(t *testing.T) {
	l := Local{Base: t.TempDir()}
	putOwned(t, l, "f", "old", "key:alice")
	b, _ := json.Marshal(replaceIntent{Data: DataDir + "/f", Sidecar: metaDir + "/f.json", OldData: LockName, OldSidecar: tmpDir + "/x"})
	if err := os.WriteFile(filepath.Join(l.Base, intentName), b, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := l.Remove("f"); err == nil || !strings.Contains(err.Error(), "invalid record") {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(filepath.Join(l.Base, LockName)); err != nil {
		t.Fatal(err)
	}
}

func lockSize(t *testing.T, base string) int64 {
	t.Helper()
	fi, err := os.Stat(filepath.Join(base, LockName))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// A staged copy is placed by StoreStaged or ReplaceStaged; Drop removes
// one that was not.
func TestStaged(t *testing.T) {
	l := Local{Base: t.TempDir()}
	s, err := l.Stage(srcFile(t, t.TempDir(), "hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Local{Base: t.TempDir()}).StoreStaged(s, "f", sidecar("id")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other base: %v", err)
	}
	if res, err := l.StoreStaged(s, "f", sidecar("id")); err != nil || res.Rel != "f" {
		t.Fatalf("%+v %v", res, err)
	}
	s.Drop()
	if got, _ := readAll(t, l, "f"); got != "hello" {
		t.Fatalf("stored %q", got)
	}
	s, err = l.Stage(srcFile(t, t.TempDir(), "unused"))
	if err != nil {
		t.Fatal(err)
	}
	s.Drop()
	s.Drop()
	if _, err := l.StoreStaged(s, "g", sidecar("id2")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("dropped: %v", err)
	}
	if sw, err := l.Sweep(-1, now()); err != nil || len(sw.Removed) != 0 {
		t.Fatalf("leftovers %+v %v", sw, err)
	}
}
