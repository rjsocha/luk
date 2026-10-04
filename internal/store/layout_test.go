package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestDotNames(t *testing.T) {
	for _, shard := range []int{0, 2} {
		t.Run(fmt.Sprint("shard ", shard), func(t *testing.T) {
			l := Local{Base: t.TempDir(), Catalog: true, Shard: shard, Hardlink: true}
			names := []string{".bashrc", "a/.env", ".luk", ".db/lock", "file/.db/meta", ".luk-tmp-0123456789abcdef01234567"}
			for i, rel := range names {
				mustPut(t, l, rel, "c-"+rel, i+1, "")
			}
			for _, rel := range names {
				if c, sc := readAll(t, l, rel); c != "c-"+rel || sc.ID != "id-c-"+rel {
					t.Fatalf("%s: %q %+v", rel, c, sc)
				}
				mustExist(t, filepath.Join(l.Base, filepath.FromSlash(l.phys(rel))))
			}
			var walked []string
			if err := l.Walk(func(rel string, _ Sidecar) error {
				walked = append(walked, rel)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			sort.Strings(walked)
			want := append([]string(nil), names...)
			sort.Strings(want)
			if fmt.Sprint(walked) != fmt.Sprint(want) {
				t.Fatalf("walk %v, want %v", walked, want)
			}
			if got := catalogNames(readCatalog(t, l)); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("catalog %v, want %v", got, want)
			}
			// Listings serve exposes with index, never on a sharded storage.
			if shard == 0 {
				ents, err := l.List("", func(string, Sidecar) bool { return true })
				if err != nil {
					t.Fatal(err)
				}
				var top []string
				for _, e := range ents {
					top = append(top, e.Name)
				}
				if fmt.Sprint(top) != "[.db a file .bashrc .luk .luk-tmp-0123456789abcdef01234567]" {
					t.Fatalf("list %v", top)
				}
				if ents, err := l.List("a/", func(string, Sidecar) bool { return true }); err != nil || len(ents) != 1 || ents[0].Name != ".env" {
					t.Fatalf("list a/: %+v %v", ents, err)
				}
			}
			old := time.Now().Add(24 * time.Hour)
			sw, err := l.Sweep(time.Hour, old)
			if err != nil || len(sw.Removed)+len(sw.Orphans)+len(sw.Dirs) != 0 {
				t.Fatalf("sweep %+v %v", sw, err)
			}
			if _, err := l.MaintainObjects(); err != nil {
				t.Fatal(err)
			}
			for _, rel := range names {
				if err := l.Remove(rel); err != nil {
					t.Fatalf("remove %s: %v", rel, err)
				}
			}
			if e := dirNames(t, filepath.Join(l.Base, DataDir)); len(e) != 0 {
				t.Fatalf("data tree left %v", e)
			}
		})
	}
}

func TestDotAlias(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "d/one", "one", 1, ".latest")
	checkAlias(t, l, ".latest", "d/one", "one")
	if c := readCatalog(t, l); c.Latest[".latest"] != "d/one" {
		t.Fatalf("latest %v", c.Latest)
	}
}

func TestLayoutTrees(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true, Hardlink: true}
	mustPut(t, l, "x", "x", 1, "")
	if _, err := l.Claim("x", "id-x", nil); err != nil {
		t.Fatal(err)
	}
	mustPut(t, l, "y", "y", 2, "")
	if e := dirNames(t, l.Base); fmt.Sprint(e) != "[.db file]" {
		t.Fatalf("base %v", e)
	}
	if e := dirNames(t, filepath.Join(l.Base, DBDir)); fmt.Sprint(e) != "[catalog.json claimed lock meta objects tmp]" {
		t.Fatalf(".db %v", e)
	}
	if e := dirNames(t, filepath.Join(l.Base, DataDir)); fmt.Sprint(e) != "[y]" {
		t.Fatalf("file %v", e)
	}
}

func TestCheckLayout(t *testing.T) {
	if err := CheckLayout(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	if err := CheckLayout(base); err != nil {
		t.Fatalf("empty base: %v", err)
	}
	mustPut(t, Local{Base: base}, "x", "x", 1, "")
	if err := CheckLayout(base); err != nil {
		t.Fatalf("base in use: %v", err)
	}
	old := t.TempDir()
	for _, p := range []string{".luk/x.json", ".luk-lock", "x"} {
		mkdirAll(t, filepath.Dir(filepath.Join(old, p)))
		if err := os.WriteFile(filepath.Join(old, p), nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	err := CheckLayout(old)
	if err == nil || !strings.Contains(err.Error(), ".luk, .luk-lock, x besides .db/ and file/") || !strings.Contains(err.Error(), "empty it") {
		t.Fatalf("old layout: %v", err)
	}
	odd := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(odd, DataDir)); err != nil {
		t.Fatal(err)
	}
	if err := CheckLayout(odd); err == nil || !strings.Contains(err.Error(), "file is not a directory") {
		t.Fatalf("symlinked data tree: %v", err)
	}
	if err := os.Remove(filepath.Join(odd, DataDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(odd, DBDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := (Local{Base: odd}).Put(srcFile(t, t.TempDir(), "x"), "x", sidecar("1")); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("put through a symlinked .db: %v", err)
	}
}
