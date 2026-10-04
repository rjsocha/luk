package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// ownedSidecar is a real sidecar of content owned by owner.
func ownedSidecar(id, content, owner string) Sidecar {
	sc := realSidecar(id, content)
	sc.OwnerKey = owner
	return sc
}

// putOwned stores content at rel from a source file of its own, so only an
// object can make two names share an inode.
func putOwned(t *testing.T, l Local, rel, content, owner string) {
	t.Helper()
	src := srcFile(t, t.TempDir(), content)
	if _, err := l.Store(src, rel, ownedSidecar(rel, content, owner)); err != nil {
		t.Fatalf("store %s: %v", rel, err)
	}
	// As the queue entry goes once its pipelines ran.
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
}

func statOf(t *testing.T, p string) fs.FileInfo {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

func dataPath(l Local, rel string) string {
	return filepath.Join(l.Base, filepath.FromSlash(l.phys(rel)))
}

func objectPath(l Local, content string) string {
	return filepath.Join(l.Base, filepath.FromSlash(objectRel(shaOf(content))))
}

func sameInode(t *testing.T, a, b string) bool {
	t.Helper()
	return os.SameFile(statOf(t, a), statOf(t, b))
}

// indexNames reads the index of content; nil when there is none.
func indexNames(t *testing.T, l Local, content string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(objectPath(l, content) + ".json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var idx objectIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatal(err)
	}
	if idx.Size != int64(len(content)) {
		t.Fatalf("index size %d", idx.Size)
	}
	return idx.Names
}

func TestObjectsShareInode(t *testing.T) {
	for _, shard := range []int{0, 2} {
		t.Run(fmt.Sprint("shard", shard), func(t *testing.T) {
			l := Local{Base: t.TempDir(), Shard: shard, Hardlink: true}
			putOwned(t, l, "a", "same", "key:alice")
			putOwned(t, l, "b", "same", "key:bob")
			putOwned(t, l, "c", "other", "key:alice")
			if !sameInode(t, dataPath(l, "a"), dataPath(l, "b")) || !sameInode(t, dataPath(l, "a"), objectPath(l, "same")) {
				t.Fatal("a, b and the object are not one inode")
			}
			if sameInode(t, dataPath(l, "a"), dataPath(l, "c")) {
				t.Fatal("other content shares the inode")
			}
			if got := indexNames(t, l, "same"); len(got) != 2 || got["a"] != "key:alice" || got["b"] != "key:bob" {
				t.Fatalf("index %v", got)
			}
			if n := l.Links("a", realSidecar("a", "same")); n != 2 {
				t.Fatalf("links of a %d", n)
			}
			if n := l.Links("c", realSidecar("c", "other")); n != 1 {
				t.Fatalf("links of c %d", n)
			}
			checkContent(t, l, "b", "same")
		})
	}
}

func checkContent(t *testing.T, l Local, rel, content string) {
	t.Helper()
	got, sc := readAll(t, l, rel)
	if got != content || sc.SHA256 != shaOf(content) {
		t.Fatalf("%s: %q %+v", rel, got, sc)
	}
}

func TestObjectRemovedWithLastName(t *testing.T) {
	l := Local{Base: t.TempDir(), Hardlink: true}
	putOwned(t, l, "a", "same", "key:alice")
	putOwned(t, l, "b", "same", "key:bob")
	if err := l.Remove("a"); err != nil {
		t.Fatal(err)
	}
	checkContent(t, l, "b", "same")
	if got := indexNames(t, l, "same"); len(got) != 1 || got["b"] != "key:bob" {
		t.Fatalf("index after removing a %v", got)
	}
	if res, err := l.MaintainObjects(); err != nil || res != (Objects{}) {
		t.Fatalf("object of b removed: %+v %v", res, err)
	}
	if err := l.RemoveIf("b", "b"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(objectPath(l, "same")); err != nil {
		t.Fatalf("object gone before the maintenance: %v", err)
	}
	if indexNames(t, l, "same") != nil {
		t.Fatal("index kept without names")
	}
	if res, err := l.MaintainObjects(); err != nil || res != (Objects{Removed: 1}) {
		t.Fatalf("maintenance %+v %v", res, err)
	}
	if _, err := os.Lstat(objectPath(l, "same")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("object left: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(l.Base, ObjectsDir, shaOf("same")[:2])); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("empty directory left: %v", err)
	}
}

func TestObjectClaimKeepsOtherName(t *testing.T) {
	l := Local{Base: t.TempDir(), Hardlink: true}
	putOwned(t, l, "a", "same", "key:alice")
	putOwned(t, l, "b", "same", "key:alice")
	claimed, err := l.Claim("a", "a", statOf(t, dataPath(l, "a")))
	if err != nil {
		t.Fatal(err)
	}
	checkContent(t, l, "b", "same")
	if !sameInode(t, dataPath(l, "b"), objectPath(l, "same")) || !sameInode(t, filepath.Join(l.Base, claimed), objectPath(l, "same")) {
		t.Fatal("claim changed the inode of b")
	}
	if got := indexNames(t, l, "same"); len(got) != 1 || got["b"] != "key:alice" {
		t.Fatalf("index %v", got)
	}
	// The claimed copy still holds the object.
	if err := l.Remove("b"); err != nil {
		t.Fatal(err)
	}
	if res, err := l.MaintainObjects(); err != nil || res.Removed != 0 {
		t.Fatalf("object removed while claimed: %+v %v", res, err)
	}
	if err := os.Remove(filepath.Join(l.Base, claimed)); err != nil {
		t.Fatal(err)
	}
	if res, err := l.MaintainObjects(); err != nil || res.Removed != 1 {
		t.Fatalf("object kept after the claim: %+v %v", res, err)
	}
}

func TestObjectReplaceBreaksOneLink(t *testing.T) {
	l := Local{Base: t.TempDir(), Hardlink: true}
	putOwned(t, l, "a", "same", "key:alice")
	putOwned(t, l, "b", "same", "key:alice")
	src := srcFile(t, t.TempDir(), "newer")
	err := l.Replace(src, "a", "a", func(sc *Sidecar) error {
		sc.Size, sc.SHA256 = 5, shaOf("newer")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	checkContent(t, l, "a", "newer")
	checkContent(t, l, "b", "same")
	if sameInode(t, dataPath(l, "a"), dataPath(l, "b")) || !sameInode(t, dataPath(l, "b"), objectPath(l, "same")) {
		t.Fatal("replace changed b")
	}
	if !sameInode(t, dataPath(l, "a"), objectPath(l, "newer")) {
		t.Fatal("no object of the new content")
	}
	if got := indexNames(t, l, "same"); len(got) != 1 || got["b"] == "" {
		t.Fatalf("old index %v", got)
	}
	if got := indexNames(t, l, "newer"); len(got) != 1 || got["a"] != "key:alice" {
		t.Fatalf("new index %v", got)
	}
}

func TestObjectVersionRotation(t *testing.T) {
	fixedNow(t, 1790000000)
	l := Local{Base: t.TempDir(), Conflict: "version", Hardlink: true}
	mustPutAt(t, l, "x", "one", 1790000000)
	mustPutAt(t, l, "x", "two", 1790000100)
	mustPutAt(t, l, "y", "one", 1790000200)
	v := "x.1790000000"
	checkBody(t, l, v, "one")
	if got := indexNames(t, l, "one"); len(got) != 2 || !hasKey(got, v) || !hasKey(got, "y") {
		t.Fatalf("index of one %v", got)
	}
	if got := indexNames(t, l, "two"); len(got) != 1 || !hasKey(got, "x") {
		t.Fatalf("index of two %v", got)
	}
	if !sameInode(t, dataPath(l, v), dataPath(l, "y")) {
		t.Fatal("version and y not shared")
	}
}

func hasKey(m map[string]string, k string) bool {
	_, ok := m[k]
	return ok
}

func TestHardlinkOffKeepsSeparateFiles(t *testing.T) {
	l := Local{Base: t.TempDir()}
	putOwned(t, l, "a", "same", "key:alice")
	putOwned(t, l, "b", "same", "key:alice")
	if sameInode(t, dataPath(l, "a"), dataPath(l, "b")) {
		t.Fatal("shared without hardlink")
	}
	if _, err := os.Lstat(filepath.Join(l.Base, ObjectsDir)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("objects without hardlink: %v", err)
	}
	if _, _, ok := l.Object(shaOf("same"), 4, "key:alice"); ok {
		t.Fatal("object found without hardlink")
	}
}

func TestMaintainAdoptsExistingFiles(t *testing.T) {
	off := Local{Base: t.TempDir()}
	putOwned(t, off, "a", "same", "key:alice")
	putOwned(t, off, "b", "same", "key:bob")
	l := off
	l.Hardlink = true
	res, err := l.MaintainObjects()
	if err != nil || res != (Objects{Adopted: 1}) {
		t.Fatalf("adopt %+v %v", res, err)
	}
	if !sameInode(t, dataPath(l, "a"), objectPath(l, "same")) && !sameInode(t, dataPath(l, "b"), objectPath(l, "same")) {
		t.Fatal("object is no stored file")
	}
	if got := indexNames(t, l, "same"); len(got) != 2 || got["a"] != "key:alice" || got["b"] != "key:bob" {
		t.Fatalf("index %v", got)
	}
	if res, err := l.MaintainObjects(); err != nil || res != (Objects{}) {
		t.Fatalf("second pass %+v %v", res, err)
	}
	putOwned(t, l, "c", "same", "key:alice")
	if !sameInode(t, dataPath(l, "c"), objectPath(l, "same")) {
		t.Fatal("a new store does not use the adopted object")
	}
	// A size that does not match the sidecar is not adopted.
	putOwned(t, off, "d", "bad", "key:alice")
	if err := os.Chmod(dataPath(l, "d"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataPath(l, "d"), []byte("longer"), 0o640); err != nil {
		t.Fatal(err)
	}
	if res, err := l.MaintainObjects(); err != nil || res.Adopted != 0 {
		t.Fatalf("adopted a wrong size %+v %v", res, err)
	}
	// Without hardlink the objects go.
	putOwned(t, l, "e", "fresh", "key:alice")
	if res, err := off.MaintainObjects(); err != nil || res != (Objects{}) {
		t.Fatalf("hardlink off %+v %v", res, err)
	}
	if _, err := os.Lstat(filepath.Join(l.Base, ObjectsDir)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("objects left without hardlink: %v", err)
	}
	checkContent(t, l, "a", "same")
}

func TestMaintainRepairsIndex(t *testing.T) {
	l := Local{Base: t.TempDir(), Hardlink: true}
	putOwned(t, l, "a", "same", "key:alice")
	idx := objectPath(l, "same") + ".json"
	if err := os.WriteFile(idx, []byte(`{"size":4,"names":{"gone":"key:mallory","a":"key:alice"}}`), 0o640); err != nil {
		t.Fatal(err)
	}
	stray := objectPath(l, "stray") + ".json"
	if err := os.MkdirAll(filepath.Dir(stray), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray, []byte(`{}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := l.MaintainObjects(); err != nil {
		t.Fatal(err)
	}
	if got := indexNames(t, l, "same"); len(got) != 1 || got["a"] != "key:alice" {
		t.Fatalf("index %v", got)
	}
	if _, err := os.Lstat(stray); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s left: %v", stray, err)
	}
}

func TestObjectLookupByOwner(t *testing.T) {
	l := Local{Base: t.TempDir(), Hardlink: true}
	putOwned(t, l, "a", "same", "key:alice")
	p, fi, ok := l.Object(shaOf("same"), 4, "key:alice")
	if !ok || p != objectPath(l, "same") || !os.SameFile(fi, statOf(t, dataPath(l, "a"))) {
		t.Fatalf("owner: %q %v", p, ok)
	}
	for _, c := range []struct {
		sum   string
		size  int64
		owner string
	}{
		{shaOf("same"), 4, "key:bob"},
		{shaOf("same"), 5, "key:alice"},
		{shaOf("other"), 4, "key:alice"},
		{shaOf("same"), 4, ""},
	} {
		if _, _, ok := l.Object(c.sum, c.size, c.owner); ok {
			t.Errorf("found %+v", c)
		}
	}
}

func TestMaintainObjectsSkipsUnchangedBase(t *testing.T) {
	l := Local{Base: t.TempDir(), Hardlink: true}
	putOwned(t, l, "a", "same", "key:alice")
	if _, err := l.MaintainObjects(); err != nil {
		t.Fatal(err)
	}
	idx := objectPath(l, "same") + ".json"
	if err := os.WriteFile(idx, []byte(`{"size":4,"names":{"x":"key:x"}}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := l.MaintainObjects(); err != nil {
		t.Fatal(err)
	}
	if got := indexNames(t, l, "same"); !hasKey(got, "x") {
		t.Fatalf("an unchanged base was reconciled again: %v", got)
	}
	h, err := lockBase(l.Base)
	if err != nil {
		t.Fatal(err)
	}
	h.unlock()
	if _, err := l.MaintainObjects(); err != nil {
		t.Fatal(err)
	}
	if got := indexNames(t, l, "same"); len(got) != 1 || !hasKey(got, "a") {
		t.Fatalf("a changed base was not reconciled: %v", got)
	}
}

func TestMaxLinks(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "version", Hardlink: true, MaxLinks: 2}
	putOwned(t, l, "a", "same", "key:robert")
	putOwned(t, l, "b", "same", "key:robert")
	var tm *TooManyLinks
	src := srcFile(t, t.TempDir(), "same")
	if _, err := l.Store(src, "c", ownedSidecar("c", "same", "key:robert")); !errors.As(err, &tm) || err.Error() != "limit of 2 links to the same content reached" {
		t.Fatalf("third name: %v", err)
	}
	// A version keeps the old name: the same path counts as a new one.
	if _, err := l.Store(src, "a", ownedSidecar("a2", "same", "key:robert")); !errors.As(err, &tm) {
		t.Fatalf("new version: %v", err)
	}
	if _, err := os.Lstat(dataPath(l, "c")); err == nil || l.Owned(shaOf("same"), "key:robert") != 2 {
		t.Fatalf("index %v", indexNames(t, l, "same"))
	}
	putOwned(t, l, "d", "same", "key:anna")
	// A replace into the content is one more name too.
	putOwned(t, l, "e", "other", "key:robert")
	err := l.Replace(srcFile(t, t.TempDir(), "same"), "e", "e", func(sc *Sidecar) error {
		sc.Size, sc.SHA256 = int64(len("same")), shaOf("same")
		return nil
	})
	if !errors.As(err, &tm) {
		t.Fatalf("replace: %v", err)
	}
	// Without versions the name replaced does not count.
	r := Local{Base: l.Base, Conflict: "replace", Hardlink: true, MaxLinks: 2}
	if _, err := r.Store(src, "a", ownedSidecar("a3", "same", "key:robert")); err != nil {
		t.Fatalf("replace conflict: %v", err)
	}
}

// The index keeps the upload id of each name, and MaintainObjects restores
// the ids an index lacks from the sidecars.
func TestOwnedIDs(t *testing.T) {
	l := Local{Base: t.TempDir(), Hardlink: true}
	putOwned(t, l, "a", "same", "key:alice")
	putOwned(t, l, "b", "same", "key:alice")
	putOwned(t, l, "c", "same", "key:bob")
	want := func() {
		t.Helper()
		n, ids := l.OwnedIDs(shaOf("same"), "key:alice")
		if n != 2 || len(ids) != 2 || !ids["a"] || !ids["b"] {
			t.Fatalf("owned %d %v", n, ids)
		}
	}
	want()
	idx := objectPath(l, "same") + ".json"
	if err := os.WriteFile(idx, []byte(`{"size":4,"names":{"a":"key:alice","b":"key:alice","c":"key:bob"}}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if n, ids := l.OwnedIDs(shaOf("same"), "key:alice"); n != 2 || len(ids) != 0 {
		t.Fatalf("index without ids: %d %v", n, ids)
	}
	if _, err := l.MaintainObjects(); err != nil {
		t.Fatal(err)
	}
	want()
}
