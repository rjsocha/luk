package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
)

// ObjectsDir holds the content objects of a base with hardlink: the object
// <sha256> is a hardlink of the stored files with that content, and
// <sha256>.json the index of the stored names holding it, each with its
// owner key and the id of its upload. Both lie under two levels of hex pair directories, the first
// characters of the sha256 (ab/cd/<sha256>). It lies in DBDir, outside the
// data tree, so no stored name can collide with it.
const ObjectsDir = DBDir + "/objects"

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// objectsFresh caches per base the generation MaintainObjects last
// reconciled the objects at.
var objectsFresh sync.Map

func objectRel(sum string) string {
	return ObjectsDir + "/" + sum[:2] + "/" + sum[2:4] + "/" + sum
}

func indexRel(sum string) string { return objectRel(sum) + ".json" }

// objectIndex lists the stored names holding the content of an object,
// each with its owner key, and the upload id of each name that has one.
type objectIndex struct {
	Size  int64             `json:"size"`
	Names map[string]string `json:"names"`
	IDs   map[string]string `json:"ids,omitempty"`
}

// objected reports whether the objects track sc: with hardlink, a stored
// file (not an alias) with a sha256.
func (l Local) objected(sc Sidecar) bool {
	return l.Hardlink && sc.AliasOf == "" && shaRe.MatchString(sc.SHA256)
}

// nlink is the link count of fi; 0 when unknown.
func nlink(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}

// object is the object of sum when it is a regular file of size bytes.
func object(r *os.Root, sum string, size int64) (fs.FileInfo, bool) {
	o := objectRel(sum)
	if noSymlinks(r, o) != nil {
		return nil, false
	}
	fi, err := r.Lstat(o)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != size {
		return nil, false
	}
	return fi, true
}

func readIndex(r *os.Root, sum string) (objectIndex, error) {
	var idx objectIndex
	p := indexRel(sum)
	if err := noSymlinks(r, p); err != nil {
		return idx, err
	}
	f, err := openRegular(r, p)
	if errors.Is(err, fs.ErrNotExist) {
		return idx, nil
	}
	if err != nil {
		return idx, err
	}
	defer f.Close()
	err = json.NewDecoder(f).Decode(&idx)
	return idx, err
}

// writeIndex replaces the index of sum; an index without names is removed.
func writeIndex(r *os.Root, sum string, idx objectIndex) error {
	p := indexRel(sum)
	if len(idx.Names) == 0 {
		err := r.Remove(p)
		if errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
		return err
	}
	if err := mkdirs(r, path.Dir(p)); err != nil {
		return err
	}
	if err := noSymlinks(r, p); err != nil {
		return err
	}
	b, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(r, b)
	if err != nil {
		return err
	}
	defer r.Remove(tmp)
	return r.Rename(tmp, p)
}

// addName records the stored name rel of sc in the index of its content.
func (l Local) addName(r *os.Root, rel string, sc Sidecar) error {
	if !l.objected(sc) {
		return nil
	}
	idx, err := readIndex(r, sc.SHA256)
	if err != nil {
		// A broken index is written anew.
		idx = objectIndex{}
	}
	if o, ok := idx.Names[rel]; ok && o == sc.OwnerKey && idx.Size == sc.Size && idx.IDs[rel] == sc.ID {
		return nil
	}
	if idx.Names == nil {
		idx.Names = map[string]string{}
	}
	idx.Size = sc.Size
	idx.Names[rel] = sc.OwnerKey
	delete(idx.IDs, rel)
	if sc.ID != "" {
		if idx.IDs == nil {
			idx.IDs = map[string]string{}
		}
		idx.IDs[rel] = sc.ID
	}
	return writeIndex(r, sc.SHA256, idx)
}

// dropName removes the stored name rel of sc from the index of its content.
func (l Local) dropName(r *os.Root, rel string, sc Sidecar) error {
	if !l.objected(sc) {
		return nil
	}
	idx, err := readIndex(r, sc.SHA256)
	if err != nil {
		return err
	}
	if _, ok := idx.Names[rel]; !ok {
		return nil
	}
	delete(idx.Names, rel)
	delete(idx.IDs, rel)
	return writeIndex(r, sc.SHA256, idx)
}

// linkObject makes the stored file at the path on disk p, the content of
// sc, the object of that content when there is none (or a broken one).
func (l Local) linkObject(r *os.Root, p string, sc Sidecar) error {
	if !l.objected(sc) {
		return nil
	}
	fi, err := r.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() != sc.Size {
		return nil
	}
	if _, ok := object(r, sc.SHA256, sc.Size); ok {
		return nil
	}
	return placeObject(r, p, sc.SHA256)
}

// placeObject links the path on disk p as the object of sum, atomically
// over whatever is there.
func placeObject(r *os.Root, p, sum string) error {
	o := objectRel(sum)
	if err := mkdirs(r, path.Dir(o)); err != nil {
		return err
	}
	if err := noSymlinks(r, o); err != nil {
		return err
	}
	tmp, err := tmpName(r)
	if err != nil {
		return err
	}
	if err := r.Link(p, tmp); err != nil {
		return err
	}
	defer r.Remove(tmp)
	return r.Rename(tmp, o)
}

// fromObject links the object of the content of sc to a new temporary name
// of the base, for a store to place instead of its own copy;
// false without a usable object.
func (l Local) fromObject(r *os.Root, sc Sidecar) (string, fs.FileInfo, bool) {
	if !l.objected(sc) {
		return "", nil, false
	}
	ofi, ok := object(r, sc.SHA256, sc.Size)
	if !ok {
		return "", nil, false
	}
	tmp, err := tmpName(r)
	if err != nil {
		return "", nil, false
	}
	if r.Link(objectRel(sc.SHA256), tmp) != nil {
		return "", nil, false
	}
	fi, err := r.Lstat(tmp)
	if err != nil || !os.SameFile(fi, ofi) {
		r.Remove(tmp)
		return "", nil, false
	}
	return tmp, fi, true
}

// Object finds the object of the content sum of size bytes for a transfer
// held by a stored name of owner: its path and its file info. It reads
// without the lock; false without hardlink, without the object or when no
// name of owner holds it.
func (l Local) Object(sum string, size int64, owner string) (string, fs.FileInfo, bool) {
	if !l.Hardlink || !shaRe.MatchString(sum) || owner == "" {
		return "", nil, false
	}
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return "", nil, false
	}
	defer r.Close()
	fi, ok := object(r, sum, size)
	if !ok {
		return "", nil, false
	}
	idx, err := readIndex(r, sum)
	if err != nil || idx.Size != size {
		return "", nil, false
	}
	for _, o := range idx.Names {
		if o == owner {
			return filepath.Join(l.Base, filepath.FromSlash(objectRel(sum))), fi, true
		}
	}
	return "", nil, false
}

// TooManyLinks refuses one more stored name of a content for an owner
// that already has Max of them in the storage (see Local.MaxLinks).
type TooManyLinks struct{ Max int }

func (e *TooManyLinks) Error() string {
	return fmt.Sprintf("limit of %d links to the same content reached", e.Max)
}

// Owned is the number of stored names holding the content sum that owner
// owns, from the index of its object. It reads without the lock; 0
// without hardlink or without an index.
func (l Local) Owned(sum, owner string) int {
	n, _ := l.OwnedIDs(sum, owner)
	return n
}

// OwnedIDs is Owned with the upload ids of those names, so that a queued
// upload already stored here is not counted again.
func (l Local) OwnedIDs(sum, owner string) (int, map[string]bool) {
	ids := map[string]bool{}
	if !l.Hardlink || !shaRe.MatchString(sum) || owner == "" {
		return 0, ids
	}
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return 0, ids
	}
	defer r.Close()
	idx, err := readIndex(r, sum)
	if err != nil {
		return 0, ids
	}
	for name, o := range idx.Names {
		if id := idx.IDs[name]; o == owner && id != "" {
			ids[id] = true
		}
	}
	return owned(idx, owner, ""), ids
}

// owned counts the names of idx owned by owner, skip aside.
func owned(idx objectIndex, owner, skip string) int {
	n := 0
	for name, o := range idx.Names {
		if o == owner && name != skip {
			n++
		}
	}
	return n
}

// overLinks refuses, under the base lock, a new stored name of sc when its
// owner already holds MaxLinks names of that content; skip is a name the
// store replaces, not counted.
func (l Local) overLinks(r *os.Root, sc Sidecar, skip string) error {
	if l.MaxLinks <= 0 || !l.objected(sc) || sc.OwnerKey == "" {
		return nil
	}
	idx, err := readIndex(r, sc.SHA256)
	if err != nil {
		// A broken index is rebuilt by MaintainObjects.
		return nil
	}
	if owned(idx, sc.OwnerKey, skip) >= l.MaxLinks {
		return &TooManyLinks{Max: l.MaxLinks}
	}
	return nil
}

// Links is the number of names holding the content of the stored file rel
// with sidecar sc: its hardlinks less its object (versions, aliases and
// claimed copies count); 0 when it cannot be read.
func (l Local) Links(rel string, sc Sidecar) int {
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return 0
	}
	defer r.Close()
	p, err := l.path(r, rel)
	if err != nil {
		return 0
	}
	fi, err := r.Lstat(p)
	if err != nil {
		return 0
	}
	n := nlink(fi)
	if shaRe.MatchString(sc.SHA256) {
		if ofi, err := r.Lstat(objectRel(sc.SHA256)); err == nil && os.SameFile(ofi, fi) && n > 0 {
			n--
		}
	}
	return int(n)
}

// Objects is what MaintainObjects changed: objects adopted from stored
// files without one, and objects removed with their last name.
type Objects struct {
	Adopted, Removed int
}

// MaintainObjects reconciles the objects with the stored files, under the
// base lock, whenever the base changed since its last run in this process:
// a stored file whose content has no object is linked as the object (its
// sha256 and size taken from its sidecar, nothing is hashed), an object
// whose only link is its own is removed with its index, every index lists
// exactly the stored names with that content and their owner keys, and
// leftovers (indexes without an object, empty directories) go; temporary
// files are left to Sweep. Without hardlink the objects directory is removed.
func (l Local) MaintainObjects() (Objects, error) {
	var res Objects
	r, err := os.OpenRoot(l.Base)
	if errors.Is(err, fs.ErrNotExist) {
		return res, nil
	}
	if err != nil {
		return res, err
	}
	defer r.Close()
	v, fresh := objectsFresh.Load(l.key())
	if fresh && v.(int64) == generation(r) {
		// Removing a claimed copy changes no generation: objects whose only
		// link is their own are looked for on every pass.
		return l.dropLonely(r, v.(int64))
	}
	h, err := takeBase(l.Base, false)
	if err != nil {
		return res, err
	}
	err = l.maintainObjects(r, h, &res)
	gen := h.end()
	h.unlock()
	if err == nil {
		objectsFresh.Store(l.key(), gen)
	}
	return res, err
}

// end is the generation the base has once h is unlocked.
func (h *held) end() int64 {
	if h.gen%2 != 0 {
		return h.gen + 1
	}
	return h.gen
}

// dropLonely removes, under the base lock, the objects whose only link is
// their own, and their indexes, in a base reconciled at the generation gen.
func (l Local) dropLonely(r *os.Root, gen int64) (Objects, error) {
	var res Objects
	if !l.Hardlink {
		return res, nil
	}
	var lonely []string
	werr := fs.WalkDir(r.FS(), ObjectsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || !shaRe.MatchString(d.Name()) || objectRel(d.Name()) != p {
			return nil
		}
		if fi, err := d.Info(); err == nil && nlink(fi) == 1 {
			lonely = append(lonely, d.Name())
		}
		return nil
	})
	if len(lonely) == 0 {
		return res, werr
	}
	h, err := takeBase(l.Base, false)
	if err != nil {
		return res, err
	}
	var errs []error
	for _, sum := range lonely {
		if fi, err := r.Lstat(objectRel(sum)); err != nil || nlink(fi) != 1 || noSymlinks(r, objectRel(sum)) != nil {
			continue
		}
		if err := h.bump(); err != nil {
			errs = append(errs, err)
			break
		}
		err := r.Remove(objectRel(sum))
		if err == nil {
			res.Removed++
			if ierr := r.Remove(indexRel(sum)); ierr != nil && !errors.Is(ierr, fs.ErrNotExist) {
				err = ierr
			}
			prune(r, objectRel(sum))
		}
		errs = append(errs, err)
	}
	if h.prev == gen {
		objectsFresh.Store(l.key(), h.end())
	}
	h.unlock()
	return res, errors.Join(append(errs, werr)...)
}

func (l Local) maintainObjects(r *os.Root, h *held, res *Objects) error {
	if _, err := r.Lstat(ObjectsDir); err != nil && !l.Hardlink {
		return nil
	}
	if err := noSymlinks(r, ObjectsDir); err != nil {
		return err
	}
	var errs []error
	change := func(f func() error) bool {
		err := h.bump()
		if err == nil {
			err = f()
		}
		errs = append(errs, err)
		return err == nil
	}
	if !l.Hardlink {
		change(func() error { return r.RemoveAll(ObjectsDir) })
		return errors.Join(errs...)
	}
	type group struct {
		size  int64
		names map[string]string
		ids   map[string]string
		// from is the path on disk of a name to adopt the object from.
		from string
		// mixed marks names of one sha256 with different sizes: no object.
		mixed bool
	}
	groups := map[string]*group{}
	errs = append(errs, l.walk(r, func(rel string, sc Sidecar) error {
		if !l.objected(sc) {
			return nil
		}
		g := groups[sc.SHA256]
		if g == nil {
			g = &group{size: sc.Size, names: map[string]string{}, ids: map[string]string{}}
			groups[sc.SHA256] = g
		}
		if sc.Size != g.size {
			g.mixed = true
		}
		g.names[rel] = sc.OwnerKey
		if sc.ID != "" {
			g.ids[rel] = sc.ID
		}
		if p := l.phys(rel); g.from == "" {
			if fi, err := r.Lstat(p); err == nil && fi.Mode().IsRegular() && fi.Size() == sc.Size {
				g.from = p
			}
		}
		return nil
	}))
	objects, indexes := map[string]fs.FileInfo{}, map[string]bool{}
	var dirs []string
	werr := fs.WalkDir(r.FS(), ObjectsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p != ObjectsDir || !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			return nil
		}
		if d.IsDir() {
			if p != ObjectsDir {
				dirs = append(dirs, p)
			}
			return nil
		}
		name := d.Name()
		if !d.Type().IsRegular() {
			return nil
		}
		sum, isIndex := strings.CutSuffix(name, ".json")
		if !shaRe.MatchString(sum) || objectRel(sum) != strings.TrimSuffix(p, ".json") {
			return nil
		}
		if isIndex {
			indexes[sum] = true
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		objects[sum] = fi
		return nil
	})
	errs = append(errs, werr)
	for sum, fi := range objects {
		g := groups[sum]
		switch {
		case g != nil && !g.mixed && fi.Size() == g.size:
		case nlink(fi) == 1:
			if change(func() error { return r.Remove(objectRel(sum)) }) {
				delete(objects, sum)
				res.Removed++
			}
		case g != nil && !g.mixed && g.from != "":
			// An object of another size than its names: replaced.
			change(func() error { return placeObject(r, g.from, sum) })
		}
	}
	for sum, g := range groups {
		if _, ok := objects[sum]; ok || g.mixed || g.from == "" {
			continue
		}
		if change(func() error { return placeObject(r, g.from, sum) }) {
			objects[sum] = nil
			res.Adopted++
		}
	}
	for sum := range indexes {
		if _, ok := objects[sum]; !ok {
			change(func() error { return r.Remove(indexRel(sum)) })
		}
	}
	for sum := range objects {
		want := objectIndex{Names: map[string]string{}}
		if g := groups[sum]; g != nil && !g.mixed {
			want = objectIndex{Size: g.size, Names: g.names}
			if len(g.ids) > 0 {
				want.IDs = g.ids
			}
		}
		cur, err := readIndex(r, sum)
		if err == nil && cur.Size == want.Size && maps.Equal(cur.Names, want.Names) && maps.Equal(cur.IDs, want.IDs) {
			continue
		}
		change(func() error { return writeIndex(r, sum, want) })
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if des, err := fs.ReadDir(r.FS(), dirs[i]); err == nil && len(des) == 0 {
			change(func() error { return rmdir(r, dirs[i]) })
		}
	}
	return errors.Join(errs...)
}
