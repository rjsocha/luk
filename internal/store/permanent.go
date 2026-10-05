package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"luk/internal/config"
	"luk/internal/wire"
)

// PermanentDir holds the permanent names of a base: the directory
// <path>/<name> per name (path being the permanent.path of its endpoint),
// holding the directory "current" with the hardlink "data" of the current
// version of the name and its sidecar "meta.json" (a copy of the
// version's sidecar with alias_of set to the version's stored name). The
// directory of a name whose version went is empty. A new version is
// prepared in full as "current.<random>" and swapped with "current" by
// renameat2(RENAME_EXCHANGE), so a reader that opens "current" once and
// reads both files through it always sees one version whole. No element
// of a path or a name is current or starts with current. (see
// wire.CheckPermanentName), so the directories of nested names never meet
// these.
const PermanentDir = DBDir + "/permanent"

const (
	permCurrent = "current"
	permData    = "data"
	permMeta    = "meta.json"
)

// ErrNoExchange fails a publish of a permanent name on a filesystem
// without renameat2(RENAME_EXCHANGE): it is never replaced by a switch
// readers could observe half done.
var ErrNoExchange = errors.New("the filesystem of the storage does not support renameat2 RENAME_EXCHANGE, which permanent names need")

// hookPermanent runs in publish after the new version is prepared (1) and
// after the exchange (2).
var hookPermanent = func(step int) {}

// exchange swaps the entries a and b of the directory fd.
var exchange = func(fd int, a, b string) error {
	err := unix.Renameat2(fd, a, fd, b, unix.RENAME_EXCHANGE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		return fmt.Errorf("%w (%v)", ErrNoExchange, err)
	}
	return err
}

// PermanentRefused is a permanent version a store does not place: a name
// its endpoint does not allocate, or a new name of a pattern that holds
// its max.
type PermanentRefused struct{ Msg string }

func (e *PermanentRefused) Error() string { return e.Msg }

// PermanentPrefix reports whether the stored name rel lies under the
// permanent.path of an endpoint of this storage (rel equal to the path
// included), with that endpoint and the permanent name after the path.
func (l Local) PermanentPrefix(rel string) (endpoint, name string, ok bool) {
	for ep, p := range l.Permanent {
		if rel == p.Path {
			return ep, "", true
		}
		if n, ok := strings.CutPrefix(rel, p.Path+"/"); ok {
			return ep, n, true
		}
	}
	return "", "", false
}

// permanentName is the permanent name a stored file is a version of, read
// from its sidecar alone: the uploaded payload (not a produced file) of a
// public direct upload with a client permanent name and its
// permanent_path; empty otherwise.
func permanentName(sc Sidecar) string {
	if sc.AliasOf != "" || sc.Produced != "" || sc.Private() || sc.Client.Permanent == "" || sc.PermanentPath == "" ||
		wire.CheckPermanentName(sc.Client.Permanent) != nil {
		return ""
	}
	return sc.Client.Permanent
}

// permanentKey is where the stored file is published, <path>/<name>
// relative to PermanentDir: a version of a name its endpoint allocates
// under its current permanent.path; empty for any other file.
func (l Local) permanentKey(sc Sidecar) string {
	name := permanentName(sc)
	p := l.Permanent[sc.Endpoint]
	if name == "" || p == nil || sc.PermanentPath != p.Path {
		return ""
	}
	if _, _, ok := p.Entry(name); !ok {
		return ""
	}
	return p.Path + "/" + name
}

// allocated reports whether key (<path>/<name>) is a permanent name the
// configuration allocates: under the permanent.path of an endpoint of
// this storage, covered by an entry of its names.
func (l Local) allocated(key string) bool {
	ep, name, ok := l.PermanentPrefix(key)
	if !ok || name == "" {
		return false
	}
	_, _, ok = l.Permanent[ep].Entry(name)
	return ok
}

func expiredNow(sc Sidecar) bool {
	if sc.Expires == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, sc.Expires)
	return err != nil || !t.After(now())
}

func permDirOf(key string) string { return PermanentDir + "/" + key }

// readCurrent reads the sidecar of the current version of the permanent
// directory dir; fs.ErrNotExist when it has none.
func readCurrent(r *os.Root, dir string) (Sidecar, error) {
	var sc Sidecar
	meta := dir + "/" + permCurrent + "/" + permMeta
	if err := noSymlinks(r, meta); err != nil {
		return sc, err
	}
	f, err := openRegular(r, meta)
	if err != nil {
		return sc, err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&sc); err != nil {
		return sc, fmt.Errorf("%s: %w", meta, err)
	}
	return sc, nil
}

// currentOf is the current version of the permanent directory dir: its
// stored name and the sidecar of current; ok false when there is none.
func currentOf(r *os.Root, dir string) (t target, ok bool, err error) {
	cur, err := readCurrent(r, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return target{}, false, nil
	}
	if err != nil {
		return target{}, false, err
	}
	return target{cur.AliasOf, cur}, true, nil
}

// acceptedAfter reports whether a was accepted after b: by acceptance
// order (Sidecar.Order), then by id.
func acceptedAfter(a, b Sidecar) bool {
	if c := a.Order().Compare(b.Order()); c != 0 {
		return c > 0
	}
	return a.ID > b.ID
}

// sameUpload reports whether a and b are the sidecars of one upload.
func sameUpload(a, b Sidecar) bool { return a.Order() == b.Order() && a.ID == b.ID }

// permanentSound reports whether the current version of dir is t: the
// same id, expiry and content, and its data the inode of t.
func (l Local) permanentSound(r *os.Root, dir string, t target) bool {
	cur, err := readCurrent(r, dir)
	if err != nil || cur.AliasOf != t.rel || cur.ID != t.sc.ID || cur.Expires != t.sc.Expires || cur.SHA256 != t.sc.SHA256 ||
		cur.Size != t.sc.Size || cur.Received != t.sc.Received || cur.Order() != t.sc.Order() || cur.Endpoint != t.sc.Endpoint {
		return false
	}
	dfi, err := r.Lstat(dir + "/" + permCurrent + "/" + permData)
	if err != nil {
		return false
	}
	tfi, err := r.Lstat(l.phys(t.rel))
	return err == nil && os.SameFile(dfi, tfi)
}

// leftovers lists the version directories of dir besides current
// (current.<random>): left by a crash before or after their exchange, or
// by an unpublish.
func leftovers(r *os.Root, dir string) []string {
	d, err := r.Open(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	names, _ := d.Readdirnames(-1)
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, permCurrent+".") {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// removeVersionDir removes a version directory of a permanent name: its
// two files and the directory itself, never through a symlink.
func removeVersionDir(r *os.Root, p string) error {
	fi, err := r.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return r.Remove(p)
	}
	var errs []error
	for _, f := range []string{permData, permMeta} {
		if err := r.Remove(p + "/" + f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := r.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// publish makes the version t the current version of the permanent name
// key, under the base lock: the new version is prepared in full beside
// the current one (synced), then swapped with it in one
// renameat2(RENAME_EXCHANGE) (a plain rename when there is none), the
// directory synced and the old version directory removed.
func (l Local) publish(r *os.Root, key string, t target) error {
	dir := permDirOf(key)
	if err := mkdirs(r, dir); err != nil {
		return err
	}
	if err := noSymlinks(r, dir); err != nil {
		return err
	}
	for _, n := range leftovers(r, dir) {
		if err := removeVersionDir(r, dir+"/"+n); err != nil {
			return err
		}
	}
	b := make([]byte, 8)
	rand.Read(b)
	next := permCurrent + "." + hex.EncodeToString(b)
	np := dir + "/" + next
	if err := r.Mkdir(np, 0o750); err != nil {
		return err
	}
	placed := false
	defer func() {
		if !placed {
			removeVersionDir(r, np)
		}
	}()
	if err := r.Link(l.phys(t.rel), np+"/"+permData); err != nil {
		return err
	}
	sc := t.sc
	sc.AliasOf = t.rel
	mb, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	stmp, err := writeTemp(r, mb)
	if err != nil {
		return err
	}
	defer r.Remove(stmp)
	if err := r.Rename(stmp, np+"/"+permMeta); err != nil {
		return err
	}
	if err := syncDir(r, np); err != nil {
		return err
	}
	hookPermanent(1)
	d, err := r.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if _, err := r.Lstat(dir + "/" + permCurrent); errors.Is(err, fs.ErrNotExist) {
		if err := r.Rename(np, dir+"/"+permCurrent); err != nil {
			return err
		}
		placed = true
		return d.Sync()
	} else if err != nil {
		return err
	}
	if err := exchange(int(d.Fd()), next, permCurrent); err != nil {
		return err
	}
	// np holds the old version now.
	placed = true
	if err := d.Sync(); err != nil {
		return err
	}
	hookPermanent(2)
	return removeVersionDir(r, np)
}

// unpublish takes the current version of the permanent name key away:
// current is renamed away in one step, so a reader sees it whole or not at
// all, and removed. The directory of the name stays, empty: the name
// answers 404 until a version is published.
func unpublish(r *os.Root, key string) error {
	dir := permDirOf(key)
	if _, err := r.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := noSymlinks(r, dir); err != nil {
		return err
	}
	var errs []error
	if _, err := r.Lstat(dir + "/" + permCurrent); err == nil {
		b := make([]byte, 8)
		rand.Read(b)
		gone := dir + "/" + permCurrent + ".gone." + hex.EncodeToString(b)
		if err := r.Rename(dir+"/"+permCurrent, gone); err != nil {
			return err
		}
		errs = append(errs, syncDir(r, dir))
	}
	for _, n := range leftovers(r, dir) {
		errs = append(errs, removeVersionDir(r, dir+"/"+n))
	}
	return errors.Join(errs...)
}

// removeName removes the directory of the permanent name key whole:
// current (see unpublish) and the directories it leaves empty (never
// PermanentDir itself, never a directory of a nested name).
func removeName(r *os.Root, key string) error {
	if err := unpublish(r, key); err != nil {
		return err
	}
	dir := permDirOf(key)
	for d := dir; d != PermanentDir && d != "." && d != DBDir; d = path.Dir(d) {
		if rmdir(r, d) != nil {
			break
		}
	}
	return nil
}

// liveVersion is the stored file the current version cur of the
// permanent name key names: still that version (same id, not an alias),
// a version of key and not expired; ok false when it is gone. An error
// when its sidecar cannot be read.
func (l Local) liveVersion(r *os.Root, key string, cur Sidecar) (target, bool, error) {
	if cur.AliasOf == "" || ValidName(cur.AliasOf) != nil {
		return target{}, false, nil
	}
	sc, err := readSidecar(r, l.phys(cur.AliasOf))
	if errors.Is(err, fs.ErrNotExist) {
		return target{}, false, nil
	}
	if err != nil {
		return target{}, false, err
	}
	if sc.ID != cur.ID || sc.AliasOf != "" || l.permanentKey(sc) != key || expiredNow(sc) {
		return target{}, false, nil
	}
	if fi, err := r.Lstat(l.phys(cur.AliasOf)); err != nil || !fi.Mode().IsRegular() {
		return target{}, false, nil
	}
	return target{cur.AliasOf, sc}, true, nil
}

// syncPermanent checks the current version of the permanent name key,
// under the base lock: a version that is gone (removed, replaced,
// expired) is unpublished and the name answers 404, never an older
// version; a version whose sidecar changed (a new ttl) is published
// again. A key the configuration does not allocate (an orphan) is left
// alone.
func (l Local) syncPermanent(r *os.Root, key string) error {
	if key == "" || !l.allocated(key) {
		return nil
	}
	dir := permDirOf(key)
	cur, err := readCurrent(r, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	t, ok, err := l.liveVersion(r, key, cur)
	switch {
	case err != nil:
		// A sidecar that cannot be read: keep what is published.
		return err
	case !ok:
		return unpublish(r, key)
	case !l.permanentSound(r, dir, t):
		return l.publish(r, key, t)
	}
	return nil
}

// versionsOf lists the stored versions of the permanent name key, live or
// not.
func (l Local) versionsOf(r *os.Root, key string) ([]target, error) {
	var out []target
	err := l.walk(r, func(rel string, sc Sidecar) error {
		if l.permanentKey(sc) == key {
			out = append(out, target{rel, sc})
		}
		return nil
	})
	return out, err
}

// placePermanent publishes the version t of the permanent name key that
// a store just placed, under the base lock h. Without a current version
// (none published yet, or it went or expired) t becomes current; with
// one, t replaces it only when accepted after it. Every other stored
// version of the name is then removed as Remove does (sidecar, objects,
// catalog): they are returned as replaced. A version accepted before the
// current one (an older upload stored late) never becomes current: it is
// removed and returned as superseded. The current version itself (its
// store run again after an interruption) is published again when its
// current is not sound.
func (l Local) placePermanent(r *os.Root, h *held, key string, t target) (replaced []PermanentVersion, superseded *PermanentVersion, err error) {
	dir := permDirOf(key)
	cur, ok, err := currentOf(r, dir)
	if err != nil {
		return nil, nil, err
	}
	ok = ok && !expiredNow(cur.sc)
	switch {
	case ok && sameUpload(t.sc, cur.sc):
		if !l.permanentSound(r, dir, t) || len(leftovers(r, dir)) > 0 {
			err = l.publish(r, key, t)
		}
	case ok && !acceptedAfter(t.sc, cur.sc):
		id := t.sc.ID
		err := l.removeHeld(r, h, t.rel, func(s Sidecar) bool { return s.ID == id })
		if errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
		return nil, &PermanentVersion{Name: t.rel, ID: t.sc.ID, Received: t.sc.Received}, err
	default:
		err = l.publish(r, key, t)
	}
	if err != nil {
		return nil, nil, err
	}
	replaced, err = l.dropOthers(r, h, key, t)
	return replaced, nil, err
}

// dropOthers removes every stored version of the permanent name key but
// keep, as Remove does, under the base lock h.
func (l Local) dropOthers(r *os.Root, h *held, key string, keep target) ([]PermanentVersion, error) {
	vs, werr := l.versionsOf(r, key)
	if werr != nil {
		// An unreadable sidecar: remove nothing on a partial view.
		return nil, werr
	}
	var out []PermanentVersion
	var errs []error
	for _, v := range vs {
		if v.rel == keep.rel {
			continue
		}
		id := v.sc.ID
		err := l.removeHeld(r, h, v.rel, func(s Sidecar) bool { return s.ID == id })
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, PermanentVersion{Name: v.rel, ID: v.sc.ID, Received: v.sc.Received})
	}
	return out, errors.Join(errs...)
}

// presentPermanent lists the keys of the permanent directories of the
// base, relative to PermanentDir: the directories under PermanentDir
// holding current or a version directory current.<random>, and the empty
// ones (a name whose version went).
func presentPermanent(r *os.Root) ([]string, error) {
	var out []string
	if _, err := r.Lstat(PermanentDir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err := noSymlinks(r, PermanentDir); err != nil {
		return nil, err
	}
	add := func(dir string) {
		if key := strings.TrimPrefix(dir, PermanentDir+"/"); dir != PermanentDir && !slices.Contains(out, key) {
			out = append(out, key)
		}
	}
	empty := func(dir string) bool {
		d, err := r.Open(dir)
		if err != nil {
			return false
		}
		defer d.Close()
		names, err := d.Readdirnames(1)
		return len(names) == 0 && errors.Is(err, io.EOF)
	}
	err := fs.WalkDir(r.FS(), PermanentDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == PermanentDir {
				return err
			}
			return nil
		}
		base := path.Base(p)
		if !d.IsDir() || p == PermanentDir {
			return nil
		}
		if base == permCurrent || strings.HasPrefix(base, permCurrent+".") {
			add(path.Dir(p))
			return fs.SkipDir
		}
		if empty(p) {
			add(p)
		}
		return nil
	})
	slices.Sort(out)
	return out, err
}

// reconcilePermanent repairs the permanent names the configuration
// allocates, under the base lock h: version directories left by a crash
// go; a current version that is gone or expired is unpublished, one whose
// sidecar changed is published again; the newest live version becomes
// current when there is none or it was accepted after the current one
// (stored, not yet published: a crash in between); every stored version of a name but its current one
// (replaced or superseded versions a crash left) is removed. Orphans
// (keys the configuration does not allocate) are left alone. With dry set
// it only reports whether a repair is needed (h may be nil); any reports
// whether the base has permanent names.
func (l Local) reconcilePermanent(r *os.Root, h *held, dry bool) (changed, any bool, err error) {
	present, perr := presentPermanent(r)
	versions := map[string][]target{}
	var werr error
	if len(l.Permanent) > 0 {
		werr = l.walk(r, func(rel string, sc Sidecar) error {
			if key := l.permanentKey(sc); key != "" {
				versions[key] = append(versions[key], target{rel, sc})
			}
			return nil
		})
	}
	errs := []error{werr, perr}
	fix := func(f func() error) {
		changed = true
		if !dry {
			errs = append(errs, f())
		}
	}
	keys := slices.Clone(present)
	for key := range versions {
		if !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	for _, key := range keys {
		if !l.allocated(key) {
			continue
		}
		dir := permDirOf(key)
		if len(leftovers(r, dir)) > 0 {
			fix(func() error {
				var errs []error
				for _, n := range leftovers(r, dir) {
					errs = append(errs, removeVersionDir(r, dir+"/"+n))
				}
				return errors.Join(errs...)
			})
		}
		keep := ""
		var current *target
		if cur, cerr := readCurrent(r, dir); cerr == nil {
			t, ok, lerr := l.liveVersion(r, key, cur)
			switch {
			case lerr != nil:
				errs = append(errs, lerr)
				keep = cur.AliasOf
			case !ok:
				fix(func() error { return unpublish(r, key) })
			case !l.permanentSound(r, dir, t):
				keep, current = t.rel, &t
				fix(func() error { return l.publish(r, key, t) })
			default:
				keep, current = t.rel, &t
			}
		} else if !errors.Is(cerr, fs.ErrNotExist) {
			errs = append(errs, cerr)
			continue
		}
		if werr != nil {
			// A sidecar that cannot be read may be a version: neither
			// publish nor remove on a partial view.
			continue
		}
		if keep != "" && current == nil {
			// The current version could not be checked: keep it.
			continue
		}
		var newest *target
		for i, v := range versions[key] {
			if !expiredNow(v.sc) && (newest == nil || newer(v, *newest)) {
				newest = &versions[key][i]
			}
		}
		if newest != nil && (current == nil || acceptedAfter(newest.sc, current.sc)) {
			t := *newest
			keep = t.rel
			fix(func() error { return l.publish(r, key, t) })
		}
		for _, v := range versions[key] {
			if v.rel == keep {
				continue
			}
			id := v.sc.ID
			fix(func() error {
				err := l.removeHeld(r, h, v.rel, func(s Sidecar) bool { return s.ID == id })
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			})
		}
	}
	return changed, len(versions) > 0 || len(present) > 0, errors.Join(errs...)
}

// OpenPermanent opens the current version of the permanent name the
// stored name rel holds (see PermanentPrefix) with its sidecar (alias_of
// is the version's stored name): both are read through one open
// directory, so they always describe one version, also while a new one
// is being published, and an open file keeps its version. fs.ErrNotExist
// when there is none, it has expired (also before the maintenance pass
// unpublishes it) or the configuration does not allocate the name.
func (l Local) OpenPermanent(rel string) (*os.File, Sidecar, error) {
	ep, name, ok := l.PermanentPrefix(rel)
	if !ok || wire.CheckPermanentName(name) != nil || !l.allocated(rel) {
		return nil, Sidecar{}, fmt.Errorf("%s: %w", rel, fs.ErrNotExist)
	}
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return nil, Sidecar{}, err
	}
	defer r.Close()
	cur := permDirOf(rel) + "/" + permCurrent
	for range 8 {
		if err := noSymlinks(r, cur); err != nil {
			return nil, Sidecar{}, err
		}
		cr, err := r.OpenRoot(cur)
		if err != nil {
			return nil, Sidecar{}, err
		}
		f, sc, err := openVersion(cr)
		cr.Close()
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// The directory was swapped or removed after it was opened.
			continue
		case err != nil:
			return nil, Sidecar{}, err
		}
		if sc.Client.Permanent != name || sc.Endpoint != ep || sc.PermanentPath != l.Permanent[ep].Path || expiredNow(sc) {
			f.Close()
			return nil, Sidecar{}, fmt.Errorf("%s: %w", rel, fs.ErrNotExist)
		}
		return f, sc, nil
	}
	return nil, Sidecar{}, fmt.Errorf("%s: %w", rel, fs.ErrNotExist)
}

// openVersion reads the sidecar and opens the data of the version
// directory cr.
func openVersion(cr *os.Root) (*os.File, Sidecar, error) {
	var sc Sidecar
	mf, err := cr.OpenFile(permMeta, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, sc, err
	}
	err = json.NewDecoder(mf).Decode(&sc)
	mf.Close()
	if err != nil {
		return nil, sc, fmt.Errorf("%s: %w", permMeta, err)
	}
	f, err := cr.OpenFile(permData, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, sc, err
	}
	fi, err := f.Stat()
	if err == nil && (!fi.Mode().IsRegular() || fi.Size() != sc.Size) {
		err = fmt.Errorf("%s: not the version of its sidecar", permData)
	}
	if err != nil {
		f.Close()
		return nil, sc, err
	}
	return f, sc, nil
}

// PermanentNames lists the permanent names of the endpoint with a live
// version in the base, read without the lock.
func (l Local) PermanentNames(endpoint string) (map[string]bool, error) {
	r, err := os.OpenRoot(l.Base)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return l.liveNames(r, endpoint)
}

func (l Local) liveNames(r *os.Root, endpoint string) (map[string]bool, error) {
	out := map[string]bool{}
	err := l.walk(r, func(rel string, sc Sidecar) error {
		if sc.Endpoint == endpoint && l.permanentKey(sc) != "" && !expiredNow(sc) {
			out[sc.Client.Permanent] = true
		}
		return nil
	})
	return out, err
}

// AdmitPermanent checks a new version of the permanent name of sc
// against the live names of its endpoint (see PermanentNames): the
// endpoint allocates the name under the permanent_path of sc, and a new
// name of a pattern stays within its max. nil for a file that is no
// permanent version, or of an endpoint without permanent names here.
func (l Local) AdmitPermanent(sc Sidecar, live map[string]bool) error {
	name := permanentName(sc)
	p := l.Permanent[sc.Endpoint]
	if name == "" || p == nil {
		return nil
	}
	key, e, ok := p.Entry(name)
	if !ok || sc.PermanentPath != p.Path {
		return &PermanentRefused{Msg: fmt.Sprintf("permanent name %q is not allocated by endpoint %s", name, sc.Endpoint)}
	}
	if live[name] || !config.IsPattern(key) {
		return nil
	}
	n := 0
	for other := range live {
		if k, _, ok := p.Entry(other); ok && k == key {
			n++
		}
	}
	if n >= e.MaxOf() {
		return &PermanentRefused{Msg: fmt.Sprintf("limit of %d permanent names of this pattern reached", e.MaxOf())}
	}
	return nil
}

// admitPermanent is AdmitPermanent under the base lock. A sidecar that
// cannot be read is left out of the live names; the janitor reports it.
func (l Local) admitPermanent(r *os.Root, sc Sidecar) error {
	if permanentName(sc) == "" || l.Permanent[sc.Endpoint] == nil {
		return nil
	}
	live, _ := l.liveNames(r, sc.Endpoint)
	return l.AdmitPermanent(sc, live)
}

// PermanentVersion is a stored version of a permanent name: its stored
// name, id and received time.
type PermanentVersion struct {
	Name     string
	ID       string
	Received string
}

// PermanentInfo is a permanent name of a base (lukd storage permanent):
// its key (<path>/<name> under PermanentDir), the path and name it was
// published under ("" when unreadable), the stored name, id, received time
// and expiry of its current version (all empty when the version is gone:
// the name is empty and answers 404) and whether it is an orphan: a name
// the configuration does not allocate (its path mapped by no endpoint of
// the storage, or its name covered by no entry of that endpoint).
type PermanentInfo struct {
	Key      string `json:"key"`
	Path     string `json:"path"`
	Name     string `json:"name"`
	Current  string `json:"current,omitempty"`
	ID       string `json:"id,omitempty"`
	Received string `json:"received,omitempty"`
	Expires  string `json:"expires,omitempty"`
	Orphan   bool   `json:"orphan"`
}

// PermanentList lists the permanent names of the base, by key, read
// without the lock.
func (l Local) PermanentList() ([]PermanentInfo, error) {
	r, err := os.OpenRoot(l.Base)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	present, err := presentPermanent(r)
	var out []PermanentInfo
	for _, key := range present {
		dir := permDirOf(key)
		pi := PermanentInfo{Key: key, Orphan: !l.allocated(key)}
		if ep, name, ok := l.PermanentPrefix(key); ok && !pi.Orphan {
			pi.Path, pi.Name = l.Permanent[ep].Path, name
		}
		if sc, err := readCurrent(r, dir); err == nil {
			pi.Path, pi.Name, pi.Current, pi.ID, pi.Received, pi.Expires = sc.PermanentPath, sc.Client.Permanent, sc.AliasOf, sc.ID, sc.Received, sc.Expires
		}
		out = append(out, pi)
	}
	return out, err
}

// PruneOrphan removes the permanent directory of key, under the base
// lock, while the configuration does not allocate it; fs.ErrNotExist for
// a key without a directory, an error for an allocated one. The versions
// stay: they are ordinary stored files.
func (l Local) PruneOrphan(key string) error {
	return l.pruneName(key, func(r *os.Root) error {
		if l.allocated(key) {
			return fmt.Errorf("%s: allocated by the configuration, not an orphan", key)
		}
		return nil
	})
}

// PruneEmpty removes the permanent directory of key, under the base lock,
// while the name has no current version (its version is gone).
// fs.ErrNotExist for a key without a directory, an
// error for a name with a current version.
func (l Local) PruneEmpty(key string) error {
	return l.pruneName(key, func(r *os.Root) error {
		if _, err := r.Lstat(permDirOf(key) + "/" + permCurrent); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: has a current version, not empty", key)
		}
		return nil
	})
}

// pruneName removes the permanent directory of key under the base lock
// while check passes.
func (l Local) pruneName(key string, check func(r *os.Root) error) error {
	if err := ValidName(key); err != nil {
		return err
	}
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return err
	}
	defer r.Close()
	h, err := lockBase(l.Base)
	if err != nil {
		return err
	}
	defer h.unlock()
	present, err := presentPermanent(r)
	if err != nil {
		return err
	}
	if !slices.Contains(present, key) {
		return fmt.Errorf("%s: %w", key, fs.ErrNotExist)
	}
	if err := check(r); err != nil {
		return err
	}
	return removeName(r, key)
}

// ProbeExchange checks that the filesystem of the base supports
// renameat2(RENAME_EXCHANGE) on directories, with two temporary
// directories of DBDir/tmp; ErrNoExchange when it does not.
func ProbeExchange(base string) error {
	r, err := os.OpenRoot(base)
	if err != nil {
		return err
	}
	defer r.Close()
	a, err := tmpName(r)
	if err != nil {
		return err
	}
	b := a + ".x"
	if err := r.Mkdir(a, 0o750); err != nil {
		return err
	}
	defer r.Remove(a)
	if err := r.Mkdir(b, 0o750); err != nil {
		return err
	}
	defer r.Remove(b)
	d, err := r.Open(tmpDir)
	if err != nil {
		return err
	}
	defer d.Close()
	return exchange(int(d.Fd()), path.Base(a), path.Base(b))
}
