package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
// holding the directory "current" with the hardlink "data" of the newest
// live version of the name and its sidecar "meta.json" (a copy of the
// version's sidecar with alias_of set to the version's stored name). A new
// version is prepared in full as "current.<random>" and swapped with
// "current" by renameat2(RENAME_EXCHANGE), so a reader that opens
// "current" once and reads both files through it always sees one version
// whole. No element of a path or a name is current or starts with
// current. (see wire.CheckPermanentName), so the directories of nested
// names never meet these.
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

// permanentTargets finds, for every permanent name the base publishes
// (by key), its newest live (not expired) version.
func (l Local) permanentTargets(r *os.Root) (map[string]target, error) {
	best := map[string]target{}
	if len(l.Permanent) == 0 {
		return best, nil
	}
	err := l.walk(r, func(rel string, sc Sidecar) error {
		key := l.permanentKey(sc)
		if key == "" || expiredNow(sc) {
			return nil
		}
		if b, ok := best[key]; !ok || newer(sc.Received, rel, b.sc.Received, b.rel) {
			best[key] = target{rel, sc}
		}
		return nil
	})
	return best, err
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

// permanentSound reports whether the current version of dir is t: the
// same id, expiry and content, and its data the inode of t.
func (l Local) permanentSound(r *os.Root, dir string, t target) bool {
	cur, err := readCurrent(r, dir)
	if err != nil || cur.AliasOf != t.rel || cur.ID != t.sc.ID || cur.Expires != t.sc.Expires || cur.SHA256 != t.sc.SHA256 ||
		cur.Size != t.sc.Size || cur.Received != t.sc.Received || cur.Endpoint != t.sc.Endpoint {
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
// renameat2(RENAME_EXCHANGE) (a plain rename for the first version), the
// directory synced, and the old version removed.
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

// unpublish removes the permanent name key: current is renamed away in
// one step, so a reader sees it whole or not at all, then removed with
// the directories it leaves empty (never PermanentDir itself, never a
// directory of a nested name).
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
	for d := dir; d != PermanentDir && d != "." && d != DBDir; d = path.Dir(d) {
		if rmdir(r, d) != nil {
			break
		}
	}
	return errors.Join(errs...)
}

// syncPermanent brings the permanent name key up to date, under the base
// lock: its newest live version becomes current (when it is not already),
// or the name goes when it has none. A key the configuration does not
// allocate (an orphan) is left alone.
func (l Local) syncPermanent(r *os.Root, key string) error {
	if key == "" || !l.allocated(key) {
		return nil
	}
	best, err := l.permanentTargets(r)
	if t, ok := best[key]; ok {
		dir := permDirOf(key)
		if !l.permanentSound(r, dir, t) || len(leftovers(r, dir)) > 0 {
			err = errors.Join(err, l.publish(r, key, t))
		}
		return err
	}
	if err != nil {
		// A sidecar that cannot be read may be the newest version: keep
		// what is published.
		return err
	}
	return unpublish(r, key)
}

// presentPermanent lists the keys of the permanent directories of the
// base: the directories under PermanentDir holding current or a version
// directory current.<random>, relative to PermanentDir.
func presentPermanent(r *os.Root) ([]string, error) {
	var out []string
	if _, err := r.Lstat(PermanentDir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err := noSymlinks(r, PermanentDir); err != nil {
		return nil, err
	}
	err := fs.WalkDir(r.FS(), PermanentDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == PermanentDir {
				return err
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		base := path.Base(p)
		if p != PermanentDir && (base == permCurrent || strings.HasPrefix(base, permCurrent+".")) {
			if dir := path.Dir(p); dir != PermanentDir && !slices.Contains(out, strings.TrimPrefix(dir, PermanentDir+"/")) {
				out = append(out, strings.TrimPrefix(dir, PermanentDir+"/"))
			}
			return fs.SkipDir
		}
		return nil
	})
	slices.Sort(out)
	return out, err
}

// reconcilePermanent repairs the permanent names the configuration
// allocates: every one with a live version has its newest as current and
// no leftover version directory, every other one goes. Orphans (keys the
// configuration does not allocate) are left alone. With dry set it only
// reports whether a repair is needed; any reports whether the base has
// permanent names.
func (l Local) reconcilePermanent(r *os.Root, dry bool) (changed, any bool, err error) {
	best, err := l.permanentTargets(r)
	present, perr := presentPermanent(r)
	errs := []error{err, perr}
	fix := func(f func() error) {
		changed = true
		if !dry {
			errs = append(errs, f())
		}
	}
	for _, key := range present {
		if !l.allocated(key) {
			continue
		}
		t, ok := best[key]
		dir := permDirOf(key)
		switch {
		case !ok && err != nil:
			// Kept while a sidecar could not be read (see syncPermanent).
		case !ok:
			fix(func() error { return unpublish(r, key) })
		case !l.permanentSound(r, dir, t) || len(leftovers(r, dir)) > 0:
			fix(func() error { return l.publish(r, key, t) })
		}
	}
	for key, t := range best {
		if !slices.Contains(present, key) {
			fix(func() error { return l.publish(r, key, t) })
		}
	}
	return changed, len(best) > 0 || len(present) > 0, errors.Join(errs...)
}

// OpenPermanent opens the current version of the permanent name the
// stored name rel holds (see PermanentPrefix) with its sidecar (alias_of
// is the version's stored name): both are read through one open
// directory, so they always describe one version, also while a new one
// is being published, and an open file keeps its version. fs.ErrNotExist
// when there is none or the configuration does not allocate the name.
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
		if sc.Client.Permanent != name || sc.Endpoint != ep || sc.PermanentPath != l.Permanent[ep].Path {
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

// PermanentVersion is a stored version of a permanent name.
type PermanentVersion struct {
	Name     string
	ID       string
	Received string
}

// prunePermanent removes, under the base lock h, the live versions of
// the permanent name of sc beyond the newest keep (the keep of its
// entry), each as Remove does (sidecar, objects, the permanent name kept
// on the newest). Expired versions are left to the janitor. It returns
// the versions removed.
func (l Local) prunePermanent(r *os.Root, h *held, sc Sidecar) ([]PermanentVersion, error) {
	key := l.permanentKey(sc)
	if key == "" {
		return nil, nil
	}
	_, e, _ := l.Permanent[sc.Endpoint].Entry(sc.Client.Permanent)
	keep := e.KeepOf()
	var vs []target
	werr := l.walk(r, func(rel string, s Sidecar) error {
		if l.permanentKey(s) == key && !expiredNow(s) {
			vs = append(vs, target{rel, s})
		}
		return nil
	})
	if werr != nil {
		// An unreadable sidecar may be a version: count nothing wrong.
		return nil, werr
	}
	slices.SortFunc(vs, func(a, b target) int {
		if newer(a.sc.Received, a.rel, b.sc.Received, b.rel) {
			return -1
		}
		return 1
	})
	var out []PermanentVersion
	var errs []error
	for _, v := range vs[min(keep, len(vs)):] {
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

// PermanentInfo is a permanent name of a base (lukd storage permanent):
// its key (<path>/<name> under PermanentDir), the path and name its
// current version records ("" when unreadable), the stored name, id and
// received time of that version, the number of live versions of the name
// in the base and whether it is an orphan: a name the configuration does
// not allocate (its path mapped by no endpoint of the storage, or its
// name covered by no entry of that endpoint).
type PermanentInfo struct {
	Key      string `json:"key"`
	Path     string `json:"path"`
	Name     string `json:"name"`
	Current  string `json:"current,omitempty"`
	ID       string `json:"id,omitempty"`
	Received string `json:"received,omitempty"`
	Versions int    `json:"versions"`
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
	counts := map[string]int{}
	werr := l.walk(r, func(rel string, sc Sidecar) error {
		if name := permanentName(sc); name != "" && !expiredNow(sc) {
			counts[sc.PermanentPath+"/"+name]++
		}
		return nil
	})
	var out []PermanentInfo
	for _, key := range present {
		pi := PermanentInfo{Key: key, Versions: counts[key], Orphan: !l.allocated(key)}
		if sc, err := readCurrent(r, permDirOf(key)); err == nil {
			pi.Path, pi.Name, pi.Current, pi.ID, pi.Received = sc.PermanentPath, sc.Client.Permanent, sc.AliasOf, sc.ID, sc.Received
		}
		out = append(out, pi)
	}
	return out, errors.Join(err, werr)
}

// PruneOrphan removes the permanent directory of key, under the base
// lock, while the configuration does not allocate it; fs.ErrNotExist for
// a key without a directory, an error for an allocated one. The versions
// stay: they are ordinary stored files.
func (l Local) PruneOrphan(key string) error {
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
	if l.allocated(key) {
		return fmt.Errorf("%s: allocated by the configuration, not an orphan", key)
	}
	present, err := presentPermanent(r)
	if err != nil {
		return err
	}
	if !slices.Contains(present, key) {
		return fmt.Errorf("%s: %w", key, fs.ErrNotExist)
	}
	return unpublish(r, key)
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
