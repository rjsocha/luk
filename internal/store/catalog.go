package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	"luk/internal/config"
	"luk/internal/wire"
)

// CatalogName is the top-level name expose serves the catalog under; with
// the catalog enabled it is reserved.
const CatalogName = "catalog.json"

// catalogFile is where the catalog is kept, outside the data tree.
const catalogFile = DBDir + "/catalog.json"

// catalogFresh caches per base the generation (see LockName) the catalog
// was current at; any mutation since, by any process, makes it stale. aliasBases records per base whether it has or had
// aliases (unknown until the first Reconcile).
// unreadable keeps per base the sidecar errors of the last locked pass,
// so the same bad entry does not force a repair on every pass.
var catalogFresh, aliasBases, unreadable sync.Map

// hookAliasSidecar runs in linkAlias between the sidecar and data renames.
var hookAliasSidecar = func() {}

// FromConfig is the Local of a local storage.
func FromConfig(st *config.Storage) Local {
	return Local{Base: st.Base, Conflict: st.Conflict, Catalog: st.Catalog, Shard: st.Shard, Dedup: st.Dedup == nil || *st.Dedup,
		Hardlink: st.Hardlink == nil || *st.Hardlink, MaxLinks: st.MaxLinks(), Nested: st.Nested(), Permanent: st.Permanents()}
}

// Batch returns l with catalog rebuilds deferred: its changes only mark
// the catalog stale, and Reconcile rebuilds it once.
func (l Local) Batch() Local {
	l.batch = true
	return l
}

func (l Local) reserved(rel string) error {
	if l.Catalog && rel == CatalogName {
		return fmt.Errorf("%q: reserved for the catalog: %w", rel, ErrInvalid)
	}
	if p, ok := l.Nests(rel); ok {
		return fmt.Errorf("%q: reserved for the nested expose under %s: %w", rel, p, ErrInvalid)
	}
	if ep, _, ok := l.PermanentPrefix(rel); ok {
		return fmt.Errorf("%q: reserved for the permanent names under %s/: %w", rel, l.Permanent[ep].Path, ErrInvalid)
	}
	return nil
}

// Nests reports whether rel is a nested expose path (without its slash)
// or a name under one, and which.
func (l Local) Nests(rel string) (string, bool) {
	for _, p := range l.Nested {
		if rel+"/" == p || strings.HasPrefix(rel, p) {
			return p, true
		}
	}
	return "", false
}

// Render is Render refusing the names reserved in this storage.
func (l Local) Render(t *template.Template, v Vars) (string, error) {
	rel, err := Render(t, v)
	if err == nil {
		err = l.reserved(rel)
	}
	if err != nil {
		return "", err
	}
	return rel, nil
}

// Private is a once, portal or private (access) upload: never listed in
// the catalog, never the target of an alias and never deduplicated.
func (sc Sidecar) Private() bool {
	return sc.Client.Once || (sc.Client.Portal != "" && sc.Client.Portal != wire.PortalDirect) || sc.Client.Access != ""
}

// alias is the `alias` of the pipeline meta; empty when absent.
func (sc Sidecar) alias() (string, error) {
	if len(sc.Meta) == 0 {
		return "", nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(sc.Meta, &m) != nil || m["alias"] == nil {
		return "", nil
	}
	var a string
	if err := json.Unmarshal(m["alias"], &a); err != nil {
		return "", fmt.Errorf("meta alias: not a string: %w", ErrInvalid)
	}
	return a, nil
}

// declares is the alias the stored file rel may have: none for an alias,
// a private file, an invalid alias, its own path or a path held by a
// stored file.
func (l Local) declares(r *os.Root, rel string, sc Sidecar) string {
	if sc.AliasOf != "" || sc.Private() {
		return ""
	}
	a, err := sc.alias()
	if err != nil || a == "" || a == rel || l.reserved(a) != nil || l.checkName(r, a) != nil || l.aliasFree(r, a) != nil {
		return ""
	}
	return a
}

// checkAlias validates a declared alias before the file is stored.
func (l Local) checkAlias(r *os.Root, alias string, sc Sidecar) error {
	if sc.Private() {
		return fmt.Errorf("alias %q: a once, portal or private upload: %w", alias, ErrInvalid)
	}
	if err := l.checkName(r, alias); err != nil {
		return fmt.Errorf("alias: %w", err)
	}
	if err := l.reserved(alias); err != nil {
		return err
	}
	return l.aliasFree(r, alias)
}

// aliasFree refuses an alias path held by anything but an alias.
func (l Local) aliasFree(r *os.Root, alias string) error {
	if _, err := r.Lstat(l.phys(alias)); err != nil {
		return nil
	}
	if cur, err := readSidecar(r, l.phys(alias)); err != nil || cur.AliasOf == "" {
		return fmt.Errorf("alias %q: a stored file: %w", alias, ErrInvalid)
	}
	return nil
}

func receivedTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// newer orders files by received, then by name.
func newer(aRecv, aRel, bRecv, bRel string) bool {
	a, b := receivedTime(aRecv), receivedTime(bRecv)
	if !a.Equal(b) {
		return a.After(b)
	}
	return aRel > bRel
}

type target struct {
	rel string
	sc  Sidecar
}

// pointAlias makes alias follow stored when stored is the newest file
// declaring it.
func (l Local) pointAlias(r *os.Root, alias, stored string, sc Sidecar) error {
	cur, err := readSidecar(r, l.phys(alias))
	switch {
	case err == nil && cur.AliasOf == "":
		return fmt.Errorf("alias %q: a stored file: %w", alias, ErrInvalid)
	case err == nil && cur.AliasOf == stored:
		return l.repoint(r, alias, "")
	case err == nil && !newer(sc.Received, stored, cur.Received, cur.AliasOf):
		return nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}
	return l.linkAlias(r, alias, stored, sc)
}

// newest finds, for every alias declared in the base, its newest
// declaring file, and lists the aliases present.
func (l Local) newest(r *os.Root) (map[string]target, map[string]Sidecar, error) {
	best, present := map[string]target{}, map[string]Sidecar{}
	err := l.walk(r, func(rel string, sc Sidecar) error {
		if sc.AliasOf != "" {
			present[rel] = sc
			return nil
		}
		if a := l.declares(r, rel, sc); a != "" {
			if b, ok := best[a]; !ok || newer(sc.Received, rel, b.sc.Received, b.rel) {
				best[a] = target{rel, sc}
			}
		}
		return nil
	})
	return best, present, err
}

// repoint moves alias to the newest file declaring it, or removes it when
// none is left. With gone set, it acts only while alias points at gone.
func (l Local) repoint(r *os.Root, alias, gone string) error {
	cur, err := readSidecar(r, l.phys(alias))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if cur.AliasOf == "" || (gone != "" && cur.AliasOf != gone) {
		return nil
	}
	best, _, werr := l.newest(r)
	if b, ok := best[alias]; ok {
		err = l.linkAlias(r, alias, b.rel, b.sc)
	} else {
		err = l.removeAlias(r, alias)
	}
	return errors.Join(err, werr)
}

// sound reports whether the alias sidecar cur describes t and the alias
// data is t's file.
func (l Local) sound(r *os.Root, alias string, cur Sidecar, t target) bool {
	if cur.AliasOf != t.rel || cur.ID != t.sc.ID || cur.Received != t.sc.Received || cur.SHA256 != t.sc.SHA256 || cur.Produced != t.sc.Produced {
		return false
	}
	afi, err := r.Lstat(l.phys(alias))
	if err != nil {
		return false
	}
	tfi, err := r.Lstat(l.phys(t.rel))
	return err == nil && os.SameFile(afi, tfi)
}

// reconcileAliases repairs aliases left dangling or stale by a crash or
// an outside change: every declared alias points at its newest declaring
// file, and an alias nobody declares is removed. With dry set it only
// reports whether a repair is needed. It also reports whether the base
// has any alias.
func (l Local) reconcileAliases(r *os.Root, dry bool) (changed, any bool, err error) {
	best, present, err := l.newest(r)
	errs := []error{err}
	fix := func(e error) {
		if e == nil {
			changed = true
		}
		errs = append(errs, e)
	}
	act := func(f func() error) error {
		if dry {
			return nil
		}
		return f()
	}
	for alias, cur := range present {
		t, ok := best[alias]
		switch {
		case !ok:
			fix(act(func() error { return l.removeAlias(r, alias) }))
		case !l.sound(r, alias, cur, t):
			fix(act(func() error { return l.linkAlias(r, alias, t.rel, t.sc) }))
		}
	}
	for alias, t := range best {
		if _, ok := present[alias]; !ok {
			fix(act(func() error { return l.linkAlias(r, alias, t.rel, t.sc) }))
		}
	}
	return changed, len(best) > 0 || len(present) > 0, errors.Join(errs...)
}

// reconcileLinks is reconcileAliases and reconcilePermanent together.
func (l Local) reconcileLinks(r *os.Root, dry bool) (changed, any bool, err error) {
	ac, aa, aerr := l.reconcileAliases(r, dry)
	pc, pa, perr := l.reconcilePermanent(r, dry)
	return ac || pc, aa || pa, errors.Join(aerr, perr)
}

// linkAlias places alias as a hardlink of target with a copy of its
// sidecar marked alias_of. The sidecar goes first: after a crash in
// between the alias is still known as one and the next update fixes it.
func (l Local) linkAlias(r *os.Root, alias, target string, sc Sidecar) error {
	if err := l.aliasFree(r, alias); err != nil {
		return err
	}
	palias := l.phys(alias)
	salias := sidecarRel(palias)
	dir, sdir := path.Dir(palias), path.Dir(salias)
	if err := mkdirs(r, dir); err != nil {
		return err
	}
	if err := mkdirs(r, sdir); err != nil {
		return err
	}
	if err := l.checkName(r, alias); err != nil {
		return err
	}
	if err := noSymlinks(r, salias); err != nil {
		return err
	}
	sc.AliasOf = target
	b, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	stmp, err := writeTemp(r, b)
	if err != nil {
		return err
	}
	defer r.Remove(stmp)
	tmp, err := tmpName(r)
	if err != nil {
		return err
	}
	if err := r.Link(l.phys(target), tmp); err != nil {
		return err
	}
	defer r.Remove(tmp)
	if err := r.Rename(stmp, salias); err != nil {
		return err
	}
	if err := syncDir(r, sdir); err != nil {
		return err
	}
	hookAliasSidecar()
	if err := r.Rename(tmp, palias); err != nil {
		return err
	}
	return syncDir(r, dir)
}

func (l Local) removeAlias(r *os.Root, alias string) error {
	p := l.phys(alias)
	err := r.Remove(p)
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	serr := r.Remove(sidecarRel(p))
	if errors.Is(serr, fs.ErrNotExist) {
		serr = nil
	}
	prune(r, p)
	prune(r, sidecarRel(p))
	return errors.Join(err, serr)
}

type catalogEntry struct {
	Name    string          `json:"name"`
	Size    int64           `json:"size"`
	SHA256  string          `json:"sha256"`
	Created string          `json:"created"`
	Tags    []string        `json:"tags"`
	Meta    json.RawMessage `json:"meta"`
}

type catalog struct {
	Version   int    `json:"version"`
	Generated string `json:"generated"`
	// Generation is the generation of the base (see LockName) the catalog
	// is current at.
	Generation int64             `json:"generation"`
	Files      []catalogEntry    `json:"files"`
	Latest     map[string]string `json:"latest"`
}

// rebuild writes the catalog when it is enabled. A failed or deferred
// rebuild leaves it stale; Reconcile rebuilds it.
func (l Local) rebuild(r *os.Root) error {
	if !l.Catalog {
		return nil
	}
	if l.batch {
		catalogFresh.Delete(l.key())
		return nil
	}
	// Under the lock of a mutation the generation is odd and the unlock
	// bumps it once.
	g := generation(r)
	if g%2 != 0 {
		g++
	}
	bad, err := l.writeCatalog(r, g)
	if err != nil {
		catalogFresh.Delete(l.key())
	} else {
		catalogFresh.Store(l.key(), g)
	}
	return errors.Join(bad, err)
}

func (l Local) key() string { return path.Clean(l.Base) }

// writeCatalog builds the catalog from the readable sidecars; bad lists
// the entries left out.
func (l Local) writeCatalog(r *os.Root, gen int64) (bad, err error) {
	c := catalog{Version: 1, Generated: now().UTC().Format(time.RFC3339), Generation: gen, Files: []catalogEntry{}, Latest: map[string]string{}}
	bad = l.walk(r, func(rel string, sc Sidecar) error {
		switch {
		case sc.Private():
		case sc.AliasOf != "":
			c.Latest[rel] = sc.AliasOf
		default:
			f := catalogEntry{Name: rel, Size: sc.Size, SHA256: sc.SHA256, Created: sc.Received,
				Tags: sc.Client.Tags, Meta: sc.Meta}
			if f.Tags == nil {
				f.Tags = []string{}
			}
			if len(f.Meta) == 0 {
				f.Meta = json.RawMessage("{}")
			}
			c.Files = append(c.Files, f)
		}
		return nil
	})
	sort.Slice(c.Files, func(i, j int) bool { return c.Files[i].Name < c.Files[j].Name })
	b, err := json.Marshal(c)
	if err != nil {
		return bad, err
	}
	tmp, err := writeTemp(r, b)
	if err != nil {
		return bad, err
	}
	defer r.Remove(tmp)
	if err := r.Rename(tmp, catalogFile); err != nil {
		return bad, err
	}
	return bad, syncDir(r, DBDir)
}

// Reconcile repairs the aliases and the permanent names of the base and
// rebuilds the catalog when it is stale: after a failed or deferred
// rebuild, a repair, or the first call in this process. The janitor calls
// it every pass. The check runs without the lock, which is taken only to
// repair; a base without catalog, aliases and permanent names is skipped
// after the first call.
func (l Local) Reconcile() error {
	if has, known := aliasBases.Load(l.key()); !l.Catalog && len(l.Permanent) == 0 && known && !has.(bool) {
		return nil
	}
	r, err := os.OpenRoot(l.Base)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer r.Close()
	needed, any, derr := l.reconcileLinks(r, true)
	if derr != nil {
		if prev, ok := unreadable.Load(l.key()); !ok || prev.(string) != derr.Error() {
			needed = true
		}
	}
	if any {
		aliasBases.Store(l.key(), true)
	} else {
		aliasBases.LoadOrStore(l.key(), false)
	}
	if !needed && (!l.Catalog || l.fresh(r, generation(r))) {
		return derr
	}
	h, err := takeBase(l.Base, false)
	if err != nil {
		return errors.Join(derr, err)
	}
	defer h.unlock()
	stale := l.Catalog && !l.fresh(r, h.prev)
	if !stale {
		needed, _, derr = l.reconcileLinks(r, true)
		if !needed {
			if derr != nil {
				unreadable.Store(l.key(), derr.Error())
			} else {
				unreadable.Delete(l.key())
			}
			return derr
		}
	}
	if err := h.bump(); err != nil {
		return err
	}
	changed, _, err := l.reconcileLinks(r, false)
	if err != nil {
		unreadable.Store(l.key(), err.Error())
	} else {
		unreadable.Delete(l.key())
	}
	if l.Catalog && (stale || changed) {
		l.batch = false
		err = errors.Join(err, l.rebuild(r))
	}
	return err
}

// RebuildCatalog writes the catalog now, under the base lock; a no-op
// without catalog.
func (l Local) RebuildCatalog() error {
	if !l.Catalog {
		return nil
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
	l.batch = false
	return l.rebuild(r)
}

// fresh reports whether the catalog is current at the even generation g:
// built by this process at g, or by another one, as its generation field
// says.
func (l Local) fresh(r *os.Root, g int64) bool {
	if g%2 != 0 {
		return false
	}
	if v, ok := catalogFresh.Load(l.key()); ok && v.(int64) == g {
		return true
	}
	f, err := openRegular(r, catalogFile)
	if err != nil {
		return false
	}
	defer f.Close()
	var c struct {
		Generation int64 `json:"generation"`
	}
	if json.NewDecoder(f).Decode(&c) != nil || c.Generation != g {
		return false
	}
	catalogFresh.Store(l.key(), g)
	return true
}

// OpenCatalog opens the catalog file; fs.ErrNotExist when it is disabled
// or not built yet.
func (l Local) OpenCatalog() (*os.File, error) {
	if !l.Catalog {
		return nil, fmt.Errorf("%s: %w", CatalogName, fs.ErrNotExist)
	}
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return openRegular(r, catalogFile)
}
