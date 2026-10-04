package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"syscall"
)

// Entry is a name of a directory listing (Local.List): a stored file with
// its sidecar, or a directory (Dir).
type Entry struct {
	Name    string
	Dir     bool
	Sidecar Sidecar
}

// List returns the entries of the directory dir of the stored names (""
// for the top, else ending with a slash), read from the disk on every
// call: the stored files directly in it that show admits, and its
// directories holding at least one such file at any depth; directories
// first, each sorted by name ignoring case, names equal but for case in
// byte order. Reserved names (the catalog, nested exposes),
// symlinks and files without a sidecar are never listed; dot names are
// names like any other. An unknown directory has no entries.
// Unreadable subdirectories are skipped. It reads the layout of a storage without shard: an expose with index
// never serves a sharded storage.
func (l Local) List(dir string, show func(rel string, sc Sidecar) bool) ([]Entry, error) {
	return l.list(dir, show, false)
}

// HasEntries reports whether List of dir has an entry, stopping at the
// first one.
func (l Local) HasEntries(dir string, show func(rel string, sc Sidecar) bool) bool {
	ents, _ := l.list(dir, show, true)
	return len(ents) > 0
}

func (l Local) list(dir string, show func(rel string, sc Sidecar) bool, first bool) ([]Entry, error) {
	if dir != "" {
		if !strings.HasSuffix(dir, "/") {
			return nil, fmt.Errorf("%q: %w", dir, ErrInvalid)
		}
		if err := ValidName(strings.TrimSuffix(dir, "/")); err != nil {
			return nil, err
		}
	}
	if _, nests := l.Nests(strings.TrimSuffix(dir, "/")); dir != "" && nests {
		return nil, nil
	}
	r, err := os.OpenRoot(l.Base)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	d := strings.TrimSuffix(DataDir+"/"+dir, "/")
	if err := noSymlinks(r, d); err != nil {
		if errors.Is(err, ErrInvalid) {
			return nil, nil
		}
		return nil, err
	}
	des, err := fs.ReadDir(r.FS(), d)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	files, dirs := map[string]Sidecar{}, map[string]bool{}
	for _, e := range des {
		name := e.Name()
		rel := dir + name
		switch {
		case e.IsDir():
			if _, nests := l.Nests(rel); !nests && l.holds(r, rel, show) {
				dirs[name] = true
			}
		case e.Type().IsRegular():
			if sc, ok := l.shown(r, rel, show); ok {
				files[name] = sc
			}
		}
		if first && len(files)+len(dirs) > 0 {
			break
		}
	}
	ents := make([]Entry, 0, len(files)+len(dirs))
	for name := range dirs {
		ents = append(ents, Entry{Name: name, Dir: true})
	}
	for name, sc := range files {
		ents = append(ents, Entry{Name: name, Sidecar: sc})
	}
	sort.Slice(ents, func(i, j int) bool {
		if ents[i].Dir != ents[j].Dir {
			return ents[i].Dir
		}
		if a, b := strings.ToLower(ents[i].Name), strings.ToLower(ents[j].Name); a != b {
			return a < b
		}
		return ents[i].Name < ents[j].Name
	})
	return ents, nil
}

// shown reads the sidecar of the regular file of the stored name rel and
// reports whether it is listed.
func (l Local) shown(r *os.Root, rel string, show func(rel string, sc Sidecar) bool) (Sidecar, bool) {
	if l.reserved(rel) != nil {
		return Sidecar{}, false
	}
	sc, err := readSidecar(r, DataDir+"/"+rel)
	if err != nil || !show(rel, sc) {
		return Sidecar{}, false
	}
	return sc, true
}

// holds reports whether the directory of the stored name rel holds a
// listed file at any depth.
func (l Local) holds(r *os.Root, rel string, show func(rel string, sc Sidecar) bool) bool {
	top := DataDir + "/"
	found := false
	_ = fs.WalkDir(r.FS(), top+rel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := p[len(top):]
		if d.IsDir() {
			if _, nests := l.Nests(name); nests {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if _, ok := l.shown(r, name, show); ok {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}
