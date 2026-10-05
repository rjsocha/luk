// Package store keeps uploaded files under a local base directory in two
// trees: DataDir holds only the stored files, under their stored names, and
// DBDir everything else (lock, sidecars, content objects, catalog, claimed
// copies, temporary files). Each stored file has a JSON sidecar in the
// mirror tree DBDir/meta. Every filesystem access goes through an os.Root on
// the base, and existing symlinks under the base are refused on top of that.
//
// Stored files and the queue payload are immutable (the payload is 0440): a
// store is a hardlink of the queue file when possible, and run step work
// directories hardlink them too. A run program must not modify its input.
//
// A local base is one local filesystem (no mount points inside, no NFS or
// CIFS). Several lukd processes may share it: mutations take the flock of
// LockName, which must never be removed. Staging of a Put is protected
// from Sweep within one process only, so Put and Sweep stay in the process
// role (lukd process).
//
// A stored name rel lies on disk at file/<rel>; with Shard N at
// file/<h1>/.../<hN>/<rel>, the hN being the first hex pairs of
// sha256(rel). Its sidecar mirrors that path under .db/meta
// (.db/meta/<h1>/.../<hN>/<rel>.json). Every API takes and reports stored
// names; a file outside that layout is foreign and ignored.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"luk/internal/config"
	"luk/internal/wire"
)

const (
	// DBDir holds everything of a base that is not a stored file.
	DBDir = ".db"
	// DataDir holds the stored files and nothing else; any name is a stored
	// name there, a leading dot included.
	DataDir = "file"
	// ClaimedDir holds once files taken out of the served tree while they
	// are downloaded.
	ClaimedDir = DBDir + "/claimed"
)

const (
	metaDir = DBDir + "/meta"
	// tmpDir holds every temporary file of a base: staged copies and files
	// written before their rename into place.
	tmpDir = DBDir + "/tmp"
	maxVer = 999999
)

// ErrInvalid marks a refused name: empty, absolute, NUL, an empty, . or ..
// element, symlink.
var ErrInvalid = errors.New("invalid path")

var (
	now            = time.Now
	link           = os.Link
	hookAfterCheck = func() {}
	hookCopy       = func() {}
	hookRotate     = func(step int) {}
	// hookReplace runs in ReplaceStaged after the data rename (1) and
	// after the sidecar rename (2); an error fails it there.
	hookReplace = func(step int) error { return nil }
)

// LockName is the lock file of a base. Every mutation of the base, by any
// lukd process, holds an exclusive flock on it; its size is the generation
// of the base: odd while a mutation runs, bumped at its start and its end,
// so a reader that saw the same even size before and after needs no lock.
// The size of an inode is read and changed atomically, unlike file content.
const LockName = DBDir + "/lock"

// baseLock serializes the mutations of one base in this process before the
// flock. staging holds the temporary names a Put staged outside the lock,
// which Sweep leaves alone.
type baseLock struct {
	mu      sync.Mutex
	staging sync.Map
}

var baseLocks sync.Map

func baseOf(base string) *baseLock {
	m, _ := baseLocks.LoadOrStore(filepath.Clean(base), &baseLock{})
	return m.(*baseLock)
}

// held is a taken base lock; prev is the generation before it.
type held struct {
	b    *baseLock
	f    *os.File
	prev int64
	gen  int64
	// dirty keeps the generation odd at unlock: the mutation left the
	// base for the next taker of the lock to repair.
	dirty bool
}

// lockBase takes the lock of a base for a mutation.
func lockBase(base string) (*held, error) { return takeBase(base, true) }

// takeBase takes the lock of a base; without mutate the generation is left
// alone until bump.
func takeBase(base string, mutate bool) (*held, error) {
	b := baseOf(base)
	b.mu.Lock()
	h := &held{b: b}
	err := h.take(base)
	if err == nil && mutate {
		err = h.bump()
	}
	if err != nil {
		h.unlock()
		return nil, err
	}
	return h, nil
}

// take opens and flocks the lock file; when the file was replaced or
// removed meanwhile, the lock of the old inode is worthless and it starts
// again.
func (h *held) take(base string) error {
	if err := ensureDB(base); err != nil {
		return fmt.Errorf("base lock: %w", err)
	}
	p := filepath.Join(base, LockName)
	for range 100 {
		f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o640)
		if err != nil {
			return fmt.Errorf("base lock: %w", err)
		}
		for {
			err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
			if err != syscall.EINTR {
				break
			}
		}
		var fi, cur fs.FileInfo
		if err == nil {
			fi, err = f.Stat()
		}
		if err == nil {
			cur, err = os.Lstat(p)
			if errors.Is(err, fs.ErrNotExist) {
				f.Close()
				continue
			}
		}
		if err != nil {
			f.Close()
			return fmt.Errorf("base lock: %w", err)
		}
		if !os.SameFile(fi, cur) {
			f.Close()
			continue
		}
		h.f, h.prev, h.gen = f, fi.Size(), fi.Size()
		done, err := rollBackReplace(base)
		if err == nil && done {
			err = h.bump()
		}
		if err != nil {
			f.Close()
			h.f = nil
			return fmt.Errorf("base lock: %w", err)
		}
		return nil
	}
	return fmt.Errorf("base lock: %s keeps being replaced", p)
}

// ensureDB creates DBDir of base when missing; it must be a real directory.
func ensureDB(base string) error {
	p := filepath.Join(base, DBDir)
	if err := os.Mkdir(p, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory", p)
	}
	return nil
}

// CheckLayout refuses a base holding anything at its top but DBDir and
// DataDir, both real directories: a base of an older layout or a directory
// that is no storage base. A missing base is fine.
func CheckLayout(base string) error {
	des, err := os.ReadDir(base)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var foreign []string
	for _, d := range des {
		switch n := d.Name(); {
		case n != DBDir && n != DataDir:
			foreign = append(foreign, n)
		case !d.IsDir():
			return fmt.Errorf("%s: %s is not a directory", base, n)
		}
	}
	if len(foreign) == 0 {
		return nil
	}
	if len(foreign) > 5 {
		foreign = append(foreign[:5], "...")
	}
	return fmt.Errorf("%s: holds %s besides %s/ and %s/: not a storage base of this layout (move its content away and empty it)",
		base, strings.Join(foreign, ", "), DBDir, DataDir)
}

// intentName records a Replace between its renames (see replaceIntent).
const intentName = DBDir + "/replace"

// replaceIntent is the record of a Replace in progress: the data and
// sidecar of the name, on disk, and the second names in tmpDir that keep
// their old versions meanwhile. It is synced before the first rename and
// removed (synced) after the last one, before the second names go. While
// it exists the base may hold the new data under the old sidecar (a
// crash between the renames); whoever takes the base lock next puts the
// old data and sidecar back (rollBackReplace).
type replaceIntent struct {
	Data       string `json:"data"`
	Sidecar    string `json:"sidecar"`
	OldData    string `json:"old_data"`
	OldSidecar string `json:"old_sidecar"`
}

// writeIntent syncs the second names of in and records in at intentName.
func writeIntent(r *os.Root, in replaceIntent) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if err := syncDir(r, tmpDir); err != nil {
		return err
	}
	tmp, err := writeTemp(r, b)
	if err != nil {
		return err
	}
	if err := r.Rename(tmp, intentName); err != nil {
		r.Remove(tmp)
		return err
	}
	return syncDir(r, DBDir)
}

// dropIntent removes the record of a Replace whose renames are done or
// undone.
func dropIntent(r *os.Root) error {
	if err := r.Remove(intentName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(r, DBDir)
}

// rollBackReplace puts back the old data and sidecar a Replace recorded
// at intentName, under the base lock: each second name still present is
// renamed over the name it keeps (a no-op for the same inode, then
// removed). done reports that there was a record; it is removed only
// once all is back.
func rollBackReplace(base string) (done bool, err error) {
	if _, err := os.Lstat(filepath.Join(base, intentName)); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	r, err := os.OpenRoot(base)
	if err != nil {
		return true, err
	}
	defer r.Close()
	return true, rollBack(r)
}

func rollBack(r *os.Root) error {
	b, err := r.ReadFile(intentName)
	if err != nil {
		return err
	}
	var in replaceIntent
	if err := json.Unmarshal(b, &in); err != nil {
		return fmt.Errorf("%s: %w", intentName, err)
	}
	for _, p := range [][2]string{{in.OldData, in.Data}, {in.OldSidecar, in.Sidecar}} {
		old, cur := p[0], p[1]
		if !strings.HasPrefix(old, tmpDir+"/") || !filepath.IsLocal(old) || !filepath.IsLocal(cur) ||
			!strings.HasPrefix(cur, DataDir+"/") && !strings.HasPrefix(cur, metaDir+"/") {
			return fmt.Errorf("%s: invalid record %q", intentName, b)
		}
		if _, err := r.Lstat(old); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := r.Rename(old, cur); err != nil {
			return err
		}
		if err := r.Remove(old); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := syncDir(r, path.Dir(cur)); err != nil {
			return err
		}
	}
	if err := syncDir(r, tmpDir); err != nil {
		return err
	}
	return dropIntent(r)
}

// bump marks the start of a mutation: the generation becomes odd.
func (h *held) bump() error {
	if h.gen != h.prev {
		return nil
	}
	h.gen = h.prev + 1
	if h.prev%2 != 0 {
		// A mutation died holding it; keep it odd.
		h.gen++
	}
	if err := h.f.Truncate(h.gen); err != nil {
		return fmt.Errorf("base lock: %w", err)
	}
	return nil
}

// unlock ends the mutation: the generation becomes even again.
func (h *held) unlock() {
	if h.f != nil {
		if h.gen%2 != 0 && !h.dirty {
			h.f.Truncate(h.gen + 1)
		}
		h.f.Close()
	}
	h.b.mu.Unlock()
}

// generation is the generation of the base read without the lock: 0 before
// the first mutation, -1 when unreadable.
func generation(r *os.Root) int64 {
	fi, err := r.Lstat(LockName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return 0
	case err != nil || !fi.Mode().IsRegular():
		return -1
	}
	return fi.Size()
}

// Vars are the values of a path template. Time is when the upload was
// received, in UTC. Hostname is the client backup.hostname, empty without
// --backup. Randoms holds the .Random of the storages with their own
// random alphabet, by storage name.
type Vars struct {
	Sender, Endpoint, Id, Random, File, Hostname string
	Time                                         time.Time
	Tags                                         []string
	Randoms                                      map[string]string `json:",omitempty"`
}

// For returns v with the .Random of storage name.
func (v Vars) For(name string) Vars {
	if r, ok := v.Randoms[name]; ok {
		v.Random = r
	}
	return v
}

// RandomName draws n characters uniformly from alphabet (at most 256
// distinct bytes) with crypto/rand, rejecting the bytes past the last whole
// multiple of len(alphabet) so no character is favoured.
func RandomName(alphabet string, n int) string {
	k := len(alphabet)
	limit := 256 - 256%k
	out := make([]byte, 0, n)
	buf := make([]byte, n+n/2+8)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		for _, b := range buf {
			if int(b) < limit && len(out) < n {
				out = append(out, alphabet[int(b)%k])
			}
		}
	}
	return string(out)
}

// Proquint spells b (an even number of bytes) as proquints: each 16 bits
// big-endian are consonant-vowel-consonant-vowel-consonant, the groups
// joined with "-" (0x7f000001 is "lusab-babad").
func Proquint(b []byte) string {
	const cons, vows = "bdfghjklmnprstvz", "aiou"
	groups := make([]string, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		w := uint16(b[i])<<8 | uint16(b[i+1])
		groups = append(groups, string([]byte{
			cons[w>>12], vows[w>>10&3], cons[w>>6&15], vows[w>>4&3], cons[w&15],
		}))
	}
	return strings.Join(groups, "-")
}

// PrettyName is a proquint of bits (a multiple of 16) from crypto/rand.
func PrettyName(bits int) string {
	b := make([]byte, bits/8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return Proquint(b)
}

func (v Vars) TemplateData() map[string]any {
	file := v.File
	if file == "" {
		file = v.Id
	}
	origin := v.Hostname
	if origin == "" {
		origin = v.Sender
	}
	return map[string]any{
		"Sender": v.Sender, "Endpoint": v.Endpoint, "Id": v.Id,
		"Year": v.Time.Format("2006"), "Month": v.Time.Format("01"), "Day": v.Time.Format("02"),
		"Hour": v.Time.Format("15"), "Minute": v.Time.Format("04"), "Seconds": v.Time.Format("05"),
		"Random": v.Random, "File": file, "Tags": strings.Join(v.Tags, "-"),
		"Hostname": v.Hostname, "Origin": origin,
	}
}

// Render executes a path template and returns a clean relative path. An
// empty .Hostname that leaves an empty element fails the path; other empty
// elements are cleaned away.
func Render(t *template.Template, v Vars) (string, error) {
	s, err := execute(t, v)
	if err != nil {
		return "", err
	}
	if v.Hostname == "" && (strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.Contains(s, "//")) {
		w := v
		w.Hostname = "h"
		if ws, err := execute(t, w); err == nil && ws != s {
			return "", fmt.Errorf("storage path %q needs a hostname (luk send --backup): %w", s, ErrInvalid)
		}
	}
	switch {
	case s == "":
		return "", fmt.Errorf("storage path is empty: %w", ErrInvalid)
	case strings.HasPrefix(s, "/"):
		return "", fmt.Errorf("storage path %q is absolute: %w", s, ErrInvalid)
	case strings.ContainsRune(s, 0):
		return "", fmt.Errorf("storage path %q holds a NUL byte: %w", s, ErrInvalid)
	}
	for _, e := range strings.Split(s, "/") {
		if e == "." || e == ".." {
			return "", fmt.Errorf("storage path %q: element %q is not a name: %w", s, e, ErrInvalid)
		}
	}
	return path.Clean(s), nil
}

// ValidName refuses a stored name that is empty, absolute or holds a NUL
// byte or an empty, . or .. element. Any other element is a name, a leading
// dot included.
func ValidName(rel string) error {
	switch {
	case rel == "":
		return fmt.Errorf("empty name: %w", ErrInvalid)
	case strings.HasPrefix(rel, "/"):
		return fmt.Errorf("%q is absolute: %w", rel, ErrInvalid)
	case strings.ContainsRune(rel, 0):
		return fmt.Errorf("%q holds a NUL byte: %w", rel, ErrInvalid)
	}
	for _, e := range strings.Split(rel, "/") {
		switch e {
		case "":
			return fmt.Errorf("%q has an empty element: %w", rel, ErrInvalid)
		case ".", "..":
			return fmt.Errorf("%q: element %q is not a name: %w", rel, e, ErrInvalid)
		}
	}
	return nil
}

func execute(t *template.Template, v Vars) (string, error) {
	var b strings.Builder
	if err := t.Execute(&b, v.TemplateData()); err != nil {
		return "", err
	}
	return b.String(), nil
}

type Sidecar struct {
	ID       string    `json:"id"`
	Sender   string    `json:"sender"`
	Endpoint string    `json:"endpoint"`
	Received string    `json:"received"`
	Size     int64     `json:"size"`
	SHA256   string    `json:"sha256"`
	Expires  string    `json:"expires,omitempty"`
	Client   wire.Meta `json:"client"`
	// Owner is what the portal pages show as the sender of the upload
	// (empty with no_owner): the key name, or "host" or "user" for a
	// certificate.
	Owner string `json:"owner,omitempty"`
	// OwnerKey is who may manage the link of the upload (see
	// auth.OwnerKey); never shown.
	OwnerKey string `json:"owner_key,omitempty"`
	// Updated is when the content was last replaced through its link.
	Updated string `json:"updated,omitempty"`
	// Pipeline is the pipeline that stored the file and Origin the .Origin
	// of its upload (the backup hostname, else the sender); with the file
	// name they make the retention series of the file (see SeriesOf).
	// Files stored before these fields have neither.
	Pipeline string `json:"pipeline,omitempty"`
	Origin   string `json:"origin,omitempty"`
	// Produced is the name of a file written by a run step; empty for the
	// uploaded payload.
	Produced string `json:"produced,omitempty"`
	// Meta is the pipeline meta of the file, from a run step.
	Meta json.RawMessage `json:"meta,omitempty"`
	// AliasOf marks an alias: the stored path of its target, whose sidecar
	// this is a copy of.
	AliasOf string `json:"alias_of,omitempty"`
	// PermanentPath is the permanent.path of the endpoint when the upload
	// of a permanent name (client permanent) was accepted: the namespace
	// the version belongs to.
	PermanentPath string `json:"permanent_path,omitempty"`
}

// Local is a storage under Base; Conflict is version (default), reject or
// replace; Catalog keeps <base>/.db/catalog.json.
//
// A file whose pipeline meta has `alias` gets file/<alias> as a hardlink
// while it is the newest (by received, then by name) file declaring it;
// every removal of a target moves the alias to the next newest or removes
// it. An alias is not a stored file of its own: it never expires, claiming
// it claims its target, and a stored path never replaces it. Once and
// portal uploads are never alias targets. An alias equal to the file's own
// stored path is ignored.
type Local struct {
	Base     string
	Conflict string
	Catalog  bool
	Shard    int
	// Dedup, with conflict version, keeps the newest version of the path
	// instead of adding one with the same size and sha256.
	Dedup bool
	// Hardlink keeps the content objects (see ObjectsDir): a store of
	// content that has an object places a hardlink of it, and stored files
	// become objects.
	Hardlink bool
	// MaxLinks, with Hardlink, is the most stored names holding one content
	// that one owner key may have here: a store of one more fails with
	// TooManyLinks. 0 is no limit.
	MaxLinks int
	// Nested is the paths of the exposes nested in the expose of the
	// storage, relative to it and ending with a slash (config
	// Storage.Nested): no stored name lies under them.
	Nested []string
	// Permanent maps the endpoints with permanent names whose respond
	// storage this is to their permanent block (config
	// Storage.Permanents): no stored name lies under a permanent.path,
	// and the uploads of the names they allocate are published as
	// permanent names (see PermanentDir).
	Permanent map[string]*config.Permanent

	batch bool
}

// SafeJoin joins the name rel to the data tree of base (without shard),
// refusing invalid names (see ValidName) and existing symlinks along the
// path.
func SafeJoin(base, rel string) (string, error) {
	r, err := os.OpenRoot(base)
	if err != nil {
		return "", err
	}
	defer r.Close()
	if err := ValidName(rel); err != nil {
		return "", err
	}
	if err := noSymlinks(r, DataDir+"/"+rel); err != nil {
		return "", err
	}
	return filepath.Join(base, DataDir, filepath.FromSlash(rel)), nil
}

// checkName is path without the path.
func (l Local) checkName(r *os.Root, rel string) error {
	_, err := l.path(r, rel)
	return err
}

// path validates the stored name rel (see ValidName) and returns its path
// on disk, refusing any existing symlink along it.
func (l Local) path(r *os.Root, rel string) (string, error) {
	if err := ValidName(rel); err != nil {
		return "", err
	}
	p := l.phys(rel)
	return p, noSymlinks(r, p)
}

// noSymlinks refuses any existing symlink along rel.
func noSymlinks(r *os.Root, rel string) error {
	elems := strings.Split(rel, "/")
	for i := range elems {
		fi, err := r.Lstat(strings.Join(elems[:i+1], "/"))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%q: symlink: %w", rel, ErrInvalid)
		}
	}
	return nil
}

// phys is the path on disk of the stored name rel.
func (l Local) phys(rel string) string {
	if l.Shard <= 0 {
		return DataDir + "/" + rel
	}
	h := sha256.Sum256([]byte(rel))
	x := hex.EncodeToString(h[:l.Shard])
	var b strings.Builder
	b.WriteString(DataDir + "/")
	for i := 0; i < len(x); i += 2 {
		b.WriteString(x[i : i+2])
		b.WriteByte('/')
	}
	b.WriteString(rel)
	return b.String()
}

// logical is the stored name of the path p on disk; false for a path
// outside the data tree or the shard layout.
func (l Local) logical(p string) (string, bool) {
	q, ok := strings.CutPrefix(p, DataDir+"/")
	if !ok || q == "" {
		return "", false
	}
	if l.Shard <= 0 {
		return q, true
	}
	elems := strings.SplitN(q, "/", l.Shard+1)
	if len(elems) <= l.Shard {
		return "", false
	}
	rel := elems[l.Shard]
	return rel, l.phys(rel) == p
}

func hexPair(s string) bool {
	return len(s) == 2 && strings.Trim(s, "0123456789abcdef") == ""
}

// SidecarPath is the sidecar file of the stored name rel.
func (l Local) SidecarPath(rel string) string {
	return filepath.Join(l.Base, filepath.FromSlash(sidecarRel(l.phys(rel))))
}

// sidecarRel is the sidecar of the path on disk p of a stored file.
func sidecarRel(p string) string {
	return metaDir + "/" + strings.TrimPrefix(p, DataDir+"/") + ".json"
}

// dataOf is the path on disk of the stored file of the sidecar srel.
func dataOf(srel string) string {
	return DataDir + "/" + strings.TrimSuffix(strings.TrimPrefix(srel, metaDir+"/"), ".json")
}

// mkdirs creates the directories of rel, syncing the parent of each new one.
func mkdirs(r *os.Root, rel string) error {
	if rel == "." {
		return nil
	}
	elems := strings.Split(rel, "/")
	for i := range elems {
		p := strings.Join(elems[:i+1], "/")
		err := r.Mkdir(p, 0o750)
		if err == nil {
			err = syncDir(r, path.Dir(p))
		}
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		fi, err := r.Lstat(p)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s: not a directory", p)
		}
	}
	return nil
}

// prune removes the directories of the path on disk p left empty, walking
// up to the top of its tree (DataDir, or a directory directly in DBDir),
// which stays; a symlink or a directory that is not empty stops it. It
// runs under the base lock, the one a Put holds from creating its
// directories to placing its files.
func prune(r *os.Root, p string) {
	for dir := path.Dir(p); !treeTop(dir); dir = path.Dir(dir) {
		if rmdir(r, dir) != nil {
			return
		}
	}
}

func treeTop(dir string) bool {
	return dir == "." || dir == DataDir || dir == DBDir || path.Dir(dir) == DBDir
}

// rmdir removes dir when it is an empty directory, never a symlink.
func rmdir(r *os.Root, dir string) error {
	fi, err := r.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory", dir)
	}
	return r.Remove(dir)
}

func syncDir(r *os.Root, dir string) error {
	d, err := r.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// tmpName is a new name in tmpDir, which it creates when missing.
func tmpName(r *os.Root) (string, error) {
	if err := mkdirs(r, tmpDir); err != nil {
		return "", err
	}
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return tmpDir + "/" + hex.EncodeToString(b), nil
}

// stage puts a copy of src in tmpDir under the temporary name tmp: a
// hardlink when possible, else a synced copy. The hardlink target is a
// new name in tmpDir, a real directory (see mkdirs), so it cannot be
// redirected.
func stage(r *os.Root, base, src, tmp string) (fs.FileInfo, error) {
	if link(src, filepath.Join(base, tmp)) != nil {
		if err := copyTo(r, src, tmp); err != nil {
			return nil, err
		}
	}
	fi, err := r.Lstat(tmp)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		r.Remove(tmp)
		return nil, fmt.Errorf("%s: not a regular file: %w", src, ErrInvalid)
	}
	return fi, nil
}

func copyTo(r *os.Root, src, tmp string) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	if fi, err := in.Stat(); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file: %w", src, ErrInvalid)
	}
	out, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	hookCopy()
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		r.Remove(tmp)
	}
	return err
}

func writeTemp(r *os.Root, b []byte) (string, error) {
	tmp, err := tmpName(r)
	if err != nil {
		return "", err
	}
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return "", err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		r.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// Put stores a copy of src at rel (resolving conflicts) with its sidecar and
// returns the final relative path. src is left in place. The sidecar is
// prepared before the data is placed, and a failure afterwards removes only
// what this call placed, so no sidecar is left describing other content.
// A non-empty path with an error means the file is stored but its alias
// was not updated. The copy is staged before the base lock is taken.
func (l Local) Put(src, rel string, sc Sidecar) (string, error) {
	res, err := l.Store(src, rel, sc)
	return res.Rel, err
}

// Stored is the outcome of Store: the final relative path, whether it
// is an existing version kept by Dedup, with nothing placed, and the
// versions of its permanent name the store removed beyond keep.
type Stored struct {
	Rel    string
	Dedup  bool
	Pruned []PermanentVersion
}

// Store is Put reporting a deduplicated store.
func (l Local) Store(src, rel string, sc Sidecar) (Stored, error) {
	s, err := l.Stage(src)
	if err != nil {
		return Stored{}, err
	}
	defer s.Drop()
	return l.StoreStaged(s, rel, sc)
}

// Staged is a copy of a file under a temporary name of a base (see
// Stage), for StoreStaged or ReplaceStaged to place; Drop removes
// what is left of it.
type Staged struct {
	base, src, tmp string
	fi             fs.FileInfo
}

// Stage puts a copy of src (a hardlink when possible) under a temporary
// name of the base, outside the base lock, so that placing it later only
// renames. Sweep leaves it alone until Drop.
func (l Local) Stage(src string) (*Staged, error) {
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b := baseOf(l.Base)
	tmp, err := tmpName(r)
	if err != nil {
		return nil, err
	}
	b.staging.Store(tmp, true)
	fi, err := stage(r, l.Base, src, tmp)
	if err != nil {
		b.staging.Delete(tmp)
		return nil, err
	}
	return &Staged{base: l.Base, src: src, tmp: tmp, fi: fi}, nil
}

// Drop removes the staged copy when it was not placed; nil or a dropped
// copy is fine.
func (s *Staged) Drop() {
	if s == nil || s.tmp == "" {
		return
	}
	if r, err := os.OpenRoot(s.base); err == nil {
		r.Remove(s.tmp)
		r.Close()
	}
	baseOf(s.base).staging.Delete(s.tmp)
	s.tmp = ""
}

// staged checks that s is a copy staged in this base and not dropped.
func (l Local) staged(s *Staged) error {
	if s == nil || s.tmp == "" || filepath.Clean(s.base) != filepath.Clean(l.Base) {
		return fmt.Errorf("no copy staged in %s: %w", l.Base, ErrInvalid)
	}
	return nil
}

// StoreStaged is Store of the copy s staged in this base.
func (l Local) StoreStaged(s *Staged, rel string, sc Sidecar) (Stored, error) {
	if err := l.staged(s); err != nil {
		return Stored{}, err
	}
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return Stored{}, err
	}
	defer r.Close()
	src, tmp, staged := s.src, s.tmp, s.fi
	h, err := lockBase(l.Base)
	if err != nil {
		return Stored{}, err
	}
	defer h.unlock()
	sc.AliasOf = ""
	p, err := l.path(r, rel)
	if err != nil {
		return Stored{}, err
	}
	if err := noSymlinks(r, sidecarRel(p)); err != nil {
		return Stored{}, err
	}
	if err := l.reserved(rel); err != nil {
		return Stored{}, err
	}
	alias, err := sc.alias()
	if err != nil {
		return Stored{}, err
	}
	if alias == rel {
		alias = ""
	}
	if alias != "" {
		if err := l.checkAlias(r, alias, sc); err != nil {
			return Stored{}, err
		}
		aliasBases.Store(l.key(), true)
	}
	oldAlias := ""
	prev, perr := readSidecar(r, p)
	if perr == nil {
		if prev.AliasOf != "" {
			return Stored{}, fmt.Errorf("%q: an alias: %w", rel, ErrInvalid)
		}
		oldAlias, _ = prev.alias()
	}
	if err := l.admitPermanent(r, sc); err != nil {
		return Stored{}, err
	}
	if otmp, ofi, ok := l.fromObject(r, sc); ok {
		defer r.Remove(otmp)
		tmp, staged = otmp, ofi
	}
	stored, old, dedup, err := l.put(r, src, tmp, staged, rel, sc)
	if err != nil || dedup {
		if dedup && err == nil {
			// A retry of a store whose publish failed finds its file.
			err = l.syncPermanent(r, l.permanentKey(sc))
		}
		return Stored{Rel: stored, Dedup: dedup}, err
	}
	l.track(r, rel, stored, old, prev, perr == nil, sc)
	if oldAlias != "" && oldAlias != alias && stored == rel {
		err = l.repoint(r, oldAlias, rel)
	}
	if alias != "" && alias != stored {
		err = errors.Join(err, l.pointAlias(r, alias, stored, sc))
	}
	key := l.permanentKey(sc)
	if pk := l.permanentKey(prev); perr == nil && pk != "" && pk != key {
		err = errors.Join(err, l.syncPermanent(r, pk))
	}
	err = errors.Join(err, l.syncPermanent(r, key))
	pruned, perr2 := l.prunePermanent(r, h, sc)
	l.rebuild(r)
	return Stored{Rel: stored, Pruned: pruned}, errors.Join(err, perr2)
}

func (l Local) versioning() bool { return l.Conflict != "replace" && l.Conflict != "reject" }

// track brings the objects up to date after a store placed sc at stored:
// prev, the sidecar rel had, left rel or went with its content to the
// version old, and stored holds the content of sc. Errors are left to
// MaintainObjects, which rebuilds the indexes.
func (l Local) track(r *os.Root, rel, stored, old string, prev Sidecar, hadPrev bool, sc Sidecar) {
	if hadPrev && stored == rel {
		l.dropName(r, rel, prev)
		if old != "" {
			if vsc, err := readSidecar(r, l.phys(old)); err == nil {
				l.addName(r, old, vsc)
			}
		}
	}
	l.linkObject(r, l.phys(stored), sc)
	l.addName(r, stored, sc)
}

// put places tmp (staged) at rel and returns the stored path, the version
// an existing file went to, and whether Dedup kept the newest version.
func (l Local) put(r *os.Root, src, tmp string, staged fs.FileInfo, rel string, sc Sidecar) (_ string, _ string, _ bool, err error) {
	p := l.phys(rel)
	srel := sidecarRel(p)
	defer func() {
		if err != nil {
			prune(r, p)
			prune(r, srel)
		}
	}()
	if err := mkdirs(r, path.Dir(p)); err != nil {
		return "", "", false, err
	}
	if err := mkdirs(r, path.Dir(srel)); err != nil {
		return "", "", false, err
	}
	hookAfterCheck()
	b, err := json.Marshal(sc)
	if err != nil {
		return "", "", false, err
	}
	stmp, err := writeTemp(r, b)
	if err != nil {
		return "", "", false, err
	}
	defer r.Remove(stmp)
	var vers []string
	if l.versioning() {
		vers = l.versions(r, rel)
	}
	if stored, err := l.resume(r, src, rel, sc, stmp, vers); stored != "" || err != nil {
		return stored, "", false, err
	}
	if l.duplicate(r, rel, sc, vers) {
		return rel, "", true, nil
	}
	// Without versions the name rel, when it holds the content, is replaced.
	skip := ""
	if !l.versioning() {
		skip = rel
	}
	if err := l.overLinks(r, sc, skip); err != nil {
		return "", "", false, err
	}
	old, backup := "", ""
	if l.versioning() {
		old, err = l.rotate(r, tmp, rel, vers)
	} else {
		// A replaced file keeps a second name until the new sidecar is
		// placed, to be put back on a failure.
		if backup, err = l.backup(r, p); err != nil {
			return "", "", false, err
		}
		if backup != "" {
			defer r.Remove(backup)
		}
		err = l.place(r, tmp, rel)
	}
	if err != nil {
		return "", "", false, err
	}
	placed := false
	err = syncDir(r, path.Dir(p))
	if err == nil {
		err = noSymlinks(r, srel)
	}
	if err == nil {
		err = r.Rename(stmp, srel)
		placed = err == nil
	}
	if err == nil {
		err = syncDir(r, path.Dir(srel))
	}
	if err != nil {
		if fi, lerr := r.Lstat(p); lerr == nil && os.SameFile(fi, staged) {
			switch {
			case old != "":
				l.restore(r, rel, old, placed)
			case backup != "" && !placed:
				r.Rename(backup, p)
			default:
				r.Remove(p)
				r.Remove(srel)
			}
		}
		return "", "", false, err
	}
	return rel, old, false, nil
}

// resume finishes a Put of the same file interrupted by a crash or a
// stop: rel already has a sidecar with the id, produced name, size and
// sha256 of sc, or has no sidecar and holds the content of src (placed
// before the sidecar); with conflict version one of its versions has such
// a sidecar, or a rotation placed the content of src at rel but not its
// sidecar yet. It returns that stored path, with the sidecar placed from
// stmp when missing.
func (l Local) resume(r *os.Root, src, rel string, sc Sidecar, stmp string, vers []string) (string, error) {
	if ok, err := adopt(r, src, l.phys(rel), sc, stmp, true); ok || err != nil {
		return rel, err
	}
	for _, v := range vers {
		if ok, err := adopt(r, src, l.phys(v), sc, stmp, false); ok || err != nil {
			return v, err
		}
	}
	if len(vers) == 0 {
		return "", nil
	}
	p := l.phys(rel)
	fi, err := r.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return "", nil
	}
	cur, err := readSidecar(r, p)
	if err != nil || !l.stale(r, cur, fi, vers) || !sameContent(r, src, p, fi, sc) {
		return "", nil
	}
	srel := sidecarRel(p)
	if err := noSymlinks(r, srel); err != nil {
		return rel, err
	}
	if err := r.Rename(stmp, srel); err != nil {
		return rel, err
	}
	return rel, syncDir(r, path.Dir(srel))
}

var versionSuffix = regexp.MustCompile(`^\.[0-9]+(\.[0-9]{6})?$`)

func sameVersion(a, b Sidecar) bool {
	return a.AliasOf == "" && b.AliasOf == "" && a.ID == b.ID && a.Produced == b.Produced && a.Size == b.Size && a.SHA256 == b.SHA256
}

// stale reports whether cur, the sidecar at a rel whose data is fi, is
// left from a rotation that placed new data at rel but not its sidecar: a
// version holds the same sidecar and other data.
func (l Local) stale(r *os.Root, cur Sidecar, fi fs.FileInfo, vers []string) bool {
	found := false
	for _, v := range vers {
		vp := l.phys(v)
		vsc, err := readSidecar(r, vp)
		if err != nil || !sameVersion(vsc, cur) {
			continue
		}
		if vfi, err := r.Lstat(vp); err == nil && os.SameFile(vfi, fi) {
			return false
		}
		found = true
	}
	return found
}

// duplicate reports whether Dedup applies and rel, the newest version,
// has the size and sha256 of sc; once, portal, private and expiring files are
// never shared.
func (l Local) duplicate(r *os.Root, rel string, sc Sidecar, vers []string) bool {
	if !l.Dedup || !l.versioning() || sc.SHA256 == "" || sc.Private() || sc.Expires != "" {
		return false
	}
	p := l.phys(rel)
	fi, err := r.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	cur, err := readSidecar(r, p)
	if err != nil || l.stale(r, cur, fi, vers) || cur.AliasOf != "" || cur.Private() || cur.Expires != "" || cur.Size != sc.Size || cur.SHA256 != sc.SHA256 {
		return false
	}
	return true
}

// versions lists the existing versions of rel. With sharding they lie
// elsewhere, so the data tree is scanned, only while rel exists: a version
// is only placed next to an existing rel.
func (l Local) versions(r *os.Root, rel string) []string {
	if l.Shard > 0 {
		if fi, err := r.Lstat(l.phys(rel)); err != nil || !fi.Mode().IsRegular() {
			return nil
		}
		var out []string
		l.files(r, func(_, name string) error {
			if rest, ok := strings.CutPrefix(name, rel); ok && versionSuffix.MatchString(rest) {
				out = append(out, name)
			}
			return nil
		})
		return out
	}
	des, err := fs.ReadDir(r.FS(), path.Dir(l.phys(rel)))
	if err != nil {
		return nil
	}
	base := path.Base(rel)
	var out []string
	for _, d := range des {
		if rest, ok := strings.CutPrefix(d.Name(), base); ok && versionSuffix.MatchString(rest) {
			out = append(out, path.Join(path.Dir(rel), d.Name()))
		}
	}
	return out
}

// adopt reports whether the path on disk rel is the file of sc; bare
// also accepts rel without a sidecar holding the content of src, and
// places the sidecar from stmp.
func adopt(r *os.Root, src, rel string, sc Sidecar, stmp string, bare bool) (bool, error) {
	fi, err := r.Lstat(rel)
	if err != nil || !fi.Mode().IsRegular() {
		return false, nil
	}
	cur, err := readSidecar(r, rel)
	if err == nil {
		return sc.ID != "" && cur.AliasOf == "" && cur.ID == sc.ID && cur.Produced == sc.Produced && cur.Size == sc.Size && cur.SHA256 == sc.SHA256, nil
	}
	if !bare || !errors.Is(err, fs.ErrNotExist) || !sameContent(r, src, rel, fi, sc) {
		return false, nil
	}
	srel := sidecarRel(rel)
	if err := mkdirs(r, path.Dir(srel)); err != nil {
		return true, err
	}
	if err := noSymlinks(r, srel); err != nil {
		return true, err
	}
	if err := r.Rename(stmp, srel); err != nil {
		return true, err
	}
	return true, syncDir(r, path.Dir(srel))
}

// sameContent reports whether rel is src itself, or has the size and
// sha256 sc gives for it.
func sameContent(r *os.Root, src, rel string, fi fs.FileInfo, sc Sidecar) bool {
	if sfi, err := os.Stat(src); err == nil && os.SameFile(fi, sfi) {
		return true
	}
	if sc.SHA256 == "" || fi.Size() != sc.Size {
		return false
	}
	f, err := openRegular(r, rel)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == sc.SHA256
}

// backup links the existing regular file at the path on disk p, for a
// replace, to a temporary name; "" when there is none.
func (l Local) backup(r *os.Root, p string) (string, error) {
	if l.Conflict != "replace" {
		return "", nil
	}
	if fi, err := r.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return "", nil
	}
	tmp, err := tmpName(r)
	if err != nil {
		return "", err
	}
	if err := r.Link(p, tmp); err != nil {
		return "", err
	}
	return tmp, nil
}

func (l Local) place(r *os.Root, tmp, rel string) error {
	if l.Conflict == "replace" {
		return r.Rename(tmp, l.phys(rel))
	}
	err := r.Link(tmp, l.phys(rel))
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s: exists: %w", rel, err)
	}
	return err
}

// rotate places tmp at rel. An existing file at rel is kept first as the
// version rel.<ts>, ts being its received time (else its mtime): a
// hardlink with a copy of its sidecar, or the copy an interrupted rotation
// already made. Only then the new data replaces rel, so a crash never
// loses a version. It returns that version.
func (l Local) rotate(r *os.Root, tmp, rel string, vers []string) (string, error) {
	p := l.phys(rel)
	err := r.Link(tmp, p)
	if err == nil || !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	fi, err := r.Lstat(p)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file: %w", rel, ErrInvalid)
	}
	old, err := l.keep(r, rel, fi, vers)
	if err != nil {
		return "", err
	}
	hookRotate(1)
	if err := r.Rename(tmp, p); err != nil {
		return "", err
	}
	hookRotate(2)
	return old, nil
}

// keep makes the version of the file fi at rel.
func (l Local) keep(r *os.Root, rel string, fi fs.FileInfo, vers []string) (string, error) {
	p := l.phys(rel)
	cur, cerr := readSidecar(r, p)
	if cerr != nil && !errors.Is(cerr, fs.ErrNotExist) {
		return "", cerr
	}
	has := cerr == nil && !l.stale(r, cur, fi, vers)
	for _, v := range vers {
		vp := l.phys(v)
		vfi, err := r.Lstat(vp)
		if err != nil || !os.SameFile(vfi, fi) {
			continue
		}
		vsc, err := readSidecar(r, vp)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if has {
				return v, copySidecar(r, p, vp)
			}
			return v, nil
		case err == nil && has && sameVersion(vsc, cur):
			return v, nil
		}
	}
	ts := fi.ModTime().Unix()
	if t := receivedTime(cur.Received); has && !t.IsZero() {
		ts = t.Unix()
	}
	for i := 0; i <= maxVer; i++ {
		v := rel + "." + strconv.FormatInt(ts, 10)
		if i > 0 {
			v += fmt.Sprintf(".%06d", i)
		}
		vp := l.phys(v)
		if err := mkdirs(r, path.Dir(vp)); err != nil {
			return "", err
		}
		if err := noSymlinks(r, vp); err != nil {
			return "", err
		}
		err := r.Link(p, vp)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			prune(r, vp)
		}
		if err == nil {
			err = syncDir(r, path.Dir(vp))
		}
		if err == nil && has {
			err = copySidecar(r, p, vp)
		}
		return v, err
	}
	return "", fmt.Errorf("%s: too many versions", rel)
}

// copySidecar writes the sidecar of the path on disk from, unchanged, as
// the sidecar of to.
func copySidecar(r *os.Root, from, to string) error {
	f, err := openRegular(r, sidecarRel(from))
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	f.Close()
	if err != nil {
		return err
	}
	srel := sidecarRel(to)
	if err := mkdirs(r, path.Dir(srel)); err != nil {
		return err
	}
	if err := noSymlinks(r, srel); err != nil {
		return err
	}
	stmp, err := writeTemp(r, b)
	if err != nil {
		return err
	}
	defer r.Remove(stmp)
	if err := r.Rename(stmp, srel); err != nil {
		return err
	}
	return syncDir(r, path.Dir(srel))
}

// restore undoes a rotation whose new sidecar failed: the version old
// goes back to rel with its sidecar.
func (l Local) restore(r *os.Root, rel, old string, placed bool) {
	p, vp := l.phys(rel), l.phys(old)
	vfi, verr := r.Lstat(vp)
	pfi, perr := r.Lstat(p)
	if verr == nil && perr == nil && os.SameFile(vfi, pfi) {
		// One inode (a content object): a rename would keep both names.
		if r.Remove(vp) != nil {
			return
		}
	} else if r.Rename(vp, p) != nil {
		return
	}
	if placed {
		r.Rename(sidecarRel(vp), sidecarRel(p))
	} else {
		r.Remove(sidecarRel(vp))
	}
	prune(r, vp)
	prune(r, sidecarRel(vp))
}

func openRegular(r *os.Root, p string) (*os.File, error) {
	f, err := r.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = fmt.Errorf("%s: not a regular file", p)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func readSidecar(r *os.Root, rel string) (Sidecar, error) {
	var sc Sidecar
	srel := sidecarRel(rel)
	if err := noSymlinks(r, srel); err != nil {
		return sc, err
	}
	f, err := openRegular(r, srel)
	if err != nil {
		return sc, err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&sc); err != nil {
		return sc, fmt.Errorf("%s: %w", srel, err)
	}
	return sc, nil
}

// Open returns the stored file at rel and its sidecar, which always
// describe the same file: it reads them without the lock and takes the
// base lock only when a mutation of the base ran meanwhile or the two do
// not match.
func (l Local) Open(rel string) (*os.File, Sidecar, error) {
	if _, _, ok := l.PermanentPrefix(rel); ok {
		return l.OpenPermanent(rel)
	}
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return nil, Sidecar{}, err
	}
	defer r.Close()
	p, err := l.path(r, rel)
	if err != nil {
		return nil, Sidecar{}, err
	}
	if f, sc, ok, err := tryOpen(r, p); ok {
		return f, sc, err
	}
	h, err := takeBase(l.Base, false)
	if err != nil {
		return nil, Sidecar{}, err
	}
	defer h.unlock()
	sc, err := readSidecar(r, p)
	if err != nil {
		return nil, Sidecar{}, err
	}
	f, err := openRegular(r, p)
	if err != nil {
		return nil, Sidecar{}, err
	}
	return f, sc, nil
}

// tryOpen is Open of the path on disk rel without the lock; ok is false
// when the result may mix two states of the base.
func tryOpen(r *os.Root, rel string) (*os.File, Sidecar, bool, error) {
	g := generation(r)
	if g%2 != 0 {
		return nil, Sidecar{}, false, nil
	}
	sc, err := readSidecar(r, rel)
	if err != nil {
		return nil, Sidecar{}, generation(r) == g, err
	}
	f, err := openRegular(r, rel)
	if err != nil {
		return nil, Sidecar{}, generation(r) == g, err
	}
	fi, err := f.Stat()
	if err == nil {
		var again Sidecar
		if again, err = readSidecar(r, rel); err == nil && generation(r) == g && again.ID == sc.ID && fi.Size() == sc.Size {
			return f, sc, true, nil
		}
	}
	f.Close()
	return nil, Sidecar{}, false, nil
}

// Remove deletes the stored file at rel and its sidecar.
func (l Local) Remove(rel string) error { return l.remove(rel, nil) }

// RemoveIf deletes the stored file at rel and its sidecar only while the
// sidecar still has the given id; otherwise it gives fs.ErrNotExist.
func (l Local) RemoveIf(rel, id string) error {
	return l.remove(rel, func(sc Sidecar) bool { return sc.ID == id })
}

// RemoveExpired is RemoveIf that also needs the sidecar to keep the given
// expiry, so a ttl changed meanwhile keeps the file.
func (l Local) RemoveExpired(rel, id, expires string) error {
	return l.remove(rel, func(sc Sidecar) bool { return sc.ID == id && sc.Expires == expires })
}

func (l Local) remove(rel string, keep func(Sidecar) bool) error {
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return err
	}
	defer r.Close()
	h, err := takeBase(l.Base, false)
	if err != nil {
		return err
	}
	defer h.unlock()
	err = l.removeHeld(r, h, rel, keep)
	l.rebuild(r)
	return err
}

// removeHeld is remove under the base lock h, without the catalog
// rebuild.
func (l Local) removeHeld(r *os.Root, h *held, rel string, keep func(Sidecar) bool) error {
	p, err := l.path(r, rel)
	if err != nil {
		return err
	}
	sc, scErr := readSidecar(r, p)
	if keep != nil {
		if scErr != nil {
			return scErr
		}
		if !keep(sc) {
			return fmt.Errorf("%s: %w", rel, fs.ErrNotExist)
		}
	}
	srel := sidecarRel(p)
	if err := noSymlinks(r, srel); err != nil {
		return err
	}
	if err := h.bump(); err != nil {
		return err
	}
	err = r.Remove(p)
	serr := r.Remove(srel)
	if errors.Is(serr, fs.ErrNotExist) {
		serr = nil
	}
	prune(r, p)
	prune(r, srel)
	var aerr error
	if scErr == nil && err == nil {
		l.dropName(r, rel, sc)
	}
	if a, _ := sc.alias(); scErr == nil && sc.AliasOf == "" && a != "" {
		aerr = l.repoint(r, a, rel)
	}
	if scErr == nil {
		aerr = errors.Join(aerr, l.syncPermanent(r, l.permanentKey(sc)))
	}
	return errors.Join(err, serr, aerr)
}

// ErrAliased refuses to change a stored file that declares an alias in
// place: the alias holds the old content and sidecar.
var ErrAliased = errors.New("declares an alias")

// current reads, under the base lock, the sidecar of the stored file rel and
// checks that it is the file id: a regular file, not an alias, without an
// alias of its own. Otherwise it gives fs.ErrNotExist (or ErrAliased).
func (l Local) current(r *os.Root, rel, id string) (Sidecar, error) {
	p, err := l.path(r, rel)
	if err != nil {
		return Sidecar{}, err
	}
	if err := noSymlinks(r, sidecarRel(p)); err != nil {
		return Sidecar{}, err
	}
	sc, err := readSidecar(r, p)
	if err != nil {
		return Sidecar{}, err
	}
	if fi, err := r.Lstat(p); err != nil || !fi.Mode().IsRegular() || sc.ID != id || sc.AliasOf != "" {
		return Sidecar{}, fmt.Errorf("%s: %w", rel, fs.ErrNotExist)
	}
	if a, _ := sc.alias(); a != "" {
		return Sidecar{}, fmt.Errorf("%s: %w", rel, ErrAliased)
	}
	return sc, nil
}

// writeSidecar replaces the sidecar of the path on disk p with sc
// atomically.
func writeSidecar(r *os.Root, p string, sc Sidecar) error {
	b, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	srel := sidecarRel(p)
	stmp, err := writeTemp(r, b)
	if err != nil {
		return err
	}
	defer r.Remove(stmp)
	if err := r.Rename(stmp, srel); err != nil {
		return err
	}
	return syncDir(r, path.Dir(srel))
}

// Update rewrites the sidecar of the stored file rel, provided it still
// has the given id, with what fn makes of it, and returns the new one. A
// file gone or replaced by another upload gives fs.ErrNotExist, as does
// an error of fn wrapping it.
func (l Local) Update(rel, id string, fn func(*Sidecar) error) (Sidecar, error) {
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return Sidecar{}, err
	}
	defer r.Close()
	h, err := lockBase(l.Base)
	if err != nil {
		return Sidecar{}, err
	}
	defer h.unlock()
	sc, err := l.current(r, rel, id)
	if err != nil {
		return Sidecar{}, err
	}
	if err := fn(&sc); err != nil {
		return Sidecar{}, err
	}
	sc.ID, sc.AliasOf = id, ""
	if err := writeSidecar(r, l.phys(rel), sc); err != nil {
		return Sidecar{}, err
	}
	// A new expiry may make another version the newest live one.
	err = l.syncPermanent(r, l.permanentKey(sc))
	l.rebuild(r)
	return sc, err
}

// Replace puts a copy of src at the stored name rel in place of its
// content, provided its sidecar still has the given id, and its sidecar
// becomes what fn makes of the current one (the id stays). The new data
// is renamed over the old, then the new sidecar over the old one; a
// failure puts the old data and sidecar back, and so does the next taker
// of the base lock after a crash between the renames (see
// replaceIntent), so the name keeps either the old or the new content
// with its sidecar. The copy is staged before the base lock is taken.
func (l Local) Replace(src, rel, id string, fn func(*Sidecar) error) error {
	s, err := l.Stage(src)
	if err != nil {
		return err
	}
	defer s.Drop()
	return l.ReplaceStaged(s, rel, id, fn)
}

// ReplaceStaged is Replace of the copy s staged in this base.
func (l Local) ReplaceStaged(s *Staged, rel, id string, fn func(*Sidecar) error) error {
	if err := l.staged(s); err != nil {
		return err
	}
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return err
	}
	defer r.Close()
	tmp := s.tmp
	h, err := lockBase(l.Base)
	if err != nil {
		return err
	}
	defer h.unlock()
	sc, err := l.current(r, rel, id)
	if err != nil {
		return err
	}
	prev := sc
	if err := fn(&sc); err != nil {
		return err
	}
	sc.ID, sc.AliasOf = id, ""
	if a, _ := sc.alias(); a != "" {
		return fmt.Errorf("%s: %w", rel, ErrAliased)
	}
	if err := l.overLinks(r, sc, rel); err != nil {
		return err
	}
	if otmp, _, ok := l.fromObject(r, sc); ok {
		defer r.Remove(otmp)
		tmp = otmp
	}
	nb, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	p := l.phys(rel)
	srel := sidecarRel(p)
	stmp, err := writeTemp(r, nb)
	if err != nil {
		return err
	}
	defer r.Remove(stmp)
	// The old data and sidecar keep a second name, recorded with the
	// names they keep, until the new ones are in place, to be put back on
	// a failure or after a crash.
	odata, err := tmpName(r)
	if err != nil {
		return err
	}
	oside, err := tmpName(r)
	if err != nil {
		return err
	}
	if err := r.Link(p, odata); err != nil {
		return err
	}
	if err := r.Link(srel, oside); err != nil {
		r.Remove(odata)
		return err
	}
	in := replaceIntent{Data: p, Sidecar: srel, OldData: odata, OldSidecar: oside}
	if err := writeIntent(r, in); err != nil {
		r.Remove(odata)
		r.Remove(oside)
		r.Remove(intentName)
		return err
	}
	// undo leaves the record in place when it fails: the next taker of
	// the lock retries it, and the generation stays odd meanwhile.
	undo := func(err error) error {
		if rerr := rollBack(r); rerr != nil {
			h.dirty = true
			return errors.Join(err, rerr)
		}
		return err
	}
	if err := r.Rename(tmp, p); err != nil {
		return undo(err)
	}
	if err := hookReplace(1); err != nil {
		return undo(err)
	}
	if err := syncDir(r, path.Dir(p)); err != nil {
		return undo(err)
	}
	if err := r.Rename(stmp, srel); err != nil {
		return undo(err)
	}
	if err := hookReplace(2); err != nil {
		return undo(err)
	}
	if err := syncDir(r, path.Dir(srel)); err != nil {
		return undo(err)
	}
	if err := dropIntent(r); err != nil {
		// Whether the record went or not, the base is consistent: the
		// new content, or the old one put back by the next taker.
		h.dirty = true
		return err
	}
	r.Remove(odata)
	r.Remove(oside)
	l.dropName(r, rel, prev)
	l.linkObject(r, p, sc)
	l.addName(r, rel, sc)
	l.rebuild(r)
	return nil
}

// Claim moves the stored file at rel to a new name under ClaimedDir and
// removes its sidecar, provided the sidecar still has the given id. A file
// already claimed, removed or replaced gives fs.ErrNotExist. A non-empty
// name with an error means the claim holds but the sidecar stayed (Sweep
// removes it later) or its alias was not updated. Claiming an alias claims
// its target. A non-nil fi (of the file the caller opened) must be the file
// claimed, else fs.ErrNotExist.
func (l Local) Claim(rel, id string, fi fs.FileInfo) (string, error) {
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		return "", err
	}
	defer r.Close()
	h, err := takeBase(l.Base, false)
	if err != nil {
		return "", err
	}
	defer h.unlock()
	p, err := l.path(r, rel)
	if err != nil {
		return "", err
	}
	sc, err := readSidecar(r, p)
	if err != nil {
		return "", err
	}
	if sc.AliasOf != "" {
		rel = sc.AliasOf
		if p, err = l.path(r, rel); err != nil {
			return "", err
		}
		if sc, err = readSidecar(r, p); err != nil {
			return "", err
		}
	}
	if sc.ID != id {
		return "", fmt.Errorf("%s: %w", rel, fs.ErrNotExist)
	}
	if fi != nil {
		if cur, err := r.Lstat(p); err != nil || !os.SameFile(cur, fi) {
			return "", fmt.Errorf("%s: replaced: %w", rel, fs.ErrNotExist)
		}
	}
	if err := h.bump(); err != nil {
		return "", err
	}
	if err := mkdirs(r, ClaimedDir); err != nil {
		return "", err
	}
	b := make([]byte, 16)
	rand.Read(b)
	claimed := ClaimedDir + "/" + hex.EncodeToString(b)
	if err := r.Rename(p, claimed); err != nil {
		return "", err
	}
	t := now()
	if err := r.Chtimes(claimed, t, t); err != nil {
		return claimed, err
	}
	err = r.Remove(sidecarRel(p))
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	prune(r, p)
	prune(r, sidecarRel(p))
	l.dropName(r, rel, sc)
	if a, _ := sc.alias(); a != "" {
		err = errors.Join(err, l.repoint(r, a, rel))
	}
	l.rebuild(r)
	return claimed, err
}

// Walk calls fn for every stored regular file that has a sidecar. Per-entry
// errors, including those of fn, are collected and returned together.
func (l Local) Walk(fn func(rel string, sc Sidecar) error) error {
	r, err := os.OpenRoot(l.Base)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer r.Close()
	return l.walk(r, fn)
}

func (l Local) walk(r *os.Root, fn func(rel string, sc Sidecar) error) error {
	return l.files(r, func(p, rel string) error {
		sc, err := readSidecar(r, p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return fn(rel, sc)
	})
}

// files calls fn with the path on disk and the stored name of every
// regular file of the data tree. Per-entry errors are collected.
func (l Local) files(r *os.Root, fn func(p, rel string) error) error {
	if err := noSymlinks(r, DataDir); err != nil {
		return err
	}
	var errs []error
	err := fs.WalkDir(r.FS(), DataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p != DataDir || !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			return nil
		}
		if p == DataDir {
			return nil
		}
		if d.IsDir() {
			if strings.Count(p, "/") <= l.Shard && !hexPair(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, ok := l.logical(p)
		if !ok {
			return nil
		}
		if err := fn(p, rel); err != nil {
			errs = append(errs, err)
		}
		return nil
	})
	return errors.Join(append(errs, err)...)
}

// Swept lists what Sweep removed (paths on disk of internal files and of
// empty directories) and the stored names of the data files it found
// without a sidecar; those are reported, never deleted.
type Swept struct {
	Removed, Dirs, Orphans []string
}

// Sweep removes crash leftovers whose mtime is older than olderThan: files
// of tmpDir not staged by this process, sidecars without data, and empty
// directories of the data and sidecar trees. It walks without the lock and
// re-checks each candidate under it; an empty directory is re-checked by
// rmdir itself.
func (l Local) Sweep(olderThan time.Duration, t time.Time) (Swept, error) {
	var sw Swept
	r, err := os.OpenRoot(l.Base)
	if errors.Is(err, fs.ErrNotExist) {
		return sw, nil
	}
	if err != nil {
		return sw, err
	}
	defer r.Close()
	b := baseOf(l.Base)
	missing := func(p string) bool {
		_, err := r.Lstat(p)
		return errors.Is(err, fs.ErrNotExist)
	}
	old := func(p string) bool {
		fi, err := r.Lstat(p)
		return err == nil && fi.Mode().IsRegular() && t.Sub(fi.ModTime()) > olderThan
	}
	const (
		tmpFile = iota
		sidecarFile
		dataFile
	)
	// stale re-checks a candidate; it runs under the lock.
	stale := func(p string, kind int) bool {
		if !old(p) {
			return false
		}
		switch kind {
		case tmpFile:
			_, busy := b.staging.Load(p)
			return !busy
		case sidecarFile:
			return missing(dataOf(p))
		}
		return missing(sidecarRel(p))
	}
	type cand struct {
		p, rel string
		kind   int
	}
	var cands []cand
	var errs []error
	// dirs are the directories that may be pruned, in walk order; entries
	// counts the entries of each directory, -1 for an unreadable one.
	var dirs []string
	entries := map[string]int{}
	for _, top := range []string{DataDir, metaDir, tmpDir} {
		if err := noSymlinks(r, top); err != nil {
			errs = append(errs, err)
			continue
		}
		err := fs.WalkDir(r.FS(), top, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p != top || !errors.Is(err, fs.ErrNotExist) {
					errs = append(errs, err)
				}
				entries[p] = -1
				return nil
			}
			if p == top {
				return nil
			}
			if entries[path.Dir(p)] >= 0 {
				entries[path.Dir(p)]++
			}
			if d.IsDir() {
				if top != tmpDir {
					dirs = append(dirs, p)
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					errs = append(errs, err)
				}
				return nil
			}
			if t.Sub(fi.ModTime()) <= olderThan {
				return nil
			}
			switch top {
			case tmpDir:
				cands = append(cands, cand{p, "", tmpFile})
			case metaDir:
				if strings.HasSuffix(p, ".json") && missing(dataOf(p)) {
					cands = append(cands, cand{p, "", sidecarFile})
				}
			default:
				if rel, ok := l.logical(p); ok && missing(sidecarRel(p)) {
					cands = append(cands, cand{p, rel, dataFile})
				}
			}
			return nil
		})
		errs = append(errs, err)
	}
	for _, c := range cands {
		h, err := lockBase(l.Base)
		if err != nil {
			errs = append(errs, err)
			break
		}
		switch {
		case !stale(c.p, c.kind):
		case c.kind == dataFile:
			sw.Orphans = append(sw.Orphans, c.rel)
		default:
			if err := r.Remove(c.p); err != nil {
				errs = append(errs, err)
			} else {
				sw.Removed = append(sw.Removed, c.p)
				prune(r, c.p)
			}
		}
		h.unlock()
	}
	// Children come after their parent in walk order, so going backwards
	// a directory is empty once all its entries are empty directories.
	var empty []string
	gone := map[string]int{}
	for i := len(dirs) - 1; i >= 0; i-- {
		if p := dirs[i]; entries[p] == gone[p] {
			empty = append(empty, p)
			gone[path.Dir(p)]++
		}
	}
	if len(empty) > 0 {
		h, err := takeBase(l.Base, false)
		if err != nil {
			return sw, errors.Join(append(errs, err)...)
		}
		for _, p := range empty {
			if rmdir(r, p) == nil {
				sw.Dirs = append(sw.Dirs, p)
			}
		}
		h.unlock()
	}
	return sw, errors.Join(errs...)
}
