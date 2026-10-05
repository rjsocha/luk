package status

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Dir is the status directory under root: one directory per role, each
// written by its role only.
func Dir(root string) string { return filepath.Join(root, "status") }

// RoleDir is the status directory of the role (receive, process).
func RoleDir(root, role string) string { return filepath.Join(Dir(root), role) }

// AlivePath is the liveness file of the role.
func AlivePath(root, role string) string { return filepath.Join(RoleDir(root, role), "alive.json") }

// BeatEvery is how often a running role touches its liveness file.
const BeatEvery = 30 * time.Second

const aliveTmpPattern = ".alive.json.tmp-*"

// AliveInfo is the content of alive.json, written once at the start of the
// role.
type AliveInfo struct {
	Role    string `json:"role"`
	PID     int    `json:"pid"`
	Started string `json:"started"`
	Version string `json:"version"`
}

// Alive is the liveness file of a running role. Its content is written at
// start; its mtime is the heartbeat (see Beat).
type Alive struct {
	path string
	info AliveInfo
}

// StartAlive writes the liveness file of role under root atomically and
// returns it for the heartbeat. The directory must exist.
func StartAlive(root, role, version string, now time.Time) (*Alive, error) {
	a := &Alive{
		path: AlivePath(root, role),
		info: AliveInfo{Role: role, PID: os.Getpid(), Started: now.UTC().Format(time.RFC3339), Version: version},
	}
	dir := filepath.Dir(a.path)
	if tmps, err := filepath.Glob(filepath.Join(dir, aliveTmpPattern)); err == nil {
		for _, t := range tmps {
			os.Remove(t)
		}
	}
	return a, a.write()
}

// Path is the file a writes.
func (a *Alive) Path() string { return a.path }

// Beat sets the mtime of the file to now without rewriting its content; a
// missing file (deleted) is written again. One goroutine beats a file.
func (a *Alive) Beat(now time.Time) error {
	err := os.Chtimes(a.path, now, now)
	if errors.Is(err, fs.ErrNotExist) {
		if err = a.write(); err == nil {
			err = os.Chtimes(a.path, now, now)
		}
	}
	return err
}

// write replaces the file with the content of a: a temporary file in the
// same directory, fsync, rename, fsync of the directory.
func (a *Alive) write() error {
	b, err := json.MarshalIndent(a.info, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(a.path)
	f, err := os.CreateTemp(dir, aliveTmpPattern)
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o640)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = rename(tmp, a.path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return syncDir(d)
}
