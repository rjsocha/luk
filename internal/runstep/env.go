package runstep

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"luk/internal/wire"
)

// MaxWorkMeta caps meta.json of a work directory.
const MaxWorkMeta = 64 << 10

// WorkServer is what lukd knows of the upload, the server part of
// meta.json.
type WorkServer struct {
	ID       string `json:"id"`
	Sender   string `json:"sender"`
	Endpoint string `json:"endpoint"`
	Received string `json:"received"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Expires  string `json:"expires,omitempty"`
}

// WorkMeta is meta.json of a step work directory. Produced marks a set
// written by an earlier run step, not the upload itself.
type WorkMeta struct {
	Server   WorkServer `json:"server"`
	Client   wire.Meta  `json:"client"`
	Pipeline string     `json:"pipeline"`
	Step     int        `json:"step"`
	Produced bool       `json:"produced,omitempty"`
}

// Env is the LUK_* metadata environment of the work directory work, whose
// meta.json is m and whose set has the file names names, as NAME=value
// entries in a fixed order; root is LUK_ROOT. LUK_FILE is there only for a
// set of exactly one file. A variable whose value would hold a control
// character (NUL, newline, ...) or invalid UTF-8 is left out: neither an
// exec environment nor a systemd-run --setenv carries it safely.
func Env(work, root string, m WorkMeta, names []string) []string {
	in := filepath.Join(work, "in")
	var env []string
	add := func(k, v string) {
		if utf8.ValidString(v) && !wire.HasControl(v) {
			env = append(env, k+"="+v)
		}
	}
	add("LUK_WORK", work)
	add("LUK_IN", in)
	add("LUK_OUT", filepath.Join(work, "out"))
	add("LUK_META", filepath.Join(work, "meta.json"))
	add("LUK_ID", m.Server.ID)
	add("LUK_SENDER", m.Server.Sender)
	add("LUK_ENDPOINT", m.Server.Endpoint)
	add("LUK_PIPELINE", m.Pipeline)
	name := ""
	if len(names) == 1 {
		add("LUK_FILE", filepath.Join(in, names[0]))
		name = names[0]
		if !m.Produced {
			name = ""
			if ValidName(m.Client.File) {
				name = m.Client.File
			}
		}
	}
	host := ""
	if m.Client.Backup != nil {
		host = m.Client.Backup.Hostname
	}
	origin := host
	if origin == "" {
		origin = m.Server.Sender
	}
	add("LUK_NAME", name)
	add("LUK_ROOT", root)
	add("LUK_STEP", strconv.Itoa(m.Step))
	add("LUK_TAGS", strings.Join(m.Client.Tags, ","))
	add("LUK_HOSTNAME", host)
	add("LUK_ORIGIN", origin)
	return env
}

// WorkEnv is Env of the work directory work, read with ReadWork.
func WorkEnv(work, root string) ([]string, error) {
	r, err := os.OpenRoot(work)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	m, names, err := ReadWork(r)
	if err != nil {
		return nil, err
	}
	return Env(work, root, m, names), nil
}

// ReadWork reads the work directory open as r: meta.json (a regular file,
// not a symlink, at most MaxWorkMeta bytes, one JSON object without
// unknown keys) and the names of the set in in/ (a directory, not a
// symlink): its regular files sorted by name, a <name>.meta.json next to
// its file being that file's meta.
func ReadWork(r *os.Root) (WorkMeta, []string, error) {
	var m WorkMeta
	f, err := openNoFollow(r, "meta.json", false)
	if err != nil {
		return m, nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxWorkMeta+1))
	f.Close()
	if err != nil {
		return m, nil, fmt.Errorf("meta.json: %w", err)
	}
	if len(b) > MaxWorkMeta {
		return m, nil, fmt.Errorf("meta.json: larger than %d bytes", MaxWorkMeta)
	}
	if err := decodeWorkMeta(b, &m); err != nil {
		return m, nil, fmt.Errorf("meta.json: %w", err)
	}
	d, err := openNoFollow(r, "in", true)
	if err != nil {
		return m, nil, err
	}
	ents, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return m, nil, fmt.Errorf("in: %w", err)
	}
	var regular []string
	for _, e := range ents {
		if e.Type().IsRegular() {
			regular = append(regular, e.Name())
		}
	}
	return m, SetNames(regular), nil
}

// decodeWorkMeta decodes b, exactly one JSON object, into m, refusing
// unknown keys.
func decodeWorkMeta(b []byte, m *WorkMeta) error {
	if t := bytes.TrimSpace(b); len(t) == 0 || t[0] != '{' {
		return errors.New("not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(m); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON object")
	}
	return nil
}

// openNoFollow opens name of r when it is a regular file (dir: a
// directory) and not a symlink, also when it is swapped between the check
// and the open.
func openNoFollow(r *os.Root, name string, dir bool) (*os.File, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		return nil, err
	}
	switch {
	case dir && !fi.IsDir():
		return nil, fmt.Errorf("%s: not a directory", name)
	case !dir && !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || !os.SameFile(fi, st) {
		f.Close()
		return nil, fmt.Errorf("%s: changed while opened", name)
	}
	return f, nil
}
