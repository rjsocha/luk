package runstep

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// MetaNames are the metadata variables whose values come from the upload
// (meta.json and the set) rather than from the path of the work
// directory. They are the only ones a client passes on to lukd run, which
// derives every other LUK_* variable itself.
var MetaNames = []string{"LUK_SENDER", "LUK_ENDPOINT", "LUK_FILE", "LUK_NAME", "LUK_TAGS", "LUK_HOSTNAME", "LUK_ORIGIN"}

// MaxMetaValue caps the value of a free-form metadata variable (not
// LUK_FILE, whose form CleanMeta fixes).
const MaxMetaValue = 1 << 10

// varOrder is the order of the LUK_* metadata variables; the names not in
// MetaNames are derived from the work directory path and the root.
var varOrder = []string{
	"LUK_WORK", "LUK_IN", "LUK_OUT", "LUK_META", "LUK_ID", "LUK_SENDER", "LUK_ENDPOINT", "LUK_PIPELINE",
	"LUK_FILE", "LUK_NAME", "LUK_ROOT", "LUK_STEP", "LUK_TAGS", "LUK_HOSTNAME", "LUK_ORIGIN",
}

// safeValue reports whether v can be the value of a variable: valid UTF-8
// without a control character. Neither an exec environment nor a
// systemd-run --setenv carries a NUL, and a newline or another control
// character would reach the job's environment raw.
func safeValue(v string) bool {
	return utf8.ValidString(v) && !wire.HasControl(v)
}

// CleanMeta is what of env may reach a step or a job of the work
// directory work as metadata: only the names of MetaNames with a safe
// value (see safeValue), LUK_NAME a valid file name or empty, LUK_FILE
// <work>/in/<a valid file name>, the free-form others at most
// MaxMetaValue bytes. Everything else is dropped. lukd and the clients of
// lukd run apply it to what they derive, lukd run to what it receives.
func CleanMeta(work string, env map[string]string) map[string]string {
	m := map[string]string{}
	for _, k := range MetaNames {
		v, ok := env[k]
		if !ok || !safeValue(v) || k != "LUK_FILE" && len(v) > MaxMetaValue {
			continue
		}
		switch k {
		case "LUK_NAME":
			if v != "" && !ValidName(v) {
				continue
			}
		case "LUK_FILE":
			if n := filepath.Base(v); !ValidName(n) || v != filepath.Join(work, "in", n) {
				continue
			}
		}
		m[k] = v
	}
	return m
}

// Vars is the LUK_* metadata environment of the work directory work
// (<root>/work/<id>/<pipeline>/<step>) as NAME=value entries in a fixed
// order: LUK_WORK, LUK_IN, LUK_OUT, LUK_META, LUK_ID, LUK_PIPELINE and
// LUK_STEP from work, LUK_ROOT root, the others from meta after
// CleanMeta. A variable without a safe value is left out.
func Vars(work, root string, meta map[string]string) []string {
	step := filepath.Dir(work)
	v := CleanMeta(work, meta)
	v["LUK_WORK"] = work
	v["LUK_IN"] = filepath.Join(work, "in")
	v["LUK_OUT"] = filepath.Join(work, "out")
	v["LUK_META"] = filepath.Join(work, "meta.json")
	v["LUK_ID"] = filepath.Base(filepath.Dir(step))
	v["LUK_PIPELINE"] = filepath.Base(step)
	v["LUK_STEP"] = filepath.Base(work)
	v["LUK_ROOT"] = root
	var env []string
	for _, k := range varOrder {
		if x, ok := v[k]; ok && safeValue(x) {
			env = append(env, k+"="+x)
		}
	}
	return env
}

// Meta is the metadata a client of lukd run passes on for the work
// directory work: the names of MetaNames that lookup finds, after
// CleanMeta.
func Meta(work string, lookup func(string) (string, bool)) map[string]string {
	env := map[string]string{}
	for _, k := range MetaNames {
		if v, ok := lookup(k); ok {
			env[k] = v
		}
	}
	return CleanMeta(work, env)
}

// Env is Vars of the work directory work, whose meta.json is m and whose
// set has the file names names; root is LUK_ROOT. LUK_FILE is there only
// for a set of exactly one file.
func Env(work, root string, m WorkMeta, names []string) []string {
	meta := map[string]string{
		"LUK_SENDER":   m.Server.Sender,
		"LUK_ENDPOINT": m.Server.Endpoint,
	}
	name := ""
	if len(names) == 1 {
		meta["LUK_FILE"] = filepath.Join(work, "in", names[0])
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
	meta["LUK_NAME"] = name
	meta["LUK_TAGS"] = strings.Join(m.Client.Tags, ",")
	meta["LUK_HOSTNAME"] = host
	meta["LUK_ORIGIN"] = origin
	return Vars(work, root, meta)
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
