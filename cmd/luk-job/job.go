package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"luk/internal/runstep"
)

// link and rename place an output; tests replace them to take the copy path.
var (
	link   = os.Link
	rename = os.Rename
)

// workDir resolves the step work directory: flag, else LUK_WORK.
func workDir(flag string) (string, error) {
	dir := flag
	if dir == "" {
		dir = os.Getenv("LUK_WORK")
	}
	if dir == "" {
		return "", errors.New("no work directory: run inside a step (LUK_WORK) or pass --work")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	in, ierr := os.Stat(filepath.Join(abs, "in"))
	out, oerr := os.Stat(filepath.Join(abs, "out"))
	meta, merr := os.Stat(filepath.Join(abs, "meta.json"))
	if ierr != nil || oerr != nil || merr != nil || !in.IsDir() || !out.IsDir() || !meta.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a step work directory (in/, out/, meta.json)", abs)
	}
	return abs, nil
}

type inputFile struct {
	Path string          `json:"path"`
	Name string          `json:"name"`
	Size int64           `json:"size"`
	Meta json.RawMessage `json:"meta"`
}

// readJSON reads at most limit bytes of p.
func readJSON(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("%s: larger than %d bytes", p, limit)
	}
	return b, err
}

// inputs lists the files of in/ sorted by name, a <name>.meta.json next to
// its file being that file's meta (runstep.SetNames).
func inputs(work string) ([]inputFile, error) {
	in := filepath.Join(work, "in")
	ents, err := os.ReadDir(in)
	if err != nil {
		return nil, err
	}
	size := map[string]int64{}
	var regular []string
	for _, e := range ents {
		fi, err := os.Lstat(filepath.Join(in, e.Name()))
		if err != nil {
			return nil, err
		}
		if fi.Mode().IsRegular() {
			size[e.Name()] = fi.Size()
			regular = append(regular, e.Name())
		}
	}
	list := []inputFile{}
	for _, name := range runstep.SetNames(regular) {
		f := inputFile{Path: filepath.Join(in, name), Name: name, Size: size[name], Meta: json.RawMessage("{}")}
		if _, has := size[name+runstep.MetaExt]; has {
			b, err := readJSON(filepath.Join(in, name+runstep.MetaExt), runstep.MaxMeta)
			if err != nil {
				return nil, err
			}
			if f.Meta, err = runstep.CheckMeta(b); err != nil {
				return nil, fmt.Errorf("%s%s: %w", name, runstep.MetaExt, err)
			}
		}
		list = append(list, f)
	}
	return list, nil
}

func printInputs(w io.Writer, work string, asJSON bool) error {
	list, err := inputs(work)
	if err != nil {
		return err
	}
	if asJSON {
		b, err := json.Marshal(list)
		if err == nil {
			_, err = fmt.Fprintf(w, "%s\n", b)
		}
		return err
	}
	for _, f := range list {
		fmt.Fprintln(w, f.Path)
	}
	return nil
}

func printInput(w io.Writer, work string) error {
	list, err := inputs(work)
	if err != nil {
		return err
	}
	if len(list) != 1 {
		return fmt.Errorf("%d inputs; use luk-job inputs", len(list))
	}
	_, err = fmt.Fprintln(w, list[0].Path)
	return err
}

func decodeJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// valueText is s raw for a string, else JSON.
func valueText(v any, asJSON bool) (string, error) {
	if s, ok := v.(string); ok && !asJSON {
		return s, nil
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func printMeta(w io.Writer, work, field string, asJSON bool) error {
	b, err := os.ReadFile(filepath.Join(work, "meta.json"))
	if err != nil {
		return err
	}
	var m map[string]any
	if err := decodeJSON(b, &m); err != nil || m == nil {
		return fmt.Errorf("meta.json: not a JSON object")
	}
	if field != "" {
		var v any = m
		for _, k := range strings.Split(field, ".") {
			obj, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("field %s: not found", field)
			}
			if v, ok = obj[k]; !ok {
				return fmt.Errorf("field %s: not found", field)
			}
		}
		s, err := valueText(v, asJSON)
		if err == nil {
			_, err = fmt.Fprintln(w, s)
		}
		return err
	}
	if asJSON {
		var c bytes.Buffer
		if err := json.Compact(&c, b); err != nil {
			return err
		}
		_, err := fmt.Fprintf(w, "%s\n", c.Bytes())
		return err
	}
	var lines []string
	var walk func(prefix string, v any) error
	walk = func(prefix string, v any) error {
		if obj, ok := v.(map[string]any); ok && len(obj) > 0 {
			for k, sub := range obj {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				if err := walk(p, sub); err != nil {
					return err
				}
			}
			return nil
		}
		s, err := valueText(v, false)
		lines = append(lines, prefix+"="+s)
		return err
	}
	if err := walk("", m); err != nil {
		return err
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return nil
}

type outputOpts struct {
	file, name, metaFile string
	meta                 []string
	move                 bool
}

// setPath sets the dotted key in obj, creating the objects on the way.
func setPath(obj map[string]any, key string, v any) error {
	parts := strings.Split(key, ".")
	for _, p := range parts {
		if p == "" {
			return fmt.Errorf("meta key %q: empty segment", key)
		}
	}
	m := obj
	for _, p := range parts[:len(parts)-1] {
		next, ok := m[p]
		if !ok {
			n := map[string]any{}
			m[p] = n
			m = n
			continue
		}
		if m, ok = next.(map[string]any); !ok {
			return fmt.Errorf("meta key %q: %s is not an object", key, p)
		}
	}
	m[parts[len(parts)-1]] = v
	return nil
}

// buildMeta is the --meta pairs merged over --meta-file, nil when neither is
// given.
func buildMeta(o outputOpts) ([]byte, error) {
	if o.metaFile == "" && len(o.meta) == 0 {
		return nil, nil
	}
	obj := map[string]any{}
	if o.metaFile != "" {
		b, err := readJSON(o.metaFile, runstep.MaxMeta)
		if err != nil {
			return nil, err
		}
		if err := decodeJSON(b, &obj); err != nil || obj == nil {
			return nil, fmt.Errorf("%s: not a JSON object", o.metaFile)
		}
	}
	for _, pair := range o.meta {
		k, raw, ok := strings.Cut(pair, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--meta %q: want key=value", pair)
		}
		var v any = raw
		if json.Valid([]byte(raw)) {
			if err := decodeJSON([]byte(raw), &v); err != nil {
				return nil, err
			}
		}
		if err := setPath(obj, k, v); err != nil {
			return nil, err
		}
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	if b, err = runstep.CheckMeta(b); err != nil {
		return nil, fmt.Errorf("meta: %w", err)
	}
	return b, nil
}

// tempIn creates a temporary file in the work directory, outside out/.
func tempIn(work, pattern string) (*os.File, error) {
	return os.CreateTemp(work, ".luk-job-"+pattern+"-*")
}

// writeTemp writes data to a synced temporary file in work.
func writeTemp(work, pattern string, data io.Reader) (string, error) {
	f, err := tempIn(work, pattern)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(f, data)
	if err == nil {
		err = f.Chmod(0o640)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// copyTo copies src to a new dst through a synced temporary file in work.
func copyTo(work, src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := writeTemp(work, "copy", in)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	return os.Link(tmp, dst)
}

func placeOutput(work string, o outputOpts) (string, error) {
	fi, err := os.Lstat(o.file)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", o.file)
	}
	name := o.name
	if name == "" {
		name = filepath.Base(o.file)
	}
	if !runstep.ValidName(name) {
		return "", fmt.Errorf("%q: invalid name (empty, starts with '.', has '/' or is too long)", name)
	}
	if strings.HasSuffix(name, runstep.MetaExt) {
		return "", fmt.Errorf("%q: a name may not end in %s", name, runstep.MetaExt)
	}
	out := filepath.Join(work, "out")
	dst, metaDst := filepath.Join(out, name), filepath.Join(out, name+runstep.MetaExt)
	for _, p := range []string{dst, metaDst} {
		if _, err := os.Lstat(p); err == nil {
			return "", fmt.Errorf("out/%s exists", filepath.Base(p))
		} else if !os.IsNotExist(err) {
			return "", err
		}
	}
	meta, err := buildMeta(o)
	if err != nil {
		return "", err
	}
	metaTmp := ""
	if meta != nil {
		if metaTmp, err = writeTemp(work, "meta", bytes.NewReader(meta)); err != nil {
			return "", err
		}
		defer os.Remove(metaTmp)
	}
	if o.move {
		err = rename(o.file, dst)
		if errors.Is(err, syscall.EXDEV) {
			if err = copyTo(work, o.file, dst); err == nil {
				err = os.Remove(o.file)
			}
		}
	} else if link(o.file, dst) != nil {
		err = copyTo(work, o.file, dst)
	}
	if err != nil {
		return "", err
	}
	if metaTmp != "" {
		if err := os.Rename(metaTmp, metaDst); err != nil {
			if !o.move {
				os.Remove(dst)
			}
			return "", err
		}
	}
	return dst, nil
}

// writeFail writes the sanitized message to <work>/fail and returns the
// error that ends luk-job with exit 1.
func writeFail(work, message string) error {
	msg := runstep.FailText([]byte(message))
	if msg == "" {
		return errors.New("--message is empty")
	}
	tmp, err := writeTemp(work, "fail", strings.NewReader(msg+"\n"))
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(work, runstep.FailFile)); err != nil {
		os.Remove(tmp)
		return err
	}
	return fmt.Errorf("step failed: %s", msg)
}
