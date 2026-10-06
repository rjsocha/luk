package pipeline

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"luk/internal/config"
	"luk/internal/runstep"
)

const (
	logCap   = 1 << 20
	tailSize = 4 << 10
)

// file is one member of the set a pipeline works on. produced marks a file
// written by a run step; it carries its own size, sha256 and meta.
type file struct {
	name, path string
	produced   bool
	size       int64
	sha256     string
	meta       json.RawMessage
}

func initialSet(j Job) []file {
	name := j.Vars.File
	if !runstep.ValidName(name) {
		name = j.Entry.ID
	}
	return []file{{name: name, path: filepath.Join(j.Entry.Dir, "payload")}}
}

// stepFailed is the message a run program left in its fail file; it
// replaces the exit status and the output tail as the step error.
type stepFailed string

func (e stepFailed) Error() string { return string(e) }

// openWork prepares the work directory dir of a run or relay step on set
// (see prepareWork), writes its meta.json and creates its log. It returns
// out/ and the log.
func openWork(j Job, p *config.Pipeline, step int, set []file, dir string) (out string, logf *os.File, err error) {
	if _, out, err = prepareWork(dir, set); err != nil {
		return "", nil, err
	}
	meta := filepath.Join(dir, "meta.json")
	sc := j.Sidecar
	// Without HTML escaping a client meta within wire.MaxMetaHeader stays
	// far below runstep.MaxWorkMeta, which ReadWork enforces.
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	err = enc.Encode(runstep.WorkMeta{
		Server: runstep.WorkServer{ID: sc.ID, Sender: sc.Sender, Endpoint: sc.Endpoint, Received: sc.Received,
			Size: sc.Size, SHA256: sc.SHA256, Expires: sc.Expires},
		Client: sc.Client, Pipeline: p.Name, Step: step, Produced: len(set) > 0 && set[0].produced,
	})
	if err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(meta, b.Bytes(), 0o440); err != nil {
		return "", nil, err
	}
	logf, err = os.OpenFile(filepath.Join(dir, "log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return "", nil, err
	}
	return out, logf, nil
}

// stepTimeout is the timeout of one run or relay step of p.
func stepTimeout(p *config.Pipeline) time.Duration {
	if t := time.Duration(p.Timeout); t > 0 {
		return t
	}
	return config.DefaultPipelineTimeout
}

// prepareWork recreates the step directory dir with an empty out/ and in/
// holding the set and its per-file meta.
func prepareWork(dir string, set []file) (in, out string, err error) {
	in, out = filepath.Join(dir, "in"), filepath.Join(dir, "out")
	if err := os.RemoveAll(dir); err != nil {
		return "", "", err
	}
	for _, d := range []string{in, out} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return "", "", err
		}
	}
	for _, f := range set {
		if err := linkOrCopy(f.path, filepath.Join(in, f.name)); err != nil {
			return "", "", err
		}
		if f.meta != nil {
			if err := os.WriteFile(filepath.Join(in, f.name+runstep.MetaExt), f.meta, 0o440); err != nil {
				return "", "", err
			}
		}
	}
	return in, out, nil
}

// errInterrupted marks a run stopped by Dispatcher.Close; the queue entry
// stays for the next start.
var errInterrupted = errors.New("interrupted by shutdown")

// capWriter writes up to left bytes to f, drops the rest and keeps the last
// tailSize bytes of everything written.
type capWriter struct {
	mu   sync.Mutex
	f    *os.File
	left int64
	err  error
	last []byte
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if n := min(int64(len(p)), w.left); n > 0 && w.err == nil {
		_, w.err = w.f.Write(p[:n])
		w.left -= n
	}
	w.last = append(w.last, p...)
	if len(w.last) > 2*tailSize {
		w.last = append(w.last[:0], w.last[len(w.last)-tailSize:]...)
	}
	return len(p), nil
}

func (w *capWriter) tail() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.last[max(0, len(w.last)-tailSize):])
}

func linkOrCopy(src, dst string) error {
	if os.Link(src, dst) == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// readOut validates out: regular files named by the rules of `file`, each
// optionally with a <name>.meta.json holding a JSON object of at most
// runstep.MaxMeta bytes, and at least one file.
func readOut(out string) ([]file, error) {
	ents, err := os.ReadDir(out)
	if err != nil {
		return nil, err
	}
	regular := map[string]bool{}
	for _, e := range ents {
		name := e.Name()
		fi, err := os.Lstat(filepath.Join(out, name))
		if err != nil {
			return nil, err
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%q: not a regular file", name)
		}
		if !runstep.ValidName(name) {
			return nil, fmt.Errorf("%q: invalid name", name)
		}
		regular[name] = true
	}
	isMeta := func(n string) bool {
		base, ok := strings.CutSuffix(n, runstep.MetaExt)
		return ok && regular[base]
	}
	var set []file
	for _, e := range ents {
		name := e.Name()
		if base, ok := strings.CutSuffix(name, runstep.MetaExt); ok && !regular[base] {
			return nil, fmt.Errorf("%q: meta without its file", name)
		}
		if isMeta(name) {
			if isMeta(strings.TrimSuffix(name, runstep.MetaExt)) {
				return nil, fmt.Errorf("%q: meta of a meta file", name)
			}
			continue
		}
		f := file{name: name, path: filepath.Join(out, name), produced: true}
		if f.size, f.sha256, err = hashFile(f.path); err != nil {
			return nil, err
		}
		if regular[name+runstep.MetaExt] {
			if f.meta, err = readMeta(filepath.Join(out, name+runstep.MetaExt)); err != nil {
				return nil, fmt.Errorf("%q: %w", name+runstep.MetaExt, err)
			}
		}
		if err := os.Chmod(f.path, 0o440); err != nil {
			return nil, err
		}
		set = append(set, f)
	}
	if len(set) == 0 {
		return nil, errors.New("no file")
	}
	return set, nil
}

func openRegular(p string) (*os.File, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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

func hashFile(p string) (int64, string, error) {
	f, err := openRegular(p)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func readMeta(p string) (json.RawMessage, error) {
	f, err := openRegular(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, runstep.MaxMeta+1))
	if err != nil {
		return nil, err
	}
	return runstep.CheckMeta(b)
}

func stepDir(work string, step int) string { return filepath.Join(work, strconv.Itoa(step)) }
