package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"luk/internal/config"
	"luk/internal/runproto"
	"luk/internal/runstep"
	"luk/internal/wire"
)

const (
	logCap      = 1 << 20
	tailSize    = 4 << 10
	defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// killAfter is the delay between SIGTERM and SIGKILL on timeout.
var killAfter = 10 * time.Second

// runSocket is the socket of lukd run that relay steps connect to.
var runSocket = runproto.DefaultSocket

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

type workServer struct {
	ID       string `json:"id"`
	Sender   string `json:"sender"`
	Endpoint string `json:"endpoint"`
	Received string `json:"received"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Expires  string `json:"expires,omitempty"`
}

type workMeta struct {
	Server   workServer `json:"server"`
	Client   wire.Meta  `json:"client"`
	Pipeline string     `json:"pipeline"`
	Step     int        `json:"step"`
}

// stepFailed is the message a run program left in its fail file; it
// replaces the exit status and the output tail as the step error.
type stepFailed string

func (e stepFailed) Error() string { return string(e) }

// readFail returns the sanitized fail message of the work directory dir, or
// "" when there is none.
func readFail(dir string) string {
	f, err := openRegular(filepath.Join(dir, runstep.FailFile))
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, runstep.MaxFail))
	return runstep.FailText(b)
}

// openWork prepares the work directory dir of a run or relay step on set
// (see prepareWork), writes its meta.json and creates its log.
func openWork(j Job, p *config.Pipeline, step int, set []file, dir string) (in, out, meta string, logf *os.File, err error) {
	if in, out, err = prepareWork(dir, set); err != nil {
		return "", "", "", nil, err
	}
	meta = filepath.Join(dir, "meta.json")
	sc := j.Sidecar
	b, err := json.Marshal(workMeta{
		Server: workServer{ID: sc.ID, Sender: sc.Sender, Endpoint: sc.Endpoint, Received: sc.Received,
			Size: sc.Size, SHA256: sc.SHA256, Expires: sc.Expires},
		Client: sc.Client, Pipeline: p.Name, Step: step,
	})
	if err != nil {
		return "", "", "", nil, err
	}
	if err := os.WriteFile(meta, b, 0o440); err != nil {
		return "", "", "", nil, err
	}
	logf, err = os.OpenFile(filepath.Join(dir, "log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return "", "", "", nil, err
	}
	return in, out, meta, logf, nil
}

// stepTimeout is the timeout of one run or relay step of p.
func stepTimeout(p *config.Pipeline) time.Duration {
	if t := time.Duration(p.Timeout); t > 0 {
		return t
	}
	return config.DefaultPipelineTimeout
}

// runStep runs s in dir on set and returns the set it produced (a tee step:
// set itself) and the tail of its output, with the error on failure.
func runStep(j Job, p *config.Pipeline, step int, s config.Step, set []file, dir, root string, stop <-chan struct{}) ([]file, string, error) {
	in, out, meta, logf, err := openWork(j, p, step, set, dir)
	if err != nil {
		return nil, "", err
	}
	sc := j.Sidecar
	w := &capWriter{f: logf, left: logCap}
	env := []string{"PATH=" + defaultPath, "LANG=C.UTF-8"}
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+s.Env[k])
	}
	env = append(env, "LUK_WORK="+dir, "LUK_IN="+in, "LUK_OUT="+out, "LUK_META="+meta,
		"LUK_ID="+j.Entry.ID, "LUK_SENDER="+sc.Sender, "LUK_ENDPOINT="+sc.Endpoint, "LUK_PIPELINE="+p.Name)
	name := ""
	if len(set) == 1 {
		env = append(env, "LUK_FILE="+filepath.Join(in, set[0].name))
		name = set[0].name
		if !set[0].produced {
			name = ""
			if runstep.ValidName(j.Vars.File) {
				name = j.Vars.File
			}
		}
	}
	origin := j.Vars.Hostname
	if origin == "" {
		origin = sc.Sender
	}
	env = append(env, "LUK_NAME="+name, "LUK_ROOT="+root, "LUK_STEP="+strconv.Itoa(step),
		"LUK_TAGS="+strings.Join(j.Vars.Tags, ","), "LUK_HOSTNAME="+j.Vars.Hostname, "LUK_ORIGIN="+origin)
	err = execute(s.Run, dir, env, w, stepTimeout(p), stop)
	if cerr := logf.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err == nil {
		err = w.err
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if msg := readFail(dir); msg != "" {
				return nil, w.tail(), stepFailed(msg)
			}
		}
		return nil, w.tail(), err
	}
	if s.Tee {
		if err := emptyOut(out, "tee"); err != nil {
			return nil, w.tail(), err
		}
		return set, w.tail(), nil
	}
	next, err := readOut(out)
	if err != nil {
		return nil, w.tail(), fmt.Errorf("out: %w", err)
	}
	return next, w.tail(), nil
}

// relayStep asks lukd run to run the job s.Relay on the work directory dir
// prepared as for a run step, under the pipeline timeout. The job only
// reads the set, which passes on unchanged. It returns the tail of the
// job's output, with the error on failure.
func relayStep(j Job, p *config.Pipeline, step int, s config.Step, set []file, dir string, stop <-chan struct{}) (string, error) {
	_, out, _, logf, err := openWork(j, p, step, set, dir)
	if err != nil {
		return "", err
	}
	w := &capWriter{f: logf, left: logCap}
	timeout := stepTimeout(p)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	interrupted := make(chan struct{})
	go func() {
		select {
		case <-stop:
			close(interrupted)
			cancel()
		case <-ctx.Done():
		}
	}()
	err = runproto.Ask(ctx, runSocket, s.Relay, dir, w, w)
	if err != nil {
		select {
		case <-interrupted:
			err = errInterrupted
		default:
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				err = fmt.Errorf("timeout after %v", timeout)
			}
		}
	}
	cancel()
	if cerr := logf.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err == nil {
		err = w.err
	}
	if err != nil {
		return w.tail(), err
	}
	if err := emptyOut(out, "relay"); err != nil {
		return w.tail(), err
	}
	return w.tail(), nil
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

// execute runs prog in its own process group. On timeout the group gets
// SIGTERM, then SIGKILL after killAfter unless it is gone by then; on stop
// it gets SIGKILL at once. Once the program has exited, whatever is left of
// the group is killed, so nothing touches out/ after validation.
func execute(prog, dir string, env []string, w io.Writer, timeout time.Duration, stop <-chan struct{}) error {
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pr.Close()
	cmd := exec.Command(prog, dir)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = pw, pw
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err = cmd.Start()
	pw.Close()
	if err != nil {
		return err
	}
	copied := make(chan struct{})
	go func() {
		io.Copy(w, pr)
		close(copied)
	}()
	pgid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var werr, reason error
	select {
	case werr = <-done:
	case <-timer.C:
		reason = fmt.Errorf("timeout after %v", timeout)
		syscall.Kill(-pgid, syscall.SIGTERM)
		waitGone(pgid, killAfter)
	case <-stop:
		reason = errInterrupted
	}
	if reason != nil {
		syscall.Kill(-pgid, syscall.SIGKILL)
		<-done
	}
	syscall.Kill(-pgid, syscall.SIGKILL)
	drain := time.NewTimer(killAfter)
	defer drain.Stop()
	select {
	case <-copied:
	case <-drain.C:
		pr.Close()
		<-copied
	}
	if reason != nil {
		return reason
	}
	return werr
}

// waitGone polls until the process group pgid has no member or d passed.
func waitGone(pgid int, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

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

// emptyOut fails when the tee or relay step (kind) left anything in out.
func emptyOut(out, kind string) error {
	ents, err := os.ReadDir(out)
	if err != nil {
		return fmt.Errorf("out: %w", err)
	}
	if len(ents) > 0 {
		return fmt.Errorf("%s step wrote out/%s", kind, ents[0].Name())
	}
	return nil
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
