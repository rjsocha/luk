package rund

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"luk/internal/runproto"
)

const lukdConfig = `listen:
  main: {addr: ":8443"}
pipeline:
  a:
    endpoint: [x]
    steps:
      - run: /x
      - relay: j1
      - relay: j2
  b:
    steps:
      - relay: j1
      - run: /y
        tee: true
        jobs: [j3, j1]
  c:
  e:
    steps:
      - store: s
        jobs: [j9]
`

// relayTree writes the lukd configuration p (lukdConfig) and config.d next
// to it below top.
func relayTree(t *testing.T) (top, p string) {
	t.Helper()
	top = t.TempDir()
	os.Chmod(top, 0o700)
	d := filepath.Join(top, "lukd")
	os.MkdirAll(filepath.Join(d, "config.d"), 0o750)
	p = filepath.Join(d, "config.yaml")
	write(t, p, lukdConfig, 0o640)
	sd := filepath.Join(d, "config.d")
	write(t, filepath.Join(sd, "10-d.yaml"), "pipeline:\n  d:\n    steps: [{store: s}, {relay: j2}]\n", 0o640)
	write(t, filepath.Join(sd, "20-e.yaml"), "limits:\n  conn: {max: 3}\npipeline:\n", 0o640)
	write(t, filepath.Join(sd, ".hidden.yaml"), "pipeline:\n  h:\n    steps: [{relay: j3}]\n", 0o640)
	write(t, filepath.Join(sd, "notes.txt"), "pipeline:\n  n:\n    steps: [{relay: j3}]\n", 0o640)
	write(t, filepath.Join(sd, "x.yaml.dpkg-old"), "pipeline:\n  o:\n    steps: [{relay: j3}]\n", 0o640)
	return top, p
}

func TestLoadJobPipelines(t *testing.T) {
	top, p := relayTree(t)
	rs, err := LoadJobPipelines(p, top, me)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 || !slices.Equal(rs["j1"], []string{"a", "b"}) || !slices.Equal(rs["j2"], []string{"a", "d"}) || !slices.Equal(rs["j3"], []string{"b"}) {
		t.Fatalf("%v", rs)
	}
	for _, missing := range []string{filepath.Join(top, "lukd", "none.yaml"), filepath.Join(top, "none", "config.yaml")} {
		if rs, err := LoadJobPipelines(missing, top, me); err != nil || len(rs) != 0 {
			t.Fatalf("missing %s: %v %v", missing, rs, err)
		}
	}
	os.RemoveAll(filepath.Join(top, "lukd", "config.d"))
	if rs, err := LoadJobPipelines(p, top, me); err != nil || len(rs) != 3 || !slices.Equal(rs["j1"], []string{"a", "b"}) || !slices.Equal(rs["j2"], []string{"a"}) {
		t.Fatalf("no config.d: %v %v", rs, err)
	}
}

// Any doubt about a file of the configuration refuses the whole
// derivation: nothing is derived from a file that someone but root may
// have written, and nothing from a set lukd itself would refuse.
func TestLoadJobPipelinesRefuses(t *testing.T) {
	for name, c := range map[string]struct {
		setup func(t *testing.T, top, p string)
		want  string
	}{
		"symlink": {func(t *testing.T, top, p string) {
			write(t, filepath.Join(top, "other.yaml"), lukdConfig, 0o640)
			os.Remove(p)
			os.Symlink(filepath.Join(top, "other.yaml"), p)
		}, "symbolic link"},
		"group-writable": {func(t *testing.T, top, p string) { os.Chmod(p, 0o660) }, "writable"},
		"huge": {func(t *testing.T, top, p string) {
			write(t, p, lukdConfig+"#"+strings.Repeat("x", maxConfigFile)+"\n", 0o640)
		}, "larger than"},
		"fifo": {func(t *testing.T, top, p string) {
			os.Remove(p)
			syscall.Mkfifo(p, 0o640)
		}, "not a regular file"},
		"directory": {func(t *testing.T, top, p string) {
			os.Remove(p)
			os.Mkdir(p, 0o750)
		}, "not a regular file"},
		"writable parent": {func(t *testing.T, top, p string) { os.Chmod(filepath.Dir(p), 0o777) }, "writable"},
		"writable config.d": {func(t *testing.T, top, p string) {
			os.Chmod(filepath.Join(filepath.Dir(p), "config.d"), 0o770)
		}, "writable"},
		"config.d symlink": {func(t *testing.T, top, p string) {
			sd := filepath.Join(filepath.Dir(p), "config.d")
			os.Rename(sd, filepath.Join(top, "elsewhere"))
			os.Symlink(filepath.Join(top, "elsewhere"), sd)
		}, "not a directory"},
		"snippet symlink": {func(t *testing.T, top, p string) {
			os.Symlink(p, filepath.Join(filepath.Dir(p), "config.d", "30-link.yaml"))
		}, "symbolic link"},
		"writable snippet": {func(t *testing.T, top, p string) {
			os.Chmod(filepath.Join(filepath.Dir(p), "config.d", "10-d.yaml"), 0o642)
		}, "writable"},
		"pipeline in two files": {func(t *testing.T, top, p string) {
			write(t, filepath.Join(filepath.Dir(p), "config.d", "30-a.yaml"), "pipeline:\n  a:\n    steps: [{relay: j9}]\n", 0o640)
		}, "pipeline a: defined in"},
		"pipeline twice in a file": {func(t *testing.T, top, p string) {
			write(t, p, lukdConfig+"pipeline:\n  z: {}\n", 0o640)
		}, "already defined"},
		"two documents": {func(t *testing.T, top, p string) {
			write(t, p, lukdConfig+"---\npipeline: {}\n", 0o640)
		}, "more than one YAML document"},
		"relay not a string": {func(t *testing.T, top, p string) {
			write(t, p, "pipeline:\n  a:\n    steps: [{relay: [j1]}]\n", 0o640)
		}, "cannot unmarshal"},
		"run and relay": {func(t *testing.T, top, p string) {
			write(t, p, "pipeline:\n  a:\n    steps: [{run: /x, relay: j1}]\n", 0o640)
		}, "pipeline a: step 1: more than one of run and relay"},
		"jobs not a list": {func(t *testing.T, top, p string) {
			write(t, p, "pipeline:\n  a:\n    steps: [{run: /x, jobs: {j1: x}}]\n", 0o640)
		}, "cannot unmarshal"},
		"broken yaml": {func(t *testing.T, top, p string) { write(t, p, "pipeline: [\n", 0o640) }, "yaml"},
		"too many snippets": {func(t *testing.T, top, p string) {
			for i := range maxSnippets {
				write(t, filepath.Join(filepath.Dir(p), "config.d", "x"+strconv.Itoa(i)+".yaml"), "", 0o640)
			}
		}, "more than"},
	} {
		t.Run(name, func(t *testing.T) {
			top, p := relayTree(t)
			c.setup(t, top, p)
			rs, err := LoadJobPipelines(p, top, me)
			if err == nil || !strings.Contains(err.Error(), c.want) || rs != nil {
				t.Fatalf("%v %v, want %q", rs, err, c.want)
			}
		})
	}
	top, p := relayTree(t)
	if _, err := LoadJobPipelines(p, top, me+1); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("owner: %v", err)
	}
}

// The pipelines of a job are those that relay to it and those whose run
// steps list it in jobs; without a usable configuration there are none.
func TestServeJobPipelines(t *testing.T) {
	e := newEnv(t)
	top := e.srv.Top
	write(t, filepath.Join(e.srv.Jobs, "relayonly.yaml"), "command: /opt/luk/r\n", 0o600)
	d := filepath.Join(top, "lukd")
	os.MkdirAll(filepath.Join(d, "config.d"), 0o750)
	cfg := filepath.Join(d, "config.yaml")
	write(t, cfg, "pipeline:\n  p:\n    steps: [{run: /x, jobs: [state]}]\n  q:\n    steps: [{relay: relayonly}, {relay: state}]\n", 0o640)
	write(t, filepath.Join(d, "config.d", "r.yaml"), "pipeline:\n  r:\n    steps: [{run: /y, tee: true, jobs: [s3-upload]}]\n", 0o640)
	works := map[string]string{"p": e.work}
	for _, p := range []string{"q", "r"} {
		works[p] = filepath.Join(filepath.Dir(filepath.Dir(e.work)), p, "1")
		os.MkdirAll(works[p], 0o750)
	}
	ran := 0
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) {
		ran++
		return 0, nil
	}
	check := func(what, job, pipeline string, ok bool) {
		t.Helper()
		before := ran
		fs, err := e.exchange(t, string(runproto.Request{Job: job, Work: works[pipeline]}.Encode()))
		if ok && (err != nil || ran != before+1) {
			t.Errorf("%s: %s on %s refused: %v %q", what, job, pipeline, err, fs)
		}
		if !ok && (err == nil || ran != before || len(fs) != 2 || !strings.Contains(fs[0].p, "pipeline "+pipeline+" not allowed")) {
			t.Errorf("%s: %s on %s allowed: %v %q", what, job, pipeline, err, fs)
		}
	}
	check("relay", "relayonly", "q", true)
	check("relay", "relayonly", "p", false)
	check("union", "state", "p", true)
	check("union", "state", "q", true)
	check("union", "state", "r", false)
	check("config.d jobs", "s3-upload", "r", true)
	check("config.d jobs", "s3-upload", "p", false)

	os.Chmod(cfg, 0o660)
	check("writable config", "state", "p", false)
	check("writable config", "relayonly", "q", false)
	os.Chmod(cfg, 0o640)
	check("restored config", "relayonly", "q", true)

	os.Remove(cfg)
	check("missing config", "state", "p", false)
	check("missing config", "s3-upload", "r", false)

	if _, err := os.Stat(filepath.Join(e.srv.Locks, "state", "r.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock of a refused pipeline: %v", err)
	}
}

// Many pipelines relaying to one job cost time linear in their number.
func TestLoadJobPipelinesMany(t *testing.T) {
	top, p := relayTree(t)
	const files, per = 8, 3000
	for f := range files {
		var b strings.Builder
		b.WriteString("pipeline:\n")
		for i := range per {
			b.WriteString("  p" + strconv.Itoa(f*per+i) + ": {steps: [{relay: many}, {run: /x, jobs: [many]}]}\n")
		}
		write(t, filepath.Join(filepath.Dir(p), "config.d", "m"+strconv.Itoa(f)+".yaml"), b.String(), 0o640)
	}
	start := time.Now()
	rs, err := LoadJobPipelines(p, top, me)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs["many"]) != files*per || !slices.IsSorted(rs["many"]) {
		t.Fatalf("%d pipelines", len(rs["many"]))
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestLoadLukdPaths(t *testing.T) {
	top, p := relayTree(t)
	lk, err := LoadLukd(p, top, me)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(lk.Paths, []string{"/var/lib/luk"}) {
		t.Fatalf("default root: %q", lk.Paths)
	}
	sd := filepath.Join(filepath.Dir(p), "config.d")
	write(t, filepath.Join(sd, "30-paths.yaml"), `root: /data/luk
auth: {nonces: /srv/nonces/}
gpg: {keys: /srv/gpg}
listen:
  web:
    tls: {mode: acme, cert: tls/c.pem, key: /etc/ssl/private/k.pem, eab: {kid: k, key_file: /etc/eab.key}}
endpoint:
  up: {path: /srv/q/up, secret: {path: /run/v/q}}
  rel: {path: queue/rel}
storage:
  s: {type: local, base: /storage/s, path: x}
  r: {type: local, base: store, path: x}
  b: {type: s3, bucket: x}
`, 0o640)
	write(t, filepath.Join(sd, "40-more.yaml"), "storage:\n  t: {type: local, base: /storage/s, path: y}\n", 0o640)
	if lk, err = LoadLukd(p, top, me); err != nil {
		t.Fatal(err)
	}
	want := []string{"/data/luk", "/etc/eab.key", "/etc/ssl/private/k.pem", "/run/v/q", "/srv/gpg", "/srv/nonces", "/srv/q/up", "/storage/s", "/var/lib/luk"}
	if !slices.Equal(lk.Paths, want) {
		t.Fatalf("paths\n got %q\nwant %q", lk.Paths, want)
	}
	if !slices.Equal(lk.Pipelines["j1"], []string{"a", "b"}) {
		t.Fatalf("pipelines %q", lk.Pipelines)
	}
}
