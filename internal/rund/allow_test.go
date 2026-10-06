package rund

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"luk/internal/config"
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

// The configuration is the main file and the *.yaml of config.d that are
// not dotfiles; a missing main file allows nothing.
func TestLoadLukdFiles(t *testing.T) {
	top, p := relayTree(t)
	lk, err := LoadLukd(p, top, me)
	if err != nil {
		t.Fatal(err)
	}
	// c has no steps, only the default timeout.
	if got := slices.Sorted(maps.Keys(lk.Steps)); !slices.Equal(got, []string{"a", "b", "d", "e"}) || lk.Timeout["c"] != config.DefaultPipelineTimeout {
		t.Fatalf("pipelines %q %v", got, lk.Timeout)
	}
	if d := lk.Steps["d"]; len(d) != 2 || d[1].Relay != "j2" || d[0].Program != "" || d[0].Relay != "" {
		t.Fatalf("d %+v", d)
	}
	if b, _ := lk.Step("b", 2); b.Program != "/y" || !slices.Equal(b.Jobs, []string{"j3", "j1"}) {
		t.Fatalf("b %+v", b)
	}
	// A store step has no nested jobs.
	if e, _ := lk.Step("e", 1); e.Jobs != nil {
		t.Fatalf("e %+v", e)
	}
	for _, missing := range []string{filepath.Join(top, "lukd", "none.yaml"), filepath.Join(top, "none", "config.yaml")} {
		if lk, err := LoadLukd(missing, top, me); err != nil || len(lk.Steps) != 0 {
			t.Fatalf("missing %s: %v %v", missing, lk, err)
		}
	}
	os.RemoveAll(filepath.Join(top, "lukd", "config.d"))
	if lk, err := LoadLukd(p, top, me); err != nil || len(lk.Steps) != 3 || lk.Steps["d"] != nil {
		t.Fatalf("no config.d: %v %v", lk, err)
	}
}

// Any doubt about a file of the configuration refuses the whole
// derivation: nothing is derived from a file that someone but root may
// have written, and nothing from a set lukd itself would refuse.
func TestLoadLukdRefuses(t *testing.T) {
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
			lk, err := LoadLukd(p, top, me)
			if err == nil || !strings.Contains(err.Error(), c.want) || lk != nil {
				t.Fatalf("%v %v, want %q", lk, err, c.want)
			}
		})
	}
	top, p := relayTree(t)
	if _, err := LoadLukd(p, top, me+1); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("owner: %v", err)
	}
}

// Many pipelines cost time linear in their number.
func TestLoadLukdMany(t *testing.T) {
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
	lk, err := LoadLukd(p, top, me)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(lk.Steps); n != files*per+4 {
		t.Fatalf("%d pipelines", n)
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
	want := []string{"/data/luk", "/etc/eab.key", "/etc/ssl/private/k.pem", "/run/v/q", "/srv/gpg", "/srv/nonces", "/srv/q/up", "/storage/s"}
	if !slices.Equal(lk.Paths, want) {
		t.Fatalf("paths\n got %q\nwant %q", lk.Paths, want)
	}
}

// lukdTree is a configuration directory owned by the test user below a
// private top: main is its config.yaml.
type lukdTree struct{ top, main string }

func lukdDir(t *testing.T) lukdTree {
	t.Helper()
	top := t.TempDir()
	os.Chmod(top, 0o700)
	d := filepath.Join(top, "lukd")
	os.Mkdir(d, 0o750)
	return lukdTree{top, filepath.Join(d, "config.yaml")}
}

func TestLoadLukdSteps(t *testing.T) {
	e := lukdDir(t)
	write(t, e.main, `pipeline:
  p:
    timeout: 2h
    steps:
      - run: /opt/luk/p
        env: {A: b}
        jobs: [s3-upload]
      - run: {job: db-dump}
      - relay: s3-upload
      - store: a
  q:
    steps: [{run: /opt/luk/q}]
`, 0o640)
	lk, err := LoadLukd(e.main, e.top, me)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := lk.Step("p", 1); !ok || d.Program != "/opt/luk/p" || d.Env["A"] != "b" || !slices.Equal(d.Jobs, []string{"s3-upload"}) {
		t.Fatalf("%+v", d)
	}
	if d, _ := lk.Step("p", 2); d.Job != "db-dump" || d.Program != "" {
		t.Fatalf("%+v", d)
	}
	if d, _ := lk.Step("p", 3); d.Relay != "s3-upload" {
		t.Fatalf("%+v", d)
	}
	if d, ok := lk.Step("p", 4); !ok || d.Program != "" || d.Job != "" || d.Relay != "" {
		t.Fatalf("store step: %+v %v", d, ok)
	}
	for _, c := range []struct {
		p string
		n int
	}{{"p", 5}, {"p", 0}, {"p", -1}, {"x", 1}} {
		if _, ok := lk.Step(c.p, c.n); ok {
			t.Fatalf("step %s %d", c.p, c.n)
		}
	}
	// lukd allows any other env name and value, and so does lukd run.
	write(t, e.main, "pipeline:\n  p:\n    steps: [{run: /x, env: {a-b: \"x\\ny\"}}]\n", 0o640)
	if lk, err := LoadLukd(e.main, e.top, me); err != nil || lk.Steps["p"][0].Env["a-b"] != "x\ny" {
		t.Fatalf("env: %v", err)
	}
	write(t, e.main, "pipeline:\n  p:\n    timeout: 2h\n    steps: [{run: /opt/luk/p}]\n  q:\n    steps: [{run: /opt/luk/q}]\n", 0o640)
	if lk, err = LoadLukd(e.main, e.top, me); err != nil {
		t.Fatal(err)
	}
	if lk.Timeout["p"] != 2*time.Hour || lk.Timeout["q"] != config.DefaultPipelineTimeout {
		t.Fatalf("%v", lk.Timeout)
	}
	const run = "run must be an absolute path or {job: NAME}"
	for body, want := range map[string]string{
		"pipeline:\n  p:\n    steps: [{run: {job: x, y: z}}]\n":      "pipeline p: step 1: " + run,
		"pipeline:\n  p:\n    steps: [{run: {job: [x]}}]\n":          "pipeline p: step 1: " + run,
		"pipeline:\n  p:\n    steps: [{run: [a]}]\n":                 "pipeline p: step 1: " + run,
		"pipeline:\n  p:\n    steps: [{run: x}]\n":                   "pipeline p: step 1: " + run,
		"pipeline:\n  p:\n    steps: [{run: 5}]\n":                   "pipeline p: step 1: " + run,
		"pipeline:\n  p:\n    steps: [{run: /x, env: [a]}]\n":        "pipeline p: step 1: env: ",
		"pipeline:\n  p:\n    steps: [{run: /x, jobs: a}]\n":         "pipeline p: step 1: jobs: ",
		"pipeline:\n  p:\n    timeout: soon\n":                       "pipeline p: timeout: ",
		"pipeline:\n  p:\n    timeout: 168h\n":                       "pipeline p: timeout: must be under 168h0m0s",
		"pipeline:\n  p:\n    timeout: 500ms\n":                      "pipeline p: timeout: 500ms: less than 1s",
		"pipeline:\n  p:\n    timeout: -1h\n":                        "pipeline p: timeout: ",
		"pipeline:\n  p:\n    steps: [{run: /x, env: {LUK_X: a}}]\n": "pipeline p: step 1: env.LUK_X: LUK_* names are reserved",
	} {
		write(t, e.main, body, 0o640)
		if _, err := LoadLukd(e.main, e.top, me); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", body, want, err)
		}
	}
}
