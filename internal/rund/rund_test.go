package rund

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/runproto"
	"luk/internal/runstep"
	"luk/internal/wire"
)

var me = uint32(os.Getuid())

func write(t *testing.T, p, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

const s3Job = `user: luk-s3
group: luk-s3
groups: [luk, backup]
command: /opt/luk/s3-upload
credentials:
  s3: /etc/site/lukd/s3.credentials
timeout: 30m
env:
  BUCKET: example-backup
`

func TestLoadGlobal(t *testing.T) {
	d := t.TempDir()
	g, err := LoadGlobal(filepath.Join(d, "missing.conf"), me)
	if err != nil || g.Root != "/var/lib/luk" || g.Peer != "" {
		t.Fatalf("%+v %v", g, err)
	}
	p := filepath.Join(d, "run.yaml")
	write(t, p, "root: "+d+"\n", 0o600)
	if g.Config != "/etc/site/lukd/config.yaml" {
		t.Fatalf("default config %q", g.Config)
	}
	write(t, p, "root: "+d+"\nconfig: "+d+"/lukd/../lukd/config.yaml\n", 0o600)
	if g, err = LoadGlobal(p, me); err != nil || g.Root != d || g.Config != d+"/lukd/config.yaml" {
		t.Fatalf("%+v %v", g, err)
	}
	if uid, err := g.PeerUID(); err != nil || uid != me {
		t.Fatalf("peer %d %v", uid, err)
	}
	for name, c := range map[string]struct {
		data string
		mode os.FileMode
	}{
		"relative root":   {"root: var\n", 0o600},
		"relative config": {"config: config.yaml\n", 0o600},
		"unknown key":     {"roots: /x\n", 0o600},
		"writable":        {"root: /x\n", 0o620},
	} {
		write(t, p, c.data, c.mode)
		if _, err := LoadGlobal(p, me); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	write(t, p, "root: /x\n", 0o600)
	if _, err := LoadGlobal(p, me+1); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("owner: %v", err)
	}
}

func TestLoadJobsRules(t *testing.T) {
	d := filepath.Join(t.TempDir(), "run.d")
	os.Mkdir(d, 0o755)
	files := map[string]string{
		"s3-upload.yaml":           s3Job,
		"min.yaml":                 "user: nobody\ncommand: /bin/true\n",
		".hidden.yaml":             s3Job,
		"notes.txt":                s3Job,
		"old.yaml~":                s3Job,
		"x.yaml.dpkg-old":          s3Job,
		"y.dpkg-new.yaml":          s3Job,
		"z.swp":                    s3Job,
		"Upper.yaml":               s3Job,
		"broken.yaml":              "user: [\n",
		"relative.yaml":            "user: a\ncommand: bin/x\n",
		"unknown-key.yaml":         s3Job + "shell: true\n",
		"luk-work.yaml":            "user: a\ncommand: /x\nenv:\n  LUK_WORK: /tmp\n",
		"luk-any.yaml":             "user: a\ncommand: /x\nenv:\n  LUK_STATE: /tmp\n",
		"bad-state.yaml":           "user: a\ncommand: /x\nstate: exclusive\n",
		"locked.yaml":              "command: /x\nstate: locked\n",
		"shared.yaml":              "user: a\ncommand: /x\nstate: shared\n",
		"no-user.yaml":             "command: /x\ngroups: [luk]\n",
		"group-no-user.yaml":       "group: luk\ncommand: /x\n",
		"no-command.yaml":          "user: a\n",
		"short.yaml":               "user: a\ncommand: /x\ntimeout: 10ms\n",
		"long.yaml":                "user: a\ncommand: /x\ntimeout: 168h\n",
		"longest.yaml":             "user: a\ncommand: /x\ntimeout: 167h\n",
		"pipelines.yaml":           "user: a\ncommand: /x\npipelines: [p]\n",
		"empty-pipelines.yaml":     "user: a\ncommand: /x\npipelines: []\n",
		"null-pipelines.yaml":      "user: a\ncommand: /x\npipelines:\n",
		"tilde-pipelines.yaml":     "user: a\ncommand: /x\npipelines: ~\n",
		"bad-cred.yaml":            "user: a\ncommand: /x\ncredentials:\n  a:b: /x\n",
		"group-writable.yaml":      s3Job,
		"symlink.yaml":             "",
		"dir.yaml/placeholder":     "",
		"world-writable-dir.yaml~": "",
	}
	os.Mkdir(filepath.Join(d, "dir.yaml"), 0o755)
	for n, data := range files {
		if strings.HasSuffix(n, "placeholder") || n == "symlink.yaml" {
			continue
		}
		write(t, filepath.Join(d, n), data, 0o600)
	}
	os.Chmod(filepath.Join(d, "group-writable.yaml"), 0o620)
	os.Symlink(filepath.Join(d, "min.yaml"), filepath.Join(d, "symlink.yaml"))

	js, err := LoadJobs(d, me)
	if err != nil {
		t.Fatal(err)
	}
	var ok, bad []string
	for n := range js.OK {
		ok = append(ok, n)
	}
	for n := range js.Bad {
		bad = append(bad, n)
	}
	slices.Sort(ok)
	slices.Sort(bad)
	if !slices.Equal(ok, []string{"locked", "longest", "min", "no-user", "s3-upload", "shared"}) {
		t.Fatalf("ok %v", ok)
	}
	wantBad := []string{"Upper", "bad-cred", "bad-state", "broken", "dir", "empty-pipelines", "group-no-user", "group-writable",
		"long", "luk-any", "luk-work", "no-command", "null-pipelines", "pipelines", "relative", "short", "symlink", "tilde-pipelines", "unknown-key"}
	if !slices.Equal(bad, wantBad) {
		t.Fatalf("bad %v", bad)
	}
	j := js.OK["s3-upload"]
	if j.User != "luk-s3" || j.Credentials["s3"] != "/etc/site/lukd/s3.credentials" || time.Duration(j.Timeout) != 30*time.Minute {
		t.Fatalf("%+v", j)
	}
	if err := js.Bad["group-no-user"]; !strings.Contains(err.Error(), "needs user") {
		t.Fatalf("group without user: %v", err)
	}
	for _, n := range []string{"pipelines", "empty-pipelines", "null-pipelines", "tilde-pipelines"} {
		if err := js.Bad[n]; !strings.Contains(err.Error(), "pipelines: removed") || !strings.Contains(err.Error(), "jobs of the run step") {
			t.Fatalf("%s: %v", n, err)
		}
	}
	if err := js.Bad["luk-any"]; !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("LUK_*: %v", err)
	}
	if time.Duration(js.OK["min"].Timeout) != time.Hour {
		t.Fatalf("default timeout %v", js.OK["min"].Timeout)
	}

	if _, err := LoadJobs(d, me+1); err == nil {
		t.Fatal("dir of another owner accepted")
	}
	os.Chmod(d, 0o777)
	if _, err := LoadJobs(d, me); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("writable dir: %v", err)
	}
}

func TestArgv(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "j.yaml"), s3Job, 0o600)
	j, err := loadJob(filepath.Join(d, "j.yaml"), me)
	if err != nil {
		t.Fatal(err)
	}
	j.State = StateLocked
	vars := []string{"LUK_WORK=/var/lib/luk/work/a/offsite/1", "LUK_PIPELINE=offsite", "LUK_TAGS=a b,$HOME"}
	got := strings.Join(j.Argv("lukd-run-s3-1", "s3-upload", "offsite", "/var/lib/luk/work/a/offsite/1", "luk", vars), " ")
	want := "systemd-run --wait --collect --pipe --quiet --expand-environment=no --unit=lukd-run-s3-1 --uid=luk-s3 " +
		"--working-directory=/var/lib/luk/work/a/offsite/1 --gid=luk-s3 -p SupplementaryGroups=luk backup " +
		"-p PrivateTmp=yes -p StateDirectory=lukd-run/s3-upload/offsite -p StateDirectoryMode=0700 " +
		"-p LoadCredential=s3:/etc/site/lukd/s3.credentials -p RuntimeMaxSec=1800 --setenv=BUCKET=example-backup " +
		"--setenv=LUK_WORK=/var/lib/luk/work/a/offsite/1 --setenv=LUK_PIPELINE=offsite --setenv=LUK_TAGS=a b,$HOME " +
		"--setenv=LUK_JOB=s3-upload --setenv=LUK_TMP=/var/tmp --setenv=LUK_STATE=/var/lib/lukd-run/s3-upload/offsite " +
		"/opt/luk/s3-upload /var/lib/luk/work/a/offsite/1"
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	if g := strings.Join(j.SupplementaryGroups("1234"), " "); g != "1234 luk backup" {
		t.Fatalf("groups %s", g)
	}
	dyn := &Job{Command: "/opt/luk/notify", Groups: []string{"mail"}, Timeout: config.Duration(time.Minute)}
	got = strings.Join(dyn.Argv("lukd-run-n-1", "notify", "p", "/w", "luk", []string{"LUK_WORK=/w", "LUK_PIPELINE=p"}), " ")
	want = "systemd-run --wait --collect --pipe --quiet --expand-environment=no --unit=lukd-run-n-1 -p DynamicUser=yes -p User=" + DynamicUser("notify", "p") + " " +
		"--working-directory=/w -p SupplementaryGroups=luk mail -p PrivateTmp=yes -p RuntimeMaxSec=60 " +
		"--setenv=LUK_WORK=/w --setenv=LUK_PIPELINE=p --setenv=LUK_JOB=notify --setenv=LUK_TMP=/var/tmp /opt/luk/notify /w"
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	if u := UnitName("s3.Up_x"); !strings.HasPrefix(u, "lukd-run-s3--p-x-") || u == UnitName("s3.Up_x") {
		t.Fatalf("unit %s", u)
	}
}

func TestDynamicUser(t *testing.T) {
	valid := regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)
	seen := map[string]string{}
	for _, c := range [][2]string{
		{"notify", "p"},
		{"a-b", "c"},
		{"a", "b-c"},
		{"s3.upload", "Offsite DB"},
		{strings.Repeat("x", 64), strings.Repeat("y", 200)},
		{strings.Repeat("x", 64), strings.Repeat("y", 201)},
	} {
		u := DynamicUser(c[0], c[1])
		if len(u) > 31 || !valid.MatchString(u) || !strings.HasPrefix(u, "lukd-") {
			t.Errorf("%q: %q", c, u)
		}
		if u != DynamicUser(c[0], c[1]) {
			t.Errorf("%q: not stable", c)
		}
		if o, ok := seen[u]; ok {
			t.Errorf("%q: %q also for %s", c, u, o)
		}
		seen[u] = c[0] + "/" + c[1]
	}
	if u := DynamicUser("notify", "p"); !strings.HasPrefix(u, "lukd-notify-p-") {
		t.Errorf("readable part: %s", u)
	}
}

// id1 is a queue entry id.
const id1 = "20261004T101500Z-0123abcd"

func TestCheckWork(t *testing.T) {
	top := t.TempDir()
	root := filepath.Join(top, "root")
	w := filepath.Join(root, "work", id1, "p", "1")
	os.MkdirAll(w, 0o750)
	outside := filepath.Join(top, "outside")
	os.MkdirAll(filepath.Join(outside, id1, "p", "1"), 0o750)
	os.Symlink(outside, filepath.Join(root, "work", id1, "esc"))
	os.MkdirAll(filepath.Join(outside, "q", "1"), 0o750)
	os.Symlink(filepath.Join(outside, "q"), filepath.Join(root, "work", id1, "q"))
	os.MkdirAll(filepath.Join(root, "work", id1, "r"), 0o750)
	os.Symlink(w, filepath.Join(root, "work", id1, "r", "1"))
	write(t, filepath.Join(w, "file"), "x", 0o600)
	write(t, filepath.Join(root, "work", id1, "p", "2"), "x", 0o600)
	syscall.Mkfifo(filepath.Join(root, "work", id1, "p", "3"), 0o600)
	alias := filepath.Join(top, "alias")
	os.Symlink(root, alias)

	// root (run.yaml) may be a symlink; nothing below it may.
	aw := filepath.Join(alias, "work", id1, "p", "1")
	if p, err := CheckWork(alias, aw, me); err != nil || p != "p" {
		t.Fatalf("%q %v", p, err)
	}
	if p, err := CheckWork(root, w, me); err != nil || p != "p" {
		t.Fatalf("%q %v", p, err)
	}
	for _, d := range []string{"p/1/x", "p/01", "p/0", "p/a", ".p/1", "-p/1", "p\x01/1"} {
		os.MkdirAll(filepath.Join(root, "work", id1, d), 0o750)
	}
	for name, c := range map[string]struct {
		work string
		uid  uint32
		want string
	}{
		"relative":       {"work/id1", me, "not absolute"},
		"outside":        {outside, me, "not under"},
		"other root":     {aw, me, "not under"},
		"work itself":    {filepath.Join(root, "work"), me, "not under"},
		"dotdot":         {w + "/../../../../../outside", me, "not clean"},
		"dotdot inside":  {filepath.Join(root, "work", id1) + "/../" + id1 + "/p/1", me, "not clean"},
		"trailing slash": {w + "/", me, "not clean"},
		"double slash":   {filepath.Join(root, "work") + "//" + id1 + "/p/1", me, "not clean"},
		"symlinked step": {filepath.Join(root, "work", id1, "r", "1"), me, "not a directory"},
		"symlinked pipe": {filepath.Join(root, "work", id1, "q", "1"), me, "not a directory"},
		"missing":        {filepath.Join(root, "work", id1, "p", "9"), me, "no such file"},
		"file":           {filepath.Join(root, "work", id1, "p", "2"), me, "not a directory"},
		"fifo":           {filepath.Join(root, "work", id1, "p", "3"), me, "not a directory"},
		"owner":          {w, me + 1, "owned by"},
		"no step":        {filepath.Join(root, "work", id1, "p"), me, "not a step work directory"},
		"deeper":         {filepath.Join(root, "work", id1, "p", "1", "x"), me, "not a step work directory"},
		"zero pad":       {filepath.Join(root, "work", id1, "p", "01"), me, "not a step work directory"},
		"step 0":         {filepath.Join(root, "work", id1, "p", "0"), me, "not a step work directory"},
		"named step":     {filepath.Join(root, "work", id1, "p", "a"), me, "not a step work directory"},
		"dot":            {filepath.Join(root, "work", id1, ".p", "1"), me, "not a step work directory"},
		"dash":           {filepath.Join(root, "work", id1, "-p", "1"), me, "not a step work directory"},
		"control":        {filepath.Join(root, "work", id1, "p\x01", "1"), me, "control character"},
	} {
		if _, err := CheckWork(root, c.work, c.uid); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// A symlinked <root>/work (luk owns it) is refused as well.
	os.Rename(filepath.Join(root, "work"), filepath.Join(top, "realwork"))
	os.Symlink(filepath.Join(top, "realwork"), filepath.Join(root, "work"))
	if _, err := CheckWork(root, w, me); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("symlinked work: %v", err)
	}
}

// A refused work directory gets one answer whatever the reason, so the
// peer learns nothing about paths root can see; the reason goes to the
// journal.
func TestServeWorkRefusalIsGeneric(t *testing.T) {
	e := newEnv(t)
	var logs strings.Builder
	var mu sync.Mutex
	e.srv.Log = slog.New(slog.NewTextHandler(lockedWriter{&mu, &logs}, nil))
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) {
		t.Error("job ran")
		return 0, nil
	}
	cwd, _ := os.Getwd()
	for _, w := range []string{
		"/etc/passwd/x", "/etc/nonexistent-xyz/x", "/proc/self/cwd/nonexistent-xyz", cwd,
		filepath.Join(filepath.Dir(e.work), "9"), e.work + "/", "relative",
	} {
		fs, err := e.exchange(t, string(runproto.Request{Job: "s3-upload", Work: w}.Encode()))
		if err == nil || len(fs) != 2 || fs[0] != (frame{'e', "lukd run: work directory refused\n"}) || fs[1] != (frame{'x', "1"}) {
			t.Errorf("%q: %v %q", w, err, fs)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(logs.String(), "not under") || !strings.Contains(logs.String(), "no such file") {
		t.Fatalf("journal: %s", logs.String())
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

type fakeRunner struct {
	mu      sync.Mutex
	argv    []string
	stopped []string
	run     func(ctx context.Context, stdout, stderr io.Writer) (int, error)
	// stop and active, when set, answer Stop and Active; a unit is
	// inactive without active.
	stop   func(unit string) error
	active func(unit string) (bool, error)
}

func (f *fakeRunner) Run(ctx context.Context, argv []string, stdout, stderr io.Writer) (int, error) {
	f.mu.Lock()
	f.argv = argv
	f.mu.Unlock()
	return f.run(ctx, stdout, stderr)
}

func (f *fakeRunner) Stop(unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, unit)
	if f.stop != nil {
		return f.stop(unit)
	}
	return nil
}

func (f *fakeRunner) Active(unit string) (bool, error) {
	if f.active != nil {
		return f.active(unit)
	}
	return false, nil
}

type env struct {
	srv  *Server
	work string
	fr   *fakeRunner
	peer uint32
}

// envConfig is the lukd configuration of newEnv: pipeline p may start
// s3-upload, state and quick, offsite relays to s3-upload.
const envConfig = `pipeline:
  p:
    steps:
      - run: /opt/luk/p
        jobs: [s3-upload, state, quick]
  offsite:
    steps: [{relay: s3-upload}]
`

func newEnv(t *testing.T) *env {
	t.Helper()
	top := t.TempDir()
	os.Chmod(top, 0o700)
	root := filepath.Join(top, "root")
	w := filepath.Join(root, "work", id1, "p", "1")
	writeWork(t, w, workMeta(id1, "p", 1), "db.sql")
	jobs := filepath.Join(top, "run.d")
	os.Mkdir(jobs, 0o755)
	write(t, filepath.Join(jobs, "s3-upload.yaml"), s3Job, 0o600)
	write(t, filepath.Join(jobs, "broken.yaml"), "user: [\n", 0o600)
	write(t, filepath.Join(jobs, "state.yaml"), "command: /opt/luk/state\nstate: locked\n", 0o600)
	lukd := filepath.Join(top, "lukd")
	os.Mkdir(lukd, 0o750)
	write(t, filepath.Join(lukd, "config.yaml"), envConfig, 0o640)
	conf := filepath.Join(top, "run.yaml")
	write(t, conf, "root: "+root+"\nconfig: "+filepath.Join(lukd, "config.yaml")+"\n", 0o600)
	e := &env{work: w, fr: &fakeRunner{}, peer: me}
	e.srv = &Server{
		Config: conf, Jobs: jobs, Locks: filepath.Join(top, "locks"), Owner: me, Top: top,
		PeerUID: func() (uint32, error) { return e.peer, nil },
		Runner:  e.fr,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return e
}

type frame struct {
	typ byte
	p   string
}

// exchange serves one connection and returns the frames the client read.
func (e *env) exchange(t *testing.T, req string) ([]frame, error) {
	t.Helper()
	c, s := net.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- e.srv.Serve(s)
		s.Close()
	}()
	go io.WriteString(c, req)
	var fs []frame
	for {
		typ, p, err := runproto.ReadFrame(c)
		if err != nil {
			break
		}
		fs = append(fs, frame{typ, string(p)})
		if typ == runproto.Exit {
			break
		}
	}
	c.Close()
	return fs, <-errc
}

func TestServeRuns(t *testing.T) {
	e := newEnv(t)
	e.fr.run = func(_ context.Context, stdout, stderr io.Writer) (int, error) {
		io.WriteString(stdout, "uploaded\n")
		io.WriteString(stderr, "warning\n")
		return 3, nil
	}
	fs, err := e.exchange(t, string(runproto.Request{Job: "s3-upload", Work: e.work}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	want := []frame{{'o', "uploaded\n"}, {'e', "warning\n"}, {'x', "3"}}
	if !slices.Equal(fs, want) {
		t.Fatalf("%q", fs)
	}
	if a := e.fr.argv; a[len(a)-1] != e.work || a[len(a)-2] != "/opt/luk/s3-upload" {
		t.Fatalf("argv %q", a)
	}
	groups := "SupplementaryGroups=" + GroupName(uint32(os.Getgid())) + " luk backup"
	if !slices.Contains(e.fr.argv, groups) {
		t.Fatalf("argv %q, want %s", e.fr.argv, groups)
	}
	if !slices.Contains(e.fr.argv, "--setenv=LUK_PIPELINE=p") || !slices.Contains(e.fr.argv, "--setenv=LUK_JOB=s3-upload") ||
		slices.ContainsFunc(e.fr.argv, func(a string) bool { return strings.HasPrefix(a, "--setenv=LUK_STATE=") }) {
		t.Fatalf("argv %q", e.fr.argv)
	}
}

// workMeta is the meta.json of an upload db.sql from db1, tagged daily.
func workMeta(id, pipeline string, step int) runstep.WorkMeta {
	return runstep.WorkMeta{
		Server: runstep.WorkServer{ID: id, Sender: "robert.socha", Endpoint: "up", Size: 1, SHA256: "ab"},
		Client: wire.Meta{File: "db.sql", Source: wire.SourceFile, Tags: []string{"daily"}, Portal: wire.PortalDirect,
			Backup: &wire.Backup{Hostname: "db1", Path: "/b/db.sql"}},
		Pipeline: pipeline, Step: step,
	}
}

// writeWork creates the work directory w with meta.json m (a
// runstep.WorkMeta or raw bytes) and the files of in/.
func writeWork(t *testing.T, w string, m any, in ...string) {
	t.Helper()
	for _, d := range []string{"in", "out"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	b, ok := m.([]byte)
	if !ok {
		var err error
		if b, err = json.Marshal(m); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(w, "meta.json"), string(b), 0o440)
	for _, n := range in {
		write(t, filepath.Join(w, "in", n), "x", 0o440)
	}
}

// setenv is the LUK_* metadata of argv, the --setenv values without
// LUK_JOB, LUK_TMP and LUK_STATE, and every --setenv value.
func setenv(argv []string) (meta, all []string) {
	for _, a := range argv {
		kv, ok := strings.CutPrefix(a, "--setenv=")
		if !ok {
			continue
		}
		all = append(all, kv)
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "LUK_") && k != "LUK_JOB" && k != "LUK_TMP" && k != "LUK_STATE" {
			meta = append(meta, kv)
		}
	}
	return meta, all
}

// clientEnv is what a client of lukd run (relay step, luk-job run) sends
// for the work directory w: the metadata of its run step environment.
func clientEnv(t *testing.T, w, root string) map[string]string {
	t.Helper()
	vars, err := runstep.WorkEnv(w, root)
	if err != nil {
		t.Fatal(err)
	}
	return runstep.Meta(w, func(k string) (string, bool) {
		for _, kv := range vars {
			if n, v, _ := strings.Cut(kv, "="); n == k {
				return v, true
			}
		}
		return "", false
	})
}

func TestServeJobEnv(t *testing.T) {
	e := newEnv(t)
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) { return 0, nil }
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(e.work))))
	req := runproto.Request{Job: "s3-upload", Work: e.work, Env: clientEnv(t, e.work, "/elsewhere")}
	if _, err := e.exchange(t, string(req.Encode())); err != nil {
		t.Fatal(err)
	}
	meta, all := setenv(e.fr.argv)
	w := e.work
	want := []string{
		"LUK_WORK=" + w, "LUK_IN=" + w + "/in", "LUK_OUT=" + w + "/out", "LUK_META=" + w + "/meta.json",
		"LUK_ID=" + id1, "LUK_SENDER=robert.socha", "LUK_ENDPOINT=up", "LUK_PIPELINE=p",
		"LUK_FILE=" + w + "/in/db.sql", "LUK_NAME=db.sql", "LUK_ROOT=" + root, "LUK_STEP=1",
		"LUK_TAGS=daily", "LUK_HOSTNAME=db1", "LUK_ORIGIN=db1",
	}
	if !slices.Equal(meta, want) {
		t.Fatalf("\n got %q\nwant %q", meta, want)
	}
	// The job's own env comes first, the LUK_* variables last.
	if all[0] != "BUCKET=example-backup" || all[len(all)-2] != "LUK_JOB=s3-upload" || all[len(all)-1] != "LUK_TMP=/var/tmp" {
		t.Fatalf("%q", all)
	}
}

// The request carries only free-form metadata: every path-bound or
// reserved name is root's, an unsafe value is dropped and no value adds
// an argument.
func TestServeHostileEnv(t *testing.T) {
	e := newEnv(t)
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) { return 0, nil }
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(e.work))))
	req := runproto.Request{Job: "state", Work: e.work, Env: map[string]string{
		"LUK_WORK": "/etc", "LUK_META": "/etc/shadow", "LUK_ROOT": "/", "LUK_ID": "x", "LUK_PIPELINE": "evil",
		"LUK_STEP": "9", "LUK_JOB": "evil", "LUK_TMP": "/", "LUK_STATE": "/", "LD_PRELOAD": "/tmp/x.so",
		"LUK_TAGS": "daily\n--uid=0", "LUK_HOSTNAME": "db1\nLUK_ROOT=/evil", "LUK_ORIGIN": "x\x00y",
		"LUK_FILE": "/etc/shadow", "LUK_NAME": "../x", "LUK_SENDER": "--uid=0",
	}}
	if _, err := e.exchange(t, string(req.Encode())); err != nil {
		t.Fatal(err)
	}
	meta, all := setenv(e.fr.argv)
	w := e.work
	want := []string{
		"LUK_WORK=" + w, "LUK_IN=" + w + "/in", "LUK_OUT=" + w + "/out", "LUK_META=" + w + "/meta.json",
		"LUK_ID=" + id1, "LUK_SENDER=--uid=0", "LUK_PIPELINE=p", "LUK_ROOT=" + root, "LUK_STEP=1",
	}
	if !slices.Equal(meta, want) {
		t.Fatalf("\n got %q\nwant %q", meta, want)
	}
	tail := []string{"LUK_JOB=state", "LUK_TMP=/var/tmp", "LUK_STATE=" + StatePath("state", "p")}
	if !slices.Equal(all[len(all)-3:], tail) || len(all) != len(meta)+3 {
		t.Fatalf("%q", all)
	}
	for _, a := range e.fr.argv {
		if strings.ContainsAny(a, "\n\x00") || a == "--uid=0" || strings.Contains(a, "LD_PRELOAD") {
			t.Fatalf("argv %q", e.fr.argv)
		}
	}
}

// lukd run never opens anything inside the work directory: a missing
// meta.json and in/, or a FIFO as meta.json, neither refuse nor block the
// job.
func TestServeNeverOpensWork(t *testing.T) {
	e := newEnv(t)
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) { return 0, nil }
	os.RemoveAll(e.work)
	os.MkdirAll(e.work, 0o750)
	if err := syscall.Mkfifo(filepath.Join(e.work, "meta.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fs, err := e.exchange(t, string(runproto.Request{Job: "s3-upload", Work: e.work}.Encode()))
		if err != nil || len(fs) != 1 || fs[0] != (frame{'x', "0"}) {
			t.Errorf("%v %q", err, fs)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("lukd run blocked on the work directory")
	}
}

// start serves req on a new connection; the client end is returned open.
func (e *env) start(req string) (net.Conn, chan error) {
	c, s := net.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- e.srv.Serve(s)
		s.Close()
	}()
	go io.WriteString(c, req)
	return c, errc
}

func TestServeStateLock(t *testing.T) {
	defer func(d time.Duration) { lockPoll = d }(lockPoll)
	lockPoll = 5 * time.Millisecond
	e := newEnv(t)
	var mu sync.Mutex
	running, runs := 0, 0
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) {
		mu.Lock()
		running++
		runs++
		if running > 1 {
			t.Error("two runs of one job and pipeline at once")
		}
		mu.Unlock()
		started <- struct{}{}
		<-release
		mu.Lock()
		running--
		mu.Unlock()
		return 0, nil
	}
	req := string(runproto.Request{Job: "state", Work: e.work}.Encode())
	c1, err1 := e.start(req)
	<-started
	if !slices.Contains(e.fr.argv, "--setenv=LUK_STATE=/var/lib/lukd-run/state/p") {
		t.Fatalf("argv %q", e.fr.argv)
	}

	// A peer that gives up while waiting for the lock starts nothing.
	c2, err2 := e.start(req)
	time.Sleep(30 * time.Millisecond)
	c2.Close()
	if err := <-err2; err != nil {
		t.Fatal(err)
	}

	c3, err3 := e.start(req)
	go func() {
		for {
			if _, _, err := runproto.ReadFrame(c3); err != nil {
				return
			}
		}
	}()
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	if runs != 1 {
		t.Fatalf("%d runs while locked", runs)
	}
	mu.Unlock()
	go func() {
		for {
			if _, _, err := runproto.ReadFrame(c1); err != nil {
				return
			}
		}
	}()
	release <- struct{}{}
	if err := <-err1; err != nil {
		t.Fatal(err)
	}
	<-started
	release <- struct{}{}
	if err := <-err3; err != nil {
		t.Fatal(err)
	}
	c1.Close()
	c3.Close()
	if runs != 2 || len(e.fr.stopped) != 0 {
		t.Fatalf("runs %d, stopped %q", runs, e.fr.stopped)
	}
	if _, err := os.Stat(filepath.Join(e.srv.Locks, "state", "p.lock")); err != nil {
		t.Fatal(err)
	}
}

// A work path that would carry anything but a queue id and a pipeline name
// into the systemd-run command line and the unit file is refused before
// any argv is built, for every job.
func TestCheckWorkRefusesUnsafeNames(t *testing.T) {
	top := t.TempDir()
	root := filepath.Join(top, "root")
	ok := filepath.Join(root, "work", id1, "p", "1")
	os.MkdirAll(ok, 0o750)
	if _, err := CheckWork(root, ok, me); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"\n", "\t", " ", "$", "${HOME}", "%", "%h", "\x1b", "\u00a0"} {
		for _, d := range []string{
			filepath.Join(id1+bad, "p", "1"),
			filepath.Join(bad+id1, "p", "1"),
			filepath.Join(id1, "p"+bad, "1"),
			filepath.Join(id1, bad+"p", "1"),
		} {
			w := filepath.Join(root, "work", d)
			if err := os.MkdirAll(w, 0o750); err != nil {
				t.Fatal(err)
			}
			if _, err := CheckWork(root, w, me); err == nil {
				t.Errorf("%q accepted", d)
			}
		}
	}
	for _, id := range []string{"x", "id1", "20261004T101500Z-0123ABCD", "20261004T101500Z-0123abc", "20261004T101500Z0123abcd", "..x"} {
		w := filepath.Join(root, "work", id, "p", "1")
		os.MkdirAll(w, 0o750)
		if _, err := CheckWork(root, w, me); err == nil || !strings.Contains(err.Error(), "not a step work directory") {
			t.Errorf("id %q: %v", id, err)
		}
	}
	// A root holding such a character is refused as well.
	odd := filepath.Join(top, "a$b")
	w := filepath.Join(odd, "work", id1, "p", "1")
	os.MkdirAll(w, 0o750)
	if _, err := CheckWork(odd, w, me); err == nil {
		t.Error("root with $ accepted")
	}
}

func TestServeRefusesPipelineName(t *testing.T) {
	e := newEnv(t)
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) {
		t.Error("job ran")
		return 0, nil
	}
	for _, p := range []string{"Offsite DB", "a%b", "x${HOME}"} {
		w := filepath.Join(filepath.Dir(filepath.Dir(e.work)), p, "1")
		os.MkdirAll(w, 0o750)
		for _, job := range []string{"state", "s3-upload"} {
			fs, err := e.exchange(t, string(runproto.Request{Job: job, Work: w}.Encode()))
			if err == nil || len(fs) != 2 || !strings.HasPrefix(fs[0].p, "lukd run: work ") || fs[1] != (frame{'x', "1"}) {
				t.Fatalf("%s %q: %v %q", job, p, err, fs)
			}
		}
	}
}

func TestGroupName(t *testing.T) {
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skip(err)
	}
	if n := GroupName(uint32(os.Getgid())); n != g.Name {
		t.Fatalf("%s, want %s", n, g.Name)
	}
	if n := GroupName(4294967200); n != "4294967200" {
		t.Fatalf("unknown gid: %s", n)
	}
}

func TestServeRefuses(t *testing.T) {
	e := newEnv(t)
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) {
		t.Error("job ran")
		return 0, nil
	}
	for name, c := range map[string]struct{ req, want string }{
		"unknown job":  {string(runproto.Request{Job: "nope", Work: e.work}.Encode()), "unknown"},
		"invalid name": {string(runproto.Request{Job: "../x", Work: e.work}.Encode()), "unknown"},
		"broken job":   {string(runproto.Request{Job: "broken", Work: e.work}.Encode()), "invalid"},
		"outside":      {string(runproto.Request{Job: "s3-upload", Work: "/etc"}.Encode()), "work directory refused"},
		"bad json":     {"{\n", "request"},
		"oversized":    {strings.Repeat(" ", runproto.MaxRequest+10) + "\n", "larger than"},
	} {
		fs, err := e.exchange(t, c.req)
		if err == nil || len(fs) != 2 || fs[0].typ != 'e' || !strings.Contains(fs[0].p, c.want) || fs[1] != (frame{'x', "1"}) {
			t.Errorf("%s: %v %q", name, err, fs)
		}
	}
}

func TestServePeerCheck(t *testing.T) {
	e := newEnv(t)
	e.peer = me + 1
	fs, err := e.exchange(t, string(runproto.Request{Job: "s3-upload", Work: e.work}.Encode()))
	if err == nil || !strings.Contains(err.Error(), "peer uid") || len(fs) != 0 {
		t.Fatalf("%v %q", err, fs)
	}
	e.peer = me
	e.srv.PeerUID = func() (uint32, error) { return 0, errors.New("no creds") }
	if _, err := e.exchange(t, "x\n"); err == nil || !strings.Contains(err.Error(), "no creds") {
		t.Fatalf("%v", err)
	}
}

func TestServeEarlyCloseStopsUnit(t *testing.T) {
	e := newEnv(t)
	started := make(chan struct{})
	e.fr.run = func(ctx context.Context, _, _ io.Writer) (int, error) {
		close(started)
		<-ctx.Done()
		return 143, nil
	}
	c, s := net.Pipe()
	errc := make(chan error, 1)
	go func() { errc <- e.srv.Serve(s) }()
	io.WriteString(c, string(runproto.Request{Job: "s3-upload", Work: e.work}.Encode()))
	<-started
	c.Close()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not end")
	}
	unit := ""
	for _, a := range e.fr.argv {
		if u, ok := strings.CutPrefix(a, "--unit="); ok {
			unit = u
		}
	}
	if len(e.fr.stopped) != 1 || e.fr.stopped[0] != unit || unit == "" {
		t.Fatalf("stopped %q, unit %q", e.fr.stopped, unit)
	}
}

func TestOneDocumentPerFile(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "run.yaml")
	write(t, p, "root: "+d+"\n---\nroot: /x\n", 0o600)
	if _, err := LoadGlobal(p, me); err == nil || !strings.Contains(err.Error(), p+": more than one YAML document") {
		t.Fatalf("run.yaml: %v", err)
	}
	write(t, p, "root: "+d+"\n# end\n", 0o600)
	if _, err := LoadGlobal(p, me); err != nil {
		t.Fatalf("trailing comment: %v", err)
	}
	jd := filepath.Join(d, "run.d")
	os.Mkdir(jd, 0o755)
	write(t, filepath.Join(jd, "two.yaml"), "user: nobody\ncommand: /bin/true\n---\ncommand: /bin/false\n", 0o600)
	write(t, filepath.Join(jd, "one.yaml"), "user: nobody\ncommand: /bin/true\n\n# end\n", 0o600)
	js, err := LoadJobs(jd, me)
	if err != nil {
		t.Fatal(err)
	}
	if err := js.Bad["two"]; err == nil || !strings.Contains(err.Error(), "two.yaml: more than one YAML document") {
		t.Fatalf("run.d: %v", err)
	}
	if js.OK["one"] == nil {
		t.Fatalf("trailing comment: %v", js.Bad["one"])
	}
}

// When the peer closes and the stop fails because the unit was not loaded
// yet, the state lock stays until the unit, loaded meanwhile, is stopped
// and inactive: a second run of the job on the pipeline starts only then.
func TestServeLockKeptWhenStopFails(t *testing.T) {
	defer func(l, a time.Duration) { lockPoll, activePoll = l, a }(lockPoll, activePoll)
	lockPoll, activePoll = 5*time.Millisecond, 5*time.Millisecond
	e := newEnv(t)
	var mu sync.Mutex
	units := map[string]int{} // polls left before inactive; -1 running
	started := make(chan string, 2)
	e.fr.run = func(ctx context.Context, _, _ io.Writer) (int, error) {
		e.fr.mu.Lock()
		unit := ""
		for _, a := range e.fr.argv {
			if u, ok := strings.CutPrefix(a, "--unit="); ok {
				unit = u
			}
		}
		e.fr.mu.Unlock()
		mu.Lock()
		for u, n := range units {
			if n != 0 {
				t.Errorf("run of %s while %s is active", unit, u)
			}
		}
		mu.Unlock()
		started <- unit
		<-ctx.Done()
		// systemd-run is killed; a unit loaded just after a failed stop
		// keeps running.
		mu.Lock()
		if _, stopped := units[unit]; !stopped {
			units[unit] = -1
		}
		mu.Unlock()
		return 137, nil
	}
	stops := 0
	e.fr.stop = func(unit string) error {
		stops++
		if stops == 1 {
			return errors.New("Unit " + unit + ".service not loaded.")
		}
		mu.Lock()
		units[unit] = 3
		mu.Unlock()
		return nil
	}
	e.fr.active = func(unit string) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if units[unit] > 0 {
			units[unit]--
		}
		return units[unit] != 0, nil
	}
	req := string(runproto.Request{Job: "state", Work: e.work}.Encode())
	c1, err1 := e.start(req)
	first := <-started
	c2, err2 := e.start(req)
	c1.Close()
	if err := <-err1; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if units[first] != 0 {
		t.Fatalf("serve ended with %s still active", first)
	}
	mu.Unlock()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("second run did not start")
	}
	c2.Close()
	if err := <-err2; err != nil {
		t.Fatal(err)
	}
	if len(e.fr.stopped) != 3 || e.fr.stopped[0] != first || e.fr.stopped[1] != first {
		t.Fatalf("stopped %q", e.fr.stopped)
	}
}

// A unit still active at the deadline fails the stop instead of waiting
// on.
func TestSettleDeadline(t *testing.T) {
	defer func(a time.Duration) { activePoll = a }(activePoll)
	activePoll = time.Millisecond
	e := newEnv(t)
	e.fr.active = func(string) (bool, error) { return true, nil }
	err := e.srv.settle("state", "u", nil, time.Now().Add(20*time.Millisecond))
	if err == nil || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("%v", err)
	}
	e.fr.active = func(string) (bool, error) { return false, nil }
	if err := e.srv.settle("state", "u", errors.New("not loaded"), time.Now()); err != nil {
		t.Fatalf("inactive after a failed stop: %v", err)
	}
}

func TestUnitActive(t *testing.T) {
	for show, want := range map[string]bool{
		"ActiveState=inactive\nJob=\n":       false,
		"ActiveState=failed\nJob=\n":         false,
		"ActiveState=inactive\nJob=1234\n":   true,
		"ActiveState=active\nJob=\n":         true,
		"ActiveState=deactivating\nJob=99\n": true,
	} {
		if got, err := unitActive(show); err != nil || got != want {
			t.Errorf("%q: %v %v, want %v", show, got, err, want)
		}
	}
	if _, err := unitActive("Job=\n"); err == nil {
		t.Error("no ActiveState accepted")
	}
}

// ends fails the test unless errc delivers within d.
func ends(t *testing.T, what string, errc <-chan error, d time.Duration) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(d):
		t.Fatalf("%s: serve did not end", what)
	}
	return nil
}

// A peer that sends no request, half a request, or does not read the
// refusal cannot hold the connection beyond requestTimeout.
func TestServeRequestDeadline(t *testing.T) {
	defer func(d time.Duration) { requestTimeout = d }(requestTimeout)
	requestTimeout = 100 * time.Millisecond
	e := newEnv(t)
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) {
		t.Error("job ran")
		return 0, nil
	}
	for name, req := range map[string]string{
		"nothing":        "",
		"half":           `{"job":"s3-upload","work":`,
		"refusal unread": `{"job":"nope","work":"/x"}` + "\n",
	} {
		c, s := net.Pipe()
		errc := make(chan error, 1)
		go func() { errc <- e.srv.Serve(s) }()
		if req != "" {
			go io.WriteString(c, req)
		}
		ends(t, name, errc, 5*time.Second)
		c.Close()
	}
}

// A peer that stops reading while the job writes cannot pin the
// connection: the deadline of the job (timeout plus stopGrace) ends the
// writes, the job is stopped and Serve returns.
func TestServeJobDeadline(t *testing.T) {
	defer func(d time.Duration) { stopGrace = d }(stopGrace)
	stopGrace = 100 * time.Millisecond
	e := newEnv(t)
	write(t, filepath.Join(e.srv.Jobs, "quick.yaml"), "command: /opt/luk/q\ntimeout: 1s\n", 0o600)
	e.fr.run = func(ctx context.Context, stdout, _ io.Writer) (int, error) {
		for ctx.Err() == nil {
			if _, err := stdout.Write([]byte("output\n")); err != nil {
				return 1, nil
			}
		}
		return 143, nil
	}
	c, s := net.Pipe()
	errc := make(chan error, 1)
	go func() { errc <- e.srv.Serve(s) }()
	io.WriteString(c, string(runproto.Request{Job: "quick", Work: e.work}.Encode()))
	ends(t, "unread output", errc, 10*time.Second)
	c.Close()
}

// A job runs only for the pipelines that relay to it or list it in jobs:
// another pipeline is refused before the work directory is looked at or a lock is created.
func TestServePipelineAllowlist(t *testing.T) {
	e := newEnv(t)
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) {
		t.Error("job ran")
		return 0, nil
	}
	for _, p := range []string{"q", "offsite2", strings.Repeat("p", 129)} {
		w := filepath.Join(filepath.Dir(filepath.Dir(e.work)), p, "1")
		os.MkdirAll(w, 0o750)
		for _, job := range []string{"state", "s3-upload"} {
			fs, err := e.exchange(t, string(runproto.Request{Job: job, Work: w}.Encode()))
			if err == nil || len(fs) != 2 || fs[1] != (frame{'x', "1"}) {
				t.Fatalf("%s %q: %v %q", job, p, err, fs)
			}
		}
	}
	if _, err := os.Stat(e.srv.Locks); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("locks: %v", err)
	}
}

// The job's group is the primary group of the peer, not the group of the
// work directory, which luk may change to any group it is in.
func TestServeGroupOfPeer(t *testing.T) {
	var other uint32
	gs, _ := os.Getgroups()
	for _, g := range gs {
		if uint32(g) != uint32(os.Getgid()) {
			other = uint32(g)
		}
	}
	if other == 0 {
		t.Skip("no supplementary group to chgrp the work directory to")
	}
	e := newEnv(t)
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) { return 0, nil }
	if err := os.Chown(e.work, -1, int(other)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.exchange(t, string(runproto.Request{Job: "s3-upload", Work: e.work}.Encode())); err != nil {
		t.Fatal(err)
	}
	u, err := user.LookupId(strconv.Itoa(int(me)))
	if err != nil {
		t.Skip(err)
	}
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	want := "SupplementaryGroups=" + GroupName(uint32(gid)) + " luk backup"
	if !slices.Contains(e.fr.argv, want) || slices.Contains(e.fr.argv, "SupplementaryGroups="+GroupName(other)+" luk backup") {
		t.Fatalf("argv %q, want %s", e.fr.argv, want)
	}
}

// A group name that would split SupplementaryGroups= is passed by gid.
func TestGroupNameOdd(t *testing.T) {
	defer func(f func(string) (*user.Group, error)) { lookupGroupID = f }(lookupGroupID)
	lookupGroupID = func(id string) (*user.Group, error) { return &user.Group{Gid: id, Name: "a b"}, nil }
	if n := GroupName(1234); n != "1234" {
		t.Fatalf("%q", n)
	}
}

func TestCheckParents(t *testing.T) {
	if err := CheckParents("/etc", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := CheckParents("/tmp", "", 0); err == nil || !strings.Contains(err.Error(), "/tmp: writable by group or others") {
		t.Fatalf("/tmp: %v", err)
	}
	top := t.TempDir()
	os.Chmod(top, 0o700)
	d := filepath.Join(top, "site", "lukd")
	os.MkdirAll(d, 0o750)
	os.Chmod(filepath.Join(top, "site"), 0o750)
	if err := CheckParents(d, top, me); err != nil {
		t.Fatal(err)
	}
	if err := CheckParents(d, top, me+1); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("owner: %v", err)
	}
	os.Chmod(filepath.Join(top, "site"), 0o770)
	if err := CheckParents(d, top, me); err == nil || !strings.Contains(err.Error(), "site: writable by group or others") {
		t.Fatalf("group writable: %v", err)
	}
	os.Chmod(filepath.Join(top, "site"), 0o755)
	os.Symlink(filepath.Join(top, "site"), filepath.Join(top, "link"))
	if err := CheckParents(filepath.Join(top, "link", "lukd"), top, me); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("symlink: %v", err)
	}
	if err := CheckParents(filepath.Dir(top), top, me); err == nil {
		t.Fatal("above top accepted")
	}
}

// run.yaml and run.d count only when no directory above them lets
// anyone but root replace them.
func TestServeParents(t *testing.T) {
	e := newEnv(t)
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) {
		t.Error("job ran")
		return 0, nil
	}
	req := string(runproto.Request{Job: "s3-upload", Work: e.work}.Encode())
	top := e.srv.Top
	os.Chmod(top, 0o777)
	if fs, err := e.exchange(t, req); err == nil || len(fs) != 0 {
		t.Fatalf("writable parent of run.yaml: %v %q", err, fs)
	}
	os.Chmod(top, 0o700)
	sub := filepath.Join(top, "etc")
	os.Mkdir(sub, 0o700)
	os.Chmod(sub, 0o775)
	os.Rename(e.srv.Jobs, filepath.Join(sub, "run.d"))
	e.srv.Jobs = filepath.Join(sub, "run.d")
	fs, err := e.exchange(t, req)
	if err == nil || len(fs) != 2 || !strings.Contains(fs[0].p, "unavailable") {
		t.Fatalf("writable parent of run.d: %v %q", err, fs)
	}
}
