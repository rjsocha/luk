package rund

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"luk/internal/config"
	"luk/internal/jobchan"
	"luk/internal/runproto"
	"luk/internal/workspace"
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
	if err != nil || g.Root != "/var/lib/luk" {
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
	write(t, p, "hide: [/srv/a/, /srv/b/../c]\n", 0o600)
	if g, err := LoadGlobal(p, me); err != nil || !slices.Equal(g.Hide, []string{"/srv/a", "/srv/c"}) {
		t.Fatalf("hide %+v %v", g, err)
	}
	write(t, p, "hide: [srv]\n", 0o600)
	if _, err := LoadGlobal(p, me); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("relative hide: %v", err)
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

func TestLoadGlobalLimits(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "run.yaml")
	write(t, p, "limits:\n  units:\n    max: 4\n", 0o600)
	g, err := LoadGlobal(p, me)
	if err != nil || g.Limits.Units.Max != 4 {
		t.Fatalf("%+v %v", g, err)
	}
	write(t, p, "", 0o600)
	if g, _ := LoadGlobal(p, me); g.Limits.Units.Max != DefaultUnitsMax {
		t.Fatalf("default %d", g.Limits.Units.Max)
	}
	if g, _ := LoadGlobal(filepath.Join(dir, "missing.yaml"), me); g.Limits.Units.Max != DefaultUnitsMax {
		t.Fatalf("missing file: %d", g.Limits.Units.Max)
	}
	for body, want := range map[string]string{
		"limits:\n  units:\n    max: 0\n":  "limits.units.max: at least 1",
		"limits:\n  units:\n    max: -2\n": "limits.units.max: at least 1",
		"limits:\n  units:\n    min: 1\n":  "field min not found",
		"peer: luk\n":                      "field peer not found",
	} {
		write(t, p, body, 0o600)
		if _, err := LoadGlobal(p, me); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", body, want, err)
		}
	}
}

func TestServiceUID(t *testing.T) {
	root := t.TempDir()
	g := &Global{Root: root}
	if _, err := g.ServiceUID(); err == nil {
		t.Fatal("missing data accepted")
	}
	os.Mkdir(filepath.Join(root, "data"), 0o750)
	if uid, err := g.ServiceUID(); err != nil || uid != me {
		t.Fatalf("%d %v", uid, err)
	}
	os.Remove(filepath.Join(root, "data"))
	write(t, filepath.Join(root, "data"), "", 0o600)
	if _, err := g.ServiceUID(); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("file: %v", err)
	}
	os.Remove(filepath.Join(root, "data"))
	os.Symlink(t.TempDir(), filepath.Join(root, "data"))
	if _, err := g.ServiceUID(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}
}

func TestPrivilegedNeedsUser(t *testing.T) {
	j := &Job{Command: "/opt/x", Privileged: true}
	if err := j.validate(); err == nil || !strings.Contains(err.Error(), "privileged needs user") {
		t.Fatalf("got %v", err)
	}
	j.User = "podman"
	if err := j.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestStepUser(t *testing.T) {
	a, b := StepUser("p", 1), DynamicUser("p", "1")
	if a == b {
		t.Fatalf("step 1 of p and job p on pipeline 1 share %s", a)
	}
	if !strings.HasPrefix(a, "lukd-p-1-") || len(a) > 31 {
		t.Fatalf("%q", a)
	}
	if u := StepUser(strings.Repeat("Long.Pipeline", 10), 12); len(u) > 31 || strings.ContainsAny(u, ".L") {
		t.Fatalf("%q", u)
	}
	if StepUser("p", 1) != StepUser("p", 1) {
		t.Fatal("not stable")
	}
}

// box is the sandbox of the argv tests.
func box(root, conf string, hide ...string) *Box {
	return &Box{Root: root, Config: conf, Hide: hide, Lukd: "/usr/bin/lukd"}
}

func TestArgvProgram(t *testing.T) {
	u := ProgramUnit("lukd-step-p-2-0123456789ab", StepDef{Program: "/opt/luk/p", Env: map[string]string{"B": "2", "A": "1"}}, 2*time.Hour, "p", 2)
	ws := "/var/lib/luk/root/job/lukd-step-p-2-0123456789ab"
	if got := u.Workspace(box("/var/lib/luk", "/etc/site/lukd")); got != ws {
		t.Fatalf("workspace %s", got)
	}
	argv, err := u.Argv(box("/var/lib/luk", "/etc/site/lukd"), []string{"LUK_WORK=" + ws, "TMPDIR=" + ws + "/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemd-run", "--wait", "--collect", "--pipe", "--quiet", "--expand-environment=no",
		"--unit=lukd-step-p-2-0123456789ab",
		"-p", "DynamicUser=yes", "-p", "User=" + StepUser("p", 2),
		"--working-directory=" + ws,
		"-p", "NoNewPrivileges=yes", "-p", "PrivateTmp=yes", "-p", "ProtectProc=invisible", "-p", "PrivatePIDs=yes",
		"-p", "InaccessiblePaths=-/etc/site/lukd", "-p", "InaccessiblePaths=-/run/luk",
		"-p", "TemporaryFileSystem=/var/lib/luk:ro", "-p", "BindPaths=" + ws + ":" + ws + ":norbind",
		"-p", "ExecStartPre=+/usr/bin/lukd run workspace own lukd-step-p-2-0123456789ab",
		"-p", "RuntimeMaxSec=7200",
		"--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "--setenv=LANG=C.UTF-8",
		"--setenv=A=1", "--setenv=B=2", "--setenv=LUK_WORK=" + ws, "--setenv=TMPDIR=" + ws + "/tmp",
		"/usr/bin/lukd", "run", "workspace", "run", ws, "--", "/opt/luk/p", ws,
	}
	if !slices.Equal(argv, want) {
		t.Fatalf("got  %q\nwant %q", argv, want)
	}
}

func TestArgvJob(t *testing.T) {
	j := &Job{User: "podman", Groups: []string{"backup", "backup"}, Command: "/opt/luk/pod", Privileged: true,
		State: StateShared, Timeout: config.Duration(time.Hour), Credentials: map[string]string{"s3": "/etc/site/lukd/s3"}}
	u := j.Unit("lukd-run-pod-0123456789ab", "pod", "p", 1)
	argv, err := u.Argv(box("/var/lib/luk", "/etc/site/lukd"), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Join(argv, " ")
	for _, want := range []string{"--uid=podman", "-p SupplementaryGroups=backup -p", "-p StateDirectory=lukd-run/pod/p",
		"-p LoadCredential=s3:/etc/site/lukd/s3", "-p RuntimeMaxSec=3600", "--setenv=LUK_JOB=pod", "--setenv=LUK_STATE=/var/lib/lukd-run/pod/p"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in %s", want, s)
		}
	}
	if strings.Contains(s, "NoNewPrivileges") {
		t.Fatalf("privileged job: %s", s)
	}
	for _, a := range argv {
		if strings.HasPrefix(a, "SupplementaryGroups=") && a != "SupplementaryGroups=backup" {
			t.Fatalf("groups: %s", a)
		}
	}
	// A dynamic user per job and pipeline, no groups, NoNewPrivileges.
	dyn := &Job{Command: "/opt/luk/n", Timeout: config.Duration(time.Minute)}
	argv, err = dyn.Unit("lukd-run-n-0123456789ab", "n", "p", 3).Argv(box("/var/lib/luk", "/etc/site/lukd"), nil)
	if err != nil {
		t.Fatal(err)
	}
	s = strings.Join(argv, " ")
	if !strings.Contains(s, "-p DynamicUser=yes -p User="+DynamicUser("n", "p")+" ") || strings.Contains(s, "SupplementaryGroups") ||
		!strings.Contains(s, "-p NoNewPrivileges=yes") || strings.Contains(s, "LUK_STATE") || !strings.Contains(s, "--setenv=LUK_JOB=n") {
		t.Fatalf("dynamic job: %s", s)
	}
}

func TestArgvRefusesPaths(t *testing.T) {
	j := &Job{User: "u", Command: "/opt/j", Timeout: config.Duration(time.Minute)}
	ok := box("/var/lib/luk", "/etc/site/lukd")
	const unit = "lukd-run-j-0123456789ab"
	for name, c := range map[string]struct {
		b     *Box
		unit  string
		cmd   string
		state bool
	}{
		"colon in unit":          {ok, "lukd-run-j:x-0123456789ab", "", false},
		"unit x/..":              {ok, "x/..", "", false},
		"unit not a unit name":   {ok, "other-0123456789ab", "", false},
		"space in unit":          {ok, "lukd-run-j x-0123456789ab", "", false},
		"space in root":          {box("/var/lib/l k", "/etc/site/lukd"), unit, "", false},
		"root is /":              {box("/", "/etc/site/lukd"), unit, "", false},
		"root is /var/lib":       {box("/var/lib", "/etc/site/lukd"), unit, "", false},
		"root is /srv":           {box("/srv", "/etc/site/lukd"), unit, "", false},
		"root not clean":         {box("/var/lib/luk/", "/etc/site/lukd"), unit, "", false},
		"space in config dir":    {box("/var/lib/luk", "/etc/l k"), unit, "", false},
		"config dir is /":        {box("/var/lib/luk", "/"), unit, "", false},
		"config dir is /etc":     {box("/var/lib/luk", "/etc"), unit, "", false},
		"space in hidden path":   {box("/var/lib/luk", "/etc/site/lukd", "/srv/a b"), unit, "", false},
		"colon in hidden path":   {box("/var/lib/luk", "/etc/site/lukd", "/srv/a:b"), unit, "", false},
		"hidden path holds root": {box("/var/lib/luk", "/etc/site/lukd", "/var/lib"), unit, "", false},
		"hidden command":         {box("/var/lib/luk", "/etc/site/lukd", "/opt/j"), unit, "", false},
		"hidden lukd":            {&Box{Root: "/var/lib/luk", Config: "/etc/site/lukd", Hide: []string{"/usr/local/lukd"}, Lukd: "/usr/local/lukd/bin/lukd"}, unit, "", false},
		"hidden /srv":            {box("/var/lib/luk", "/etc/site/lukd", "/srv"), unit, "", false},
		"hidden /usr/bin":        {box("/var/lib/luk", "/etc/site/lukd", "/usr/bin"), unit, "", false},
		"hidden state":           {box("/var/lib/luk", "/etc/site/lukd", "/var/lib/lukd-run"), unit, "", true},
		"relative lukd":          {&Box{Root: "/var/lib/luk", Config: "/etc/site/lukd", Lukd: "lukd"}, unit, "", false},
		"relative command":       {ok, unit, "opt/j", false},
		"command not clean":      {ok, unit, "/opt/../opt/j", false},
		"command under root":     {ok, unit, "/var/lib/luk/bin/j", false},
		"command in workspace":   {ok, unit, "/var/lib/luk/root/job/" + unit + "/j", false},
		"command in config":      {ok, unit, "/etc/site/lukd/j", false},
		"command in /run/luk":    {ok, unit, "/run/luk/j", false},
	} {
		jc := *j
		if c.cmd != "" {
			jc.Command = c.cmd
		}
		if c.state {
			jc.State = StateShared
		}
		if a, err := jc.Unit(c.unit, "j", "p", 1).Argv(c.b, nil); err == nil {
			t.Errorf("%s: job accepted: %q", name, a)
		}
		if c.state {
			continue
		}
		if a, err := ProgramUnit(c.unit, StepDef{Program: jc.Command}, time.Minute, "p", 1).Argv(c.b, nil); err == nil {
			t.Errorf("%s: program accepted: %q", name, a)
		}
	}
	if _, err := j.Unit(unit, "j", "p", 1).Argv(ok, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ProgramUnit(unit, StepDef{Program: "/opt/j"}, time.Minute, "p", 1).Argv(ok, nil); err != nil {
		t.Fatal(err)
	}
	if a, err := ProgramUnit(unit, StepDef{Program: "/opt/j"}, 0, "p", 1).Argv(ok, nil); err == nil {
		t.Fatalf("no timeout accepted: %q", a)
	}
	dyn := &Job{Command: "/opt/j", Timeout: config.Duration(time.Minute)}
	u := dyn.Unit(unit, "j", "p", 1)
	u.Privileged = true
	if a, err := u.Argv(ok, nil); err == nil || !strings.Contains(err.Error(), "privileged needs user") {
		t.Fatalf("privileged dynamic user: %q %v", a, err)
	}
	// A hidden path under root, the configuration directory or /run/luk
	// is left out, whatever its characters.
	a, err := j.Unit(unit, "j", "p", 1).Argv(box("/var/lib/luk", "/etc/site/lukd", "/var/lib/luk/a b", "/run/luk/x:y"), nil)
	if err != nil || strings.Count(strings.Join(a, " "), "InaccessiblePaths=") != 2 {
		t.Fatalf("%q %v", a, err)
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

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// fakeRunner records every argv it runs. The create and remove helpers
// (workspace.HelperArgv) exit with createExit and removeExit (create and
// remove, when set, decide instead), a unit runs run.
type fakeRunner struct {
	mu         sync.Mutex
	runs       [][]string
	stdin      []*os.File
	stopped    []string
	createExit int
	removeExit int
	create     func(ctx context.Context) int
	remove     func(ctx context.Context, unit string) int
	run        func(ctx context.Context, stdout, stderr io.Writer) (int, error)
	// stop and active, when set, answer Stop and Active; a unit is
	// inactive without active.
	stop   func(unit string) error
	active func(unit string) (bool, error)
}

// helperAction is the action of the helper argv a, empty for a unit.
func helperAction(a []string) string {
	if n := len(a); n >= 3 && a[n-3] == "workspace" {
		return a[n-2]
	}
	return ""
}

func (f *fakeRunner) Run(ctx context.Context, argv []string, stdin *os.File, stdout, stderr io.Writer) (int, error) {
	f.mu.Lock()
	f.runs = append(f.runs, argv)
	f.stdin = append(f.stdin, stdin)
	run, create, remove := f.run, f.create, f.remove
	f.mu.Unlock()
	switch helperAction(argv) {
	case "create":
		if create != nil {
			return create(ctx), nil
		}
		return f.createExit, nil
	case "remove":
		if remove != nil {
			return remove(ctx, argv[len(argv)-1]), nil
		}
		return f.removeExit, nil
	}
	return run(ctx, stdout, stderr)
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

// argvs is every argv run so far.
func (f *fakeRunner) argvs() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.runs)
}

// units is the argv of every unit run so far.
func (f *fakeRunner) units() [][]string {
	var us [][]string
	for _, a := range f.argvs() {
		if helperAction(a) == "" {
			us = append(us, a)
		}
	}
	return us
}

func (f *fakeRunner) unitRuns() int { return len(f.units()) }

// unitArgv is the argv of the last unit run.
func (f *fakeRunner) unitArgv() []string {
	us := f.units()
	if len(us) == 0 {
		return nil
	}
	return us[len(us)-1]
}

// unitName is the --unit= of argv.
func unitName(argv []string) string {
	for _, a := range argv {
		if u, ok := strings.CutPrefix(a, "--unit="); ok {
			return u
		}
	}
	return ""
}

type env struct {
	srv  *Server
	fr   *fakeRunner
	peer uint32
	// root is the root of run.yaml, conf the lukd configuration.
	root, conf string
}

// envConfig is the lukd configuration of newEnv: step 1 of p runs a
// program that may ask for s3-upload and state, step 2 runs s3-upload,
// step 3 relays to state, step 4 stores.
const envConfig = `pipeline:
  p:
    timeout: 30m
    steps:
      - run: /opt/luk/p
        jobs: [s3-upload, state]
      - run: {job: s3-upload}
      - relay: state
      - store: a
`

func newEnv(t *testing.T) *env {
	t.Helper()
	top := t.TempDir()
	os.Chmod(top, 0o700)
	root := filepath.Join(top, "root")
	for _, d := range []string{root, filepath.Join(root, "data"), filepath.Join(root, "root"), filepath.Join(top, "locks")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	jobs := filepath.Join(top, "run.d")
	os.Mkdir(jobs, 0o755)
	write(t, filepath.Join(jobs, "s3-upload.yaml"), s3Job, 0o600)
	write(t, filepath.Join(jobs, "broken.yaml"), "user: [\n", 0o600)
	write(t, filepath.Join(jobs, "state.yaml"), "command: /opt/luk/state\nstate: locked\n", 0o600)
	lukd := filepath.Join(top, "lukd")
	os.Mkdir(lukd, 0o750)
	conf := filepath.Join(lukd, "config.yaml")
	write(t, conf, envConfig, 0o640)
	run := filepath.Join(top, "run.yaml")
	write(t, run, "root: "+root+"\nconfig: "+conf+"\n", 0o600)
	e := &env{peer: me, root: root, conf: conf, fr: &fakeRunner{
		run: func(context.Context, io.Writer, io.Writer) (int, error) { return 0, nil },
	}}
	e.srv = &Server{
		Config: run, Jobs: jobs, Locks: filepath.Join(top, "locks"), Owner: me, Top: top,
		Lukd:    "/usr/bin/lukd",
		PeerUID: func() (uint32, error) { return e.peer, nil },
		Runner:  e.fr,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return e
}

// unixPair is a connected SOCK_STREAM pair.
func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var c [2]*net.UnixConn
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		fc, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		c[i] = fc.(*net.UnixConn)
		t.Cleanup(func() { c[i].Close() })
	}
	return c[0], c[1]
}

// sendRaw serves one connection and sends line on it, with the remote end
// of a channel attached when withChannel; the client end is returned
// open.
func (e *env) sendRaw(t *testing.T, line []byte, withChannel bool) (*net.UnixConn, chan error) {
	t.Helper()
	srv, cli := unixPair(t)
	errc := make(chan error, 1)
	go func() {
		errc <- e.srv.Serve(srv)
		srv.Close()
	}()
	var oob []byte
	if withChannel {
		local, remote, err := jobchan.Pair()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { local.Close() })
		defer remote.Close()
		oob = unix.UnixRights(int(remote.Fd()))
	}
	if len(line) > 0 {
		if _, _, err := cli.WriteMsgUnix(line, oob, nil); err != nil {
			t.Fatal(err)
		}
	}
	return cli, errc
}

// start serves req, with a channel, on a new connection; the client end
// is returned open.
func (e *env) start(t *testing.T, req runproto.StepRequest) (*net.UnixConn, chan error) {
	return e.sendRaw(t, req.Encode(), true)
}

type frame struct {
	typ byte
	p   string
}

// frames reads the frames of c up to the exit frame or the end.
func frames(c net.Conn) []frame {
	var fs []frame
	for {
		typ, p, err := runproto.ReadFrame(c)
		if err != nil {
			return fs
		}
		fs = append(fs, frame{typ, string(p)})
		if typ == runproto.Exit {
			return fs
		}
	}
}

// exchange serves one request and returns the frames the client read
// and the error of Serve.
func (e *env) exchange(t *testing.T, req runproto.StepRequest, withChannel bool) ([]frame, error) {
	t.Helper()
	return e.exchangeRaw(t, req.Encode(), withChannel)
}

func (e *env) exchangeRaw(t *testing.T, line []byte, withChannel bool) ([]frame, error) {
	t.Helper()
	c, errc := e.sendRaw(t, line, withChannel)
	fs := frames(c)
	c.Close()
	return fs, ends(t, "exchange", errc, 10*time.Second)
}

// waitFrame reads c up to a frame of typ.
func waitFrame(t *testing.T, c net.Conn, typ byte) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	for {
		got, _, err := runproto.ReadFrame(c)
		if err != nil {
			t.Fatalf("waiting for %q: %v", typ, err)
		}
		if got == typ {
			return
		}
	}
}

// frameWithin is the type of the next frame of c if it comes within d,
// else 0.
func frameWithin(c net.Conn, d time.Duration) byte {
	c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	typ, _, err := runproto.ReadFrame(c)
	if err != nil {
		return 0
	}
	return typ
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

// setenv is every --setenv value of argv.
func setenv(argv []string) []string {
	var all []string
	for _, a := range argv {
		if kv, ok := strings.CutPrefix(a, "--setenv="); ok {
			all = append(all, kv)
		}
	}
	return all
}

func TestServeProgramStep(t *testing.T) {
	e := newEnv(t)
	e.fr.run = func(_ context.Context, stdout, _ io.Writer) (int, error) {
		io.WriteString(stdout, "hi\n")
		return 0, nil
	}
	fs, err := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1, Env: map[string]string{"LUK_NAME": "db.sql"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 || fs[0].typ != runproto.Started || fs[1].p != "hi\n" || fs[2].typ != runproto.Exit || fs[2].p != "0" {
		t.Fatalf("%+v", fs)
	}
	runs := e.fr.argvs()
	if len(runs) != 3 || !slices.Contains(runs[0], "create") || !slices.Contains(runs[2], "remove") {
		t.Fatalf("%q", runs)
	}
	unit := strings.TrimPrefix(runs[1][6], "--unit=")
	if !strings.HasPrefix(unit, "lukd-step-p-1-") || runs[0][len(runs[0])-1] != unit || runs[2][len(runs[2])-1] != unit {
		t.Fatalf("unit %q in %q", unit, runs)
	}
	// The helpers get the fixed command line, with a unit name of their own.
	for i, action := range map[int]string{0: "create", 2: "remove"} {
		want := workspace.HelperArgv("/usr/bin/lukd", e.root, action, unit)
		if !slices.Equal(runs[i][:4], want[:4]) || !slices.Equal(runs[i][5:], want[5:]) || !strings.HasPrefix(runs[i][4], "--unit=lukd-workspace-") {
			t.Fatalf("%s %q", action, runs[i])
		}
	}
	s := strings.Join(runs[1], " ")
	for _, want := range []string{"User=" + StepUser("p", 1), "RuntimeMaxSec=1800", "--setenv=LUK_NAME=db.sql", "-- /opt/luk/p "} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if e.fr.stdin[1] == nil || e.fr.stdin[0] != nil || e.fr.stdin[2] != nil {
		t.Fatalf("stdin %v: the channel goes to the unit only", e.fr.stdin)
	}
	if strings.Contains(s, "LUK_JOB") {
		t.Fatalf("program with LUK_JOB: %s", s)
	}
	// The workspace lock is gone with the workspace.
	if ents, err := os.ReadDir(filepath.Join(e.srv.Locks, workspace.LockDir)); err != nil || len(ents) != 0 {
		t.Fatalf("workspace locks %v %v", ents, err)
	}
	// The unit slots lie in .slot, apart from the state locks of a job
	// (<job>/<pipeline>.lock), which a job named slot would share.
	if _, err := os.Stat(filepath.Join(e.srv.Locks, SlotDir, "1.lock")); err != nil {
		t.Fatal(err)
	}
}

// The job of a run: {job} step, of a relay step and a nested job run as
// lukd-run-<job>-<random> with LUK_JOB.
func TestServeJobs(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		req       runproto.StepRequest
		job, user string
	}{
		{runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1}, "s3-upload", "--uid=luk-s3"},
		{runproto.StepRequest{Pipeline: "p", Step: 3, ID: id1}, "state", "User=" + DynamicUser("state", "p")},
		{runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1, Job: "s3-upload"}, "s3-upload", "--uid=luk-s3"},
	} {
		fs, err := e.exchange(t, c.req, true)
		if err != nil || len(fs) != 2 || fs[0].typ != runproto.Started || fs[1] != (frame{runproto.Exit, "0"}) {
			t.Fatalf("%+v: %+v %v", c.req, fs, err)
		}
		a := e.fr.unitArgv()
		s := strings.Join(a, " ")
		if !strings.HasPrefix(unitName(a), "lukd-run-"+c.job+"-") || !strings.Contains(s, c.user) ||
			!strings.Contains(s, "--setenv=LUK_JOB="+c.job) || !strings.Contains(s, "--setenv=LUK_STEP="+strconv.Itoa(c.req.Step)) {
			t.Fatalf("%+v: %s", c.req, s)
		}
	}
}

func TestServeRefusals(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		req  runproto.StepRequest
		want string
	}{
		{runproto.StepRequest{Pipeline: "p", Step: 4, ID: id1}, "pipeline p step 4: not a run or relay step"},
		{runproto.StepRequest{Pipeline: "p", Step: 5, ID: id1}, "pipeline p step 5: not a run or relay step"},
		{runproto.StepRequest{Pipeline: "nope", Step: 1, ID: id1}, "pipeline nope step 1: not a run or relay step"},
		{runproto.StepRequest{Pipeline: "p", Step: 1, ID: "x"}, `id "x": not a queue entry id`},
		{runproto.StepRequest{Pipeline: ".p", Step: 1, ID: id1}, `pipeline ".p": invalid name`},
		{runproto.StepRequest{Pipeline: "Offsite DB", Step: 1, ID: id1}, `pipeline "Offsite DB": invalid name`},
		{runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1, Job: "../x"}, `job "../x": unknown`},
		{runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1, Job: "broken"}, "job broken: not allowed for pipeline p step 1"},
		{runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1, Job: "s3-upload"}, "job s3-upload: not allowed for pipeline p step 2"},
		{runproto.StepRequest{Pipeline: "p", Step: 3, ID: id1, Job: "state"}, "job state: not allowed for pipeline p step 3"},
		{runproto.StepRequest{Pipeline: "p", Step: 9, ID: id1, Job: "state"}, "job state: not allowed for pipeline p step 9"},
	} {
		fs, _ := e.exchange(t, c.req, true)
		if len(fs) != 2 || fs[0] != (frame{runproto.Stderr, "lukd run: " + c.want + "\n"}) || fs[1] != (frame{runproto.Exit, "1"}) {
			t.Errorf("%+v: %+v", c.req, fs)
		}
	}
	if n := len(e.fr.argvs()); n != 0 {
		t.Fatalf("%d runs for refused requests", n)
	}
	fs, _ := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1}, false)
	if len(fs) != 2 || fs[0].p != "lukd run: request: without its descriptor\n" {
		t.Fatalf("no channel: %+v", fs)
	}
	fs, _ = e.exchangeRaw(t, []byte("{\n"), true)
	if len(fs) != 2 || !strings.HasPrefix(fs[0].p, "lukd run: request: ") || fs[1].p != "1" {
		t.Fatalf("bad json: %+v", fs)
	}
	// Nothing is created for a refused request: no slot, no lock.
	if ents, err := os.ReadDir(e.srv.Locks); err != nil || len(ents) != 0 {
		t.Fatalf("locks %v %v", ents, err)
	}
}

// A job named by the configuration must be a valid file of run.d.
func TestServeJobFiles(t *testing.T) {
	e := newEnv(t)
	write(t, e.conf, `pipeline:
  p:
    steps:
      - run: /opt/luk/p
        jobs: [broken, gone]
      - relay: Bad.Name
`, 0o640)
	for _, c := range []struct {
		req  runproto.StepRequest
		want string
	}{
		{runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1, Job: "broken"}, "job broken: invalid, see the journal of lukd-run@.service"},
		{runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1, Job: "gone"}, `job "gone": unknown`},
		{runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1}, `job "Bad.Name": unknown`},
	} {
		fs, _ := e.exchange(t, c.req, true)
		if len(fs) != 2 || fs[0] != (frame{runproto.Stderr, "lukd run: " + c.want + "\n"}) {
			t.Errorf("%+v: %+v", c.req, fs)
		}
	}
	// A refused configuration allows no step.
	os.Chmod(e.conf, 0o660)
	fs, _ := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1}, true)
	if len(fs) != 2 || fs[0].p != "lukd run: pipeline p step 1: not a run or relay step\n" {
		t.Fatalf("writable config: %+v", fs)
	}
	fs, _ = e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1, Job: "gone"}, true)
	if len(fs) != 2 || fs[0].p != "lukd run: job gone: not allowed for pipeline p step 1\n" {
		t.Fatalf("writable config, nested: %+v", fs)
	}
	os.Remove(e.conf)
	fs, _ = e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1}, true)
	if len(fs) != 2 || fs[0].p != "lukd run: pipeline p step 1: not a run or relay step\n" {
		t.Fatalf("missing config: %+v", fs)
	}
	if n := len(e.fr.argvs()); n != 0 {
		t.Fatalf("%d runs for refused requests", n)
	}
}

func TestServeWorkspaceNotCreated(t *testing.T) {
	e := newEnv(t)
	e.fr.createExit = 1
	fs, _ := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1}, true)
	if len(fs) != 3 || fs[0].typ != runproto.Started || fs[1].p != "lukd run: workspace not created\n" || fs[2].p != "1" {
		t.Fatalf("%+v", fs)
	}
	if n := len(e.fr.argvs()); n != 1 {
		t.Fatalf("%d runs", n)
	}
	if ents, err := os.ReadDir(filepath.Join(e.srv.Locks, workspace.LockDir)); err != nil || len(ents) != 0 {
		t.Fatalf("workspace locks %v %v", ents, err)
	}
}

// A failed remove is logged and changes neither the result nor the
// frames.
func TestServeWorkspaceNotRemoved(t *testing.T) {
	e := newEnv(t)
	var logs strings.Builder
	var mu sync.Mutex
	e.srv.Log = slog.New(slog.NewTextHandler(lockedWriter{&mu, &logs}, nil))
	e.fr.removeExit = 1
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) { return 3, nil }
	fs, err := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1}, true)
	if err != nil || len(fs) != 2 || fs[1] != (frame{runproto.Exit, "3"}) {
		t.Fatalf("%+v %v", fs, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(logs.String(), `level=WARN msg="workspace not removed" unit=lukd-run-s3-upload-`) || !strings.Contains(logs.String(), "exit=1") {
		t.Fatalf("journal: %s", logs.String())
	}
}

func TestServeSlotWait(t *testing.T) {
	defer func(d time.Duration) { lockPoll = d }(lockPoll)
	lockPoll = 5 * time.Millisecond
	e := newEnv(t)
	write(t, e.srv.Config, "root: "+e.root+"\nconfig: "+e.conf+"\nlimits:\n  units:\n    max: 1\n", 0o600)
	release := make(chan struct{})
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) { <-release; return 0, nil }
	first, errFirst := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1})
	waitFrame(t, first, runproto.Started)
	second, errc := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1})
	if typ := frameWithin(second, 300*time.Millisecond); typ == runproto.Started {
		t.Fatal("second step started over limits.units.max")
	}
	second.Close() // lukd process stops while the step waits
	if err := ends(t, "waiting step", errc, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := ends(t, "first step", errFirst, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := e.fr.unitRuns(); n != 1 {
		t.Fatalf("%d units started", n)
	}
	// The slot is free again.
	if fs, err := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1}, true); err != nil || len(fs) != 2 {
		t.Fatalf("after the first: %+v %v", fs, err)
	}
}

// A nested job runs inside a step that holds a slot: it takes none.
func TestServeNestedTakesNoSlot(t *testing.T) {
	e := newEnv(t)
	write(t, e.srv.Config, "root: "+e.root+"\nconfig: "+e.conf+"\nlimits:\n  units:\n    max: 1\n", 0o600)
	release := make(chan struct{})
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) { <-release; return 0, nil }
	step, errStep := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1})
	waitFrame(t, step, runproto.Started)
	nested, errNested := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1, Job: "s3-upload"})
	waitFrame(t, nested, runproto.Started)
	close(release)
	for what, errc := range map[string]chan error{"step": errStep, "nested job": errNested} {
		if err := ends(t, what, errc, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.fr.unitRuns(); n != 2 {
		t.Fatalf("%d units", n)
	}
}

// Only the service user, the owner of <root>/data, gets an answer.
func TestServeServiceUser(t *testing.T) {
	e := newEnv(t)
	e.peer = me + 1
	fs, err := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1}, true)
	if len(fs) != 0 || err == nil || err.Error() != "peer uid "+strconv.Itoa(int(me+1))+" refused, want "+strconv.Itoa(int(me)) {
		t.Fatalf("other peer answered: %+v %v", fs, err)
	}
	os.Remove(filepath.Join(e.root, "data"))
	os.Symlink(t.TempDir(), filepath.Join(e.root, "data"))
	e.peer = me
	fs, err = e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1}, true)
	if len(fs) != 0 || err == nil || err.Error() != "service user: "+filepath.Join(e.root, "data")+": a symlink" {
		t.Fatalf("symlinked data answered: %+v %v", fs, err)
	}
	os.Remove(filepath.Join(e.root, "data"))
	os.Mkdir(filepath.Join(e.root, "data"), 0o700)
	e.srv.PeerUID = func() (uint32, error) { return 0, errors.New("no creds") }
	if fs, err := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1}, true); len(fs) != 0 || err == nil || err.Error() != "peer: no creds" {
		t.Fatalf("no peer: %+v %v", fs, err)
	}
	if n := len(e.fr.argvs()); n != 0 {
		t.Fatalf("%d runs", n)
	}
}

// The request carries only free-form metadata: every workspace-bound or
// step-bound name is root's, an unsafe value is dropped and no value adds
// an argument.
func TestServeHostileEnv(t *testing.T) {
	e := newEnv(t)
	req := runproto.StepRequest{Pipeline: "p", Step: 3, ID: id1, Env: map[string]string{
		"LUK_WORK": "/etc", "LUK_META": "/etc/shadow", "LUK_ID": "x", "LUK_PIPELINE": "evil",
		"LUK_STEP": "9", "LUK_JOB": "evil", "LUK_TMP": "/", "LUK_STATE": "/", "LD_PRELOAD": "/tmp/x.so", "TMPDIR": "/",
		"LUK_TAGS": "daily\n--uid=0", "LUK_HOSTNAME": "db1\nLUK_ROOT=/evil", "LUK_ORIGIN": "x\x00y",
		"LUK_FILE": "/etc/shadow", "LUK_NAME": "../x", "LUK_SENDER": "--uid=0",
	}}
	if _, err := e.exchange(t, req, true); err != nil {
		t.Fatal(err)
	}
	a := e.fr.unitArgv()
	ws := workspace.Path(e.root, unitName(a))
	want := []string{
		"PATH=" + DefaultPath, "LANG=C.UTF-8",
		"LUK_WORK=" + ws, "LUK_IN=" + ws + "/in", "LUK_OUT=" + ws + "/out", "LUK_META=" + ws + "/meta.json",
		"LUK_TMP=" + ws + "/tmp", "LUK_ID=" + id1, "LUK_SENDER=--uid=0", "LUK_PIPELINE=p", "LUK_STEP=3",
		"TMPDIR=" + ws + "/tmp", "LUK_JOB=state", "LUK_STATE=" + StatePath("state", "p"),
	}
	if got := setenv(a); !slices.Equal(got, want) {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
	for _, x := range a {
		if strings.ContainsAny(x, "\n\x00") || x == "--uid=0" || strings.Contains(x, "LD_PRELOAD") {
			t.Fatalf("argv %q", a)
		}
	}
}

// The unit sees of root only its workspace and nothing of the lukd
// configuration of run.yaml.
func TestServeSandbox(t *testing.T) {
	e := newEnv(t)
	top := e.srv.Top
	write(t, e.conf, envConfig+`root: `+e.root+`
auth:
  nonces: /srv/nonces
gpg:
  keys: /srv/gpg
listen:
  tls:
    tls: {mode: files, cert: /etc/ssl/luk.crt, key: /etc/ssl/private/luk.key}
endpoint:
  up:
    path: /srv/queue/up
    secret: {path: /run/luk/volatile/queue}
storage:
  backup: {type: local, base: /storage/backup, path: x}
`, 0o640)
	write(t, e.srv.Config, "root: "+e.root+"\nconfig: "+e.conf+"\nhide: [/srv/extra, /srv/queue]\n", 0o600)
	if _, err := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 3, ID: id1}, true); err != nil {
		t.Fatal(err)
	}
	a := e.fr.unitArgv()
	ws := workspace.Path(e.root, unitName(a))
	got := strings.Join(a, " ")
	hidden := []string{filepath.Join(top, "lukd"), "/run/luk", "/etc/ssl/luk.crt", "/etc/ssl/private/luk.key", "/srv/extra", "/srv/gpg", "/srv/nonces", "/srv/queue", "/storage/backup"}
	want := "-p ProtectProc=invisible -p PrivatePIDs=yes -p InaccessiblePaths=-" + strings.Join(hidden, " -p InaccessiblePaths=-") + " " +
		"-p TemporaryFileSystem=" + e.root + ":ro -p BindPaths=" + ws + ":" + ws + ":norbind " +
		"-p ExecStartPre=+/usr/bin/lukd run workspace own " + unitName(a) + " "
	if !strings.Contains(got, want) {
		t.Fatalf("argv %s\nwant %s", got, want)
	}
	if !strings.HasSuffix(got, " /usr/bin/lukd run workspace run "+ws+" -- /opt/luk/state "+ws) {
		t.Fatalf("argv %s", got)
	}
	// A command the sandbox hides is refused before anything runs.
	before := len(e.fr.argvs())
	write(t, filepath.Join(e.srv.Jobs, "state.yaml"), "command: /storage/backup/quick\n", 0o600)
	fs, err := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 3, ID: id1}, true)
	if err == nil || len(fs) != 2 || fs[0] != (frame{runproto.Stderr, "lukd run: job state: unavailable\n"}) || len(e.fr.argvs()) != before {
		t.Fatalf("%v %q", err, fs)
	}
	write(t, e.conf, "pipeline:\n  p:\n    steps: [{run: /storage/backup/p}]\n"+"storage:\n  backup: {type: local, base: /storage/backup, path: x}\n", 0o640)
	fs, err = e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1}, true)
	if err == nil || len(fs) != 2 || fs[0] != (frame{runproto.Stderr, "lukd run: pipeline p step 1: unavailable\n"}) || len(e.fr.argvs()) != before {
		t.Fatalf("%v %q", err, fs)
	}
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
	relay := runproto.StepRequest{Pipeline: "p", Step: 3, ID: id1}
	nested := runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1, Job: "state"}
	c1, err1 := e.start(t, relay)
	<-started
	if !slices.Contains(e.fr.unitArgv(), "--setenv=LUK_STATE=/var/lib/lukd-run/state/p") {
		t.Fatalf("argv %q", e.fr.unitArgv())
	}

	// A peer that gives up while waiting for the lock starts nothing,
	// not even its workspace.
	c2, err2 := e.start(t, nested)
	waitFrame(t, c2, runproto.Started)
	time.Sleep(30 * time.Millisecond)
	c2.Close()
	if err := ends(t, "waiting for the lock", err2, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := len(e.fr.argvs()); n != 2 {
		t.Fatalf("%d runs", n)
	}

	c3, err3 := e.start(t, nested)
	waitFrame(t, c3, runproto.Started)
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	if runs != 1 {
		t.Fatalf("%d runs while locked", runs)
	}
	mu.Unlock()
	release <- struct{}{}
	if err := ends(t, "relay", err1, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	<-started
	release <- struct{}{}
	if err := ends(t, "nested", err3, 5*time.Second); err != nil {
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

// A peer that closes during the run stops the unit; the workspace is
// removed only once the unit is inactive.
func TestServeEarlyCloseStopsUnit(t *testing.T) {
	defer func(a time.Duration) { activePoll = a }(activePoll)
	activePoll = time.Millisecond
	e := newEnv(t)
	started := make(chan struct{})
	e.fr.run = func(ctx context.Context, _, _ io.Writer) (int, error) {
		close(started)
		<-ctx.Done()
		return 143, nil
	}
	var polls, removedAt atomic.Int32
	e.fr.active = func(string) (bool, error) { return polls.Add(1) < 3, nil }
	e.fr.remove = func(context.Context, string) int {
		removedAt.Store(polls.Load())
		return 0
	}
	c, errc := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1})
	<-started
	c.Close()
	if err := ends(t, "early close", errc, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	unit := unitName(e.fr.unitArgv())
	if len(e.fr.stopped) != 1 || e.fr.stopped[0] != unit || unit == "" {
		t.Fatalf("stopped %q, unit %q", e.fr.stopped, unit)
	}
	runs := e.fr.argvs()
	if len(runs) != 3 || helperAction(runs[2]) != "remove" || removedAt.Load() != 3 {
		t.Fatalf("remove after %d polls: %q", removedAt.Load(), runs)
	}
}

// A byte from the peer during the run is a protocol error: the unit is
// stopped as for a closed peer.
func TestServePeerSpeaks(t *testing.T) {
	e := newEnv(t)
	started := make(chan struct{})
	e.fr.run = func(ctx context.Context, _, _ io.Writer) (int, error) {
		close(started)
		<-ctx.Done()
		return 143, nil
	}
	c, errc := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1})
	<-started
	c.Write([]byte("x"))
	if err := ends(t, "peer speaks", errc, 5*time.Second); err == nil || err.Error() != "peer sent data after its request" {
		t.Fatalf("%v", err)
	}
	if len(e.fr.stopped) != 1 || helperAction(e.fr.argvs()[2]) != "remove" {
		t.Fatalf("stopped %q, runs %q", e.fr.stopped, e.fr.argvs())
	}
}

// A unit still active once the stop deadline passed keeps its workspace
// for prune.
func TestServeActiveKeepsWorkspace(t *testing.T) {
	defer func(a, g time.Duration) { activePoll, stopGrace = a, g }(activePoll, stopGrace)
	activePoll, stopGrace = time.Millisecond, 10*time.Millisecond
	e := newEnv(t)
	write(t, filepath.Join(e.srv.Jobs, "s3-upload.yaml"), "command: /opt/luk/s3-upload\ntimeout: 1s\n", 0o600)
	started := make(chan struct{})
	e.fr.run = func(ctx context.Context, _, _ io.Writer) (int, error) {
		close(started)
		<-ctx.Done()
		return 143, nil
	}
	e.fr.active = func(string) (bool, error) { return true, nil }
	var logs strings.Builder
	var mu sync.Mutex
	e.srv.Log = slog.New(slog.NewTextHandler(lockedWriter{&mu, &logs}, nil))
	c, errc := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1})
	<-started
	c.Close()
	if err := ends(t, "active unit", errc, 5*time.Second); err == nil || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("%v", err)
	}
	if runs := e.fr.argvs(); len(runs) != 2 {
		t.Fatalf("removed an active unit: %q", runs)
	}
	mu.Lock()
	defer mu.Unlock()
	want := `level=WARN msg="unit still active: workspace left to prune, unit slot and state lock released" job=s3-upload unit=` + unitName(e.fr.unitArgv())
	if !strings.Contains(logs.String(), want) {
		t.Fatalf("journal: %s", logs.String())
	}
}

// A hung helper cannot hold the slot: lukd run gives up on it after
// helperTimeout, a create as not created, a remove as not removed.
func TestServeHelperTimeout(t *testing.T) {
	defer func(d time.Duration) { helperTimeout = d }(helperTimeout)
	helperTimeout = 20 * time.Millisecond
	e := newEnv(t)
	hang := func(ctx context.Context) int {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("helper without a deadline")
		}
		<-ctx.Done()
		return 143
	}
	e.fr.create = hang
	fs, _ := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1}, true)
	if len(fs) != 3 || fs[1].p != "lukd run: workspace not created\n" || e.fr.unitRuns() != 0 {
		t.Fatalf("hung create: %+v", fs)
	}
	e.fr.create = nil
	e.fr.remove = func(ctx context.Context, _ string) int { return hang(ctx) }
	fs, err := e.exchange(t, runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1}, true)
	if err != nil || len(fs) != 2 || fs[1] != (frame{runproto.Exit, "0"}) {
		t.Fatalf("hung remove: %+v %v", fs, err)
	}
	if runs := e.fr.argvs(); len(runs) != 4 || helperAction(runs[3]) != "remove" {
		t.Fatalf("%q", runs)
	}
}

// A byte from the peer while the step waits for a slot or the state lock
// is the protocol error it is during the run; nothing starts.
func TestServePeerSpeaksWhileWaiting(t *testing.T) {
	defer func(d time.Duration) { lockPoll = d }(lockPoll)
	lockPoll = 5 * time.Millisecond
	e := newEnv(t)
	write(t, e.srv.Config, "root: "+e.root+"\nconfig: "+e.conf+"\nlimits:\n  units:\n    max: 1\n", 0o600)
	release := make(chan struct{})
	e.fr.run = func(context.Context, io.Writer, io.Writer) (int, error) { <-release; return 0, nil }
	first, errFirst := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 3, ID: id1})
	waitFrame(t, first, runproto.Started)
	// Waiting for the slot.
	second, errc := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1})
	time.Sleep(30 * time.Millisecond)
	second.Write([]byte("x"))
	if err := ends(t, "slot wait", errc, 5*time.Second); err == nil || err.Error() != "peer sent data after its request" {
		t.Fatalf("slot wait: %v", err)
	}
	// Waiting for the state lock (a nested job takes no slot).
	third, errc := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 1, ID: id1, Job: "state"})
	waitFrame(t, third, runproto.Started)
	third.Write([]byte("x"))
	if err := ends(t, "state lock wait", errc, 5*time.Second); err == nil || err.Error() != "peer sent data after its request" {
		t.Fatalf("state lock wait: %v", err)
	}
	close(release)
	if err := ends(t, "first", errFirst, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := e.fr.unitRuns(); n != 1 {
		t.Fatalf("%d units", n)
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
		unit := unitName(e.fr.unitArgv())
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
	req := runproto.StepRequest{Pipeline: "p", Step: 3, ID: id1}
	c1, err1 := e.start(t, req)
	first := <-started
	c2, err2 := e.start(t, req)
	c1.Close()
	if err := ends(t, "first", err1, 5*time.Second); err != nil {
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
	if err := ends(t, "second", err2, 5*time.Second); err != nil {
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

// A peer that sends no request, half a request, or does not read the
// refusal cannot hold the connection beyond requestTimeout.
func TestServeRequestDeadline(t *testing.T) {
	defer func(d time.Duration) { requestTimeout = d }(requestTimeout)
	requestTimeout = 100 * time.Millisecond
	e := newEnv(t)
	for name, req := range map[string]string{
		"nothing":        "",
		"half":           `{"pipeline":"p","step":1,`,
		"refusal unread": string(runproto.StepRequest{Pipeline: "nope", Step: 1, ID: id1}.Encode()),
	} {
		c, errc := e.sendRaw(t, []byte(req), true)
		ends(t, name, errc, 5*time.Second)
		c.Close()
	}
	if n := len(e.fr.argvs()); n != 0 {
		t.Fatalf("%d runs", n)
	}
}

// A peer that stops reading while the unit writes cannot pin the
// connection: the deadline of the unit (timeout plus stopGrace) ends the
// writes, the unit is stopped and Serve returns.
func TestServeJobDeadline(t *testing.T) {
	defer func(d time.Duration) { stopGrace = d }(stopGrace)
	stopGrace = 100 * time.Millisecond
	e := newEnv(t)
	write(t, filepath.Join(e.srv.Jobs, "s3-upload.yaml"), "command: /opt/luk/q\ntimeout: 1s\n", 0o600)
	e.fr.run = func(ctx context.Context, stdout, _ io.Writer) (int, error) {
		for ctx.Err() == nil {
			if _, err := stdout.Write([]byte("output\n")); err != nil {
				return 1, nil
			}
		}
		return 143, nil
	}
	c, errc := e.start(t, runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1})
	ends(t, "unread output", errc, 10*time.Second)
	c.Close()
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
	req := runproto.StepRequest{Pipeline: "p", Step: 2, ID: id1}
	top := e.srv.Top
	os.Chmod(top, 0o777)
	if fs, err := e.exchange(t, req, true); err == nil || len(fs) != 0 {
		t.Fatalf("writable parent of run.yaml: %v %q", err, fs)
	}
	os.Chmod(top, 0o700)
	sub := filepath.Join(top, "etc")
	os.Mkdir(sub, 0o700)
	os.Chmod(sub, 0o775)
	os.Rename(e.srv.Jobs, filepath.Join(sub, "run.d"))
	e.srv.Jobs = filepath.Join(sub, "run.d")
	fs, err := e.exchange(t, req, true)
	if err == nil || len(fs) != 2 || fs[0].p != "lukd run: job s3-upload: unavailable\n" {
		t.Fatalf("writable parent of run.d: %v %q", err, fs)
	}
	if n := len(e.fr.argvs()); n != 0 {
		t.Fatalf("%d runs", n)
	}
}
