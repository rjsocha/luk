package runstep

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"luk/internal/wire"
)

// newWork writes a work directory with meta.json m (a WorkMeta or raw
// bytes) and the files of in/.
func newWork(t *testing.T, m any, in ...string) string {
	t.Helper()
	w := filepath.Join(t.TempDir(), "work", "20261006T100000Z-0a1b2c3d", "offsite", "2")
	if err := os.MkdirAll(filepath.Join(w, "in"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(w, "out"), 0o750); err != nil {
		t.Fatal(err)
	}
	b, ok := m.([]byte)
	if !ok {
		var err error
		if b, err = json.Marshal(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(w, "meta.json"), b, 0o440); err != nil {
		t.Fatal(err)
	}
	for _, n := range in {
		if err := os.WriteFile(filepath.Join(w, "in", n), []byte("x"), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func upload(file, host string, tags ...string) WorkMeta {
	m := WorkMeta{
		Server:   WorkServer{ID: "20261006T100000Z-0a1b2c3d", Sender: "robert.socha", Endpoint: "up", Size: 1, SHA256: "ab"},
		Client:   wire.Meta{File: file, Source: wire.SourceFile, Tags: tags, Portal: wire.PortalDirect},
		Pipeline: "offsite", Step: 2,
	}
	if host != "" {
		m.Client.Backup = &wire.Backup{Hostname: host, Path: "/var/backups/db.sql"}
	}
	return m
}

func workEnv(t *testing.T, w string) []string {
	t.Helper()
	env, err := WorkEnv(w, "/var/lib/luk")
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestWorkEnvOneFile(t *testing.T) {
	w := newWork(t, upload("db.sql", "db1", "daily", "prod"), "db.sql")
	want := []string{
		"LUK_WORK=" + w, "LUK_IN=" + w + "/in", "LUK_OUT=" + w + "/out", "LUK_META=" + w + "/meta.json",
		"LUK_ID=20261006T100000Z-0a1b2c3d", "LUK_SENDER=robert.socha", "LUK_ENDPOINT=up", "LUK_PIPELINE=offsite",
		"LUK_FILE=" + w + "/in/db.sql", "LUK_NAME=db.sql", "LUK_ROOT=/var/lib/luk", "LUK_STEP=2",
		"LUK_TAGS=daily,prod", "LUK_HOSTNAME=db1", "LUK_ORIGIN=db1",
	}
	if got := workEnv(t, w); !slices.Equal(got, want) {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func TestWorkEnvSets(t *testing.T) {
	const id = "20261006T100000Z-0a1b2c3d"
	produced := upload("db.sql", "", "daily")
	produced.Produced = true
	for name, c := range map[string]struct {
		meta     WorkMeta
		in       []string
		file     string // "" means unset
		name     string
		tags     string
		hostname string
		origin   string
	}{
		"unnamed stream":   {upload("", "db1"), []string{id}, "in/" + id, "", "", "db1", "db1"},
		"invalid name":     {upload(".hidden", ""), []string{id}, "in/" + id, "", "", "", "robert.socha"},
		"no hostname":      {upload("db.sql", "", "daily"), []string{"db.sql"}, "in/db.sql", "db.sql", "daily", "", "robert.socha"},
		"produced":         {produced, []string{"db.sql.gz", "db.sql.gz.meta.json"}, "in/db.sql.gz", "db.sql.gz", "daily", "", "robert.socha"},
		"produced id name": {produced, []string{id}, "in/" + id, id, "daily", "", "robert.socha"},
		"several files":    {produced, []string{"a", "b", "b.meta.json"}, "", "", "daily", "", "robert.socha"},
		"lone meta file":   {produced, []string{"a", "x.meta.json"}, "", "", "daily", "", "robert.socha"},
	} {
		w := newWork(t, c.meta, c.in...)
		env := workEnv(t, w)
		m := envMap(env)
		f, ok := m["LUK_FILE"]
		if c.file == "" && ok || c.file != "" && f != filepath.Join(w, c.file) {
			t.Errorf("%s: LUK_FILE %q (%v)", name, f, ok)
		}
		if v, ok := m["LUK_NAME"]; !ok || v != c.name {
			t.Errorf("%s: LUK_NAME %q (%v), want %q", name, v, ok, c.name)
		}
		if m["LUK_TAGS"] != c.tags || m["LUK_HOSTNAME"] != c.hostname || m["LUK_ORIGIN"] != c.origin {
			t.Errorf("%s: %q", name, env)
		}
	}
}

func TestWorkEnvDropsUnsafeValues(t *testing.T) {
	m := upload("db.sql", "db1\nLUK_ROOT=/evil", "a,b", "x y$HOME'\"", "nl\nLUK_STEP=9", "nul\x00")
	m.Server.Endpoint = "up\u0085"
	w := newWork(t, m, "db.sql")
	env := workEnv(t, w)
	got := envMap(env)
	for _, k := range []string{"LUK_TAGS", "LUK_HOSTNAME", "LUK_ORIGIN", "LUK_ENDPOINT"} {
		if v, ok := got[k]; ok {
			t.Errorf("%s=%q kept", k, v)
		}
	}
	if got["LUK_ROOT"] != "/var/lib/luk" || got["LUK_STEP"] != "2" || got["LUK_NAME"] != "db.sql" {
		t.Errorf("%q", env)
	}
	for _, kv := range env {
		if strings.ContainsAny(kv, "\x00\n") {
			t.Errorf("%q", kv)
		}
	}

	m = upload("db.sql", "", "a,b", "x y$HOME'\"")
	got = envMap(workEnv(t, newWork(t, m, "db.sql")))
	if got["LUK_TAGS"] != `a,b,x y$HOME'"` {
		t.Errorf("tags %q", got["LUK_TAGS"])
	}
}

func TestWorkEnvRefuses(t *testing.T) {
	good, _ := json.Marshal(upload("db.sql", ""))
	for name, b := range map[string]string{
		"unknown key":   `{"server":{},"client":{"source":"file","portal":"direct"},"pipeline":"p","step":1,"x":1}`,
		"unknown inner": `{"server":{"id":"i","sender":"s","endpoint":"e","received":"","size":0,"sha256":"","bad":1},"client":{},"pipeline":"p","step":1}`,
		"trailing":      string(good) + ` {}`,
		"null":          `null`,
		"array":         `[]`,
		"broken":        `{"server":`,
		"oversized":     `{"pipeline":"` + strings.Repeat("p", MaxWorkMeta) + `"}`,
	} {
		w := newWork(t, []byte(b), "db.sql")
		if env, err := WorkEnv(w, "/r"); err == nil {
			t.Errorf("%s: accepted: %q", name, env)
		}
	}
	w := newWork(t, upload("db.sql", ""), "db.sql")
	os.Rename(filepath.Join(w, "meta.json"), filepath.Join(w, "real.json"))
	os.Symlink("real.json", filepath.Join(w, "meta.json"))
	if _, err := WorkEnv(w, "/r"); err == nil {
		t.Error("symlinked meta.json accepted")
	}
	w = newWork(t, upload("db.sql", ""))
	os.Remove(filepath.Join(w, "in"))
	os.Mkdir(filepath.Join(w, "elsewhere"), 0o750)
	os.Symlink("elsewhere", filepath.Join(w, "in"))
	if _, err := WorkEnv(w, "/r"); err == nil {
		t.Error("symlinked in/ accepted")
	}
}

func TestWorkEnvSkipsNonRegular(t *testing.T) {
	w := newWork(t, upload("db.sql", ""), "db.sql")
	os.Mkdir(filepath.Join(w, "in", "d"), 0o750)
	os.Symlink("db.sql", filepath.Join(w, "in", "l"))
	if m := envMap(workEnv(t, w)); m["LUK_FILE"] != filepath.Join(w, "in", "db.sql") {
		t.Errorf("%v", m)
	}
}

func TestCleanMeta(t *testing.T) {
	const w = "/var/lib/luk/work/20261006T100000Z-0a1b2c3d/offsite/2"
	kib := strings.Repeat("é", 512)
	got := CleanMeta(w, map[string]string{
		"LUK_SENDER": "robert.socha", "LUK_ENDPOINT": "", "LUK_TAGS": kib, "LUK_HOSTNAME": kib + "x",
		"LUK_ORIGIN": "db1\n", "LUK_NAME": "db.sql", "LUK_FILE": w + "/in/db.sql",
		"LUK_WORK": "/etc", "LUK_IN": "/etc", "LUK_OUT": "/etc", "LUK_META": "/etc/shadow", "LUK_ROOT": "/",
		"LUK_ID": "x", "LUK_PIPELINE": "x", "LUK_STEP": "9", "LUK_JOB": "x", "LUK_TMP": "/", "LUK_STATE": "/",
		"LD_PRELOAD": "/tmp/x.so", "PATH": "/tmp", "luk_tags": "x",
	})
	want := map[string]string{
		"LUK_SENDER": "robert.socha", "LUK_ENDPOINT": "", "LUK_TAGS": kib, "LUK_NAME": "db.sql", "LUK_FILE": w + "/in/db.sql",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
	for name, v := range map[string]string{
		"nul": "a\x00b", "newline": "a\nb", "escape": "a\x1b[2J", "del": "a\x7f", "c1": "a\u0085", "invalid utf-8": "a\xffb",
		"long": strings.Repeat("a", MaxMetaValue+1),
	} {
		if got := CleanMeta(w, map[string]string{"LUK_TAGS": v}); len(got) != 0 {
			t.Errorf("%s kept: %q", name, got)
		}
	}
	for _, n := range []string{"", ".hidden", "a/b", "..", strings.Repeat("x", 256)} {
		if got := CleanMeta(w, map[string]string{"LUK_NAME": n}); n != "" && len(got) != 0 || n == "" && got["LUK_NAME"] != "" {
			t.Errorf("LUK_NAME %q: %q", n, got)
		}
	}
	for _, f := range []string{"", "db.sql", "/etc/passwd", w + "/in", w + "/in/", w + "/in/.x", w + "/in/a/b", w + "/in/../meta.json",
		w + "/out/x", w + "/in//x", "/var/lib/luk/work/20261006T100000Z-0a1b2c3d/offsite/3/in/x"} {
		if got := CleanMeta(w, map[string]string{"LUK_FILE": f}); len(got) != 0 {
			t.Errorf("LUK_FILE %q kept", f)
		}
	}
}

func TestVarsPathBound(t *testing.T) {
	const w = "/var/lib/luk/work/20261006T100000Z-0a1b2c3d/offsite/2"
	sent := map[string]string{
		"LUK_WORK": "/etc", "LUK_IN": "/etc", "LUK_OUT": "/etc", "LUK_META": "/etc/shadow", "LUK_ROOT": "/",
		"LUK_ID": "x", "LUK_PIPELINE": "x", "LUK_STEP": "9", "LUK_SENDER": "robert.socha", "LUK_TAGS": "a,b",
	}
	want := []string{
		"LUK_WORK=" + w, "LUK_IN=" + w + "/in", "LUK_OUT=" + w + "/out", "LUK_META=" + w + "/meta.json",
		"LUK_ID=20261006T100000Z-0a1b2c3d", "LUK_SENDER=robert.socha", "LUK_PIPELINE=offsite",
		"LUK_ROOT=/srv/luk", "LUK_STEP=2", "LUK_TAGS=a,b",
	}
	if got := Vars(w, "/srv/luk", sent); !slices.Equal(got, want) {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
}

// The 1 KiB cap is for the free-form values: a long root keeps every
// path-bound variable and LUK_FILE.
func TestVarsLongRoot(t *testing.T) {
	root := "/" + strings.Repeat("r", 2*MaxMetaValue)
	w := root + "/work/20261006T100000Z-0a1b2c3d/offsite/2"
	sent := map[string]string{"LUK_FILE": w + "/in/db.sql", "LUK_NAME": "db.sql", "LUK_TAGS": strings.Repeat("t", MaxMetaValue+1)}
	want := []string{
		"LUK_WORK=" + w, "LUK_IN=" + w + "/in", "LUK_OUT=" + w + "/out", "LUK_META=" + w + "/meta.json",
		"LUK_ID=20261006T100000Z-0a1b2c3d", "LUK_PIPELINE=offsite", "LUK_FILE=" + w + "/in/db.sql",
		"LUK_NAME=db.sql", "LUK_ROOT=" + root, "LUK_STEP=2",
	}
	if got := Vars(w, root, sent); !slices.Equal(got, want) {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
}

func TestMetaOfEnv(t *testing.T) {
	w := newWork(t, upload("db.sql", "db1", "daily"), "db.sql")
	env := workEnv(t, w)
	lookup := func(k string) (string, bool) {
		v, ok := envMap(env)[k]
		return v, ok
	}
	sent := Meta(w, lookup)
	if len(sent) != len(MetaNames) || sent["LUK_FILE"] != w+"/in/db.sql" || sent["LUK_WORK"] != "" {
		t.Fatalf("%q", sent)
	}
	// What a client sends gives lukd run the environment the run step had.
	if got := Vars(w, "/var/lib/luk", sent); !slices.Equal(got, env) {
		t.Fatalf("\n got %q\nwant %q", got, env)
	}
}

func TestUnitVars(t *testing.T) {
	ws := "/var/lib/luk/root/job/lukd-step-offsite-2-0123456789ab"
	meta := StepMeta(upload("db.sql", "web1", "prod", "daily"), []string{"db.sql"})
	got := UnitVars(ws, "20261006T100000Z-0a1b2c3d", "offsite", 2, meta)
	want := []string{
		"LUK_WORK=" + ws, "LUK_IN=" + ws + "/in", "LUK_OUT=" + ws + "/out", "LUK_META=" + ws + "/meta.json",
		"LUK_TMP=" + ws + "/tmp", "LUK_ID=20261006T100000Z-0a1b2c3d", "LUK_SENDER=robert.socha",
		"LUK_ENDPOINT=up", "LUK_PIPELINE=offsite", "LUK_FILE=" + ws + "/in/db.sql", "LUK_NAME=db.sql",
		"LUK_STEP=2", "LUK_TAGS=prod,daily", "LUK_HOSTNAME=web1", "LUK_ORIGIN=web1", "TMPDIR=" + ws + "/tmp",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestUnitVarsFilter(t *testing.T) {
	ws := "/ws"
	got := UnitVars(ws, "i", "p", 1, map[string]string{
		"LUK_FILE": "/etc/passwd", "LUK_NAME": "a\nb", "LUK_TAGS": strings.Repeat("t", 1025),
		"LUK_WORK": "/elsewhere", "LUK_ROOT": "/x", "OTHER": "y", "LUK_SENDER": "ok", "TMPDIR": "/x",
	})
	want := []string{
		"LUK_WORK=/ws", "LUK_IN=/ws/in", "LUK_OUT=/ws/out", "LUK_META=/ws/meta.json", "LUK_TMP=/ws/tmp",
		"LUK_ID=i", "LUK_SENDER=ok", "LUK_PIPELINE=p", "LUK_STEP=1", "TMPDIR=/ws/tmp",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestStepMetaSeveralFiles(t *testing.T) {
	m := StepMeta(upload("db.sql", ""), []string{"a", "b"})
	if _, ok := m["LUK_FILE"]; ok || m["LUK_NAME"] != "" || m["LUK_ORIGIN"] != "robert.socha" {
		t.Fatalf("%v", m)
	}
}

func TestCleanStepMeta(t *testing.T) {
	for _, f := range []string{"db.sql", "a b", strings.Repeat("x", 255)} {
		if got := CleanStepMeta(map[string]string{"LUK_FILE": f}); got["LUK_FILE"] != f {
			t.Errorf("LUK_FILE %q dropped", f)
		}
	}
	for _, f := range []string{"", ".x", "..", "a/b", "/ws/in/db.sql", "a\nb", strings.Repeat("x", 256)} {
		if got := CleanStepMeta(map[string]string{"LUK_FILE": f}); len(got) != 0 {
			t.Errorf("LUK_FILE %q kept", f)
		}
	}
	got := CleanStepMeta(map[string]string{"LUK_SENDER": "s", "LUK_NAME": "", "LUK_TMP": "/", "LUK_ID": "x", "PATH": "/tmp"})
	if want := map[string]string{"LUK_SENDER": "s", "LUK_NAME": ""}; !maps.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}
