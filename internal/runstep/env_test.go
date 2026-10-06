package runstep

import (
	"encoding/json"
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
	w := t.TempDir()
	if err := os.Mkdir(filepath.Join(w, "in"), 0o750); err != nil {
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
