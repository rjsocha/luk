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

// stepMeta is StepMeta of the work directory w, read with ReadWork.
func stepMeta(t *testing.T, w string) map[string]string {
	t.Helper()
	m, names, err := readWork(w)
	if err != nil {
		t.Fatal(err)
	}
	return StepMeta(m, names)
}

func readWork(w string) (WorkMeta, []string, error) {
	r, err := os.OpenRoot(w)
	if err != nil {
		return WorkMeta{}, nil, err
	}
	defer r.Close()
	return ReadWork(r)
}

func TestStepMetaOfWork(t *testing.T) {
	w := newWork(t, upload("db.sql", "db1", "daily", "prod"), "db.sql")
	want := map[string]string{
		"LUK_SENDER": "robert.socha", "LUK_ENDPOINT": "up", "LUK_FILE": "db.sql", "LUK_NAME": "db.sql",
		"LUK_TAGS": "daily,prod", "LUK_HOSTNAME": "db1", "LUK_ORIGIN": "db1",
	}
	if got := stepMeta(t, w); !maps.Equal(got, want) {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
}

func TestStepMetaSets(t *testing.T) {
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
		"unnamed stream":   {upload("", "db1"), []string{id}, id, "", "", "db1", "db1"},
		"invalid name":     {upload(".hidden", ""), []string{id}, id, "", "", "", "robert.socha"},
		"no hostname":      {upload("db.sql", "", "daily"), []string{"db.sql"}, "db.sql", "db.sql", "daily", "", "robert.socha"},
		"produced":         {produced, []string{"db.sql.gz", "db.sql.gz.meta.json"}, "db.sql.gz", "db.sql.gz", "daily", "", "robert.socha"},
		"produced id name": {produced, []string{id}, id, id, "daily", "", "robert.socha"},
		"several files":    {produced, []string{"a", "b", "b.meta.json"}, "", "", "daily", "", "robert.socha"},
		"lone meta file":   {produced, []string{"a", "x.meta.json"}, "", "", "daily", "", "robert.socha"},
	} {
		m := stepMeta(t, newWork(t, c.meta, c.in...))
		f, ok := m["LUK_FILE"]
		if c.file == "" && ok || c.file != "" && f != c.file {
			t.Errorf("%s: LUK_FILE %q (%v)", name, f, ok)
		}
		if v, ok := m["LUK_NAME"]; !ok || v != c.name {
			t.Errorf("%s: LUK_NAME %q (%v), want %q", name, v, ok, c.name)
		}
		if m["LUK_TAGS"] != c.tags || m["LUK_HOSTNAME"] != c.hostname || m["LUK_ORIGIN"] != c.origin {
			t.Errorf("%s: %q", name, m)
		}
	}
}

func TestStepMetaDropsUnsafeValues(t *testing.T) {
	m := upload("db.sql", "db1\nLUK_ROOT=/evil", "a,b", "x y$HOME'\"", "nl\nLUK_STEP=9", "nul\x00")
	m.Server.Endpoint = "up\u0085"
	got := stepMeta(t, newWork(t, m, "db.sql"))
	for _, k := range []string{"LUK_TAGS", "LUK_HOSTNAME", "LUK_ORIGIN", "LUK_ENDPOINT"} {
		if v, ok := got[k]; ok {
			t.Errorf("%s=%q kept", k, v)
		}
	}
	if got["LUK_NAME"] != "db.sql" || got["LUK_FILE"] != "db.sql" {
		t.Errorf("%q", got)
	}

	m = upload("db.sql", "", "a,b", "x y$HOME'\"")
	got = stepMeta(t, newWork(t, m, "db.sql"))
	if got["LUK_TAGS"] != `a,b,x y$HOME'"` {
		t.Errorf("tags %q", got["LUK_TAGS"])
	}
}

func TestReadWorkRefuses(t *testing.T) {
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
		if m, _, err := readWork(w); err == nil {
			t.Errorf("%s: accepted: %+v", name, m)
		}
	}
	w := newWork(t, upload("db.sql", ""), "db.sql")
	os.Rename(filepath.Join(w, "meta.json"), filepath.Join(w, "real.json"))
	os.Symlink("real.json", filepath.Join(w, "meta.json"))
	if _, _, err := readWork(w); err == nil {
		t.Error("symlinked meta.json accepted")
	}
	w = newWork(t, upload("db.sql", ""))
	os.Remove(filepath.Join(w, "in"))
	os.Mkdir(filepath.Join(w, "elsewhere"), 0o750)
	os.Symlink("elsewhere", filepath.Join(w, "in"))
	if _, _, err := readWork(w); err == nil {
		t.Error("symlinked in/ accepted")
	}
}

func TestReadWorkSkipsNonRegular(t *testing.T) {
	w := newWork(t, upload("db.sql", ""), "db.sql")
	os.Mkdir(filepath.Join(w, "in", "d"), 0o750)
	os.Symlink("db.sql", filepath.Join(w, "in", "l"))
	if m := stepMeta(t, w); m["LUK_FILE"] != "db.sql" {
		t.Errorf("%v", m)
	}
}

func TestCleanStepMetaValues(t *testing.T) {
	kib := strings.Repeat("é", 512)
	got := CleanStepMeta(map[string]string{
		"LUK_SENDER": "robert.socha", "LUK_ENDPOINT": "", "LUK_TAGS": kib, "LUK_HOSTNAME": kib + "x",
		"LUK_ORIGIN": "db1\n", "LUK_NAME": "db.sql", "LUK_FILE": "db.sql",
		"LUK_WORK": "/etc", "LUK_IN": "/etc", "LUK_OUT": "/etc", "LUK_META": "/etc/shadow", "LUK_ROOT": "/",
		"LUK_ID": "x", "LUK_PIPELINE": "x", "LUK_STEP": "9", "LUK_JOB": "x", "LUK_TMP": "/", "LUK_STATE": "/",
		"LD_PRELOAD": "/tmp/x.so", "PATH": "/tmp", "luk_tags": "x",
	})
	want := map[string]string{
		"LUK_SENDER": "robert.socha", "LUK_ENDPOINT": "", "LUK_TAGS": kib, "LUK_NAME": "db.sql", "LUK_FILE": "db.sql",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
	for name, v := range map[string]string{
		"nul": "a\x00b", "newline": "a\nb", "escape": "a\x1b[2J", "del": "a\x7f", "c1": "a\u0085", "invalid utf-8": "a\xffb",
		"long": strings.Repeat("a", MaxMetaValue+1),
	} {
		if got := CleanStepMeta(map[string]string{"LUK_TAGS": v}); len(got) != 0 {
			t.Errorf("%s kept: %q", name, got)
		}
	}
	for _, n := range []string{"", ".hidden", "a/b", "..", strings.Repeat("x", 256)} {
		if got := CleanStepMeta(map[string]string{"LUK_NAME": n}); n != "" && len(got) != 0 || n == "" && got["LUK_NAME"] != "" {
			t.Errorf("LUK_NAME %q: %q", n, got)
		}
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
