package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"luk/internal/runstep"
)

const workMeta = `{"server":{"id":"id1","sender":"robert.socha","size":3},` +
	`"client":{"file":"db.sql","source":"file","portal":"direct","backup":{"hostname":"web1"},"tags":["a","b"]},` +
	`"pipeline":"p","step":1}`

func newWork(t *testing.T, inputs map[string]string) string {
	t.Helper()
	w := t.TempDir()
	for _, d := range []string{"in", "out"} {
		if err := os.Mkdir(filepath.Join(w, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{"meta.json": workMeta}
	for n, data := range inputs {
		files["in/"+n] = data
	}
	for n, data := range files {
		if err := os.WriteFile(filepath.Join(w, n), []byte(data), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("LUK_WORK", w)
	return w
}

func runJob(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	code, out, errs := runJob(t, args...)
	if code != 0 {
		t.Fatalf("%v: exit %d: %s", args, code, errs)
	}
	return out
}

func wantFail(t *testing.T, want string, args ...string) {
	t.Helper()
	code, _, errs := runJob(t, args...)
	if code != 1 || !strings.Contains(errs, want) {
		t.Fatalf("%v: exit %d, stderr %q, want %q", args, code, errs, want)
	}
}

func TestWorkDirRequired(t *testing.T) {
	t.Setenv("LUK_WORK", "")
	for _, cmd := range []string{"inputs", "input", "meta"} {
		wantFail(t, "no work directory", cmd)
	}
	wantFail(t, "no work directory", "fail", "--message", "x")
	wantFail(t, "no work directory", "output", "--file", "/etc/hostname")
	t.Setenv("LUK_WORK", t.TempDir())
	wantFail(t, "not a step work directory", "inputs")
}

func TestWorkFlagOverridesEnv(t *testing.T) {
	w := newWork(t, map[string]string{"x": "1"})
	t.Setenv("LUK_WORK", t.TempDir())
	if out := mustRun(t, "input", "--work", w); out != filepath.Join(w, "in", "x")+"\n" {
		t.Fatalf("%q", out)
	}
}

func TestInputs(t *testing.T) {
	w := newWork(t, map[string]string{
		"b.bin": "bb", "a.txt": "a", "a.txt.meta.json": `{ "kind": "logical" }`, "lone.meta.json": "{}",
	})
	in := filepath.Join(w, "in")
	want := strings.Join([]string{filepath.Join(in, "a.txt"), filepath.Join(in, "b.bin"), filepath.Join(in, "lone.meta.json")}, "\n") + "\n"
	if out := mustRun(t, "inputs"); out != want {
		t.Fatalf("%q", out)
	}
	var got []inputFile
	if err := json.Unmarshal([]byte(mustRun(t, "inputs", "--json")), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != "a.txt" || got[0].Size != 1 || string(got[0].Meta) != `{"kind":"logical"}` ||
		got[1].Path != filepath.Join(in, "b.bin") || got[1].Size != 2 || string(got[1].Meta) != "{}" || got[2].Name != "lone.meta.json" {
		t.Fatalf("%+v", got)
	}
	wantFail(t, "3 inputs; use luk-job inputs", "input")
}

func TestInputsEmpty(t *testing.T) {
	newWork(t, nil)
	if out := mustRun(t, "inputs"); out != "" {
		t.Fatalf("%q", out)
	}
	if out := mustRun(t, "inputs", "--json"); out != "[]\n" {
		t.Fatalf("%q", out)
	}
	wantFail(t, "0 inputs; use luk-job inputs", "input")
}

func TestInputBadMeta(t *testing.T) {
	newWork(t, map[string]string{"a": "1", "a.meta.json": "[]"})
	wantFail(t, "a.meta.json: not a JSON object", "inputs", "--json")
}

func TestMeta(t *testing.T) {
	newWork(t, nil)
	for field, want := range map[string]string{
		"client.backup.hostname": "web1",
		"server.sender":          "robert.socha",
		"server.size":            "3",
		"client.tags":            `["a","b"]`,
		"client.backup":          `{"hostname":"web1"}`,
		"step":                   "1",
	} {
		if out := mustRun(t, "meta", "--field", field); out != want+"\n" {
			t.Errorf("%s: %q", field, out)
		}
	}
	if out := mustRun(t, "meta", "--field", "server.sender", "--json"); out != `"robert.socha"`+"\n" {
		t.Fatalf("%q", out)
	}
	wantFail(t, "field client.nope: not found", "meta", "--field", "client.nope")
	wantFail(t, "field server.sender.x: not found", "meta", "--field", "server.sender.x")
	if out := mustRun(t, "meta", "--json"); out != workMeta+"\n" {
		t.Fatalf("%q", out)
	}
	out := mustRun(t, "meta")
	for _, l := range []string{"client.backup.hostname=web1", "client.tags=[\"a\",\"b\"]", "server.size=3", "pipeline=p"} {
		if !strings.Contains(out, l+"\n") {
			t.Fatalf("%q lacks %q", out, l)
		}
	}
}

func readMetaFile(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func inode(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func TestOutputLinkWithMeta(t *testing.T) {
	w := newWork(t, map[string]string{"db.sql": "data"})
	src := filepath.Join(w, "in", "db.sql")
	mf := filepath.Join(t.TempDir(), "m.json")
	os.WriteFile(mf, []byte(`{"kind":"raw","backup":{"host":"h","n":1},"keep":true}`), 0o640)
	out := mustRun(t, "output", "--file", src, "--meta-file", mf,
		"--meta", "kind=logical", "--meta", "backup.n=2", "--meta", "backup.deep.x=y",
		"--meta", "count=42", "--meta", `list=[1,"a"]`, "--meta", "text=a=b", "--meta", "empty=")
	dst := filepath.Join(w, "out", "db.sql")
	if out != dst+"\n" {
		t.Fatalf("%q", out)
	}
	if inode(t, dst) != inode(t, src) {
		t.Fatal("not a hardlink")
	}
	got, _ := json.Marshal(readMetaFile(t, dst+runstep.MetaExt))
	want := `{"backup":{"deep":{"x":"y"},"host":"h","n":2},"count":42,"empty":"","keep":true,"kind":"logical","list":[1,"a"],"text":"a=b"}`
	if string(got) != want {
		t.Fatalf("meta %s", got)
	}
	if ents, _ := os.ReadDir(w); len(ents) != 3 {
		t.Fatalf("temporary files left: %v", ents)
	}
}

func TestOutputNameAndNoMeta(t *testing.T) {
	w := newWork(t, map[string]string{"x": "1"})
	src := filepath.Join(w, "scratch")
	os.WriteFile(src, []byte("s"), 0o640)
	if out := mustRun(t, "output", "--file", src, "--name", "res.gz"); out != filepath.Join(w, "out", "res.gz")+"\n" {
		t.Fatalf("%q", out)
	}
	if _, err := os.Stat(filepath.Join(w, "out", "res.gz"+runstep.MetaExt)); !os.IsNotExist(err) {
		t.Fatalf("meta written: %v", err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatal("source removed without --move")
	}
}

func TestOutputRefused(t *testing.T) {
	w := newWork(t, map[string]string{"x": "1"})
	src := filepath.Join(w, "in", "x")
	os.Symlink(src, filepath.Join(w, "sym"))
	mustRun(t, "output", "--file", src)
	os.WriteFile(filepath.Join(w, "out", "m"+runstep.MetaExt), []byte("{}"), 0o640)
	notObj := filepath.Join(w, "arr.json")
	os.WriteFile(notObj, []byte("[1]"), 0o640)
	for _, c := range []struct {
		want string
		args []string
	}{
		{"out/x exists", []string{"--file", src}},
		{"out/m.meta.json exists", []string{"--file", src, "--name", "m"}},
		{"invalid name", []string{"--file", src, "--name", ".hidden"}},
		{"invalid name", []string{"--file", src, "--name", "a/b"}},
		{"invalid name", []string{"--file", src, "--name", strings.Repeat("n", 256)}},
		{"may not end in .meta.json", []string{"--file", src, "--name", "y.meta.json"}},
		{"not a regular file", []string{"--file", filepath.Join(w, "sym"), "--name", "s"}},
		{"not a regular file", []string{"--file", filepath.Join(w, "in"), "--name", "d"}},
		{"no such file", []string{"--file", filepath.Join(w, "missing")}},
		{"want key=value", []string{"--file", src, "--name", "k", "--meta", "novalue"}},
		{"want key=value", []string{"--file", src, "--name", "k", "--meta", "=v"}},
		{"empty segment", []string{"--file", src, "--name", "k", "--meta", "a..b=1"}},
		{`"a.b": a is not an object`, []string{"--file", src, "--name", "k", "--meta", "a=1", "--meta", "a.b=2"}},
		{"not a JSON object", []string{"--file", src, "--name", "k", "--meta-file", notObj}},
		{"required flag", nil},
	} {
		wantFail(t, c.want, append([]string{"output"}, c.args...)...)
	}
	if ents, _ := os.ReadDir(filepath.Join(w, "out")); len(ents) != 2 {
		t.Fatalf("out %v", ents)
	}
}

func TestOutputMetaCap(t *testing.T) {
	w := newWork(t, map[string]string{"x": "1"})
	wantFail(t, "meta: larger than", "output", "--file", filepath.Join(w, "in", "x"), "--meta", "big="+strings.Repeat("v", runstep.MaxMeta))
	big := filepath.Join(t.TempDir(), "big.json")
	os.WriteFile(big, []byte(`{"a":"`+strings.Repeat("v", runstep.MaxMeta)+`"}`), 0o640)
	wantFail(t, "larger than", "output", "--file", filepath.Join(w, "in", "x"), "--meta-file", big)
	if ents, _ := os.ReadDir(filepath.Join(w, "out")); len(ents) != 0 {
		t.Fatalf("out %v", ents)
	}
	mustRun(t, "output", "--file", filepath.Join(w, "in", "x"), "--meta", "fits="+strings.Repeat("v", runstep.MaxMeta-20))
}

func crossFS(t *testing.T) {
	t.Helper()
	oldLink, oldRename := link, rename
	t.Cleanup(func() { link, rename = oldLink, oldRename })
	link = func(_, _ string) error { return &os.LinkError{Op: "link", Err: syscall.EXDEV} }
	rename = func(_, _ string) error { return &os.LinkError{Op: "rename", Err: syscall.EXDEV} }
}

func TestOutputCopyAcrossFilesystems(t *testing.T) {
	w := newWork(t, map[string]string{"x": "payload"})
	crossFS(t)
	src := filepath.Join(w, "in", "x")
	mustRun(t, "output", "--file", src, "--meta", "kind=copy")
	dst := filepath.Join(w, "out", "x")
	if b, _ := os.ReadFile(dst); string(b) != "payload" || inode(t, dst) == inode(t, src) {
		t.Fatalf("copy %q", b)
	}
	if m := readMetaFile(t, dst+runstep.MetaExt); m["kind"] != "copy" {
		t.Fatalf("meta %v", m)
	}
	if ents, _ := os.ReadDir(w); len(ents) != 3 {
		t.Fatalf("temporary files left: %v", ents)
	}
}

func TestOutputMove(t *testing.T) {
	w := newWork(t, nil)
	src := filepath.Join(w, "res")
	os.WriteFile(src, []byte("r"), 0o640)
	ino := inode(t, src)
	mustRun(t, "output", "--file", src, "--move")
	if _, err := os.Stat(src); !os.IsNotExist(err) || inode(t, filepath.Join(w, "out", "res")) != ino {
		t.Fatalf("not renamed: %v", err)
	}
	crossFS(t)
	os.WriteFile(src, []byte("r2"), 0o640)
	mustRun(t, "output", "--file", src, "--move", "--name", "res2")
	if b, _ := os.ReadFile(filepath.Join(w, "out", "res2")); string(b) != "r2" {
		t.Fatalf("%q", b)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source kept: %v", err)
	}
}

func TestFail(t *testing.T) {
	w := newWork(t, nil)
	code, out, errs := runJob(t, "fail", "--message", "disk full\x1b[2J\nsee log")
	if code != 1 || out != "" || !strings.Contains(errs, "disk full [2J") {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(w, runstep.FailFile)); string(b) != "disk full [2J\nsee log\n" {
		t.Fatalf("%q", b)
	}
	runJob(t, "fail", "--message", strings.Repeat("x", 2*runstep.MaxFail))
	if b, _ := os.ReadFile(filepath.Join(w, runstep.FailFile)); len(b) != runstep.MaxFail+1 {
		t.Fatalf("len %d", len(b))
	}
	wantFail(t, "--message is empty", "fail", "--message", " ")
	wantFail(t, "required flag", "fail")
}

func TestVersionAndArgs(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		if out := mustRun(t, args...); out != buildVersion+"\n" {
			t.Fatalf("%v: %q", args, out)
		}
	}
	newWork(t, nil)
	wantFail(t, "unexpected argument", "inputs", "x")
	wantFail(t, "--work given more than once", "inputs", "--work", "a", "--work", "b")
	wantFail(t, "--name needs a value", "output", "--file", "f", "--name", "-x")
}
