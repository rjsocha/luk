package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/store"
	"luk/internal/wire"
)

// storageConfig has the exposed local storage drop with three files: c
// (newest, a certificate owner), a (2h old, once reveal) and sub/b (10d
// old, mutable, another key).
func storageConfig(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	text := `root: ` + root + `
listen: {main: {addr: "127.0.0.1:0", public: "https://drop.example.com"}}
auth:
  keys: [{name: robert.socha, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"}]
endpoint:
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha], respond: url, storage: drop}
pipeline:
  drop: {endpoint: [drop], steps: [{store: drop}]}
storage:
  drop: {type: local, base: s/drop, path: "{{ .Random }}", expose: drop}
  plain: {type: local, base: s/plain, path: "{{ .File }}"}
  off: {type: s3, bucket: b}
expose:
  drop: {listen: main, path: /d/}
`
	if err := os.WriteFile(cfgPath, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	l := store.FromConfig(cfg.Storage["drop"])
	if err := os.MkdirAll(l.Base, 0o750); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, f := range []struct {
		name string
		sc   store.Sidecar
	}{
		{"c", store.Sidecar{ID: "id-c", Owner: "host", OwnerKey: "cert:hosts:web1", Received: now.Format(time.RFC3339)}},
		{"a", store.Sidecar{ID: "id-a", Owner: "robert.socha", OwnerKey: "key:robert.socha", Received: now.Add(-2 * time.Hour).Format(time.RFC3339),
			Expires: now.Add(time.Hour).Format(time.RFC3339), Client: wire.Meta{Once: true, Portal: wire.PortalReveal}}},
		{"sub/b", store.Sidecar{ID: "id-b", OwnerKey: "key:other", Received: now.Add(-10 * 24 * time.Hour).Format(time.RFC3339),
			Client: wire.Meta{Mutable: true, Portal: wire.PortalDirect}}},
	} {
		src := filepath.Join(t.TempDir(), "src")
		if err := os.WriteFile(src, []byte(f.name), 0o640); err != nil {
			t.Fatal(err)
		}
		f.sc.Endpoint, f.sc.Size = "drop", int64(len(f.name))
		if _, err := l.Put(src, f.name, f.sc); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(src); err != nil {
			t.Fatal(err)
		}
	}
	return cfgPath, l.Base
}

// names is the first column of the rows of a table.
func names(out string) string {
	var n []string
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n")[1:] {
		n = append(n, strings.Fields(l)[0])
	}
	return strings.Join(n, ",")
}

func TestStorageLs(t *testing.T) {
	cfg, _ := storageConfig(t)
	out, err := runLukd(t, "storage", "ls", "--storage", "drop", "-c", cfg)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "NAME") || !strings.HasSuffix(lines[0], "URL") || names(out) != "c,a,sub/b" {
		t.Fatalf("table:\n%s", out)
	}
	a := strings.Fields(lines[2])
	if a[1] != "1" || a[4] != "robert.socha" || a[5] != "key:robert.socha" || a[6] != "drop" || a[7] != "once,reveal" || a[8] != "https://drop.example.com/d/a" {
		t.Fatalf("a: %q", lines[2])
	}
	if b := strings.Fields(lines[3]); b[3] != "-" || b[4] != "-" || b[7] != "mutable" || b[8] != "https://drop.example.com/d/sub/b" {
		t.Fatalf("sub/b: %q", lines[3])
	}
	for flags, want := range map[string]string{
		"--owner robert.socha":            "a",
		"--owner key:robert.socha":        "a",
		"--owner cert:hosts:web1":         "c",
		"--owner hosts:web1":              "",
		"--older 7d":                      "sub/b",
		"--older 1h":                      "a,sub/b",
		"--older 1h --owner other":        "sub/b",
		"--owner robert.socha --older 7d": "",
	} {
		out, err := runLukd(t, append([]string{"storage", "ls", "--storage", "drop", "-c", cfg}, strings.Fields(flags)...)...)
		if err != nil || names(out) != want {
			t.Errorf("%s: %v\n%s", flags, err, out)
		}
	}
	out, err = runLukd(t, "storage", "ls", "--storage", "drop", "--json", "-c", cfg)
	var got []storageFile
	if err != nil || json.Unmarshal([]byte(out), &got) != nil || len(got) != 3 || got[1].Name != "a" || got[1].OwnerKey != "key:robert.socha" ||
		got[1].URL != "https://drop.example.com/d/a" || !got[1].Client.Once || got[1].ID != "id-a" || got[2].Name != "sub/b" {
		t.Fatalf("json %q %v", out, err)
	}
	out, err = runLukd(t, "storage", "ls", "--storage", "drop", "--json", "--owner", "nobody", "-c", cfg)
	if err != nil || out != "[]\n" {
		t.Fatalf("empty json %q %v", out, err)
	}
	for args, want := range map[string]string{
		"--storage off":               "storage off is not a local storage (s3)",
		"--storage nope":              `unknown storage "nope"`,
		"--storage drop --older soon": "--older",
		"--storage drop --older 0s":   "--older",
	} {
		if _, err := runLukd(t, append([]string{"storage", "ls", "-c", cfg}, strings.Fields(args)...)...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", args, err)
		}
	}
	if _, err := runLukd(t, "storage", "ls", "--storage", "drop", "extra", "-c", cfg); err == nil {
		t.Fatal("positional argument accepted")
	}
}

func TestStorageLsShared(t *testing.T) {
	cfg, base := storageConfig(t)
	c, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l := store.FromConfig(c.Storage["drop"])
	sum := sha256.Sum256([]byte("same"))
	for _, name := range []string{"x", "y"} {
		src := filepath.Join(t.TempDir(), "src")
		if err := os.WriteFile(src, []byte("same"), 0o640); err != nil {
			t.Fatal(err)
		}
		sc := store.Sidecar{ID: "id-" + name, OwnerKey: "key:robert.socha", Endpoint: "drop", Size: 4, SHA256: hex.EncodeToString(sum[:]),
			Received: time.Now().UTC().Format(time.RFC3339), Client: wire.Meta{Portal: wire.PortalDirect}}
		if _, err := l.Put(src, name, sc); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(src); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(base, store.ObjectsDir)); err != nil {
		t.Fatalf("no objects: %v", err)
	}
	out, err := runLukd(t, "storage", "ls", "--storage", "drop", "-c", cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out, "\n")[1:] {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case f[0] == "x" || f[0] == "y":
			if f[7] != "shared" {
				t.Errorf("%q not shared", line)
			}
		case strings.Contains(line, "shared"):
			t.Errorf("%q shared", line)
		}
	}
	out, err = runLukd(t, "storage", "ls", "--storage", "drop", "--json", "-c", cfg)
	var got []storageFile
	if err != nil || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("json %q %v", out, err)
	}
	for _, f := range got {
		want := 1
		if f.Name == "x" || f.Name == "y" {
			want = 2
		}
		if f.Links != want {
			t.Errorf("%s: links %d, want %d", f.Name, f.Links, want)
		}
	}
}

func TestStorageLsNotExposed(t *testing.T) {
	cfg, base := storageConfig(t)
	plain := filepath.Join(filepath.Dir(base), "plain")
	if err := os.MkdirAll(plain, 0o750); err != nil {
		t.Fatal(err)
	}
	out, err := runLukd(t, "storage", "ls", "--storage", "plain", "-c", cfg)
	if err != nil || strings.Contains(out, "URL") || strings.Count(out, "\n") != 1 {
		t.Fatalf("%q %v", out, err)
	}
}

func TestStorageRm(t *testing.T) {
	cfg, base := storageConfig(t)
	isTerm := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = isTerm })
	stdinIsTerminal = func() bool { return false }
	// rel is under the data tree, .db/... under the base.
	exists := func(rel string) bool {
		p := filepath.Join(base, "file", rel)
		if strings.HasPrefix(rel, ".db/") {
			p = filepath.Join(base, rel)
		}
		_, err := os.Lstat(p)
		return err == nil
	}
	if _, _, err := runLukdIn(t, "", "storage", "rm", "--storage", "drop", "--name", "a", "-c", cfg); err == nil || !strings.Contains(err.Error(), "without --yes") || !exists("a") {
		t.Fatalf("no terminal: %v", err)
	}
	for bad, why := range map[string]string{"../x": `element ".." is not a name`, "/a": "is absolute", "sub/../a": `element ".." is not a name`,
		"sub/./b": `element "." is not a name`, "sub//b": "empty element"} {
		_, _, err := runLukdIn(t, "", "storage", "rm", "--storage", "drop", "--name", "a", "--name", bad, "--yes", "-c", cfg)
		if err == nil || !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, _, err := runLukdIn(t, "", "storage", "rm", "--storage", "drop", "--name", "a", "--name", "nope", "--yes", "-c", cfg); err == nil || !strings.Contains(err.Error(), `no stored file "nope"`) {
		t.Fatalf("unknown: %v", err)
	}
	if !exists("a") {
		t.Fatal("a removed by a refused command")
	}
	if _, err := runLukd(t, "storage", "rm", "--storage", "off", "--name", "a", "--yes", "-c", cfg); err == nil || !strings.Contains(err.Error(), "not a local storage") {
		t.Fatalf("s3: %v", err)
	}

	stdinIsTerminal = func() bool { return true }
	if _, prompt, err := runLukdIn(t, "n\n", "storage", "rm", "--storage", "drop", "--name", "a", "-c", cfg); err == nil || err.Error() != "nothing removed" ||
		!strings.Contains(prompt, "Remove from storage drop:\n  a (1 bytes, received ") || !exists("a") {
		t.Fatalf("declined: %v %q", err, prompt)
	}
	out, _, err := runLukdIn(t, "y\n", "storage", "rm", "--storage", "drop", "--name", "a", "-c", cfg)
	if err != nil || out != "a: removed\n" || exists("a") || exists(".db/meta/a.json") {
		t.Fatalf("confirmed: %v %q", err, out)
	}

	stdinIsTerminal = func() bool { return false }
	out, _, err = runLukdIn(t, "", "storage", "rm", "--storage", "drop", "--name", "sub/b", "--name", "c", "--yes", "-c", cfg)
	if err != nil || out != "sub/b: removed\nc: removed\n" {
		t.Fatalf("--yes: %v %q", err, out)
	}
	for _, rel := range []string{"sub", ".db/meta/sub", "c", ".db/meta/c.json"} {
		if exists(rel) {
			t.Errorf("%s left", rel)
		}
	}
	if !exists(".db/meta/") || !exists("") {
		t.Error("tree root pruned")
	}
}

func TestStorageAsOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	cfg, base := storageConfig(t)
	t.Setenv(reexecEnv, "")
	euid, re := geteuid, reexecAs
	t.Cleanup(func() { geteuid, reexecAs = euid, re })
	geteuid = func() int { return 0 }
	var uid uint32 = 1 << 31
	reexecAs = func(u, _ uint32, _ []uint32) error {
		uid = u
		return exitCode(0)
	}
	if _, err := runLukd(t, "storage", "rm", "--storage", "drop", "--name", "a", "--yes", "-c", cfg); err != exitCode(0) || uid != uint32(os.Getuid()) {
		t.Fatalf("root: %v uid %d", err, uid)
	}
	if _, err := os.Lstat(filepath.Join(base, "file", "a")); err != nil {
		t.Fatal("root removed in the first run")
	}
	geteuid = func() int { return os.Getuid() + 1 }
	if _, err := runLukd(t, "storage", "ls", "--storage", "drop", "-c", cfg); err == nil || !strings.Contains(err.Error(), "lukd storage must run as root or as") ||
		!strings.Contains(err.Error(), "(owner of "+base+")") {
		t.Fatalf("other user: %v", err)
	}
}

func TestStorageDotNames(t *testing.T) {
	cfg, base := storageConfig(t)
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte("rc"), 0o640); err != nil {
		t.Fatal(err)
	}
	l := store.Local{Base: base}
	if _, err := l.Put(src, ".bashrc", store.Sidecar{ID: "id-rc", Received: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	out, err := runLukd(t, "storage", "ls", "--storage", "drop", "-c", cfg)
	if err != nil || !strings.Contains(out, "\n.bashrc ") {
		t.Fatalf("ls: %q %v", out, err)
	}
	if out, _, err := runLukdIn(t, "", "storage", "rm", "--storage", "drop", "--name", ".bashrc", "--yes", "-c", cfg); err != nil || out != ".bashrc: removed\n" {
		t.Fatalf("rm: %q %v", out, err)
	}
}

func TestStorageOldLayout(t *testing.T) {
	cfg, base := storageConfig(t)
	if err := os.WriteFile(filepath.Join(base, ".luk-lock"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"storage", "ls", "--storage", "drop"}, {"storage", "rm", "--storage", "drop", "--name", "a", "--yes"}} {
		if _, err := runLukd(t, append(args, "-c", cfg)...); err == nil || !strings.Contains(err.Error(), "storage drop: "+base+": holds .luk-lock besides .db/ and file/") {
			t.Errorf("%s: %v", args[1], err)
		}
	}
	_, errOut, err := runCheck(t, "--no-running", "-c", cfg)
	if err == nil || !strings.Contains(errOut, "storage drop: "+base+": holds .luk-lock besides") {
		t.Fatalf("check: %q %v", errOut, err)
	}
	if err := os.Remove(filepath.Join(base, ".luk-lock")); err != nil {
		t.Fatal(err)
	}
	if out, errOut, err := runCheck(t, "--no-running", "-c", cfg); err != nil || out != "ok\n" {
		t.Fatalf("check: %q %q %v", out, errOut, err)
	}
}
