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
	"luk/internal/status"
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

// storedSidecar reads the sidecar of the stored name of the storage drop of
// storageConfig.
func storedSidecar(t *testing.T, base, name string) store.Sidecar {
	t.Helper()
	f, sc, err := store.Local{Base: base, Conflict: "version"}.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	return sc
}

func TestStorageTTL(t *testing.T) {
	cfg, base := storageConfig(t)
	ttl := func(args ...string) (string, error) {
		return runLukd(t, append([]string{"storage", "ttl", "--storage", "drop", "-c", cfg}, args...)...)
	}
	for expires, why := range map[string]string{
		"soon":                 "want never, a duration such as 30d or 12h, or an RFC 3339 time",
		"0s":                   "want a positive duration",
		"2026-10-07":           "want never, a duration",
		"2020-01-01T00:00:00Z": "in the past",
	} {
		if _, err := ttl("--name", "c", "--expires", expires); err == nil || !strings.Contains(err.Error(), "--expires") || !strings.Contains(err.Error(), why) {
			t.Errorf("--expires %s: %v", expires, err)
		}
	}
	for name, why := range map[string]string{"nope": `storage drop: no stored file "nope"`, "../x": "refused"} {
		if _, err := ttl("--name", "c", "--name", name, "--expires", "30d"); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("--name %s: %v", name, err)
		}
	}
	if _, err := ttl("--name", "c"); err == nil || !strings.Contains(err.Error(), "expires") {
		t.Errorf("no --expires: %v", err)
	}
	if sc := storedSidecar(t, base, "c"); sc.Expires != "" {
		t.Fatalf("a refused command set %q", sc.Expires)
	}

	// The ttl policy of the storage does not bind the operator.
	before := time.Now()
	out, err := ttl("--name", "c", "--name", "sub/b", "--expires", "400d")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"c", "sub/b"} {
		sc := storedSidecar(t, base, name)
		at, perr := time.Parse(time.RFC3339, sc.Expires)
		if d := at.Sub(before.Add(400 * 24 * time.Hour)); perr != nil || d < -2*time.Second || d > time.Minute {
			t.Errorf("%s: expires %q", name, sc.Expires)
		}
		if !strings.Contains(out, name+": expires "+sc.Expires+"\n") {
			t.Errorf("%s: output %q", name, out)
		}
	}
	if sc := storedSidecar(t, base, "c"); sc.ID != "id-c" || sc.OwnerKey != "cert:hosts:web1" {
		t.Fatalf("sidecar %+v", sc)
	}
	out, err = ttl("--name", "c", "--expires", "2030-01-02T03:04:05+02:00")
	if err != nil || out != "c: expires 2030-01-02T01:04:05Z\n" || storedSidecar(t, base, "c").Expires != "2030-01-02T01:04:05Z" {
		t.Fatalf("timestamp: %v %q", err, out)
	}
	out, err = ttl("--name", "a", "--expires", "never")
	if err != nil || out != "a: expires never\n" || storedSidecar(t, base, "a").Expires != "" {
		t.Fatalf("never: %v %q", err, out)
	}

	// An alias is refused like rm refuses it, and follows its target.
	l := store.Local{Base: base, Conflict: "version"}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	sc := store.Sidecar{ID: "id-t", Endpoint: "drop", Size: 1, Received: time.Now().UTC().Format(time.RFC3339),
		Client: wire.Meta{Portal: wire.PortalDirect}, Meta: json.RawMessage(`{"alias":"latest"}`)}
	if _, err := l.Put(src, "target", sc); err != nil {
		t.Fatal(err)
	}
	if _, err := ttl("--name", "latest", "--expires", "1h"); err == nil || !strings.Contains(err.Error(), `"latest" is an alias of "target"; name that file`) {
		t.Fatalf("alias: %v", err)
	}
	if _, err := ttl("--name", "target", "--expires", "2031-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if a := storedSidecar(t, base, "latest"); a.AliasOf != "target" || a.Expires != "2031-01-01T00:00:00Z" {
		t.Fatalf("alias sidecar %+v", a)
	}
}

func TestStorageHold(t *testing.T) {
	cfg, base := storageConfig(t)
	run := func(cmd string, args ...string) (string, error) {
		out, _, err := runLukdIn(t, "", append([]string{"storage", cmd, "--storage", "drop", "-c", cfg}, args...)...)
		return out, err
	}
	flags := func(name string) string {
		t.Helper()
		out, err := run("ls")
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(out, "\n")[1:] {
			if f := strings.Fields(l); len(f) > 7 && f[0] == name {
				return f[7]
			}
		}
		t.Fatalf("no %s in\n%s", name, out)
		return ""
	}
	// Every name is checked first: a once upload is never held.
	if _, err := run("hold", "--name", "c", "--name", "a"); err == nil || !strings.Contains(err.Error(), `storage drop: "a": a once upload cannot be held`) {
		t.Fatalf("once: %v", err)
	}
	if _, err := run("hold", "--name", "c", "--name", "nope"); err == nil || !strings.Contains(err.Error(), `no stored file "nope"`) {
		t.Fatalf("unknown: %v", err)
	}
	if storedSidecar(t, base, "c").Hold || flags("c") != "-" {
		t.Fatal("a refused command held c")
	}
	out, err := run("hold", "--name", "c", "--name", "sub/b")
	if err != nil || out != "c: on hold\nsub/b: on hold\n" {
		t.Fatalf("hold: %v %q", err, out)
	}
	if flags("c") != "hold" || flags("sub/b") != "mutable,hold" || flags("a") != "once,reveal" {
		t.Fatalf("flags %s %s %s", flags("c"), flags("sub/b"), flags("a"))
	}
	out, err = run("ls", "--json")
	var got []storageFile
	if err != nil || json.Unmarshal([]byte(out), &got) != nil || len(got) != 3 || !got[0].Hold || got[1].Hold || !got[2].Hold ||
		strings.Count(out, `"hold": true`) != 2 || strings.Contains(out, `"hold": false`) {
		t.Fatalf("json %v %q", err, out)
	}
	// Held again, it stays held.
	if out, err := run("hold", "--name", "c"); err != nil || out != "c: on hold\n" || !storedSidecar(t, base, "c").Hold {
		t.Fatalf("hold twice: %v %q", err, out)
	}

	// rm refuses a file on hold, and removes nothing beside it.
	if _, err := run("rm", "--name", "a", "--name", "c", "--yes"); err == nil ||
		!strings.Contains(err.Error(), `storage drop: "c" is on hold; release it first (lukd storage release)`) {
		t.Fatalf("rm: %v", err)
	}
	for _, name := range []string{"a", "c"} {
		if _, err := os.Lstat(filepath.Join(base, "file", name)); err != nil {
			t.Fatalf("%s removed by a refused rm: %v", name, err)
		}
	}
	// The expiry of a file on hold changes.
	if _, err := run("ttl", "--name", "c", "--expires", "1h"); err != nil || !storedSidecar(t, base, "c").Hold || storedSidecar(t, base, "c").Expires == "" {
		t.Fatalf("ttl of a held file: %v", err)
	}

	out, err = run("release", "--name", "c", "--name", "a")
	if err != nil || out != "c: released\na: released\n" || storedSidecar(t, base, "c").Hold || flags("c") != "-" {
		t.Fatalf("release: %v %q", err, out)
	}
	if !storedSidecar(t, base, "sub/b").Hold {
		t.Fatal("release of c released sub/b")
	}
	if out, err := run("rm", "--name", "c", "--yes"); err != nil || out != "c: removed\n" {
		t.Fatalf("rm after release: %v %q", err, out)
	}
	for _, cmd := range []string{"hold", "release"} {
		if _, err := run(cmd); err == nil || !strings.Contains(err.Error(), "name") {
			t.Errorf("%s without --name: %v", cmd, err)
		}
		if _, err := runLukd(t, "storage", cmd, "--storage", "off", "--name", "a", "-c", cfg); err == nil || !strings.Contains(err.Error(), "not a local storage") {
			t.Errorf("%s of s3: %v", cmd, err)
		}
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
	writeIdentity(t, cfg)
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

func TestStorageRetention(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	text := `root: ` + root + `
listen: {main: {addr: "127.0.0.1:0"}}
auth:
  keys: [{name: robert.socha, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"}]
endpoint:
  backup: {listen: main, endpoint: /backup, path: q/backup, allow: [robert.socha]}
pipeline:
  nightly: {endpoint: [backup], steps: [{store: archive}]}
storage:
  archive:
    type: local
    base: s/archive
    path: "{{ .Origin }}/{{ .File }}"
    retention:
      - origin: ["*-prod"]
        keep: {last: 1, daily: 2}
`
	if err := os.WriteFile(cfgPath, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	l := store.FromConfig(cfg.Storage["archive"])
	if err := os.MkdirAll(l.Base, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct{ name, origin, at string }{
		{"db1-prod/db.sql", "db1-prod", "2026-10-04T18:00:00Z"},
		{"db1-prod/db.sql.1759550400", "db1-prod", "2026-10-04T06:00:00Z"},
		{"db1-prod/db.sql.1759464000", "db1-prod", "2026-10-03T06:00:00Z"},
		{"db1-stage/db.sql", "db1-stage", "2026-10-04T06:00:00Z"},
	} {
		src := filepath.Join(t.TempDir(), "src")
		if err := os.WriteFile(src, []byte(f.name), 0o640); err != nil {
			t.Fatal(err)
		}
		sc := store.Sidecar{ID: "id-" + f.name, Sender: "robert.socha", Endpoint: "backup", Received: f.at, Size: int64(len(f.name)),
			Pipeline: "nightly", Origin: f.origin, Client: wire.Meta{File: "db.sql"}}
		if _, err := l.Put(src, f.name, sc); err != nil {
			t.Fatal(err)
		}
	}
	out, err := runLukd(t, "storage", "retention", "--storage", "archive", "-c", cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	want := `series pipeline=nightly origin=db1-prod file=db.sql: rule 1 (origin *-prod; keep last 1, daily 2)
  NAME                        RECEIVED              ACTION  REASONS
  db1-prod/db.sql             2026-10-04T18:00:00Z  KEEP    last, daily 2026-10-04
  db1-prod/db.sql.1759550400  2026-10-04T06:00:00Z  PRUNE   -
  db1-prod/db.sql.1759464000  2026-10-03T06:00:00Z  KEEP    daily 2026-10-03

series pipeline=nightly origin=db1-stage file=db.sql: no rule
  NAME              RECEIVED              ACTION  REASONS
  db1-stage/db.sql  2026-10-04T06:00:00Z  KEEP    no rule
`
	if out != want {
		t.Fatalf("plan:\n%s\nwant:\n%s", out, want)
	}
	out, err = runLukd(t, "storage", "retention", "--storage", "archive", "--json", "-c", cfgPath)
	var plans []store.SeriesPlan
	if err != nil || json.Unmarshal([]byte(out), &plans) != nil || len(plans) != 2 || plans[0].Rule != 1 || plans[0].Keep.Daily != 2 ||
		plans[0].Files[1].Keep || plans[1].Rule != 0 || plans[1].Files[0].Reasons[0] != "no rule" {
		t.Fatalf("json: %v\n%s", err, out)
	}
	for _, f := range []string{"db1-prod/db.sql", "db1-prod/db.sql.1759550400", "db1-prod/db.sql.1759464000", "db1-stage/db.sql"} {
		if _, err := os.Stat(filepath.Join(l.Base, store.DataDir, f)); err != nil {
			t.Errorf("plan removed %s: %v", f, err)
		}
	}

	// A file on hold is kept and takes no place in the counts of its rule.
	if out, err := runLukd(t, "storage", "hold", "--storage", "archive", "--name", "db1-prod/db.sql", "-c", cfgPath); err != nil || out != "db1-prod/db.sql: on hold\n" {
		t.Fatalf("hold: %v %q", err, out)
	}
	out, err = runLukd(t, "storage", "retention", "--storage", "archive", "-c", cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	want = `series pipeline=nightly origin=db1-prod file=db.sql: rule 1 (origin *-prod; keep last 1, daily 2)
  NAME                        RECEIVED              ACTION  REASONS
  db1-prod/db.sql             2026-10-04T18:00:00Z  HELD    hold
  db1-prod/db.sql.1759550400  2026-10-04T06:00:00Z  KEEP    last, daily 2026-10-04
  db1-prod/db.sql.1759464000  2026-10-03T06:00:00Z  KEEP    daily 2026-10-03

series pipeline=nightly origin=db1-stage file=db.sql: no rule
  NAME              RECEIVED              ACTION  REASONS
  db1-stage/db.sql  2026-10-04T06:00:00Z  KEEP    no rule
`
	if out != want {
		t.Fatalf("plan with a hold:\n%s\nwant:\n%s", out, want)
	}
	out, err = runLukd(t, "storage", "retention", "--storage", "archive", "--json", "-c", cfgPath)
	if err != nil || json.Unmarshal([]byte(out), &plans) != nil || !plans[0].Files[0].Hold || !plans[0].Files[0].Keep || plans[0].Files[1].Hold ||
		!strings.Contains(out, `"hold": true`) {
		t.Fatalf("json with a hold: %v\n%s", err, out)
	}
}

func TestKeepText(t *testing.T) {
	k := config.Keep{Last: 3, Daily: 14, Within: config.Duration(48 * time.Hour)}
	if got := keepText(k); got != "last 3, daily 14, within 2d" {
		t.Fatalf("%q", got)
	}
}

func TestStorageWatch(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	text := `root: ` + root + `
listen: {main: {addr: "127.0.0.1:0"}}
auth:
  keys: [{name: robert.socha, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"}]
endpoint:
  backup: {listen: main, endpoint: /backup, path: q/backup, allow: [robert.socha]}
pipeline:
  nightly: {endpoint: [backup], steps: [{store: archive}]}
storage:
  archive:
    type: local
    base: s/archive
    path: "{{ .Origin }}/{{ .Id }}/{{ .File }}"
    watch:
      - origin: ["db1-prod"]
        file: ["db.sql*"]
        every: 26h
        size: {min: 2G, step: 500M}
      - origin: ["*-dev"]
        same: 2
`
	if err := os.WriteFile(cfgPath, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	l := store.FromConfig(cfg.Storage["archive"])
	if err := os.MkdirAll(l.Base, 0o750); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	const M = int64(1) << 20
	for _, f := range []struct {
		name, origin string
		ago          time.Duration
		size         int64
	}{
		{"db1-prod/3/db.sql", "db1-prod", 31 * time.Hour, 980 * M},
		{"db1-prod/2/db.sql", "db1-prod", 55 * time.Hour, 3000 * M},
		{"db1-prod/1/db.sql", "db1-prod", 79 * time.Hour, 2900 * M},
		{"web1/1/db.sql", "web1", time.Hour, M},
	} {
		src := filepath.Join(t.TempDir(), "src")
		if err := os.WriteFile(src, []byte(f.name), 0o640); err != nil {
			t.Fatal(err)
		}
		sc := store.Sidecar{ID: "id-" + f.name, Sender: "robert.socha", Endpoint: "backup", Received: now.Add(-f.ago).Format(time.RFC3339),
			Size: f.size, SHA256: f.name, Pipeline: "nightly", Origin: f.origin, Client: wire.Meta{File: "db.sql"}}
		if _, err := l.Put(src, f.name, sc); err != nil {
			t.Fatal(err)
		}
	}
	out, err := runLukd(t, "storage", "watch", "--storage", "archive", "-c", cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	at := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	want := `rule 1: origin db1-prod; file db.sql*: every 26h, size.min 2G, size.step 500M
rule 2: origin *-dev: same 2

STORAGE  SERIES           PIPELINE  RULE  STATE  NEWEST                SIZE  COPIES  MESSAGE
archive  db1-prod/db.sql  nightly   1     CRIT   ` + at(31*time.Hour) + `  980M  3       db1-prod/db.sql: 980M below min 2G; last copy 31h ago (every 26h); shrank by 2G to 980M (step 500M)
archive  web1/db.sql      nightly   -     -      ` + at(time.Hour) + `  1M    1       not watched
archive  -                -         2     WARN   -                     -     0       rule 2 (origin *-dev): no series matches
`
	if out != want {
		t.Fatalf("watch:\n%s\nwant:\n%s", out, want)
	}
	out, err = runLukd(t, "storage", "watch", "--storage", "archive", "--suggest", "-c", cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	wantHints := `HINTS: observed on the newest 30 copies of each series; not thresholds
SERIES           PIPELINE  COPIES  NEWEST SIZE  MIN SIZE  MAX SIZE  MAX STEP  INTERVAL  MIN INTERVAL  MAX INTERVAL  SAME
db1-prod/db.sql  nightly   3       980M         980M      2.9G      2G        24h       24h           24h           1
web1/db.sql      nightly   1       1M           1M        1M        0         -         -             -             1
`
	if !strings.HasPrefix(out, want) || !strings.HasSuffix(out, "\n"+wantHints) {
		t.Fatalf("suggest:\n%s", out)
	}
	out, err = runLukd(t, "storage", "watch", "--storage", "archive", "--json", "--suggest", "-c", cfgPath)
	var rows []struct {
		status.Watch
		Hints *struct {
			Copies   int    `json:"copies"`
			MaxStep  int64  `json:"max_step"`
			Interval string `json:"interval"`
		} `json:"hints"`
	}
	if err != nil || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 3 || rows[0].State != "CRIT" || rows[0].Rule != 1 ||
		rows[0].Hints == nil || rows[0].Hints.Copies != 3 || rows[0].Hints.MaxStep != 2020*M || rows[0].Hints.Interval != "24h" ||
		rows[1].Rule != 0 || rows[1].Message != "not watched" || rows[2].State != "WARN" || rows[2].Hints != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got := strings.Join(complete(t, "storage", "watch", "-c", cfgPath, "--storage", ""), ","); got != "archive" {
		t.Errorf("completion %q", got)
	}
}

// The public files of a storage behind an auth.ssh expose have luk://
// URLs.
func TestStorageFilesSignedExpose(t *testing.T) {
	cfg, err := config.Parse([]byte(`root: ` + t.TempDir() + `
listen: {main: {addr: "127.0.0.1:0", public: "https://drop.example.com"}}
auth:
  keys: [{name: robert.socha, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"}]
endpoint:
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha], respond: url, storage: vault}
pipeline:
  drop: {endpoint: [drop], steps: [{store: vault}]}
storage:
  vault: {type: local, base: s/vault, path: "{{ .File }}", expose: vault}
expose:
  vault: {listen: main, path: /v/, auth: {ssh: {allow: [robert.socha]}}}
`))
	if err != nil {
		t.Fatal(err)
	}
	l := store.FromConfig(cfg.Storage["vault"])
	if err := os.MkdirAll(l.Base, 0o750); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(src, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(src, "2026/x", store.Sidecar{ID: "id-x", Received: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	files, err := storageFiles(cfg, "vault", l, "", 0, time.Now())
	if err != nil || len(files) != 1 || files[0].URL != "luk://drop.example.com/v/2026/x" {
		t.Fatalf("%+v %v", files, err)
	}
}
