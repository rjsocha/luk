package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/store"
	"luk/internal/wire"
)

const permanentText = `listen: {main: {addr: "127.0.0.1:0", public: "https://drop.example.com"}}
auth:
  keys: [{name: robert.socha, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"}]
endpoint:
  drop:
    listen: main
    endpoint: /drop
    path: q/drop
    allow: [robert.socha]
    respond: url
    storage: drop
    permanent: {names: NAMES}
pipeline:
  drop: {endpoint: [drop], steps: [{store: drop}]}
storage:
  drop: {type: local, base: s/drop, path: "{{ .Random }}", expose: drop}
expose:
  drop: {listen: main, path: /d/}
`

// permanentConfig writes to cfgPath a config whose endpoint drop
// allocates names (YAML flow) and loads it.
func permanentConfig(t *testing.T, root, cfgPath, names string) *config.Config {
	t.Helper()
	text := "root: " + root + "\n" + strings.Replace(permanentText, "NAMES", names, 1)
	if err := os.WriteFile(cfgPath, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestStoragePermanent(t *testing.T) {
	root, cfgPath := t.TempDir(), filepath.Join(t.TempDir(), "config.yaml")
	cfg := permanentConfig(t, root, cfgPath, `{one: {allow: ['*']}, two: {allow: ['*']}}`)
	l := store.FromConfig(cfg.Storage["drop"])
	if err := os.MkdirAll(l.Base, 0o750); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-time.Hour).UTC()
	for i, v := range []struct{ rel, name string }{{"a", "one"}, {"b", "two"}, {"c", "two"}} {
		src := filepath.Join(t.TempDir(), "src")
		if err := os.WriteFile(src, []byte(v.rel), 0o640); err != nil {
			t.Fatal(err)
		}
		sc := store.Sidecar{ID: "id-" + v.rel, Endpoint: "drop", Size: 1, Received: t0.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			PermanentPath: "permanent", Client: wire.Meta{Portal: wire.PortalDirect, Permanent: v.name}}
		if _, err := l.Put(src, v.rel, sc); err != nil {
			t.Fatal(err)
		}
	}
	out, err := runLukd(t, "storage", "permanent", "--storage", "drop", "-c", cfgPath)
	if err != nil || names(out) != "permanent,permanent" || strings.Count(out, "ORPHAN") != 1 { // the header only
		t.Fatalf("%v\n%s", err, out)
	}
	// c replaced b: one version per name, the current one listed.
	if !strings.HasPrefix(out, "PATH       NAME  CURRENT  RECEIVED") || !strings.Contains(out, "two   c ") || !strings.Contains(out, "never") {
		t.Fatalf("list\n%s", out)
	}
	// The entry of two goes: an orphan, reported by lukd check, kept by
	// lukd, removed by --prune.
	permanentConfig(t, root, cfgPath, `{one: {allow: ['*']}}`)
	writeIdentity(t, cfgPath)
	_, errOut, err := runLukdIn(t, "", "check", "--no-running", "-c", cfgPath)
	if err != nil || !strings.Contains(errOut, "warning: storage drop: permanent name permanent/two is an orphan") {
		t.Fatalf("check: %v %q", err, errOut)
	}
	out, err = runLukd(t, "storage", "permanent", "--storage", "drop", "-c", cfgPath)
	if err != nil || strings.Count(out, "ORPHAN") != 2 { // the header and two
		t.Fatalf("orphan list: %v\n%s", err, out)
	}
	isTerm := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = isTerm })
	stdinIsTerminal = func() bool { return false }
	if _, _, err := runLukdIn(t, "", "storage", "permanent", "--storage", "drop", "--prune", "-c", cfgPath); err == nil || !strings.Contains(err.Error(), "without --yes") {
		t.Fatalf("no terminal: %v", err)
	}
	stdinIsTerminal = func() bool { return true }
	if _, prompt, err := runLukdIn(t, "n\n", "storage", "permanent", "--storage", "drop", "--prune", "-c", cfgPath); err == nil ||
		!strings.Contains(prompt, "permanent/two (current c)") {
		t.Fatalf("declined: %v %q", err, prompt)
	}
	out, _, err = runLukdIn(t, "", "storage", "permanent", "--storage", "drop", "--prune", "--yes", "-c", cfgPath)
	if err != nil || out != "permanent/two: removed\n" {
		t.Fatalf("prune: %v %q", err, out)
	}
	if _, err := os.Lstat(filepath.Join(l.Base, store.PermanentDir, "permanent/two")); !os.IsNotExist(err) {
		t.Fatalf("orphan left: %v", err)
	}
	// The versions stay; one is untouched.
	if out, err := runLukd(t, "storage", "ls", "--storage", "drop", "-c", cfgPath); err != nil || names(out) != "c,a" {
		t.Fatalf("versions: %v\n%s", err, out)
	}
	out, err = runLukd(t, "storage", "permanent", "--storage", "drop", "--json", "-c", cfgPath)
	if err != nil || !strings.Contains(out, `"key": "permanent/one"`) || strings.Contains(out, "permanent/two") {
		t.Fatalf("json: %v\n%s", err, out)
	}
	_, errOut, err = runLukdIn(t, "", "check", "--no-running", "-c", cfgPath)
	if err != nil || strings.Contains(errOut, "orphan") {
		t.Fatalf("check after prune: %v %q", err, errOut)
	}
	// The version of one goes: the name is empty, listed without a
	// current version until --prune removes it.
	if err := l.Remove("a"); err != nil {
		t.Fatal(err)
	}
	out, err = runLukd(t, "storage", "permanent", "--storage", "drop", "-c", cfgPath)
	if err != nil || !strings.Contains(out, "permanent  one   -        -         -        -") {
		t.Fatalf("empty list: %v\n%s", err, out)
	}
	out, _, err = runLukdIn(t, "", "storage", "permanent", "--storage", "drop", "--prune", "--yes", "-c", cfgPath)
	if err != nil || out != "permanent/one: removed\n" {
		t.Fatalf("prune empty: %v %q", err, out)
	}
	if out, err := runLukd(t, "storage", "permanent", "--storage", "drop", "-c", cfgPath); err != nil || out != "" {
		t.Fatalf("after prune empty: %v\n%s", err, out)
	}
}
