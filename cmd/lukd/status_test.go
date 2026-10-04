package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"luk/internal/status"
)

func statusConfig(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	text := `root: ` + root + `
listen: {main: {addr: "127.0.0.1:0"}}
auth:
  keys: [{name: robert.socha, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"}]
endpoint:
  backup: {listen: main, endpoint: /backup, path: q/backup, allow: [robert.socha]}
pipeline:
  archive: {endpoint: [backup], steps: [{store: archive}]}
storage:
  archive: {type: local, base: s/archive, path: "{{ .File }}"}
`
	if err := os.WriteFile(cfg, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	return cfg, root
}

func runLukd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := rootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	err := cmd.Execute()
	return out.String(), err
}

func TestStatusCommand(t *testing.T) {
	cfg, root := statusConfig(t)
	out, err := runLukd(t, "status", "-c", cfg)
	if err != nil || strings.Count(out, "\n") != 1 || !strings.HasPrefix(out, "PIPELINE") {
		t.Fatalf("missing file: %q %v", out, err)
	}
	st := status.New(status.Path(root))
	if err := st.Record(status.Result{Pipeline: "archive", Sender: "robert.socha", ID: "id1", Size: 7}); err != nil {
		t.Fatal(err)
	}
	out, err = runLukd(t, "status", "-c", cfg)
	if err != nil || !strings.Contains(out, "archive") || !strings.Contains(out, "robert.socha") || strings.Count(out, "\n") != 2 {
		t.Fatalf("table: %q %v", out, err)
	}
	out, err = runLukd(t, "status", "--json", "-c", cfg)
	raw, _ := os.ReadFile(status.Path(root))
	if err != nil || out != string(raw) {
		t.Fatalf("json: %q %v", out, err)
	}
	if _, err := runLukd(t, "status", "extra", "-c", cfg); err == nil {
		t.Fatal("positional argument accepted")
	}
}

func TestFlagGuard(t *testing.T) {
	if _, err := runLukd(t, "status", "-c", "-x"); err == nil || !strings.Contains(err.Error(), "--config needs a value") {
		t.Errorf("err %v", err)
	}
	if _, err := runLukd(t, "status", "-c", "a", "-c", "b"); err == nil || !strings.Contains(err.Error(), "--config given more than once") {
		t.Errorf("err %v", err)
	}
}
