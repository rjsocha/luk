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
	// The process role creates the directory (see prepareDirs).
	if err := os.MkdirAll(filepath.Dir(status.Path(root)), 0o750); err != nil {
		t.Fatal(err)
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

func TestStatusCommandWatch(t *testing.T) {
	cfg, root := statusConfig(t)
	// The process role creates the directory (see prepareDirs).
	if err := os.MkdirAll(filepath.Dir(status.Path(root)), 0o750); err != nil {
		t.Fatal(err)
	}
	st := status.New(status.Path(root))
	if err := st.SetWatch([]status.Watch{{Storage: "archive", Rule: 1, Pipeline: "archive", Origin: "db1-prod", File: "db.sql", State: "CRIT",
		Message: "db1-prod/db.sql: last copy 31h ago (every 26h)", NewestReceived: "2026-10-03T05:00:00Z", Size: 4 << 30, Copies: 2,
		Evaluated: "2026-10-04T12:00:00Z"}}); err != nil {
		t.Fatal(err)
	}
	out, err := runLukd(t, "status", "-c", cfg)
	want := "PIPELINE  SENDER  FAILED  LAST RECEIVED  LAST SUCCESS  LAST FAILURE  STEP  SIZE  LAST ID  ERROR\n\n" +
		"STORAGE  SERIES           PIPELINE  RULE  STATE  NEWEST                SIZE  COPIES  MESSAGE\n" +
		"archive  db1-prod/db.sql  archive   1     CRIT   2026-10-03T05:00:00Z  4G    2       db1-prod/db.sql: last copy 31h ago (every 26h)\n"
	if err != nil || out != want {
		t.Fatalf("table: %v\n%s\nwant:\n%s", err, out, want)
	}
}
