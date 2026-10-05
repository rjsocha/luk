package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// passwordConfig is a configuration directory everyone may search whose
// pipeline names the passwords pw-a (symmetric) and pw-b (openssl); it
// returns the main file.
func passwordConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "config.yaml")
	text := `root: ` + filepath.Join(dir, "root") + `
listen: {main: {addr: "127.0.0.1:0"}}
auth:
  keys: [{name: robert.socha, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"}]
endpoint:
  backup: {listen: main, endpoint: /backup, path: q/backup, allow: [robert.socha]}
pipeline:
  archive:
    endpoint: [backup]
    steps:
      - encrypt: {wkd: [a@b.example], insecure: {symmetric: [pw-a], openssl: {key: pw-b, files: ['*-latest.sql.zst']}}}
      - store: archive
storage:
  archive: {type: local, base: s/archive, path: "{{ .File }}"}
`
	if err := os.WriteFile(cfg, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writePassword(t *testing.T, cfg, name, body string, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(filepath.Dir(cfg), "password.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckPasswords(t *testing.T) {
	cfg := passwordConfig(t)
	dir := filepath.Join(filepath.Dir(cfg), "password.d")
	check := func(args ...string) (string, error) {
		_, errOut, err := runCheck(t, append([]string{"-c", cfg, "--no-running", "--no-identity"}, args...)...)
		return errOut, err
	}
	var code exitCode
	errOut, err := check()
	if !errors.As(err, &code) || code != 1 ||
		!strings.Contains(errOut, filepath.Join(dir, "pw-a")) || !strings.Contains(errOut, filepath.Join(dir, "pw-b")) {
		t.Fatalf("missing: %q %v", errOut, err)
	}
	if errOut, err := check("--no-passwords"); err != nil || errOut != "" {
		t.Fatalf("--no-passwords: %q %v", errOut, err)
	}
	writePassword(t, cfg, "pw-a", "secret\n", 0o640)
	writePassword(t, cfg, "pw-b", "\n", 0o640)
	if errOut, err := check(); err == nil || !strings.Contains(errOut, filepath.Join(dir, "pw-b")+": empty password") || strings.Contains(errOut, "pw-a") {
		t.Fatalf("empty: %q %v", errOut, err)
	}
	writePassword(t, cfg, "pw-b", "other", 0o640)
	if errOut, err := check(); err != nil || errOut != "" {
		t.Fatalf("fixed: %q %v", errOut, err)
	}
}

func TestCheckPasswordsReadableByServiceUser(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the permission math is not exercised as root's own files")
	}
	cfg := passwordConfig(t)
	writePassword(t, cfg, "pw-a", "secret\n", 0o640)
	pwB := writePassword(t, cfg, "pw-b", "other\n", 0o600)
	fakeUser(t, true)
	old := geteuid
	geteuid = func() int { return 0 }
	defer func() { geteuid = old }()
	_, errOut, err := runCheck(t, "-c", cfg, "--no-running", "--no-identity")
	if err == nil || !strings.Contains(errOut, pwB+": not readable by luk") || strings.Contains(errOut, "pw-a") {
		t.Fatalf("root: %q %v", errOut, err)
	}
	if out, errOut, err := runCheck(t, "-c", cfg, "--no-running", "--no-identity", "--no-passwords"); err != nil || out != "ok\n" {
		t.Fatalf("--no-passwords: %q %q %v", out, errOut, err)
	}
	os.Chmod(pwB, 0o640)
	if out, errOut, err := runCheck(t, "-c", cfg, "--no-running", "--no-identity"); err != nil || out != "ok\n" {
		t.Fatalf("fixed: %q %q %v", out, errOut, err)
	}
}
