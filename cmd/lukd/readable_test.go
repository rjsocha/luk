package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"luk/internal/config"
)

// readableDir is a configuration directory everyone may search, with
// config.yaml, a snippet, a ssh.d key, tls files of a self listener and a
// gpg key; it returns the directory.
func readableDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	text := `root: ` + filepath.Join(dir, "root") + `
listen: {main: {addr: "127.0.0.1:0", tls: {mode: self, cert: ` + filepath.Join(dir, "tls/c.crt") + `, key: ` + filepath.Join(dir, "tls/c.key") + `, host: lukd.vm}}}
endpoint:
  backup: {listen: main, endpoint: /backup, path: q/backup, allow: [robert.socha]}
pipeline:
  archive: {endpoint: [backup], steps: [{store: archive}]}
storage:
  archive: {type: local, base: s/archive, path: "{{ .File }}"}
gpg: {keys: ` + filepath.Join(dir, "gpg") + `}
`
	for _, f := range []struct {
		path, body string
	}{
		{"config.yaml", text},
		{"config.d/log.yaml", "log: {level: info}\n"},
		{"ssh.d/robert.socha.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha\n"},
		{"tls/c.crt", "cert"},
		{"tls/c.key", "key"},
		{"gpg/a.asc", "key"},
	} {
		p := filepath.Join(dir, f.path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// fakeUser makes luk a user that is not the owner of the test files, in
// the group of the files when inGroup.
func fakeUser(t *testing.T, inGroup bool) {
	t.Helper()
	old := lookupUser
	t.Cleanup(func() { lookupUser = old })
	lookupUser = func(name string) (int, []int, error) {
		if name != "luk" {
			return 0, nil, errors.New("unknown user " + name)
		}
		gids := []int{os.Getgid() + 1000}
		if inGroup {
			gids = append(gids, os.Getgid())
		}
		return os.Getuid() + 1000, gids, nil
	}
}

func readProblems(t *testing.T, dir string) string {
	t.Helper()
	cfg, err := config.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, err := range checkReadable(cfg, "luk") {
		lines = append(lines, err.Error())
	}
	return strings.Join(lines, "\n")
}

func TestCheckReadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the permission math is not exercised as root's own files")
	}
	dir := readableDir(t)
	fakeUser(t, false)
	if got := readProblems(t, dir); got != "" {
		t.Fatalf("all readable: %s", got)
	}
	cfg, _ := config.Load(filepath.Join(dir, "config.yaml"))
	files, dirs := inputs(cfg)
	for _, want := range []string{"config.yaml", "config.d/log.yaml", "ssh.d/robert.socha.pub", "tls/c.crt", "tls/c.key", "gpg/a.asc"} {
		if !strings.Contains(strings.Join(files, " "), filepath.Join(dir, want)) {
			t.Errorf("inputs lack %s: %v", want, files)
		}
	}
	if !strings.Contains(strings.Join(dirs, " "), filepath.Join(dir, "ssh.d")) || strings.Contains(strings.Join(dirs, " "), "ssh.d/ca") {
		t.Errorf("dirs %v", dirs)
	}

	for _, c := range []struct {
		path string
		mode os.FileMode
		want string
	}{
		{"ssh.d/robert.socha.pub", 0o640, "ssh.d/robert.socha.pub: not readable by luk"},
		{"tls/c.key", 0o600, "tls/c.key: not readable by luk"},
		{"config.d/log.yaml", 0o640, "config.d/log.yaml: not readable by luk"},
		{"gpg", 0o750, "gpg: not readable by luk"},
		{"tls", 0o754, "tls: not searchable by luk"},
	} {
		p := filepath.Join(dir, c.path)
		fi, _ := os.Stat(p)
		if err := os.Chmod(p, c.mode); err != nil {
			t.Fatal(err)
		}
		got := readProblems(t, dir)
		if !strings.Contains(got, filepath.Join(dir, c.want)) {
			t.Errorf("%s %o: %q", c.path, c.mode, got)
		}
		if c.mode&0o040 != 0 {
			fakeUser(t, true)
			if got := readProblems(t, dir); got != "" {
				t.Errorf("%s in the group: %q", c.path, got)
			}
			fakeUser(t, false)
		}
		os.Chmod(p, fi.Mode().Perm())
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := readProblems(t, dir); !strings.Contains(got, dir+": not searchable by luk") {
		t.Errorf("config dir: %q", got)
	}
	os.Chmod(dir, 0o755)
}

func TestCheckCommandReadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the permission math is not exercised as root's own files")
	}
	dir := readableDir(t)
	fakeUser(t, false)
	key := filepath.Join(dir, "tls/c.key")
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	writeIdentity(t, cfg)
	// Not root: skipped.
	if out, errOut, err := runCheck(t, "-c", cfg, "--no-running"); err != nil || out != "ok\n" {
		t.Fatalf("not root: %q %q %v", out, errOut, err)
	}
	old := geteuid
	geteuid = func() int { return 0 }
	defer func() { geteuid = old }()
	out, errOut, err := runCheck(t, "-c", cfg, "--no-running")
	var code exitCode
	if !errors.As(err, &code) || code != 1 || out != "" || !strings.Contains(errOut, key+": not readable by luk") {
		t.Fatalf("root: %q %q %v", out, errOut, err)
	}
	if _, errOut, err := runCheck(t, "-c", cfg, "--no-running", "--user", "nobody-here"); err == nil || !strings.Contains(errOut, "service user nobody-here") {
		t.Fatalf("unknown user: %q %v", errOut, err)
	}
	os.Chmod(key, 0o644)
	// The identity key is 0640: the service user reads it as a group member.
	fakeUser(t, true)
	if out, _, err := runCheck(t, "-c", cfg, "--no-running"); err != nil || out != "ok\n" {
		t.Fatalf("fixed: %q %v", out, err)
	}
}
