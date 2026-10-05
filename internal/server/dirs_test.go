package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"luk/internal/config"
)

func dirsConfig(root string) *config.Config {
	return &config.Config{
		Root: root,
		Listen: map[string]*config.Listen{"l": {Addr: ":1", TLS: &config.TLS{Mode: "self",
			Cert: filepath.Join(root, "tls", "tls.crt"),
			Key:  filepath.Join(root, "tls", "tls.key"),
		}}},
		Endpoint: map[string]*config.Endpoint{"b": {Path: filepath.Join(root, "queue", "b")}},
		Storage: map[string]*config.Storage{
			"a": {Type: "local", Base: filepath.Join(root, "storage", "a")},
			"s": {Type: "s3", Bucket: "x"},
		},
	}
}

func TestPrepareDirsCreates(t *testing.T) {
	root := t.TempDir()
	if err := prepareDirs(dirsConfig(root), "receive"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"queue/b", "storage/a", "storage/a/.db", "storage/a/file", "tls", "work", "gpg-cache"} {
		fi, err := os.Stat(filepath.Join(root, d))
		if err != nil || !fi.IsDir() {
			t.Fatalf("%s not created: %v", d, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o750 {
			t.Errorf("%s mode %o", d, perm)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "storage", "s")); err == nil {
		t.Error("s3 storage got a directory")
	}
}

func TestPrepareDirsNotADirectory(t *testing.T) {
	root := t.TempDir()
	cfg := dirsConfig(root)
	file := filepath.Join(root, "queue-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Endpoint["b"].Path = file
	if err := prepareDirs(cfg, "receive"); err == nil || !strings.Contains(err.Error(), file) {
		t.Fatalf("err = %v", err)
	}
}

func TestPrepareDirsOldLayout(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "storage", "a")
	if err := os.MkdirAll(filepath.Join(base, ".luk"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "x"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	err := prepareDirs(dirsConfig(root), "receive")
	if err == nil || !strings.Contains(err.Error(), "storage a: "+base+": holds .luk, x besides .db/ and file/") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "file")); !os.IsNotExist(err) {
		t.Fatalf("data tree created in an old base: %v", err)
	}
}

func TestPrepareDirsUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	cfg := dirsConfig(root)
	cfg.Storage["a"].Base = locked
	err := prepareDirs(cfg, "receive")
	if err == nil || !strings.Contains(err.Error(), locked) || !strings.Contains(err.Error(), "ReadWritePaths") {
		t.Fatalf("err = %v", err)
	}
}

func TestPrepareDirsUnreadableTLS(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	root := t.TempDir()
	cfg := dirsConfig(root)
	if err := os.MkdirAll(filepath.Join(root, "tls"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Listen["l"].TLS.Key, nil, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := prepareDirs(cfg, "receive"); err == nil || !strings.Contains(err.Error(), cfg.Listen["l"].TLS.Key) {
		t.Fatalf("err = %v", err)
	}
}
