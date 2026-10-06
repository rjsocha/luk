package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"luk/internal/config"
)

func TestOwnerDecision(t *testing.T) {
	for _, c := range []struct {
		uid, owner int
		reexeced   bool
		want       ownerAction
	}{
		{0, 997, false, ownerReexec},
		{0, 997, true, ownerDeny},
		{997, 997, false, ownerRun},
		{997, 997, true, ownerRun},
		{0, 0, false, ownerRun},
		{1000, 997, false, ownerDeny},
		{1000, 0, false, ownerDeny},
	} {
		if got := ownerDecision(c.uid, c.owner, c.reexeced); got != c.want {
			t.Errorf("uid %d owner %d reexeced %v: %v, want %v", c.uid, c.owner, c.reexeced, got, c.want)
		}
	}
}

func TestAsOwnerNotOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	err := asOwner("lukd queue", "/")
	if err == nil || !strings.Contains(err.Error(), "lukd queue must run as root or as root (owner of /)") {
		t.Fatalf("%v", err)
	}
}

// A symlink in place of the directory is refused before its owner decides
// anything: the service user owns the parent and could point it at a
// directory root owns.
func TestAsOwnerRefusesSymlink(t *testing.T) {
	link := filepath.Join(t.TempDir(), "acme")
	if err := os.Symlink("/usr", link); err != nil {
		t.Fatal(err)
	}
	old, oldRe := geteuid, reexecAs
	defer func() { geteuid, reexecAs = old, oldRe }()
	geteuid = func() int { return 0 }
	reexecAs = func(uint32, uint32, []uint32) error { t.Fatal("reexec"); return nil }
	err := asOwner("lukd tls acme", link)
	if err == nil || err.Error() != "lukd tls acme: "+link+" is a symlink" {
		t.Fatalf("%v", err)
	}
}

func TestAsServiceUserRefusesSymlinkedData(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, "data")); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Root: root}
	err := asServiceUser("lukd queue", cfg)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(root, "data")+" is a symlink") {
		t.Fatalf("got %v", err)
	}
}

func TestAsServiceUserNamesData(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "data"), 0o750)
	geteuid = func() int { return 4242 }
	t.Cleanup(func() { geteuid = os.Geteuid })
	err := asServiceUser("lukd queue", &config.Config{Root: root})
	if err == nil || !strings.Contains(err.Error(), "(owner of "+filepath.Join(root, "data")+")") {
		t.Fatalf("got %v", err)
	}
}
