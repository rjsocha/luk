package status

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func aliveRoot(t *testing.T, role string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(RoleDir(root, role), 0o750); err != nil {
		t.Fatal(err)
	}
	return root
}

func inode(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func TestStartAliveWritesAtomically(t *testing.T) {
	root := aliveRoot(t, "receive")
	dir := RoleDir(root, "receive")
	left := filepath.Join(dir, ".alive.json.tmp-123")
	if err := os.WriteFile(left, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	synced := false
	defer func(f func(*os.File) error) { syncDir = f }(syncDir)
	syncDir = func(d *os.File) error {
		if d.Name() != dir {
			t.Errorf("synced %s", d.Name())
		}
		synced = true
		return nil
	}
	var renamed [2]string
	defer func(f func(string, string) error) { rename = f }(rename)
	rename = func(from, to string) error {
		renamed = [2]string{from, to}
		return os.Rename(from, to)
	}
	a, err := StartAlive(root, "receive", "1.2.3", t0)
	if err != nil {
		t.Fatal(err)
	}
	if a.Path() != AlivePath(root, "receive") || renamed[1] != a.Path() || filepath.Dir(renamed[0]) != dir || !synced {
		t.Fatalf("path %s, renamed %v, dir synced %v", a.Path(), renamed, synced)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "alive.json" {
		t.Fatalf("dir: %v", ents)
	}
	fi, _ := os.Stat(a.Path())
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
	b, _ := os.ReadFile(a.Path())
	var got AliveInfo
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	want := AliveInfo{Role: "receive", PID: os.Getpid(), Started: "2026-09-30T12:00:00Z", Version: "1.2.3"}
	if got != want {
		t.Fatalf("%+v, want %+v", got, want)
	}
}

func TestStartAliveFailsWithoutDir(t *testing.T) {
	if _, err := StartAlive(t.TempDir(), "process", "dev", t0); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestBeatTouchesWithoutRewrite(t *testing.T) {
	root := aliveRoot(t, "process")
	a, err := StartAlive(root, "process", "dev", t0)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(a.Path())
	ino := inode(t, a.Path())
	defer func(f func(string, string) error) { rename = f }(rename)
	rename = func(string, string) error { t.Error("beat rewrote the file"); return nil }
	beat := t0.Add(time.Hour)
	if err := a.Beat(beat); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(a.Path())
	after, _ := os.ReadFile(a.Path())
	if !fi.ModTime().Equal(beat) || string(after) != string(before) || inode(t, a.Path()) != ino {
		t.Fatalf("mtime %v, content %q, inode changed %v", fi.ModTime(), after, inode(t, a.Path()) != ino)
	}
}

func TestBeatRecreatesDeleted(t *testing.T) {
	root := aliveRoot(t, "receive")
	a, err := StartAlive(root, "receive", "dev", t0)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(a.Path())
	if err := os.Remove(a.Path()); err != nil {
		t.Fatal(err)
	}
	beat := t0.Add(time.Minute)
	if err := a.Beat(beat); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(a.Path())
	after, _ := os.ReadFile(a.Path())
	if err != nil || !fi.ModTime().Equal(beat) || string(after) != string(before) {
		t.Fatalf("%v %v %q", err, fi, after)
	}
}
