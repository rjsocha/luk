package workspace

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLeftoverCount(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	if c, err := ReadCount(filepath.Join(dir, CountName)); c != nil || err != nil {
		t.Fatalf("missing file: %v %v", c, err)
	}
	if err := AddLeftover(dir, now); err != nil {
		t.Fatal(err)
	}
	if err := AddLeftover(dir, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	c, err := ReadCount(filepath.Join(dir, CountName))
	if err != nil || c.Leftover != 2 || c.Updated != "2026-10-06T12:01:00Z" {
		t.Fatalf("%+v %v", c, err)
	}
	fi, _ := os.Stat(filepath.Join(dir, CountName))
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if err := SetLeftover(dir, 2, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if c, _ := ReadCount(filepath.Join(dir, CountName)); c.Updated != "2026-10-06T12:01:00Z" {
		t.Fatalf("unchanged count rewritten: %+v", c)
	}
	SetLeftover(dir, 0, now.Add(time.Hour))
	if c, _ := ReadCount(filepath.Join(dir, CountName)); c.Leftover != 0 || c.Updated != "2026-10-06T13:00:00Z" {
		t.Fatalf("%+v", c)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Fatalf("left in dir: %v", ents)
	}
}

func TestSetLeftoverWritesMissingCount(t *testing.T) {
	dir := t.TempDir()
	if err := SetLeftover(dir, 0, time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if c, err := ReadCount(filepath.Join(dir, CountName)); err != nil || c == nil || c.Leftover != 0 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestCountRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(t.TempDir(), "x")
	os.WriteFile(other, []byte(`{"leftover":1,"updated":"x"}`), 0o600)
	os.Symlink(other, filepath.Join(dir, CountName))
	if _, err := ReadCount(filepath.Join(dir, CountName)); err == nil {
		t.Fatal("ReadCount followed a symlink")
	}
	if err := AddLeftover(dir, time.Now()); err == nil {
		t.Fatal("AddLeftover followed a symlink")
	}
	os.Remove(filepath.Join(dir, CountName))
	os.Remove(filepath.Join(dir, LockName))
	os.Symlink(other, filepath.Join(dir, LockName))
	if err := AddLeftover(dir, time.Now()); err == nil {
		t.Fatal("AddLeftover locked through a symlink")
	}
}
