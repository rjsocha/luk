package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLeftoverCount(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	if c, err := ReadCount(filepath.Join(dir, CountName)); c != nil || err != nil {
		t.Fatalf("missing file: %v %v", c, err)
	}
	if err := AddLeftover(dir, now, quiet); err != nil {
		t.Fatal(err)
	}
	if err := AddLeftover(dir, now.Add(time.Minute), quiet); err != nil {
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
	var dst, fst unix.Stat_t
	unix.Stat(dir, &dst)
	unix.Stat(filepath.Join(dir, CountName), &fst)
	if fst.Gid != dst.Gid {
		t.Fatalf("group %d, dir %d", fst.Gid, dst.Gid)
	}
	if err := SetLeftover(dir, 2, now.Add(time.Hour), quiet); err != nil {
		t.Fatal(err)
	}
	if c, _ := ReadCount(filepath.Join(dir, CountName)); c.Updated != "2026-10-06T12:01:00Z" {
		t.Fatalf("unchanged count rewritten: %+v", c)
	}
	if err := SetLeftover(dir, 0, now.Add(time.Hour), quiet); err != nil {
		t.Fatal(err)
	}
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
	if err := SetLeftover(dir, 0, time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC), quiet); err != nil {
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
	if err := AddLeftover(dir, time.Now(), quiet); err == nil {
		t.Fatal("AddLeftover followed a symlink")
	}
	os.Remove(filepath.Join(dir, CountName))
	os.Remove(filepath.Join(dir, LockName))
	os.Symlink(other, filepath.Join(dir, LockName))
	if err := AddLeftover(dir, time.Now(), quiet); err == nil {
		t.Fatal("AddLeftover locked through a symlink")
	}
}

func TestCorruptCount(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, CountName)
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for _, bad := range []string{"{", "not json", strings.Repeat(" ", 5000)} {
		os.WriteFile(p, []byte(bad), 0o640)
		if c, err := ReadCount(p); c != nil || !errors.Is(err, ErrCorruptCount) {
			t.Fatalf("%q: %v %v", bad, c, err)
		}
		if err := AddLeftover(dir, now, quiet); err != nil {
			t.Fatal(err)
		}
		if c, err := ReadCount(p); err != nil || c.Leftover != 1 {
			t.Fatalf("add over %q: %+v %v", bad, c, err)
		}
		os.WriteFile(p, []byte(bad), 0o640)
		if err := SetLeftover(dir, 3, now, quiet); err != nil {
			t.Fatal(err)
		}
		if c, err := ReadCount(p); err != nil || c.Leftover != 3 {
			t.Fatalf("set over %q: %+v %v", bad, c, err)
		}
	}
	os.Remove(p)
	os.Mkdir(p, 0o700)
	if _, err := ReadCount(p); !errors.Is(err, ErrCorruptCount) {
		t.Fatalf("directory: %v", err)
	}
}
