package btrfs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func cloneFiles(t *testing.T, data []byte) (src, dst *os.File) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "src")
	if err := os.WriteFile(p, data, 0o400); err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	dst, err = os.OpenFile(filepath.Join(dir, "dst"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close(); dst.Close() })
	return src, dst
}

func content(t *testing.T, f *os.File) []byte {
	t.Helper()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCloneCopiesWhenCloneUnsupported(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 70000) // over 1 MiB
	for _, e := range []error{unix.EXDEV, unix.EOPNOTSUPP, unix.EINVAL} {
		ficlone = func(int, int) error { return e }
		src, dst := cloneFiles(t, data)
		if err := Clone(dst, src); err != nil {
			t.Fatalf("%v: %v", e, err)
		}
		if !bytes.Equal(content(t, dst), data) {
			t.Fatalf("%v: content differs", e)
		}
	}
	ficlone = unix.IoctlFileClone
}

func TestCloneReturnsOtherErrors(t *testing.T) {
	ficlone = func(int, int) error { return unix.EBADF }
	t.Cleanup(func() { ficlone = unix.IoctlFileClone })
	src, dst := cloneFiles(t, []byte("x"))
	if err := Clone(dst, src); !errors.Is(err, unix.EBADF) {
		t.Fatalf("got %v", err)
	}
}

// The descriptor of a received file shares its offset with the sender:
// a copy must not move it.
func TestCloneKeepsSourceOffset(t *testing.T) {
	ficlone = func(int, int) error { return unix.EOPNOTSUPP }
	t.Cleanup(func() { ficlone = unix.IoctlFileClone })
	src, dst := cloneFiles(t, []byte("abcdefgh"))
	if _, err := src.Seek(3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := Clone(dst, src); err != nil {
		t.Fatal(err)
	}
	if off, _ := src.Seek(0, io.SeekCurrent); off != 3 {
		t.Fatalf("offset %d", off)
	}
	if got := content(t, dst); string(got) != "abcdefgh" {
		t.Fatalf("%q", got)
	}
}

func TestCloneEmpty(t *testing.T) {
	src, dst := cloneFiles(t, nil)
	if err := Clone(dst, src); err != nil {
		t.Fatal(err)
	}
	if len(content(t, dst)) != 0 {
		t.Fatal("not empty")
	}
}

func placeDir(t *testing.T) *os.File {
	t.Helper()
	d, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func srcFile(t *testing.T, data string) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// names lists the entries of dir.
func names(t *testing.T, dir *os.File) []string {
	t.Helper()
	es, err := os.ReadDir(dir.Name())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestPlace(t *testing.T) {
	d := placeDir(t)
	if err := Place(d, "a.txt", srcFile(t, "hello"), 0o440, true); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d.Name(), "a.txt")
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != 0o440 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if b, _ := os.ReadFile(p); string(b) != "hello" {
		t.Fatalf("%q", b)
	}
	if n := names(t, d); !slices.Equal(n, []string{"a.txt"}) {
		t.Fatalf("entries %v", n)
	}
}

func TestPlaceNoReplace(t *testing.T) {
	d := placeDir(t)
	p := filepath.Join(d.Name(), "a")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Place(d, "a", srcFile(t, "new"), 0o400, true); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("got %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Fatalf("replaced: %q", b)
	}
	if n := names(t, d); !slices.Equal(n, []string{"a"}) {
		t.Fatalf("temporary file left: %v", n)
	}
	if err := Place(d, "a", srcFile(t, "new"), 0o400, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Fatalf("not replaced: %q", b)
	}
}

func TestPlaceRemovesTemporaryOnFailure(t *testing.T) {
	ficlone = func(int, int) error { return unix.EBADF }
	t.Cleanup(func() { ficlone = unix.IoctlFileClone })
	d := placeDir(t)
	if err := Place(d, "a", srcFile(t, "x"), 0o400, true); !errors.Is(err, unix.EBADF) {
		t.Fatalf("got %v", err)
	}
	if n := names(t, d); len(n) != 0 {
		t.Fatalf("entries %v", n)
	}
}

func TestPlaceName(t *testing.T) {
	d := placeDir(t)
	for _, name := range []string{"", ".", "..", "a/b", "../a"} {
		if err := Place(d, name, srcFile(t, "x"), 0o400, true); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}
