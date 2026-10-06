package btrfs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestLayout(t *testing.T) {
	for _, x := range []struct {
		what      string
		got, want uintptr
	}{
		{"vol_args_v2", unsafe.Sizeof(volArgsV2{}), 4096},
		{"search_key", unsafe.Sizeof(searchKey{}), 104},
		{"search_args", unsafe.Sizeof(searchArgs{}), 4096},
		{"search_header", unsafe.Sizeof(searchHeader{}), 32},
		{"ino_lookup_args", unsafe.Sizeof(inoLookupArgs{}), 4096},
	} {
		if x.got != x.want {
			t.Errorf("%s: %d bytes, want %d", x.what, x.got, x.want)
		}
	}
	for _, x := range []struct {
		what      string
		got, want uintptr
	}{
		{"SUBVOL_CREATE_V2", iocSubvolCreateV2, 0x50009418},
		{"SNAP_DESTROY_V2", iocSnapDestroyV2, 0x5000943f},
		{"TREE_SEARCH", iocTreeSearch, 0xd0009411},
		{"INO_LOOKUP", iocInoLookup, 0xd0009412},
	} {
		if x.got != x.want {
			t.Errorf("%s: %#x, want %#x", x.what, x.got, x.want)
		}
	}
}

func TestSubvolumeName(t *testing.T) {
	for name, ok := range map[string]bool{
		"lukd-run-x-0123456789ab":  true,
		"":                         false,
		".":                        false,
		"..":                       false,
		"a/b":                      false,
		string(make([]byte, 4040)): false,
	} {
		var a volArgsV2
		if err := a.setName(name); (err == nil) != ok {
			t.Errorf("%q: %v", name, err)
		}
	}
}

// item appends one search result: header and an item body of n bytes.
func item(b []byte, objectid, typ, offset uint64, n int) []byte {
	h := make([]byte, 32)
	binary.NativeEndian.PutUint64(h[8:], objectid)
	binary.NativeEndian.PutUint64(h[16:], offset)
	binary.NativeEndian.PutUint32(h[24:], uint32(typ))
	binary.NativeEndian.PutUint32(h[28:], uint32(n))
	return append(append(b, h...), make([]byte, n)...)
}

func TestParseRootRefs(t *testing.T) {
	var buf []byte
	buf = item(buf, 300, rootRefKey, 301, 20)
	buf = item(buf, 300, rootBackrefKey, 299, 10)
	buf = item(buf, 300, rootRefKey, 305, 0)
	ids, last, err := parseRootRefs(buf, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids, []uint64{301, 305}) || last != 305 {
		t.Fatalf("ids %v last %d", ids, last)
	}
	if _, _, err := parseRootRefs(buf[:40], 2); err == nil {
		t.Fatal("truncated buffer accepted")
	}
}

func TestLeavesFirst(t *testing.T) {
	tree := map[uint64][]uint64{1: {2, 3}, 2: {4}, 4: {5}, 3: nil}
	got, err := leavesFirst(1, func(id uint64) ([]uint64, error) { return tree[id], nil })
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []uint64{5, 4, 2, 3}) {
		t.Fatalf("%v", got)
	}
	loop := map[uint64][]uint64{1: {2}, 2: {1}}
	if _, err := leavesFirst(1, func(id uint64) ([]uint64, error) { return loop[id], nil }); err == nil {
		t.Fatal("cycle accepted")
	}
}

func TestIsBtrfsMissing(t *testing.T) {
	if _, err := IsBtrfs(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("no error for a missing path")
	}
}

// btrfsDir is the opt-in test directory on btrfs: LUK_TEST_BTRFS, as root.
func btrfsDir(t *testing.T) string {
	t.Helper()
	d := os.Getenv("LUK_TEST_BTRFS")
	if d == "" {
		t.Skip("LUK_TEST_BTRFS not set")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	return d
}

func TestSubvolumesOnBtrfs(t *testing.T) {
	dir, err := os.MkdirTemp(btrfsDir(t), "luk-btrfs-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := CreateSubvolume(int(d.Fd()), "ws"); err != nil {
		t.Fatal(err)
	}
	ws, err := os.Open(filepath.Join(dir, "ws"))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if ok, err := IsSubvolume(int(ws.Fd())); !ok || err != nil {
		t.Fatalf("subvolume %v %v", ok, err)
	}
	if err := CreateSubvolume(int(ws.Fd()), "inner"); err != nil {
		t.Fatal(err)
	}
	inner, _ := os.Open(filepath.Join(dir, "ws", "inner"))
	if err := CreateSubvolume(int(inner.Fd()), "leaf"); err != nil {
		t.Fatal(err)
	}
	inner.Close()
	id, err := SubvolumeID(int(ws.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	ds, err := Descendants(int(ws.Fd()), id)
	if err != nil || len(ds) != 2 {
		t.Fatalf("descendants %v %v", ds, err)
	}
	for _, x := range append(ds, id) {
		if err := DestroyByID(int(d.Fd()), x); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "ws")); !os.IsNotExist(err) {
		t.Fatalf("workspace left: %v", err)
	}
	if ok, _ := IsBtrfs(dir); !ok {
		t.Fatal("LUK_TEST_BTRFS is not on btrfs")
	}
	_ = unix.BTRFS_SUPER_MAGIC
}
