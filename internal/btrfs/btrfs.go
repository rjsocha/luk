// Package btrfs is the part of the btrfs ioctl interface lukd uses for
// the workspaces of lukd run: the filesystem magic, subvolume create,
// the id of a subvolume, its nested subvolumes from the tree of tree
// roots, destroy by id, and FICLONE. The structs mirror
// include/uapi/linux/btrfs.h; nothing runs btrfs-progs.
package btrfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	SuperMagic  = unix.BTRFS_SUPER_MAGIC
	SubvolInode = 256

	ioctlMagic       = 0x94
	iocWrite         = 1
	iocRead          = 2
	subvolNameMax    = 4039
	subvolSpecByID   = 1 << 4
	rootTreeObjectID = 1
	rootRefKey       = 156
	rootBackrefKey   = 144
	searchBufSize    = 4096 - 104
)

func ioc(dir, nr, size uintptr) uintptr { return dir<<30 | size<<16 | ioctlMagic<<8 | nr }

type volArgsV2 struct {
	Fd      int64
	Transid uint64
	Flags   uint64
	Unused  [4]uint64
	// Name is the name of the subvolume, or its id in the first 8 bytes
	// with subvolSpecByID.
	Name [4040]byte
}

type searchKey struct {
	TreeID, MinObjectID, MaxObjectID, MinOffset, MaxOffset, MinTransid, MaxTransid uint64
	MinType, MaxType, NrItems, unused                                              uint32
	unused1, unused2, unused3, unused4                                             uint64
}

type searchArgs struct {
	Key searchKey
	Buf [searchBufSize]byte
}

type searchHeader struct {
	Transid, ObjectID, Offset uint64
	Type, Len                 uint32
}

type inoLookupArgs struct {
	TreeID, ObjectID uint64
	Name             [4080]byte
}

var (
	iocSubvolCreateV2 = ioc(iocWrite, 24, unsafe.Sizeof(volArgsV2{}))
	iocSnapDestroyV2  = ioc(iocWrite, 63, unsafe.Sizeof(volArgsV2{}))
	iocTreeSearch     = ioc(iocWrite|iocRead, 17, unsafe.Sizeof(searchArgs{}))
	iocInoLookup      = ioc(iocWrite|iocRead, 18, unsafe.Sizeof(inoLookupArgs{}))
)

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if e != 0 {
		return e
	}
	return nil
}

func (a *volArgsV2) setName(name string) error {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") || len(name) > subvolNameMax {
		return fmt.Errorf("subvolume name %q: invalid", name)
	}
	copy(a.Name[:], name)
	return nil
}

func IsBtrfs(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	return uint32(st.Type) == SuperMagic, nil
}

func IsBtrfsFd(fd int) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		return false, err
	}
	return uint32(st.Type) == SuperMagic, nil
}

func IsSubvolume(fd int) (bool, error) {
	ok, err := IsBtrfsFd(fd)
	if err != nil || !ok {
		return false, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false, err
	}
	return st.Ino == SubvolInode && st.Mode&unix.S_IFMT == unix.S_IFDIR, nil
}

func CreateSubvolume(parentFd int, name string) error {
	var a volArgsV2
	if err := a.setName(name); err != nil {
		return err
	}
	if err := ioctl(parentFd, iocSubvolCreateV2, unsafe.Pointer(&a)); err != nil {
		return fmt.Errorf("create subvolume %s: %w", name, err)
	}
	return nil
}

// SubvolumeID is the id of the subvolume fd lies in. The lookup of inode
// 256 in tree 0 needs no capability.
func SubvolumeID(fd int) (uint64, error) {
	a := inoLookupArgs{ObjectID: SubvolInode}
	if err := ioctl(fd, iocInoLookup, unsafe.Pointer(&a)); err != nil {
		return 0, fmt.Errorf("subvolume id: %w", err)
	}
	return a.TreeID, nil
}

// Children are the ids of the subvolumes directly inside parent: the
// offsets of its ROOT_REF items in the tree of tree roots. Needs
// CAP_SYS_ADMIN.
func Children(fd int, parent uint64) ([]uint64, error) {
	var out []uint64
	min := uint64(0)
	for {
		a := searchArgs{Key: searchKey{
			TreeID: rootTreeObjectID, MinObjectID: parent, MaxObjectID: parent,
			MinOffset: min, MaxOffset: math.MaxUint64, MaxTransid: math.MaxUint64,
			MinType: rootRefKey, MaxType: rootRefKey, NrItems: 4096,
		}}
		if err := ioctl(fd, iocTreeSearch, unsafe.Pointer(&a)); err != nil {
			return nil, fmt.Errorf("tree search: %w", err)
		}
		if a.Key.NrItems == 0 {
			return out, nil
		}
		ids, last, err := parseRootRefs(a.Buf[:], a.Key.NrItems)
		if err != nil {
			return nil, err
		}
		out = append(out, ids...)
		if last == math.MaxUint64 {
			return out, nil
		}
		min = last + 1
	}
}

// parseRootRefs reads n search results from buf: the offsets of the
// ROOT_REF items (the child ids) and the offset of the last item.
func parseRootRefs(buf []byte, n uint32) (ids []uint64, last uint64, err error) {
	off := 0
	for range n {
		if off+32 > len(buf) {
			return nil, 0, errors.New("tree search: truncated result")
		}
		h := searchHeader{
			ObjectID: binary.NativeEndian.Uint64(buf[off+8:]),
			Offset:   binary.NativeEndian.Uint64(buf[off+16:]),
			Type:     binary.NativeEndian.Uint32(buf[off+24:]),
			Len:      binary.NativeEndian.Uint32(buf[off+28:]),
		}
		off += 32 + int(h.Len)
		if off > len(buf) {
			return nil, 0, errors.New("tree search: truncated item")
		}
		if h.Type == rootRefKey {
			ids = append(ids, h.Offset)
		}
		last = h.Offset
	}
	return ids, last, nil
}

func Descendants(fd int, id uint64) ([]uint64, error) {
	return leavesFirst(id, func(p uint64) ([]uint64, error) { return Children(fd, p) })
}

// leavesFirst lists every subvolume below id, each after the ones inside
// it, so destroying them in order never meets a non-empty one.
func leavesFirst(id uint64, children func(uint64) ([]uint64, error)) ([]uint64, error) {
	var out []uint64
	seen := map[uint64]bool{id: true}
	var walk func(uint64) error
	walk = func(p uint64) error {
		cs, err := children(p)
		if err != nil {
			return err
		}
		for _, c := range cs {
			if seen[c] {
				return fmt.Errorf("subvolume %d: seen twice", c)
			}
			seen[c] = true
			if err := walk(c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return nil
	}
	return out, walk(id)
}

// DestroyByID deletes the subvolume id of the filesystem of fd. Needs
// CAP_SYS_ADMIN; a subvolume still mounted somewhere gives EBUSY.
func DestroyByID(fd int, id uint64) error {
	a := volArgsV2{Flags: subvolSpecByID}
	binary.NativeEndian.PutUint64(a.Name[:8], id)
	if err := ioctl(fd, iocSnapDestroyV2, unsafe.Pointer(&a)); err != nil {
		return fmt.Errorf("destroy subvolume %d: %w", id, err)
	}
	return nil
}
