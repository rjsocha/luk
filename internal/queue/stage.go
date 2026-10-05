package queue

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Stage is an entry received in parts: they land at their offsets in
// <dir>/<id>/.payload.tmp in any order, and the sha256 of the whole grows
// over the contiguous prefix of the parts marked complete. Finish turns
// it into a received entry, Abort removes it. Writes may run
// concurrently; the bookkeeping is guarded.
type Stage struct {
	Entry Entry
	q     *Queue
	f     *os.File
	tmp   string
	// size is the size of a file, -1 for a stream.
	size int64
	res  *Reservation

	mu sync.Mutex
	// prefix is the length hashed so far: every byte before it is
	// complete.
	prefix int64
	sum    hash.Hash
	// early are the complete ranges past the prefix, by offset.
	early map[int64]int64
	// allocated marks a file whose space was taken at once; otherwise
	// the reservation is consumed as bytes land.
	allocated  bool
	sinceCheck int64
	closed     bool
}

// Stage creates the staging file of the entry <dir>/<id>: a file of size
// bytes (preallocated where the filesystem can), or a stream (size -1).
// The reservation res, held for the stage, is released by Finish or Abort.
func (q *Queue) Stage(dir, id string, size int64, res *Reservation) (st *Stage, err error) {
	if !validID(id) {
		return nil, errors.New("queue: invalid id")
	}
	if size < -1 {
		return nil, errors.New("queue: negative size")
	}
	edir := filepath.Join(dir, id)
	if err = os.Mkdir(edir, 0o750); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(edir)
			err = mapErr(err)
		}
	}()
	tmp := filepath.Join(edir, ".payload.tmp")
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return nil, err
	}
	st = &Stage{Entry: Entry{Dir: edir, ID: id}, q: q, f: f, tmp: tmp, size: size, res: res, sum: sha256.New(), early: map[int64]int64{}}
	if size > 0 {
		allocated, err := allocate(f, size)
		if err != nil {
			f.Close()
			return nil, err
		}
		if allocated {
			st.allocated = true
			res.Consume(size)
		}
	}
	return st, nil
}

// allocate gives f its size, taking the space at once where the
// filesystem can (true), else as a sparse file.
func allocate(f *os.File, size int64) (bool, error) {
	if preallocate(f, size) == nil {
		return true, nil
	}
	return false, f.Truncate(size)
}

// inBounds checks the range [off, off+n) against the size of a file.
func (st *Stage) inBounds(off, n int64) error {
	if off < 0 || n < 0 || (st.size >= 0 && off+n > st.size) {
		return fmt.Errorf("%w: range %d+%d outside %d bytes", ErrTooLarge, off, n, st.size)
	}
	return nil
}

// WriteAt writes p at off. A stream checks the free space before its
// first write and then every checkEvery bytes, as Receive does.
func (st *Stage) WriteAt(p []byte, off int64) error {
	if err := st.inBounds(off, int64(len(p))); err != nil {
		return err
	}
	st.mu.Lock()
	check := st.size < 0 && (st.sinceCheck == 0 || st.sinceCheck >= checkEvery)
	if check {
		st.sinceCheck = 0
	}
	st.sinceCheck += int64(len(p))
	closed := st.closed
	st.mu.Unlock()
	if closed {
		return os.ErrClosed
	}
	if check {
		if err := st.q.checkFree(filepath.Dir(st.Entry.Dir)); err != nil {
			return err
		}
	}
	if _, err := st.f.WriteAt(p, off); err != nil {
		return mapErr(err)
	}
	if !st.allocated {
		st.res.Consume(int64(len(p)))
	}
	return nil
}

// Advance marks [off, off+n) complete: its bytes are written and final.
// The hash extends over the contiguous prefix, reading back the ranges
// that came before it.
func (st *Stage) Advance(off, n int64) error {
	if err := st.inBounds(off, n); err != nil {
		return err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return os.ErrClosed
	}
	if off < st.prefix {
		return fmt.Errorf("queue: range %d+%d already complete", off, n)
	}
	st.early[off] = n
	for {
		l, ok := st.early[st.prefix]
		if !ok {
			return nil
		}
		delete(st.early, st.prefix)
		if _, err := io.Copy(st.sum, io.NewSectionReader(st.f, st.prefix, l)); err != nil {
			return err
		}
		st.prefix += l
	}
}

// Finish ends a stage of size bytes: every byte hashed, the sha256 equal
// to sha when given (else ErrMismatch), then the staging file becomes the
// read-only payload of the entry, synced. It returns the size and the
// sha256. On an error the stage stays for Abort.
func (st *Stage) Finish(size int64, sha string) (int64, string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return 0, "", os.ErrClosed
	}
	if size < 0 || st.prefix != size || len(st.early) > 0 || (st.size >= 0 && size != st.size) {
		return 0, "", fmt.Errorf("%w: %d bytes complete of %d", ErrMismatch, st.prefix, size)
	}
	got := hex.EncodeToString(st.sum.Sum(nil))
	if sha != "" && !strings.EqualFold(sha, got) {
		return 0, "", ErrMismatch
	}
	// A stream may hold the bytes of a longer attempt at its last part.
	err := st.f.Truncate(size)
	if err == nil {
		err = st.f.Chmod(0o440)
	}
	if err == nil {
		err = st.f.Sync()
	}
	if err != nil {
		return 0, "", mapErr(err)
	}
	st.closed = true
	err = st.f.Close()
	if err == nil {
		err = os.Rename(st.tmp, filepath.Join(st.Entry.Dir, "payload"))
	}
	if err == nil {
		err = syncDir(st.Entry.Dir)
	}
	st.res.Release()
	if err != nil {
		os.RemoveAll(st.Entry.Dir)
		return 0, "", mapErr(err)
	}
	return size, got, nil
}

// Abort removes the stage and releases its reservation; it is
// idempotent and safe after Finish failed.
func (st *Stage) Abort() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.res.Release()
	if !st.closed {
		st.closed = true
		st.f.Close()
	}
	os.RemoveAll(st.Entry.Dir)
}
