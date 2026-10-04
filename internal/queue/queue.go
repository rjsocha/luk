// Package queue receives upload bodies into per-endpoint directories.
package queue

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	ErrNoSpace  = errors.New("queue: not enough free space")
	ErrMismatch = errors.New("queue: size or sha256 mismatch")
	ErrTooLarge = errors.New("queue: body exceeds the size limit")
	// ErrNotSynced is a Commit whose meta.json is in place but whose
	// directories could not be synced: the entry is committed.
	ErrNotSynced = errors.New("queue: committed, directory not synced")
)

var checkEvery int64 = 64 << 20

const bufSize = 256 << 10

type Queue struct {
	reserve int64
	// dirReserve replaces reserve for the directories it lists.
	dirReserve map[string]int64
	freeSpace  func(dir string) (int64, error)

	mu       sync.Mutex
	reserved map[string]int64
}

type Entry struct{ Dir, ID string }

// FailedName is the directory in a queue directory holding failed entries;
// Pending and Cleanup skip it.
const FailedName = "failed"

// New returns a Queue keeping reserve bytes free; nil freeSpace uses statfs.
func New(reserve int64, freeSpace func(dir string) (int64, error)) *Queue {
	if freeSpace == nil {
		freeSpace = statfsFree
	}
	return &Queue{reserve: reserve, freeSpace: freeSpace, reserved: map[string]int64{}}
}

// SetReserve changes the free space kept from now on; reservations held
// stay.
func (q *Queue) SetReserve(reserve int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reserve = reserve
}

// SetDirReserves makes the free space kept for each directory of m its
// value instead of the reserve (the secret queues); reservations held stay.
func (q *Queue) SetDirReserves(m map[string]int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.dirReserve = m
}

// reserveOf is the free space kept for dir; q.mu held.
func (q *Queue) reserveOf(dir string) int64 {
	if r, ok := q.dirReserve[dir]; ok {
		return r
	}
	return q.reserve
}

// Reservation is space held for one upload; Consume shrinks it as bytes land.
type Reservation struct {
	q    *Queue
	key  string
	left int64
}

// Reserve holds size bytes on the filesystem of dir until Release is called.
func (q *Queue) Reserve(dir string, size int64) (*Reservation, error) {
	if size < 0 {
		return nil, errors.New("queue: negative size")
	}
	key := fsKey(dir)
	q.mu.Lock()
	defer q.mu.Unlock()
	free, err := q.freeSpace(dir)
	if err != nil {
		return nil, err
	}
	if free-q.reserved[key]-size < q.reserveOf(dir) {
		return nil, ErrNoSpace
	}
	q.reserved[key] += size
	return &Reservation{q: q, key: key, left: size}, nil
}

// Consume marks n reserved bytes as written to disk.
func (r *Reservation) Consume(n int64) {
	if r == nil {
		return
	}
	r.q.mu.Lock()
	defer r.q.mu.Unlock()
	if n > r.left {
		n = r.left
	}
	r.left -= n
	r.q.reserved[r.key] -= n
}

// Release frees what is still held; it is idempotent.
func (r *Reservation) Release() {
	if r == nil {
		return
	}
	r.q.mu.Lock()
	defer r.q.mu.Unlock()
	r.q.reserved[r.key] -= r.left
	r.left = 0
}

func fsKey(dir string) string {
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return "path:" + dir
	}
	return fmt.Sprintf("dev:%d", uint64(st.Dev))
}

func mapErr(err error) error {
	if err != nil && !errors.Is(err, ErrNoSpace) && errors.Is(err, syscall.ENOSPC) {
		return fmt.Errorf("%w: %w", ErrNoSpace, err)
	}
	return err
}

// idShape is the shape of the ids NewID makes.
var idShape = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)

// NewID is the id of an entry received at now: the UTC time and 8 random
// hex digits.
func NewID(now time.Time) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

// IsID reports whether s has the shape of an id made by NewID.
func IsID(s string) bool { return idShape.MatchString(s) }

func validID(id string) bool {
	return id != "" && id != "." && id != ".." && id != FailedName && filepath.Base(id) == id
}

// Receive streams body into <dir>/<id>/payload, read-only (0440) once
// accepted. max > 0 caps the body.
func (q *Queue) Receive(ctx context.Context, dir, id string, body io.Reader, max int64, signedSize *int64, signedSHA string, res *Reservation) (e Entry, size int64, sha string, err error) {
	if !validID(id) {
		err = errors.New("queue: invalid id")
		return
	}
	if signedSize != nil && *signedSize < 0 {
		err = errors.New("queue: negative signed size")
		return
	}
	edir := filepath.Join(dir, id)
	if err = os.Mkdir(edir, 0o750); err != nil {
		return
	}
	defer func() {
		err = mapErr(err)
		if err != nil {
			os.RemoveAll(edir)
		}
	}()
	tmp := filepath.Join(edir, ".payload.tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return
	}
	defer f.Close()

	src := body
	if signedSize != nil {
		src = io.LimitReader(body, *signedSize+1)
	}
	h := sha256.New()
	buf := make([]byte, bufSize)
	// An unsized body checks the free space before its first write and
	// then every checkEvery bytes.
	sinceCheck := checkEvery
	for {
		if err = ctx.Err(); err != nil {
			return
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if signedSize == nil && sinceCheck >= checkEvery {
				sinceCheck = 0
				if err = q.checkFree(dir); err != nil {
					return
				}
			}
			if _, err = f.Write(buf[:n]); err != nil {
				return
			}
			h.Write(buf[:n])
			size += int64(n)
			res.Consume(int64(n))
			if max > 0 && size > max {
				err = ErrTooLarge
				return
			}
			if signedSize != nil && size > *signedSize {
				err = ErrMismatch
				return
			}
			sinceCheck += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			err = rerr
			return
		}
	}
	sha = hex.EncodeToString(h.Sum(nil))
	if signedSize != nil && size != *signedSize {
		err = ErrMismatch
		return
	}
	if signedSHA != "" && !strings.EqualFold(signedSHA, sha) {
		err = ErrMismatch
		return
	}
	if err = f.Chmod(0o440); err != nil {
		return
	}
	if err = f.Sync(); err != nil {
		return
	}
	if err = f.Close(); err != nil {
		return
	}
	if err = os.Rename(tmp, filepath.Join(edir, "payload")); err != nil {
		return
	}
	if err = syncDir(edir); err != nil {
		return
	}
	return Entry{Dir: edir, ID: id}, size, sha, nil
}

// Link makes the entry <dir>/<id> with src as its payload, a hardlink
// instead of a received body. fi is src as the caller checked it: the
// link must be that file.
func (q *Queue) Link(dir, id, src string, fi os.FileInfo) (e Entry, err error) {
	if !validID(id) {
		return Entry{}, errors.New("queue: invalid id")
	}
	edir := filepath.Join(dir, id)
	if err = os.Mkdir(edir, 0o750); err != nil {
		return
	}
	defer func() {
		if err != nil {
			os.RemoveAll(edir)
		}
	}()
	tmp := filepath.Join(edir, ".payload.tmp")
	if err = os.Link(src, tmp); err != nil {
		return
	}
	got, err := os.Lstat(tmp)
	if err != nil {
		return
	}
	if !os.SameFile(got, fi) || !got.Mode().IsRegular() {
		err = fmt.Errorf("queue: %s changed", src)
		return
	}
	if err = os.Rename(tmp, filepath.Join(edir, "payload")); err != nil {
		return
	}
	if err = syncDir(edir); err != nil {
		return
	}
	return Entry{Dir: edir, ID: id}, nil
}

// checkFree fails with ErrNoSpace when the free space of dir, less what is
// reserved on its filesystem, is under the reserve.
func (q *Queue) checkFree(dir string) error {
	free, err := q.freeSpace(dir)
	if err != nil {
		return err
	}
	q.mu.Lock()
	held, reserve := q.reserved[fsKey(dir)], q.reserveOf(dir)
	q.mu.Unlock()
	if free-held < reserve {
		return ErrNoSpace
	}
	return nil
}

// Commit writes meta.json atomically; the entry is accepted once it exists.
// After the rename only ErrNotSynced can come back: the entry is committed.
func (q *Queue) Commit(e Entry, meta any) error {
	err := q.commit(e, meta)
	if errors.Is(err, ErrNotSynced) {
		return err
	}
	return mapErr(err)
}

func (q *Queue) commit(e Entry, meta any) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	tmp := filepath.Join(e.Dir, ".meta.tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err = os.Rename(tmp, filepath.Join(e.Dir, "meta.json")); err != nil {
		os.Remove(tmp)
		return err
	}
	if err = errors.Join(syncDir(e.Dir), syncDir(filepath.Dir(e.Dir))); err != nil {
		return fmt.Errorf("%w: %w", ErrNotSynced, err)
	}
	return nil
}

// Remove deletes the entry. meta.json goes first, so an entry removed only
// in part is never pending again (Cleanup takes the rest at the start).
func (q *Queue) Remove(e Entry) error {
	if err := os.Remove(filepath.Join(e.Dir, "meta.json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.RemoveAll(e.Dir)
}

// Pending lists accepted entries, oldest first.
func Pending(dir string) ([]Entry, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type item struct {
		e  Entry
		mt int64
	}
	var items []item
	for _, d := range ents {
		if !d.IsDir() || d.Name() == FailedName {
			continue
		}
		edir := filepath.Join(dir, d.Name())
		st, err := os.Stat(filepath.Join(edir, "meta.json"))
		if err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(edir, "payload")); err != nil {
			continue
		}
		items = append(items, item{Entry{Dir: edir, ID: d.Name()}, st.ModTime().UnixNano()})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].mt != items[j].mt {
			return items[i].mt < items[j].mt
		}
		return items[i].e.ID < items[j].e.ID
	})
	out := make([]Entry, len(items))
	for i, it := range items {
		out[i] = it.e
	}
	return out, nil
}

// Cleanup removes entry directories without meta.json: directories whose
// name has the shape of an id (IsID). Anything else is left alone.
func Cleanup(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, d := range ents {
		if !d.IsDir() || !IsID(d.Name()) {
			continue
		}
		edir := filepath.Join(dir, d.Name())
		if _, err := os.Stat(filepath.Join(edir, "meta.json")); err == nil {
			continue
		}
		if err := os.RemoveAll(edir); err != nil {
			return fmt.Errorf("queue cleanup: %w", err)
		}
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
