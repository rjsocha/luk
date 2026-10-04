package queue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func fakeFree(v *int64) func(string) (int64, error) {
	return func(string) (int64, error) { return *v, nil }
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestReserve(t *testing.T) {
	free := int64(100)
	q := New(10, fakeFree(&free))
	r1, err := q.Reserve("d", 50)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Reserve("d", 50); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("want ErrNoSpace, got %v", err)
	}
	r1.Release()
	r1.Release()
	r2, err := q.Reserve("d", 50)
	if err != nil {
		t.Fatal(err)
	}
	r2.Release()
}

func TestReceiveOK(t *testing.T) {
	dir := t.TempDir()
	q := New(0, func(string) (int64, error) { return 1 << 40, nil })
	data := []byte("hello world")
	n := int64(len(data))
	e, size, sha, err := q.Receive(context.Background(), dir, "id1", bytes.NewReader(data), 0, &n, sum(data), nil)
	if err != nil {
		t.Fatal(err)
	}
	if size != n || sha != sum(data) {
		t.Fatalf("size %d sha %s", size, sha)
	}
	fi, err := os.Stat(filepath.Join(e.Dir, "payload"))
	if err != nil || fi.Mode().Perm() != 0o440 {
		t.Fatalf("payload mode: %v %v", err, fi)
	}
	got, err := os.ReadFile(filepath.Join(e.Dir, "payload"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("payload: %v %q", err, got)
	}
	ents, _ := os.ReadDir(e.Dir)
	if len(ents) != 1 {
		t.Fatalf("leftovers: %v", ents)
	}
}

func TestReceiveMismatch(t *testing.T) {
	dir := t.TempDir()
	q := New(0, func(string) (int64, error) { return 1 << 40, nil })
	data := []byte("hello world")
	n := int64(len(data))
	cases := map[string]struct {
		size *int64
		sha  string
	}{
		"sha":      {&n, sum([]byte("other"))},
		"short":    {ptr(n + 1), ""},
		"long":     {ptr(n - 1), ""},
		"shaempty": {nil, sum([]byte("other"))},
	}
	for name, c := range cases {
		_, _, _, err := q.Receive(context.Background(), dir, name, bytes.NewReader(data), 0, c.size, c.sha, nil)
		if !errors.Is(err, ErrMismatch) {
			t.Fatalf("%s: got %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s: entry dir left: %v", name, err)
		}
	}
}

type countReader struct{ n int64 }

func (c *countReader) Read(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

func TestReceiveStopsAtSignedSizePlusOne(t *testing.T) {
	dir := t.TempDir()
	q := New(0, func(string) (int64, error) { return 1 << 40, nil })
	r := &countReader{}
	n := int64(10)
	_, _, _, err := q.Receive(context.Background(), dir, "x", r, 0, &n, "", nil)
	if !errors.Is(err, ErrMismatch) {
		t.Fatal(err)
	}
	if r.n > 1<<20 {
		t.Fatalf("read %d bytes", r.n)
	}
}

func TestReceiveMax(t *testing.T) {
	dir := t.TempDir()
	q := New(0, func(string) (int64, error) { return 1 << 40, nil })
	_, _, _, err := q.Receive(context.Background(), dir, "x", &countReader{}, 100, nil, "", nil)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x")); !os.IsNotExist(err) {
		t.Fatal("entry left")
	}
}

func TestReceiveUnsizedNoSpace(t *testing.T) {
	old := checkEvery
	checkEvery = 1024
	defer func() { checkEvery = old }()
	dir := t.TempDir()
	calls := 0
	q := New(100, func(string) (int64, error) {
		calls++
		if calls > 2 {
			return 50, nil
		}
		return 1 << 30, nil
	})
	_, _, _, err := q.Receive(context.Background(), dir, "x", &countReader{}, 0, nil, "", nil)
	if !errors.Is(err, ErrNoSpace) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x")); !os.IsNotExist(err) {
		t.Fatal("entry left")
	}
}

func TestReceiveContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q := New(0, func(string) (int64, error) { return 1 << 40, nil })
	_, _, _, err := q.Receive(ctx, t.TempDir(), "x", io.LimitReader(&countReader{}, 1<<20), 0, nil, "", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestPendingCommitRemoveCleanup(t *testing.T) {
	dir := t.TempDir()
	q := New(0, func(string) (int64, error) { return 1 << 40, nil })
	var es []Entry
	b, a, c := "20261004T100000Z-0000000b", "20261004T100000Z-0000000a", "20261004T100000Z-0000000c"
	for _, id := range []string{b, a, c} {
		e, _, _, err := q.Receive(context.Background(), dir, id, bytes.NewReader([]byte(id)), 0, nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, e)
	}
	base := time.Now().Add(-time.Hour)
	for i, e := range es[:2] {
		if err := q.Commit(e, map[string]string{"id": e.ID}); err != nil {
			t.Fatal(err)
		}
		mt := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(filepath.Join(e.Dir, "meta.json"), mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Pending(dir)
	if err != nil || len(got) != 2 || got[0].ID != b || got[1].ID != a {
		t.Fatalf("pending %v %v", got, err)
	}
	half := "20261004T100000Z-0000000d"
	if err := os.MkdirAll(filepath.Join(dir, half), 0o755); err != nil {
		t.Fatal(err)
	}
	// Directories without the shape of an id are no entries: a nested
	// queue, a failed/ directory, anything an admin put there.
	for _, other := range []string{"backup", FailedName, "20261004T100000Z-0000000D", "x" + half} {
		if err := os.MkdirAll(filepath.Join(dir, other, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := Cleanup(dir); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{c, half} {
		if _, err := os.Stat(filepath.Join(dir, id)); !os.IsNotExist(err) {
			t.Fatalf("%s not removed", id)
		}
	}
	for _, other := range []string{"backup", FailedName, "20261004T100000Z-0000000D", "x" + half} {
		if _, err := os.Stat(filepath.Join(dir, other, "sub")); err != nil {
			t.Fatalf("%s removed: %v", other, err)
		}
	}
	if err := q.Remove(es[0]); err != nil {
		t.Fatal(err)
	}
	got, _ = Pending(dir)
	if len(got) != 1 || got[0].ID != a {
		t.Fatalf("after remove %v", got)
	}
}

func ptr(n int64) *int64 { return &n }

func TestSharedFilesystemPool(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	os.Mkdir(a, 0o755)
	os.Mkdir(b, 0o755)
	free := int64(100)
	q := New(0, fakeFree(&free))
	if _, err := q.Reserve(a, 60); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Reserve(b, 60); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("want ErrNoSpace, got %v", err)
	}
}

func TestUnsizedCountsReservations(t *testing.T) {
	old := checkEvery
	checkEvery = 1024
	defer func() { checkEvery = old }()
	dir := t.TempDir()
	free := int64(1000)
	q := New(100, fakeFree(&free))
	if _, err := q.Reserve(dir, 800); err != nil {
		t.Fatal(err)
	}
	free = 850
	_, _, _, err := q.Receive(context.Background(), dir, "x", io.LimitReader(&countReader{}, 1<<20), 0, nil, "", nil)
	if !errors.Is(err, ErrNoSpace) {
		t.Fatal(err)
	}
}

func TestMapENOSPC(t *testing.T) {
	err := mapErr(&os.PathError{Op: "write", Path: "x", Err: syscall.ENOSPC})
	if !errors.Is(err, ErrNoSpace) || !errors.Is(err, syscall.ENOSPC) {
		t.Fatal(err)
	}
	if mapErr(io.EOF) != io.EOF {
		t.Fatal("unrelated error altered")
	}
}

func TestReservationConsume(t *testing.T) {
	free := int64(100)
	q := New(0, fakeFree(&free))
	r, _ := q.Reserve("d", 60)
	r.Consume(50)
	free = 50
	if r2, err := q.Reserve("d", 40); err != nil {
		t.Fatal(err)
	} else {
		r2.Release()
	}
	r.Release()
	r.Release()
	if q.reserved[fsKey("d")] != 0 {
		t.Fatalf("held %d", q.reserved[fsKey("d")])
	}
}

func TestBadInput(t *testing.T) {
	q := New(0, func(string) (int64, error) { return 1 << 40, nil })
	if _, err := q.Reserve("d", -1); err == nil {
		t.Fatal("negative reserve accepted")
	}
	dir := t.TempDir()
	neg := int64(-1)
	if _, _, _, err := q.Receive(context.Background(), dir, "x", bytes.NewReader(nil), 0, &neg, "", nil); err == nil {
		t.Fatal("negative signed size accepted")
	}
	for _, id := range []string{"", ".", "..", "a/b", "../x"} {
		if _, _, _, err := q.Receive(context.Background(), dir, id, bytes.NewReader(nil), 0, nil, "", nil); err == nil {
			t.Fatalf("id %q accepted", id)
		}
	}
}

func TestParallelReserve(t *testing.T) {
	free := int64(1000)
	q := New(0, fakeFree(&free))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if r, err := q.Reserve("d", 10); err == nil {
					r.Consume(3)
					r.Release()
				}
			}
		}()
	}
	wg.Wait()
	if q.reserved[fsKey("d")] != 0 {
		t.Fatalf("held %d", q.reserved[fsKey("d")])
	}
}

func TestReceiveUnsizedChecksBeforeFirstWrite(t *testing.T) {
	dir := t.TempDir()
	free := int64(50)
	q := New(100, fakeFree(&free))
	_, _, _, err := q.Receive(context.Background(), dir, "x", bytes.NewReader([]byte("abc")), 0, nil, "", nil)
	if !errors.Is(err, ErrNoSpace) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x")); !os.IsNotExist(err) {
		t.Fatal("entry left")
	}
	free = 1 << 30
	if _, n, _, err := q.Receive(context.Background(), dir, "y", bytes.NewReader([]byte("abc")), 0, nil, "", nil); err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestCommitNotSyncedIsCommitted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens any directory")
	}
	dir := t.TempDir()
	q := New(0, nil)
	e, _, _, err := q.Receive(context.Background(), dir, "id1", bytes.NewReader([]byte("x")), 0, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	err = q.Commit(e, map[string]string{"a": "b"})
	if !errors.Is(err, ErrNotSynced) {
		t.Fatalf("commit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
}

func TestLink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(t.TempDir(), "object")
	if err := os.WriteFile(src, []byte("held"), 0o440); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	q := New(0, nil)
	e, err := q.Link(dir, "id1", src, fi)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.Lstat(filepath.Join(e.Dir, "payload"))
	if err != nil || !os.SameFile(got, fi) {
		t.Fatalf("payload %v", err)
	}
	if _, err := q.Link(dir, "../x", src, fi); err == nil {
		t.Fatal("invalid id accepted")
	}
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("held"), 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Link(dir, "id2", other, fi); err == nil {
		t.Fatal("another file linked")
	}
	if _, err := os.Lstat(filepath.Join(dir, "id2")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry left: %v", err)
	}
}

func TestDirReserve(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	free := int64(100)
	q := New(90, fakeFree(&free))
	q.SetDirReserves(map[string]int64{b: 10})
	if _, err := q.Reserve(a, 20); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("general reserve: %v", err)
	}
	if _, err := q.Reserve(b, 20); err != nil {
		t.Fatalf("dir reserve: %v", err)
	}
	if _, _, _, err := q.Receive(context.Background(), a, "x", bytes.NewReader([]byte("x")), 0, nil, "", nil); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("unsized general: %v", err)
	}
	if _, _, _, err := q.Receive(context.Background(), b, "x", bytes.NewReader([]byte("x")), 0, nil, "", nil); err != nil {
		t.Fatalf("unsized dir: %v", err)
	}
}

// An entry removed only in part (a subdirectory that cannot be emptied)
// is no longer pending: meta.json goes first.
func TestRemoveMetaFirst(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes anything")
	}
	dir := t.TempDir()
	q := New(0, func(string) (int64, error) { return 1 << 40, nil })
	e, _, _, err := q.Receive(context.Background(), dir, "id1", bytes.NewReader([]byte("x")), 0, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Commit(e, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	stuck := filepath.Join(e.Dir, "stuck")
	if err := os.Mkdir(stuck, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stuck, "f"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	os.Chmod(stuck, 0o500)
	defer os.Chmod(stuck, 0o750)
	if err := q.Remove(e); err == nil {
		t.Fatal("removed")
	}
	if p, err := Pending(dir); err != nil || len(p) != 0 {
		t.Fatalf("pending %v %v", p, err)
	}
}
