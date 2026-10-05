package queue

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newStageQueue() *Queue {
	return New(0, func(string) (int64, error) { return 1 << 40, nil })
}

// TestStageOutOfOrder writes a file of 3.5 parts in the order 2, 0, 3, 1.
func TestStageOutOfOrder(t *testing.T) {
	const part = 1000
	data := bytes.Repeat([]byte("0123456789abcdefghij"), 175) // 3500 bytes
	dir := t.TempDir()
	q := newStageQueue()
	st, err := q.Stage(dir, "id1", int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "id1", ".payload.tmp")); err != nil || fi.Size() != int64(len(data)) {
		t.Fatalf("staging file: %v %v", fi, err)
	}
	for _, n := range []int64{2, 0, 3, 1} {
		off := n * part
		end := min(off+part, int64(len(data)))
		if err := st.WriteAt(data[off:end], off); err != nil {
			t.Fatal(err)
		}
		if err := st.Advance(off, end-off); err != nil {
			t.Fatal(err)
		}
	}
	size, sha, err := st.Finish(int64(len(data)), sum(data))
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(data)) || sha != sum(data) {
		t.Fatalf("size %d sha %s", size, sha)
	}
	got, err := os.ReadFile(filepath.Join(st.Entry.Dir, "payload"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("payload: %v", err)
	}
	if _, err := os.Stat(filepath.Join(st.Entry.Dir, ".payload.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging file left: %v", err)
	}
}

// A stream has no size: Finish takes the size the parts made, and the
// sha256 is computed, not checked.
func TestStageStream(t *testing.T) {
	data := []byte("stream data of some length")
	q := newStageQueue()
	st, err := q.Stage(t.TempDir(), "id1", -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A longer attempt at the last part before the verified one.
	if err := st.WriteAt(append(bytes.Clone(data[10:]), "garbage"...), 10); err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{10, 0} {
		end := min(off+10, int64(len(data)))
		if off == 10 {
			end = int64(len(data))
		}
		if err := st.WriteAt(data[off:end], off); err != nil {
			t.Fatal(err)
		}
		if err := st.Advance(off, end-off); err != nil {
			t.Fatal(err)
		}
	}
	size, sha, err := st.Finish(int64(len(data)), "")
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(data)) || sha != sum(data) {
		t.Fatalf("size %d sha %s, want %d %s", size, sha, len(data), sum(data))
	}
	if got, _ := os.ReadFile(filepath.Join(st.Entry.Dir, "payload")); !bytes.Equal(got, data) {
		t.Fatalf("payload %q", got)
	}
}

func TestStageMismatch(t *testing.T) {
	data := []byte("hello")
	q := newStageQueue()
	st, err := q.Stage(t.TempDir(), "id1", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteAt(data, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.Advance(0, 5); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Finish(5, sum([]byte("other"))); !errors.Is(err, ErrMismatch) {
		t.Fatalf("sha: %v", err)
	}

	st, err = q.Stage(t.TempDir(), "id2", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteAt(data[:3], 0); err != nil {
		t.Fatal(err)
	}
	if err := st.Advance(0, 3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Finish(5, sum(data)); !errors.Is(err, ErrMismatch) {
		t.Fatalf("missing bytes: %v", err)
	}
}

func TestStageBounds(t *testing.T) {
	q := newStageQueue()
	st, err := q.Stage(t.TempDir(), "id1", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Abort()
	if err := st.WriteAt([]byte("abc"), 3); err == nil {
		t.Fatal("write past the size")
	}
	if err := st.WriteAt([]byte("a"), -1); err == nil {
		t.Fatal("write at a negative offset")
	}
	if err := st.Advance(4, 2); err == nil {
		t.Fatal("advance past the size")
	}
}

func TestStageAbort(t *testing.T) {
	dir := t.TempDir()
	free := int64(1000)
	q := New(0, fakeFree(&free))
	res, err := q.Reserve(dir, 600)
	if err != nil {
		t.Fatal(err)
	}
	st, err := q.Stage(dir, "id1", 600, res)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteAt([]byte("abc"), 0); err != nil {
		t.Fatal(err)
	}
	st.Abort()
	st.Abort()
	if _, err := os.Stat(filepath.Join(dir, "id1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry dir left: %v", err)
	}
	// The reservation went back with the stage.
	if r, err := q.Reserve(dir, 600); err != nil {
		t.Fatal(err)
	} else {
		r.Release()
	}
}

// An empty file has no parts; Finish takes it at once.
func TestStageEmpty(t *testing.T) {
	q := newStageQueue()
	st, err := q.Stage(t.TempDir(), "id1", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if size, sha, err := st.Finish(0, sum(nil)); err != nil || size != 0 || sha != sum(nil) {
		t.Fatalf("%d %s %v", size, sha, err)
	}
}

func TestStageInvalidID(t *testing.T) {
	if _, err := newStageQueue().Stage(t.TempDir(), "..", 1, nil); err == nil {
		t.Fatal("invalid id staged")
	}
}
