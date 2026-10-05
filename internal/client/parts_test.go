package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/wire"
)

// testPartSize is the part size of the parts tests.
const testPartSize = 128 << 10

// partsEnv is a lukd with parts of 128KiB, at most 4 at once, on both
// endpoints. hook, when set, sees every transport request first and
// answers it itself when it returns false.
type partsEnv struct {
	base   string
	pins   []channel.Pin
	root   string
	signer ssh.Signer

	mu   sync.Mutex
	hook func(w http.ResponseWriter, r *http.Request, id [16]byte, n channel.Nonce) bool
}

func newPartsEnv(t *testing.T) *partsEnv {
	t.Helper()
	shortRetries(t)
	e := &partsEnv{signer: newSigner(t)}
	k, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, root := newLukdWith(t, e.signer.PublicKey(), func(s string) string {
		s = strings.Replace(s, "allow: [robert.socha]}", "allow: [robert.socha], parts: {size: 128K}}", 1)
		return strings.Replace(s, "respond: url, storage: drop}", "respond: url, storage: drop, parts: {size: 128K}}", 1)
	})
	srv.SetIdentity(k)
	e.root = root
	h := srv.Handler("127.0.0.1:0")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		if len(b) >= 25 && b[0] == 0x02 {
			var id [16]byte
			copy(id[:], b[1:17])
			n, err := channel.ParseNonce(binary.BigEndian.Uint64(b[17:25]))
			e.mu.Lock()
			hook := e.hook
			e.mu.Unlock()
			if err == nil && hook != nil && !hook(w, r, id, n) {
				return
			}
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	e.base = ts.URL
	e.pins = mustPins(t, channel.Words(k.Public))
	return e
}

func (e *partsEnv) setHook(h func(w http.ResponseWriter, r *http.Request, id [16]byte, n channel.Nonce) bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hook = h
}

// shortRetries makes the waits between the attempts of a part short.
func shortRetries(t *testing.T) {
	old := partBackoff
	partBackoff = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond}
	t.Cleanup(func() { partBackoff = old })
}

// file is the options of an upload of data as a regular file.
func (e *partsEnv) file(endpoint string, data []byte) Options {
	n := int64(len(data))
	sum := sha256.Sum256(data)
	return Options{URL: e.base + endpoint, Pins: e.pins, Signer: e.signer, Source: bytes.NewReader(data), Size: n,
		Meta: wire.Meta{Portal: wire.PortalDirect, File: "f", Source: wire.SourceFile, Size: &n, SHA256: hex.EncodeToString(sum[:])}}
}

// stream is the options of an upload of data as a stream.
func (e *partsEnv) stream(endpoint string, data []byte) Options {
	return Options{URL: e.base + endpoint, Pins: e.pins, Signer: e.signer, Body: bytes.NewReader(data), Size: -1,
		Meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourcePipe}}
}

// queued is the sha256 of the payload of the backup queue entry id.
func (e *partsEnv) queued(t *testing.T, id string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.root, "q/backup", id, "payload"))
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sha256Sum(string(b)))
}

// staged lists the entries of the backup queue: none once an upload
// ended without a commit.
func (e *partsEnv) staged(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(e.root, "q/backup"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range ents {
		out = append(out, d.Name())
	}
	return out
}

// patterned is n bytes that differ from part to part.
func patterned(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i/testPartSize*7 + i%251)
	}
	return b
}

func TestUploadBoundaries(t *testing.T) {
	e := newPartsEnv(t)
	for _, n := range []int{0, 1, 65536, testPartSize, 3 * testPartSize, 3*testPartSize + 1} {
		data := patterned(n)
		want := hex.EncodeToString(sha256Sum(string(data)))
		for _, mode := range []string{"file", "stream"} {
			t.Run(fmt.Sprintf("%s/%d", mode, n), func(t *testing.T) {
				o := e.file("/backup", data)
				if mode == "stream" {
					o = e.stream("/backup", data)
				}
				o.Parallel = 3
				a, err := Upload(context.Background(), o)
				if err != nil {
					t.Fatal(err)
				}
				if a.Receipt.Size != int64(n) || a.Receipt.SHA256 != want || a.Receipt.Deduplicated {
					t.Fatalf("%+v", a.Receipt)
				}
				if got := e.queued(t, a.Receipt.ID); got != want {
					t.Fatalf("stored sha256 %s, want %s", got, want)
				}
			})
		}
	}
}

// changingFile is a file whose mtime changes once its first part is read.
type changingFile struct {
	*bytes.Reader
	size  int64
	mtime time.Time
	read  atomic.Bool
}

func (f *changingFile) ReadAt(p []byte, off int64) (int, error) {
	f.read.Store(true)
	return f.Reader.ReadAt(p, off)
}

func (f *changingFile) Stat() (os.FileInfo, error) {
	m := f.mtime
	if f.read.Load() {
		m = m.Add(time.Second)
	}
	return fileInfo{size: f.size, mtime: m}, nil
}

type fileInfo struct {
	os.FileInfo
	size  int64
	mtime time.Time
}

func (fi fileInfo) Size() int64        { return fi.size }
func (fi fileInfo) ModTime() time.Time { return fi.mtime }

func TestUploadFileChanged(t *testing.T) {
	e := newPartsEnv(t)
	data := patterned(3*testPartSize + 5)
	o := e.file("/backup", data)
	mtime := time.Now().Add(-time.Hour)
	o.Source = &changingFile{Reader: bytes.NewReader(data), size: int64(len(data)), mtime: mtime}
	o.Mtime = mtime
	_, err := Upload(context.Background(), o)
	if err == nil || err.Error() != "file changed while sending: send it again" {
		t.Fatalf("%v", err)
	}
	if left := e.staged(t); len(left) != 0 {
		t.Fatalf("staging left: %v", left)
	}
}

func TestUploadParallelRetries(t *testing.T) {
	e := newPartsEnv(t)
	var mu sync.Mutex
	seen := map[uint16]bool{}
	e.setHook(func(w http.ResponseWriter, r *http.Request, _ [16]byte, n channel.Nonce) bool {
		if n.Kind != channel.KindPart || n.Number != 2 {
			return true
		}
		mu.Lock()
		seen[n.Attempt] = true
		mu.Unlock()
		if n.Attempt == 0 {
			panic(http.ErrAbortHandler)
		}
		return true
	})
	data := patterned(6*testPartSize + 9)
	for _, mode := range []string{"file", "stream"} {
		mu.Lock()
		clear(seen)
		mu.Unlock()
		o := e.file("/backup", data)
		if mode == "stream" {
			o = e.stream("/backup", data)
		}
		o.Parallel = 4
		var progress bytes.Buffer
		o.Progress = &progress
		a, err := Upload(context.Background(), o)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if a.Receipt.SHA256 != hex.EncodeToString(sha256Sum(string(data))) {
			t.Fatalf("%s: %+v", mode, a.Receipt)
		}
		mu.Lock()
		if !seen[0] || !seen[1] {
			t.Fatalf("%s: attempts of part 2: %v", mode, seen)
		}
		mu.Unlock()
		if !strings.Contains(progress.String(), HumanBytes(int64(len(data)))+" in ") {
			t.Fatalf("%s: progress %q", mode, progress.String())
		}
	}
}

func TestUploadAbortOnCancel(t *testing.T) {
	e := newPartsEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var aborts atomic.Int32
	e.setHook(func(w http.ResponseWriter, r *http.Request, _ [16]byte, n channel.Nonce) bool {
		switch {
		case n.Kind == channel.KindAbort:
			aborts.Add(1)
		case n.Kind == channel.KindPart && n.Number == 1:
			cancel()
			<-r.Context().Done()
			return false
		}
		return true
	})
	o := e.file("/backup", patterned(4*testPartSize))
	_, err := Upload(ctx, o)
	var te *TransferError
	if !errors.As(err, &te) || te.Reason != Interrupted {
		t.Fatalf("%v", err)
	}
	if aborts.Load() != 1 {
		t.Fatalf("%d aborts", aborts.Load())
	}
	if left := e.staged(t); len(left) != 0 {
		t.Fatalf("staging left: %v", left)
	}
}

// lostSession answers a PART n of the first session it sees, or its
// COMPLETE, as a lukd that restarted: 404 unknown session in the clear.
func lostSession(kind channel.Kind, number uint32) func(w http.ResponseWriter, r *http.Request, id [16]byte, n channel.Nonce) bool {
	var mu sync.Mutex
	var first *[16]byte
	return func(w http.ResponseWriter, r *http.Request, id [16]byte, n channel.Nonce) bool {
		mu.Lock()
		defer mu.Unlock()
		if first == nil {
			first = &id
		}
		if id == *first && n.Kind == kind && (kind != channel.KindPart || n.Number == number) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"unknown session"}`)
			return false
		}
		return true
	}
}

func TestUploadSessionLost(t *testing.T) {
	e := newPartsEnv(t)
	data := patterned(3*testPartSize + 1)
	e.setHook(lostSession(channel.KindPart, 1))
	a, err := Upload(context.Background(), e.file("/backup", data))
	if err != nil || a.Receipt.SHA256 != hex.EncodeToString(sha256Sum(string(data))) {
		t.Fatalf("file started over: %+v %v", a, err)
	}
	e.setHook(lostSession(channel.KindPart, 1))
	if _, err := Upload(context.Background(), e.stream("/backup", data)); err == nil || err.Error() != "server lost the upload; the stream cannot be sent again" {
		t.Fatalf("stream: %v", err)
	}
	var completes atomic.Int32
	hook := lostSession(channel.KindComplete, 0)
	e.setHook(func(w http.ResponseWriter, r *http.Request, id [16]byte, n channel.Nonce) bool {
		if n.Kind == channel.KindComplete {
			completes.Add(1)
		}
		return hook(w, r, id, n)
	})
	// Other content: the same would be deduplicated at the OP.
	if _, err := Upload(context.Background(), e.file("/backup", patterned(2*testPartSize))); !errors.Is(err, ErrResultUnknown) {
		t.Fatalf("complete: %v", err)
	}
	if completes.Load() != 1 {
		t.Fatalf("%d completes", completes.Load())
	}
}

// A part past the window of lukd waits for it and goes again.
func TestUploadWindowWait(t *testing.T) {
	e := newPartsEnv(t)
	var tries atomic.Int32
	e.setHook(func(w http.ResponseWriter, r *http.Request, _ [16]byte, n channel.Nonce) bool {
		switch {
		case n.Kind == channel.KindPart && n.Number == 0 && n.Attempt == 0:
			// Parts 1 to 7 go on meanwhile; part 8 is past the window
			// of 2 x 4 parts after the missing part 0.
			time.Sleep(1500 * time.Millisecond)
		case n.Kind == channel.KindPart && n.Number == 8:
			tries.Add(1)
		}
		return true
	})
	o := e.file("/backup", patterned(9*testPartSize))
	o.Parallel = 4
	if _, err := Upload(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if tries.Load() < 2 {
		t.Fatalf("part 8 sent %d times", tries.Load())
	}
}

func TestUploadNoBodyOffered(t *testing.T) {
	e := newPartsEnv(t)
	data := patterned(10)
	o := e.file("/backup", data)
	o.Source, o.NoBody = nil, true
	if _, err := Upload(context.Background(), o); !errors.Is(err, ErrBodyWanted) {
		t.Fatalf("%v", err)
	}
	if left := e.staged(t); len(left) != 0 {
		t.Fatalf("staging left: %v", left)
	}
}

// A read error of the file is reported as such, not as a transfer error.
func TestUploadSourceError(t *testing.T) {
	e := newPartsEnv(t)
	o := e.file("/backup", patterned(2*testPartSize))
	bad := errors.New("disk on fire")
	o.Source = failingReaderAt{bad}
	_, err := Upload(context.Background(), o)
	var te *TransferError
	if !errors.Is(err, bad) || errors.As(err, &te) {
		t.Fatalf("%v", err)
	}
	if left := e.staged(t); len(left) != 0 {
		t.Fatalf("staging left: %v", left)
	}
}

type failingReaderAt struct{ err error }

func (f failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, f.err }

// A part whose answer does not come is sent again; one that never gets
// one ends the upload as stalled.
func TestUploadPartStalled(t *testing.T) {
	e := newPartsEnv(t)
	old := partIdle
	partIdle = 200 * time.Millisecond
	t.Cleanup(func() { partIdle = old })
	e.setHook(func(w http.ResponseWriter, r *http.Request, _ [16]byte, n channel.Nonce) bool {
		if n.Kind == channel.KindPart && n.Number == 1 && n.Attempt == 0 {
			<-r.Context().Done()
			return false
		}
		return true
	})
	if _, err := Upload(context.Background(), e.file("/backup", patterned(2*testPartSize))); err != nil {
		t.Fatal(err)
	}
	e.setHook(func(w http.ResponseWriter, r *http.Request, _ [16]byte, n channel.Nonce) bool {
		if n.Kind == channel.KindPart && n.Number == 1 {
			<-r.Context().Done()
			return false
		}
		return true
	})
	_, err := Upload(context.Background(), e.file("/backup", patterned(2*testPartSize+1)))
	var te *TransferError
	if !errors.As(err, &te) || te.Reason != Stalled || te.Total != 2*testPartSize+1 || te.Done != testPartSize {
		t.Fatalf("%v", err)
	}
}

// slowFile is a file whose reads take a while each.
type slowFile struct{ *bytes.Reader }

func (f slowFile) ReadAt(p []byte, off int64) (int, error) {
	time.Sleep(150 * time.Millisecond)
	return f.Reader.ReadAt(p, off)
}

// A slow source is luk waiting for itself, not for lukd: it never trips
// the idle time of a part.
func TestUploadSlowSourceNotStalled(t *testing.T) {
	e := newPartsEnv(t)
	old := partIdle
	partIdle = 100 * time.Millisecond
	t.Cleanup(func() { partIdle = old })
	data := patterned(testPartSize + 3)
	o := e.file("/backup", data)
	o.Source = slowFile{bytes.NewReader(data)}
	if _, err := Upload(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	go func() {
		for _, b := range [][]byte{data[:10], data[10:]} {
			time.Sleep(300 * time.Millisecond)
			w.Write(b)
		}
		w.Close()
	}()
	o = e.stream("/backup", nil)
	o.Body = r
	if _, err := Upload(context.Background(), o); err != nil {
		t.Fatal(err)
	}
}
