package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"luk/internal/channel"
	"luk/internal/queue"
	"luk/internal/wire"
)

const testPart = 64 << 10

// partsFixture is the channel fixture with parts of 64KiB on /drop, at
// most parallel at once; mod rewrites the config further.
func partsFixture(t *testing.T, parallel string, mod func(string) string) (*fixture, string, []byte) {
	t.Helper()
	return chanFixture(t, func(s string) string {
		s = strings.Replace(s, `respond: url, storage: drop}`, `respond: url, storage: drop, parts: {size: 64K, parallel: `+parallel+`}}`, 1)
		if mod != nil {
			s = mod(s)
		}
		return s
	})
}

// content is n bytes that differ from part to part.
func content(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i/testPart*7 + i%251)
	}
	return b
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// partOf is part n of data.
func partOf(data []byte, n int) []byte {
	return data[n*testPart : min((n+1)*testPart, len(data))]
}

// uploadOf is the upload of the session of c.
func uploadOf(t *testing.T, f *fixture, c *testChan) *partsUpload {
	t.Helper()
	cs := f.srv.chans.get(c.sess.ID())
	if cs == nil {
		t.Fatal("no session")
	}
	pu := cs.uploadOf()
	if pu == nil {
		t.Fatal("no upload")
	}
	return pu
}

func created(t *testing.T, body []byte) wire.Created {
	t.Helper()
	var out wire.Created
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return out
}

// sendAll sends every part of data in order and completes with seq 0.
func sendAll(t *testing.T, c *testChan, data []byte) (channel.Response, []byte) {
	t.Helper()
	for n := 0; n*testPart < len(data); n++ {
		head, body := c.part(t, uint32(n), 0, partOf(data, n))
		wantInner(t, "part", head, body, http.StatusOK)
	}
	return c.control(t, channel.KindComplete, 0, 0)
}

func TestUploadInParts(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(2*testPart + 1000)
	a, offer := create(t, f, srvURL, pin, fileMeta(data))
	if offer.Parts.Size != testPart || offer.Parts.Parallel != 4 {
		t.Fatalf("%+v", offer)
	}
	b, _ := create(t, f, srvURL, pin, fileMeta(data[:100]))
	for _, n := range []int{2, 0, 1} {
		head, body := a.part(t, uint32(n), 0, partOf(data, n))
		wantInner(t, "part", head, body, http.StatusOK)
	}
	head, body := sendAll(t, b, data[:100])
	wantInner(t, "complete B", head, body, http.StatusCreated)
	outB := created(t, body)
	head, body = a.control(t, channel.KindComplete, 0, 0)
	wantInner(t, "complete A", head, body, http.StatusCreated)
	outA := created(t, body)
	if outA.Size != int64(len(data)) || outA.SHA256 != sha(data) {
		t.Fatalf("%+v", outA)
	}
	// The acceptance order is the order of the creates.
	q := f.srv.config().Endpoint["drop"].Path
	accA := queue.AcceptanceOf(filepath.Join(q, outA.ID, "meta.json"))
	accB := queue.AcceptanceOf(filepath.Join(q, outB.ID, "meta.json"))
	if accA.NS == 0 || accA.Compare(accB) >= 0 {
		t.Fatalf("accepted A %+v, B %+v", accA, accB)
	}
	f.settle(t)
	if code, got := f.fetch(t, outA.URL); code != 200 || got != string(data) {
		t.Fatalf("%d, %d bytes", code, len(got))
	}
	// A repeated part of a verified part is answered without its body.
	head, body = a.part(t, 0, 1, []byte("x"))
	wantInner(t, "after commit", head, body, http.StatusOK)
	// A repeated nonce is refused.
	wantOuter(t, "repeated nonce", a.post(t, a.path, channel.Nonce{Kind: channel.KindComplete}, nil), http.StatusConflict)
}

// TestPartRetryWhileReceiving: a part is sent again while the first
// attempt is still arriving; the new attempt takes the part over and the
// first one writes no more.
func TestPartRetryWhileReceiving(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(2 * testPart)
	c, _ := create(t, f, srvURL, pin, fileMeta(data))
	pu := uploadOf(t, f, c)

	stale := bytes.Repeat([]byte{'A'}, testPart)
	n0 := channel.Nonce{Kind: channel.KindPart, Number: 1}
	msg := c.seal(t, n0, stale)
	pr, pw := io.Pipe()
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := http.Post(srvURL+"/drop", channel.ContentType, pr)
		done <- result{resp, err}
	}()
	// The clear header and the first frame.
	if _, err := pw.Write(msg[:25+channel.FrameSize+16]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for pu.partState(1) != partReceiving {
		if time.Now().After(deadline) {
			t.Fatal("the first attempt is not receiving")
		}
		time.Sleep(5 * time.Millisecond)
	}
	head, body := c.part(t, 1, 1, partOf(data, 1))
	wantInner(t, "retry", head, body, http.StatusOK)
	if _, err := pw.Write(msg[25+channel.FrameSize+16:]); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.resp.Body.Close()
	head, body = c.inner(t, r.resp, n0)
	wantInner(t, "first attempt", head, body, http.StatusConflict)

	head, body = c.part(t, 0, 0, partOf(data, 0))
	wantInner(t, "part 0", head, body, http.StatusOK)
	head, body = c.control(t, channel.KindComplete, 0, 0)
	wantInner(t, "complete", head, body, http.StatusCreated)
	if out := created(t, body); out.SHA256 != sha(data) {
		t.Fatalf("%+v", out)
	}
}

func TestPartBounds(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "1", nil)
	data := content(3*testPart + 10)
	c, _ := create(t, f, srvURL, pin, fileMeta(data))
	head, body := c.part(t, 4, 0, []byte("x"))
	wantInner(t, "beyond the file", head, body, http.StatusBadRequest)
	head, body = c.part(t, 0, 0, partOf(data, 0)[:100])
	wantInner(t, "short part", head, body, http.StatusBadRequest)
	head, body = c.part(t, 1, 0, append(bytes.Clone(partOf(data, 1)), 'x'))
	wantInner(t, "long part", head, body, http.StatusBadRequest)
	// The window is 2 x parallel parts past the contiguous prefix.
	head, body = c.part(t, 2, 0, partOf(data, 2))
	wantInner(t, "ahead of the window", head, body, http.StatusTooManyRequests)
	// A failed attempt leaves the part to a new one.
	head, body = c.part(t, 1, 1, partOf(data, 1))
	wantInner(t, "part 1", head, body, http.StatusOK)
	head, body = c.part(t, 0, 1, partOf(data, 0))
	wantInner(t, "part 0", head, body, http.StatusOK)
	head, body = c.part(t, 3, 0, append(bytes.Clone(partOf(data, 3)), 'x'))
	wantInner(t, "long last part", head, body, http.StatusBadRequest)
	for _, n := range []int{2, 3} {
		head, body = c.part(t, uint32(n), 1, partOf(data, n))
		wantInner(t, "part", head, body, http.StatusOK)
	}
	if got := readPayloadAfter(t, f, c); got != sha(data) {
		t.Fatalf("staged sha %s", got)
	}
}

func TestCompleteMissing(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(3 * testPart)
	c, _ := create(t, f, srvURL, pin, fileMeta(data))
	for _, n := range []int{0, 2} {
		head, body := c.part(t, uint32(n), 0, partOf(data, n))
		wantInner(t, "part", head, body, http.StatusOK)
	}
	head, body := c.control(t, channel.KindComplete, 0, 0)
	wantInner(t, "complete with a gap", head, body, http.StatusConflict)
	var m wire.PartsMissing
	if err := json.Unmarshal(body, &m); err != nil || len(m.Missing) != 1 || m.Missing[0] != 1 {
		t.Fatalf("%v %s", err, body)
	}
	head, body = c.part(t, 1, 0, partOf(data, 1))
	wantInner(t, "part 1", head, body, http.StatusOK)
	head, first := c.control(t, channel.KindComplete, 1, 0)
	wantInner(t, "complete", head, first, http.StatusCreated)
	// A complete sent again (its answer lost) gets the same answer.
	head, again := c.control(t, channel.KindComplete, 1, 1)
	wantInner(t, "complete again", head, again, http.StatusCreated)
	if !bytes.Equal(first, again) {
		t.Fatalf("%s\n%s", first, again)
	}
}

func TestUploadDedupAtCreate(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(100)
	c, _ := create(t, f, srvURL, pin, fileMeta(data))
	head, body := sendAll(t, c, data)
	wantInner(t, "first", head, body, http.StatusCreated)
	f.settle(t)
	c = chanOpen(t, srvURL, "/drop", pin)
	head, body = c.op(t, c.putReq(t, f.user, fileMeta(data)), nil)
	wantInner(t, "second", head, body, http.StatusCreated)
	if out := created(t, body); !out.Deduplicated {
		t.Fatalf("%s", body)
	}
	if f.srv.chans.get(c.sess.ID()) != nil {
		t.Fatal("session kept without an upload")
	}
}

func TestUploadDryRun(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	c := chanOpen(t, srvURL, "/drop", pin)
	m := fileMeta(content(100))
	m.DryRun = true
	head, body := c.op(t, c.putReq(t, f.user, m), nil)
	wantInner(t, "dry run", head, body, http.StatusOK)
	var r wire.Response
	if err := json.Unmarshal(body, &r); err != nil || r.Endpoint != "drop" || len(r.Pipelines) != 1 {
		t.Fatalf("%v %s", err, body)
	}
	if f.srv.chans.get(c.sess.ID()) != nil {
		t.Fatal("session kept without an upload")
	}
}

func TestUploadLimits(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", func(s string) string { return s + "limits: {uploads: {identity: 1}}\n" })
	data := content(100)
	first, _ := create(t, f, srvURL, pin, fileMeta(data))
	c := chanOpen(t, srvURL, "/drop", pin)
	head, body := c.op(t, c.putReq(t, f.user, fileMeta(data)), nil)
	wantInner(t, "second open upload", head, body, http.StatusTooManyRequests)
	head, body = first.control(t, channel.KindAbort, 0, 0)
	wantInner(t, "abort", head, body, http.StatusOK)
	head, body = first.control(t, channel.KindComplete, 0, 0)
	wantInner(t, "complete after abort", head, body, http.StatusGone)
	create(t, f, srvURL, pin, fileMeta(data))
}

func TestUploadIdleExpiry(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", func(s string) string {
		return strings.Replace(s, `parts: {size: 64K`, `limits: {body: {idle: 10s}}, parts: {size: 64K`, 1)
	})
	var mu sync.Mutex
	now := time.Now()
	f.srv.SetClock(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	})
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}
	data := content(2 * testPart)
	c, _ := create(t, f, srvURL, pin, fileMeta(data))
	head, body := c.part(t, 0, 0, partOf(data, 0))
	wantInner(t, "part", head, body, http.StatusOK)
	pu := uploadOf(t, f, c)
	dir := pu.stage.Entry.Dir
	advance(5 * time.Second)
	f.srv.sweepChannels()
	if pu.stateOf() != upOpen {
		t.Fatalf("expired while active: %s", pu.stateOf())
	}
	advance(11 * time.Second)
	f.srv.sweepChannels()
	if pu.stateOf() != upExpired {
		t.Fatalf("state %s", pu.stateOf())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("staging left: %v", err)
	}
	head, body = c.control(t, channel.KindComplete, 0, 0)
	wantInner(t, "complete after expiry", head, body, http.StatusGone)
	// The tombstone goes after 3 x idle.
	advance(31 * time.Second)
	f.srv.sweepChannels()
	wantOuter(t, "after the tombstone", c.post(t, c.path, channel.Nonce{Kind: channel.KindComplete, Number: 1}, nil), http.StatusNotFound)
}

func TestStreamUpload(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(2*testPart + 500)
	c, _ := create(t, f, srvURL, pin, wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin})
	for _, n := range []int{1, 0} {
		head, body := c.part(t, uint32(n), 0, partOf(data, n))
		wantInner(t, "part", head, body, http.StatusOK)
	}
	head, body := c.control(t, channel.KindComplete, 0, 0)
	wantInner(t, "complete before the end", head, body, http.StatusConflict)
	var m wire.PartsMissing
	if err := json.Unmarshal(body, &m); err != nil || len(m.Missing) != 1 || m.Missing[0] != 2 {
		t.Fatalf("%v %s", err, body)
	}
	head, body = c.part(t, 2, 0, partOf(data, 2))
	wantInner(t, "short last part", head, body, http.StatusOK)
	head, body = c.part(t, 3, 0, nil)
	wantInner(t, "past the end", head, body, http.StatusBadRequest)
	head, body = c.control(t, channel.KindComplete, 1, 0)
	wantInner(t, "complete", head, body, http.StatusCreated)
	if out := created(t, body); out.Size != int64(len(data)) || out.SHA256 != sha(data) {
		t.Fatalf("%+v", out)
	}
}

// A stream of a multiple of the part size ends with an empty part.
func TestStreamEmptyLastPart(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(testPart)
	c, _ := create(t, f, srvURL, pin, wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin})
	head, body := c.part(t, 0, 0, data)
	wantInner(t, "part", head, body, http.StatusOK)
	head, body = c.part(t, 1, 0, nil)
	wantInner(t, "empty part", head, body, http.StatusOK)
	head, body = c.control(t, channel.KindComplete, 0, 0)
	wantInner(t, "complete", head, body, http.StatusCreated)
	if out := created(t, body); out.Size != int64(len(data)) || out.SHA256 != sha(data) {
		t.Fatalf("%+v", out)
	}
}

func TestSecretUploadStagesInSecretQueue(t *testing.T) {
	vol := filepath.Join(t.TempDir(), "volatile")
	f, srvURL, pin := partsFixture(t, "4", func(s string) string {
		return strings.NewReplacer(
			`storage: drop, parts:`, `storage: drop, secret: {allow: ['*'], path: `+vol+`/queue, storage: volatile}, parts:`,
			"storage:\n", "storage:\n  volatile: {type: local, base: "+vol+"/storage, path: \"{{ .Random }}\", expose: volatile, ttl: {user: true}}\n",
			"  drop: {listen: main, path: /d/}\n", "  drop: {listen: main, path: /d/}\n  volatile: {listen: main, path: /d/volatile/}\n",
		).Replace(s)
	})
	c, _ := create(t, f, srvURL, pin, secretMeta("s3cr3t"))
	pu := uploadOf(t, f, c)
	if filepath.Dir(pu.stage.Entry.Dir) != filepath.Join(vol, "queue") {
		t.Fatalf("staged in %s", pu.stage.Entry.Dir)
	}
	if v := visible(t, filepath.Join(f.root, "q/drop")); len(v) != 0 {
		t.Fatalf("endpoint queue holds %v", v)
	}
	head, body := sendAll(t, c, []byte("s3cr3t"))
	wantInner(t, "complete", head, body, http.StatusCreated)
	if b, err := os.ReadFile(filepath.Join(vol, "queue", created(t, body).ID, "payload")); err != nil || string(b) != "s3cr3t" {
		t.Fatalf("%v %q", err, b)
	}
}

func TestLinkReplaceInParts(t *testing.T) {
	f, srvURL, pin := chanFixture(t, func(s string) string {
		return strings.Replace(s, `respond: url, storage: drop}`, strings.Replace(allLinks, "}}", "}, parts: {size: 64K}}", 1), 1)
	})
	link := f.drop(t, f.user, wire.Meta{File: "a.txt", Mutable: true, Portal: wire.PortalDownload}, "old")
	data := content(testPart + 10)
	m := fileMeta(data)
	c := chanOpen(t, srvURL, "/drop", pin)
	metaS, err := wire.EncodeMeta(m)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set(wire.HeaderLink, link)
	h.Set(wire.HeaderLinkAction, wire.LinkReplace)
	h.Set(wire.HeaderMeta, metaS)
	signHeaders(t, f.user, h, wire.LinkNamespace, func(ts, nonce string) []byte {
		return wire.LinkCanonicalText(http.MethodPut, c.host, "/drop", link, wire.LinkReplace, ts, nonce, metaS, c.sess.H())
	})
	head, body := c.op(t, channel.Request{Method: http.MethodPut, Target: "/drop", Header: h}, nil)
	wantInner(t, "replace", head, body, http.StatusOK)
	head, body = sendAll(t, c, data)
	wantInner(t, "complete", head, body, http.StatusAccepted)
	var a wire.LinkAnswer
	if err := json.Unmarshal(body, &a); err != nil || a.URL != link || a.Size == nil || *a.Size != int64(len(data)) || a.SHA256 != m.SHA256 {
		t.Fatalf("%v %s", err, body)
	}
	f.settle(t)
	if sc := f.dropSidecar(t, link); sc.SHA256 != m.SHA256 {
		t.Fatalf("%+v", sc)
	}
}

// readPayloadAfter completes the upload of c and returns the sha256 of
// the committed payload.
func readPayloadAfter(t *testing.T, f *fixture, c *testChan) string {
	t.Helper()
	head, body := c.control(t, channel.KindComplete, 9, 0)
	wantInner(t, "complete", head, body, http.StatusCreated)
	out := created(t, body)
	b, err := os.ReadFile(filepath.Join(f.srv.config().Endpoint["drop"].Path, out.ID, "payload"))
	if err != nil {
		t.Fatal(err)
	}
	return sha(b)
}

// A forged PART with the id of a session changes nothing of its upload.
func TestPartForged(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(testPart + 1)
	c, _ := create(t, f, srvURL, pin, fileMeta(data))
	pu := uploadOf(t, f, c)
	cs := f.srv.chans.get(c.sess.ID())
	cs.mu.Lock()
	last := cs.last
	cs.mu.Unlock()
	msg := c.seal(t, channel.Nonce{Kind: channel.KindPart, Number: 0}, partOf(data, 0))
	msg[len(msg)-1] ^= 1
	resp, err := http.Post(srvURL+"/drop", channel.ContentType, bytes.NewReader(msg[:25+100]))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if pu.partState(0) != partAbsent {
		t.Fatalf("part state %v", pu.partState(0))
	}
	cs.mu.Lock()
	if !cs.last.Equal(last) {
		t.Error("a forged part refreshed the session")
	}
	cs.mu.Unlock()
	// The nonce of the forged message is still free.
	head, body := c.part(t, 0, 0, partOf(data, 0))
	wantInner(t, "part", head, body, http.StatusOK)
}

// A part that stops arriving after its first frame is answered 408 inside
// the channel, by the idle time of a read or by the rate limit, and the
// part goes back to a new attempt.
func TestPartStalled(t *testing.T) {
	for name, body := range map[string]string{
		"idle": "{idle: 1s, rate: 0}",
		"rate": "{idle: 30s, rate: 64K}",
	} {
		t.Run(name, func(t *testing.T) {
			f, srvURL, pin := partsFixture(t, "4", func(s string) string {
				return strings.Replace(s, `parts: {size: 64K`, `limits: {body: `+body+`}, parts: {size: 64K`, 1)
			})
			data := content(testPart)
			c, _ := create(t, f, srvURL, pin, fileMeta(data))
			pu := uploadOf(t, f, c)
			n := channel.Nonce{Kind: channel.KindPart}
			msg := c.seal(t, n, data)
			u, _ := url.Parse(srvURL)
			conn, err := net.Dial("tcp", u.Host)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(conn, "POST /drop HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", u.Host, channel.ContentType, len(msg))
			if _, err := conn.Write(msg[:25+channel.FrameSize+16]); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			head, out := c.inner(t, resp, n)
			wantInner(t, "stalled part", head, out, http.StatusRequestTimeout)
			if pu.partState(0) != partAbsent {
				t.Fatalf("part state %v", pu.partState(0))
			}
		})
	}
}

// openUploads is the number of open uploads in parts.
func openUploads(f *fixture) int {
	f.srv.uploads.mu.Lock()
	defer f.srv.uploads.mu.Unlock()
	return f.srv.uploads.total
}

// Two copies of the same upload OP (a replay on the path) open one
// upload, and the session keeps working for it. The copy is past the
// check for an OP already taken while the first one opens the upload.
func TestUploadOpReplayed(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(testPart + 10)
	c := chanOpen(t, srvURL, "/drop", pin)
	n := channel.Nonce{Kind: channel.KindOp}
	msg := c.seal(t, n, opPlain(t, c.putReq(t, f.user, fileMeta(data)), nil))
	pr, pw := io.Pipe()
	done := make(chan int, 1)
	go func() {
		resp, err := http.Post(srvURL+"/drop", channel.ContentType, pr)
		if err != nil {
			t.Error(err)
			done <- 0
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	if _, err := pw.Write(msg[:25]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	head, body := c.inner(t, c.postRaw(t, msg), n)
	wantInner(t, "first copy", head, body, http.StatusOK)
	if _, err := pw.Write(msg[25:]); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if code := <-done; code != http.StatusConflict {
		t.Fatalf("second copy: %d", code)
	}
	if n := openUploads(f); n != 1 {
		t.Fatalf("%d open uploads", n)
	}
	head, body = sendAll(t, c, data)
	wantInner(t, "complete", head, body, http.StatusCreated)
	if out := created(t, body); out.SHA256 != sha(data) {
		t.Fatalf("%+v", out)
	}
	if n := openUploads(f); n != 0 {
		t.Fatalf("%d open uploads after the commit", n)
	}
}

// Dropping a session ends its open upload: nothing of it is left.
func TestUploadDroppedWithSession(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(2 * testPart)
	c, _ := create(t, f, srvURL, pin, fileMeta(data))
	head, body := c.part(t, 0, 0, partOf(data, 0))
	wantInner(t, "part", head, body, http.StatusOK)
	pu := uploadOf(t, f, c)
	dir := pu.stage.Entry.Dir
	f.srv.chans.drop(f.srv.chans.get(c.sess.ID()))
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("staging left: %v", err)
	}
	if pu.stateOf() != upAborted {
		t.Fatalf("state %s", pu.stateOf())
	}
	if n := openUploads(f); n != 0 {
		t.Fatalf("%d open uploads", n)
	}
}

// Parts sent at once, the later ones first, make the whole content.
func TestPartsParallel(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(8*testPart - 77)
	c, _ := create(t, f, srvURL, pin, fileMeta(data))
	var codes [8]int
	var wg sync.WaitGroup
	for i := 7; i >= 0; i-- {
		wg.Go(func() {
			n := channel.Nonce{Kind: channel.KindPart, Number: uint32(i)}
			var buf bytes.Buffer
			if err := c.sess.SealRequest(&buf, n, bytes.NewReader(partOf(data, i))); err != nil {
				t.Error(err)
				return
			}
			resp, err := http.Post(srvURL+"/drop", channel.ContentType, &buf)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			rc, err := c.sess.OpenResponse(resp.Body, n)
			if err != nil {
				t.Error(err)
				return
			}
			var head channel.Response
			if err := channel.ReadHead(rc, &head); err != nil {
				t.Error(err)
				return
			}
			codes[i] = head.Status
		})
	}
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("part %d: %d", i, code)
		}
	}
	head, body := c.control(t, channel.KindComplete, 0, 0)
	wantInner(t, "complete", head, body, http.StatusCreated)
	if out := created(t, body); out.SHA256 != sha(data) || out.Size != int64(len(data)) {
		t.Fatalf("%+v", out)
	}
}

func TestPartWindowRetryAfter(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "1", nil)
	data := content(3 * testPart)
	c, _ := create(t, f, srvURL, pin, fileMeta(data))
	head, body := c.part(t, 2, 0, partOf(data, 2))
	wantInner(t, "ahead of the window", head, body, http.StatusTooManyRequests)
	if ra := head.Header.Get("Retry-After"); ra != "1" {
		t.Fatalf("Retry-After %q", ra)
	}
}

// A session that leaves the table while its OP opens an upload (evicted,
// swept) takes nothing of the upload with it.
func TestUploadSessionGoneBeforeAttach(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	testHookAttach = func(cs *chanSession) { f.srv.chans.drop(cs) }
	t.Cleanup(func() { testHookAttach = nil })
	c := chanOpen(t, srvURL, "/drop", pin)
	head, body := c.op(t, c.putReq(t, f.user, fileMeta(content(100))), nil)
	wantInner(t, "create in a dropped session", head, body, http.StatusNotFound)
	if v := visible(t, filepath.Join(f.root, "q/drop")); len(v) != 0 {
		t.Fatalf("queue holds %v", v)
	}
	if n := openUploads(f); n != 0 {
		t.Fatalf("%d open uploads", n)
	}
}

// An OP is not taken by a session that left the table while it was read.
func TestClaimOpSessionGone(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	c := chanOpen(t, srvURL, "/drop", pin)
	cs := f.srv.chans.get(c.sess.ID())
	f.srv.chans.drop(cs)
	if ok, gone := f.srv.chans.claim(cs, channel.Nonce{Kind: channel.KindOp}, f.srv.now()); ok || !gone {
		t.Fatalf("claimed %v, gone %v", ok, gone)
	}
}

// A session dropped while a complete holds its upload (here one that
// answers missing parts) ends the upload once the complete is done.
func TestUploadDroppedWhileFinishing(t *testing.T) {
	f, srvURL, pin := partsFixture(t, "4", nil)
	data := content(2 * testPart)
	c, _ := create(t, f, srvURL, pin, fileMeta(data))
	pu := uploadOf(t, f, c)
	dir := pu.stage.Entry.Dir
	pu.finish.Lock()
	f.srv.chans.drop(f.srv.chans.get(c.sess.ID()))
	if pu.stateOf() != upOpen {
		t.Fatalf("state %s while finishing", pu.stateOf())
	}
	a := pu.completeLocked(f.srv, httptest.NewRequest(http.MethodPut, "/drop", nil))
	if a.code != http.StatusConflict {
		t.Fatalf("complete %d", a.code)
	}
	pu.releaseFinish()
	if pu.stateOf() != upAborted {
		t.Fatalf("state %s", pu.stateOf())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("staging left: %v", err)
	}
	if n := openUploads(f); n != 0 {
		t.Fatalf("%d open uploads", n)
	}
}
