package server

import (
	"bufio"
	"bytes"
	"encoding/base64"
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

	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/config"
	"luk/internal/sshsig"
	"luk/internal/wire"
)

// writeIdentity writes a new identity key next to the config file cfgPath.
func writeIdentity(t *testing.T, cfgPath string) channel.Key {
	t.Helper()
	k, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.WriteKey(config.IdentityPath(cfgPath), k); err != nil {
		t.Fatal(err)
	}
	return k
}

// chanFixture is the fixture loaded from a directory with an identity key
// next to its config, served over HTTP; mod rewrites the config text. It
// returns the URL of the server and the public identity key, the pin.
func chanFixture(t *testing.T, mod func(string) string) (*fixture, string, []byte) {
	t.Helper()
	var k channel.Key
	f := newFixtureDir(t, mod, func(dir string, _ ssh.Signer) { k = writeIdentity(t, filepath.Join(dir, "config.yaml")) })
	if err := f.srv.loadIdentity(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return f, srv.URL, k.Public
}

// testChan is the client side of one channel session.
type testChan struct {
	url, host, path string
	sess            *channel.Session
}

// handshake posts the first handshake message to path.
func handshake(t *testing.T, srvURL, path string) (*channel.ClientHandshake, *http.Response, []byte) {
	t.Helper()
	u, err := url.Parse(srvURL)
	if err != nil {
		t.Fatal(err)
	}
	hs, msg, err := channel.NewClientHandshake(u.Host, path)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(srvURL+path, channel.ContentType, bytes.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return hs, resp, body
}

// chanOpen finishes a handshake on path and checks the key of lukd
// against pin.
func chanOpen(t *testing.T, srvURL, path string, pin []byte) *testChan {
	t.Helper()
	hs, resp, body := handshake(t, srvURL, path)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != channel.ContentType {
		t.Fatalf("handshake: %d %s: %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	sess, static, err := hs.Finish(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(static, pin) {
		t.Fatal("lukd key is not the pinned one")
	}
	u, _ := url.Parse(srvURL)
	return &testChan{url: srvURL, host: u.Host, path: path, sess: sess}
}

// post sends a transport request of nonce n carrying plain to path.
func (c *testChan) post(t *testing.T, path string, n channel.Nonce, plain []byte) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if err := c.sess.SealRequest(&buf, n, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(c.url+path, channel.ContentType, &buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// opPlain is the plaintext of an OP.
func opPlain(t *testing.T, req channel.Request, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := channel.WriteHead(&buf, req); err != nil {
		t.Fatal(err)
	}
	buf.Write(body)
	return buf.Bytes()
}

// opRaw sends the OP and returns the outer response.
func (c *testChan) opRaw(t *testing.T, req channel.Request, body []byte) *http.Response {
	t.Helper()
	return c.post(t, c.path, channel.Nonce{Kind: channel.KindOp}, opPlain(t, req, body))
}

// op sends the OP of the session and returns the inner response.
func (c *testChan) op(t *testing.T, req channel.Request, body []byte) (channel.Response, []byte) {
	t.Helper()
	resp := c.opRaw(t, req, body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("op: outer %d: %s", resp.StatusCode, b)
	}
	rc, err := c.sess.OpenResponse(resp.Body, channel.Nonce{Kind: channel.KindOp})
	if err != nil {
		t.Fatal(err)
	}
	var head channel.Response
	if err := channel.ReadHead(rc, &head); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return head, out
}

// chanDo runs one OP in a new session on path.
func chanDo(t *testing.T, srvURL, path string, pin []byte, req channel.Request, body []byte) (channel.Response, []byte) {
	t.Helper()
	return chanOpen(t, srvURL, path, pin).op(t, req, body)
}

// signHeaders sets the signature headers of text signed under ns on h.
func signHeaders(t *testing.T, signer ssh.Signer, h http.Header, ns string, text func(ts, nonce string) []byte) http.Header {
	t.Helper()
	if h == nil {
		h = http.Header{}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := wire.NewNonce()
	sig, err := sshsig.Sign(signer, ns, text(ts, nonce))
	if err != nil {
		t.Fatal(err)
	}
	h.Set(wire.HeaderTimestamp, ts)
	h.Set(wire.HeaderNonce, nonce)
	h.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
	return h
}

// listReq is a signed endpoint listing OP of c whose text uses session
// hash h under the v2 namespace.
func (c *testChan) listReq(t *testing.T, signer ssh.Signer, h []byte) channel.Request {
	t.Helper()
	return channel.Request{Method: http.MethodGet, Target: wire.EndpointsPath, Header: signHeaders(t, signer, nil, wire.ListNamespaceV2,
		func(ts, nonce string) []byte {
			return wire.ListCanonicalTextV2(http.MethodGet, c.host, wire.EndpointsPath, ts, nonce, h)
		})}
}

func wantOuter(t *testing.T, what string, resp *http.Response, code int) {
	t.Helper()
	if resp.StatusCode != code {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s: %d, want %d: %s", what, resp.StatusCode, code, b)
	}
}

func TestChannelExposeNotReachable(t *testing.T) {
	f, srvURL, pin := chanFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{File: "a.txt"}, "hello")
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, resp, body := handshake(t, srvURL, u.Path); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("handshake on an expose path: %d %s", resp.StatusCode, body)
	}
	if head, body := chanDo(t, srvURL, "/drop", pin, channel.Request{Method: http.MethodGet, Target: u.Path}, nil); head.Status != http.StatusNotFound {
		t.Fatalf("expose GET inside the channel: %d %s", head.Status, body)
	}
	resp, err := http.Get(srvURL + u.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); resp.StatusCode != 200 || string(b) != "hello" {
		t.Fatalf("plain GET: %d %s", resp.StatusCode, b)
	}
}

func TestChannelSignedList(t *testing.T) {
	f, srvURL, pin := chanFixture(t, nil)
	c := chanOpen(t, srvURL, wire.EndpointsPath, pin)
	head, body := c.op(t, c.listReq(t, f.user, c.sess.H()), nil)
	if head.Status != http.StatusOK {
		t.Fatalf("%d %s", head.Status, body)
	}
	var list wire.EndpointList
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Endpoints) != 2 || list.Endpoints[1].Name != "drop" {
		t.Fatalf("%+v", list)
	}

	v1 := chanOpen(t, srvURL, wire.EndpointsPath, pin)
	req := channel.Request{Method: http.MethodGet, Target: wire.EndpointsPath, Header: signHeaders(t, f.user, nil, wire.ListNamespace,
		func(ts, nonce string) []byte {
			return wire.ListCanonicalText(http.MethodGet, v1.host, wire.EndpointsPath, ts, nonce)
		})}
	if head, body := v1.op(t, req, nil); head.Status != http.StatusUnauthorized {
		t.Fatalf("v1 text: %d %s", head.Status, body)
	}

	other := chanOpen(t, srvURL, wire.EndpointsPath, pin)
	if head, body := other.op(t, other.listReq(t, f.user, c.sess.H()), nil); head.Status != http.StatusUnauthorized {
		t.Fatalf("h of another session: %d %s", head.Status, body)
	}
}

func TestChannelLinkList(t *testing.T) {
	f, srvURL, pin := chanFixture(t, func(s string) string {
		return strings.Replace(s, `respond: url, storage: drop}`, `respond: url, storage: drop, link: {list: ['*']}}`, 1)
	})
	link := f.drop(t, f.user, wire.Meta{File: "a.txt"}, "hello")
	c := chanOpen(t, srvURL, "/drop", pin)
	metaS, err := wire.EncodeLinkMeta(wire.LinkMeta{})
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set(wire.HeaderLinkAction, wire.LinkList)
	h.Set(wire.HeaderMeta, metaS)
	signHeaders(t, f.user, h, wire.LinkNamespaceV2, func(ts, nonce string) []byte {
		return wire.LinkCanonicalTextV2(http.MethodGet, c.host, "/drop", "", wire.LinkList, ts, nonce, metaS, c.sess.H())
	})
	head, body := c.op(t, channel.Request{Method: http.MethodGet, Target: "/drop", Header: h}, nil)
	if head.Status != http.StatusOK {
		t.Fatalf("%d %s", head.Status, body)
	}
	var a wire.LinkListAnswer
	if err := json.Unmarshal(body, &a); err != nil {
		t.Fatal(err)
	}
	if len(a.Links) != 1 || a.Links[0].URL != link {
		t.Fatalf("%+v, want %s", a, link)
	}
}

func TestChannelUpload(t *testing.T) {
	f, srvURL, pin := chanFixture(t, nil)
	meta := wire.Meta{Portal: wire.PortalDirect, File: "a.txt", Source: wire.SourceStdin}
	c, offer := create(t, f, srvURL, pin, meta)
	if offer.Parts.Size != 8<<20 || offer.Parts.Parallel != 4 {
		t.Fatalf("%+v", offer)
	}
	head, body := c.part(t, 0, 0, []byte("hello"))
	wantInner(t, "part", head, body, http.StatusOK)
	head, body = c.control(t, channel.KindComplete, 0, 0)
	wantInner(t, "complete", head, body, http.StatusCreated)
	var out wire.Created
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	f.settle(t)
	if code, got := f.fetch(t, out.URL); code != 200 || got != "hello" {
		t.Fatalf("%d %s", code, got)
	}
}

// An upload OP carries no body inside the channel.
func TestChannelUploadBodyRefused(t *testing.T) {
	f, srvURL, pin := chanFixture(t, nil)
	c := chanOpen(t, srvURL, "/drop", pin)
	head, body := c.op(t, c.putReq(t, f.user, wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}), []byte("hello"))
	wantInner(t, "OP with a body", head, body, http.StatusBadRequest)
	if f.srv.chans.get(c.sess.ID()) != nil {
		t.Fatal("session kept without an upload")
	}
}

func TestChannelWrongPath(t *testing.T) {
	_, srvURL, pin := chanFixture(t, nil)
	c := chanOpen(t, srvURL, "/drop", pin)
	resp := c.post(t, "/other", channel.Nonce{Kind: channel.KindOp}, opPlain(t, channel.Request{Method: http.MethodGet, Target: "/drop"}, nil))
	wantOuter(t, "transport to another path", resp, http.StatusNotFound)
}

func TestChannelSessionEndsAfterOp(t *testing.T) {
	f, srvURL, pin := chanFixture(t, nil)
	c := chanOpen(t, srvURL, wire.EndpointsPath, pin)
	req := channel.Request{Method: http.MethodGet, Target: wire.EndpointsPath}
	if head, body := c.op(t, req, nil); head.Status != http.StatusUnauthorized {
		t.Fatalf("unsigned list: %d %s", head.Status, body)
	}
	if f.srv.chans.get(c.sess.ID()) != nil {
		t.Fatal("session kept after its OP was answered")
	}
	wantOuter(t, "after the OP", c.opRaw(t, req, nil), http.StatusNotFound)
}

// A forged OP to a session that has had its OP, with the channel id
// from the clear header, is refused without ending the session.
func TestChannelForgedSecondOp(t *testing.T) {
	f, srvURL, pin := chanFixture(t, nil)
	c := chanOpen(t, srvURL, "/drop", pin)
	cs := f.srv.chans.get(c.sess.ID())
	if !cs.claimOp(channel.Nonce{Kind: channel.KindOp, Attempt: 9}, f.srv.now()) {
		t.Fatal("claim")
	}
	f.srv.chans.opened(cs)
	var buf bytes.Buffer
	if err := c.sess.SealRequest(&buf, channel.Nonce{Kind: channel.KindOp}, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	forged := append(buf.Bytes()[:25:25], bytes.Repeat([]byte{7}, 40)...)
	resp, err := http.Post(srvURL+"/drop", channel.ContentType, bytes.NewReader(forged))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	wantOuter(t, "forged second OP", resp, http.StatusConflict)
	if f.srv.chans.get(c.sess.ID()) != cs {
		t.Fatal("a forged OP ended the session")
	}
}

func TestChannelConcurrentOps(t *testing.T) {
	_, srvURL, pin := chanFixture(t, nil)
	c := chanOpen(t, srvURL, wire.EndpointsPath, pin)
	var bodies [2][]byte
	for i := range bodies {
		var buf bytes.Buffer
		plain := opPlain(t, channel.Request{Method: http.MethodGet, Target: wire.EndpointsPath}, nil)
		if err := c.sess.SealRequest(&buf, channel.Nonce{Kind: channel.KindOp, Attempt: uint16(i)}, bytes.NewReader(plain)); err != nil {
			t.Fatal(err)
		}
		bodies[i] = buf.Bytes()
	}
	var codes [2]int
	var wg sync.WaitGroup
	for i := range bodies {
		wg.Go(func() {
			resp, err := http.Post(srvURL+wire.EndpointsPath, channel.ContentType, bytes.NewReader(bodies[i]))
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			codes[i] = resp.StatusCode
		})
	}
	wg.Wait()
	won := 0
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			won++
		case http.StatusConflict, http.StatusNotFound:
		default:
			t.Errorf("status %d", code)
		}
	}
	if won != 1 {
		t.Fatalf("%v: %d OPs ran, want 1", codes, won)
	}
}

// stalled sends the head of a POST with a body of n bytes and only
// prefix of it, and returns the status lukd answers before the client
// gives up.
func stalled(t *testing.T, srvURL, path string, n int, prefix []byte) int {
	t.Helper()
	u, err := url.Parse(srvURL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", path, u.Host, channel.ContentType, n)
	if _, err := conn.Write(prefix); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer to a stalled body: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestChannelStalledBody(t *testing.T) {
	_, srvURL, pin := chanFixture(t, func(s string) string { return s + "limits: {header: {timeout: 1s}, channel: {auth: 1s}}\n" })
	if code := stalled(t, srvURL, "/drop", 33, []byte{1}); code != http.StatusRequestTimeout {
		t.Fatalf("stalled handshake: %d", code)
	}
	c := chanOpen(t, srvURL, "/drop", pin)
	var buf bytes.Buffer
	if err := c.sess.SealRequest(&buf, channel.Nonce{Kind: channel.KindOp}, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	if code := stalled(t, srvURL, "/drop", 1000, buf.Bytes()[:25]); code != http.StatusRequestTimeout {
		t.Fatalf("stalled OP: %d", code)
	}
}

// A v2 signature in HTTP headers, outside the channel, does not verify.
func TestChannelV2OutsideChannel(t *testing.T) {
	f, _, _ := chanFixture(t, nil)
	const host = "lukd.test"
	hr := httptest.NewRequest(http.MethodGet, "https://"+host+wire.EndpointsPath, nil)
	hr.Header = signHeaders(t, f.user, nil, wire.ListNamespaceV2, func(ts, nonce string) []byte {
		return wire.ListCanonicalTextV2(http.MethodGet, host, wire.EndpointsPath, ts, nonce, nil)
	})
	rec := httptest.NewRecorder()
	f.handler().ServeHTTP(rec, hr)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// A PART to a session without an upload is refused in the clear.
func TestChannelPartWithoutUpload(t *testing.T) {
	_, srvURL, pin := chanFixture(t, nil)
	c := chanOpen(t, srvURL, "/drop", pin)
	wantOuter(t, "PART", c.post(t, "/drop", channel.Nonce{Kind: channel.KindPart, Number: 1}, []byte("x")), http.StatusNotFound)
}

func TestChannelTamperedOp(t *testing.T) {
	_, srvURL, pin := chanFixture(t, nil)
	c := chanOpen(t, srvURL, wire.EndpointsPath, pin)
	var buf bytes.Buffer
	if err := c.sess.SealRequest(&buf, channel.Nonce{Kind: channel.KindOp}, bytes.NewReader(opPlain(t, channel.Request{Method: http.MethodGet, Target: wire.EndpointsPath}, nil))); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	b[len(b)-1] ^= 1
	resp, err := http.Post(srvURL+wire.EndpointsPath, channel.ContentType, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	wantOuter(t, "tampered OP", resp, http.StatusBadRequest)
	// A message that did not open is no OP: the session still takes one.
	if head, body := c.op(t, channel.Request{Method: http.MethodGet, Target: wire.EndpointsPath}, nil); head.Status != http.StatusUnauthorized {
		t.Fatalf("%d %s", head.Status, body)
	}
}

func TestChannelPendingEviction(t *testing.T) {
	_, srvURL, pin := chanFixture(t, func(s string) string { return s + "limits: {channel: {pending: 2}}\n" })
	first := chanOpen(t, srvURL, wire.EndpointsPath, pin)
	chanOpen(t, srvURL, wire.EndpointsPath, pin)
	third := chanOpen(t, srvURL, wire.EndpointsPath, pin)
	req := channel.Request{Method: http.MethodGet, Target: wire.EndpointsPath}
	wantOuter(t, "evicted session", first.opRaw(t, req, nil), http.StatusNotFound)
	wantOuter(t, "newest session", third.opRaw(t, req, nil), http.StatusOK)
}

func TestChannelAuthTimeout(t *testing.T) {
	f, srvURL, pin := chanFixture(t, func(s string) string { return s + "limits: {channel: {auth: 1s}}\n" })
	var mu sync.Mutex
	now := time.Now()
	f.srv.SetClock(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	})
	old := chanOpen(t, srvURL, wire.EndpointsPath, pin)
	mu.Lock()
	now = now.Add(2 * time.Second)
	mu.Unlock()
	fresh := chanOpen(t, srvURL, wire.EndpointsPath, pin)
	f.srv.chans.sweep(f.srv.now())
	req := channel.Request{Method: http.MethodGet, Target: wire.EndpointsPath}
	wantOuter(t, "expired session", old.opRaw(t, req, nil), http.StatusNotFound)
	wantOuter(t, "fresh session", fresh.opRaw(t, req, nil), http.StatusOK)
}

func TestChannelIdentityRequired(t *testing.T) {
	f := newFixtureDir(t, nil, func(string, ssh.Signer) {})
	err := f.srv.loadIdentity()
	if err == nil || !strings.Contains(err.Error(), "lukd key generate") || !strings.Contains(err.Error(), f.srv.config().IdentityPath) {
		t.Fatalf("%v", err)
	}
}

func TestChannelIdentityReload(t *testing.T) {
	f, srvURL, pin := chanFixture(t, nil)
	if err := os.WriteFile(f.srv.config().IdentityPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.srv.reload()
	// A key that does not load keeps the one in use.
	chanOpen(t, srvURL, wire.EndpointsPath, pin)
	k, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.WriteKey(f.srv.config().IdentityPath, k); err != nil {
		t.Fatal(err)
	}
	f.srv.reload()
	chanOpen(t, srvURL, wire.EndpointsPath, k.Public)
}

// seal is the body of a transport request of nonce n carrying plain.
func (c *testChan) seal(t *testing.T, n channel.Nonce, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := c.sess.SealRequest(&buf, n, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// inner is the inner response to the request of nonce n; the outer
// response must be a 200.
func (c *testChan) inner(t *testing.T, resp *http.Response, n channel.Nonce) (channel.Response, []byte) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("outer %d: %s", resp.StatusCode, b)
	}
	rc, err := c.sess.OpenResponse(resp.Body, n)
	if err != nil {
		t.Fatal(err)
	}
	var head channel.Response
	if err := channel.ReadHead(rc, &head); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return head, out
}

// part sends part n, attempt a, carrying data; it returns the inner
// response.
func (c *testChan) part(t *testing.T, n uint32, a uint16, data []byte) (channel.Response, []byte) {
	t.Helper()
	nonce := channel.Nonce{Kind: channel.KindPart, Number: n, Attempt: a}
	return c.inner(t, c.post(t, c.path, nonce, data), nonce)
}

// control sends a COMPLETE or an ABORT of sequence seq, attempt a; it
// returns the inner response.
func (c *testChan) control(t *testing.T, kind channel.Kind, seq uint32, a uint16) (channel.Response, []byte) {
	t.Helper()
	nonce := channel.Nonce{Kind: kind, Number: seq, Attempt: a}
	return c.inner(t, c.post(t, c.path, nonce, nil), nonce)
}

// putReq is the signed upload OP of meta on the session path.
func (c *testChan) putReq(t *testing.T, signer ssh.Signer, meta wire.Meta) channel.Request {
	t.Helper()
	if err := meta.Normalize(); err != nil {
		t.Fatal(err)
	}
	metaS, err := wire.EncodeMeta(meta)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set(wire.HeaderMeta, metaS)
	signHeaders(t, signer, h, wire.NamespaceV2, func(ts, nonce string) []byte {
		return wire.CanonicalTextV2(c.host, c.path, ts, nonce, metaS, c.sess.H())
	})
	return channel.Request{Method: http.MethodPut, Target: c.path, Header: h}
}

// create opens an upload of meta in a new session on /drop and returns
// the session and the offer.
func create(t *testing.T, f *fixture, srvURL string, pin []byte, meta wire.Meta) (*testChan, wire.PartsOffer) {
	t.Helper()
	c := chanOpen(t, srvURL, "/drop", pin)
	head, body := c.op(t, c.putReq(t, f.user, meta), nil)
	if head.Status != http.StatusOK {
		t.Fatalf("create: %d %s", head.Status, body)
	}
	var offer wire.PartsOffer
	if err := json.Unmarshal(body, &offer); err != nil {
		t.Fatal(err)
	}
	return c, offer
}

func wantInner(t *testing.T, what string, head channel.Response, body []byte, code int) {
	t.Helper()
	if head.Status != code {
		t.Fatalf("%s: %d, want %d: %s", what, head.Status, code, body)
	}
}
