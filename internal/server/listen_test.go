package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/config"
	"luk/internal/sshsig"
	"luk/internal/tlsself"
	"luk/internal/wire"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// signedPut is a signed upload of body to base+path with the given Host.
func signedPut(t *testing.T, signer ssh.Signer, base, host, path string, body []byte) *http.Request {
	t.Helper()
	return signedPutMeta(t, signer, base, host, path, fileMeta(body), body)
}

func signedPutMeta(t *testing.T, signer ssh.Signer, base, host, path string, meta wire.Meta, body []byte) *http.Request {
	t.Helper()
	if err := meta.Normalize(); err != nil {
		t.Fatal(err)
	}
	metaS, err := wire.EncodeMeta(meta)
	if err != nil {
		t.Fatal(err)
	}
	ts, nonce := time.Now().UTC().Format(time.RFC3339), wire.NewNonce()
	sig, err := sshsig.Sign(signer, wire.Namespace, wire.CanonicalText(host, path, ts, nonce, metaS))
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPut, base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = host
	r.Header.Set(wire.HeaderMeta, metaS)
	r.Header.Set(wire.HeaderTimestamp, ts)
	r.Header.Set(wire.HeaderNonce, nonce)
	r.Header.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
	return r
}

type listenEnv struct {
	user          ssh.Signer
	shared, plain string
	pins          map[string]string
	client        *http.Client
}

// serveListeners runs both lukd roles with two TLS listeners sharing one address
// (intake: uploads for a.vm, download: the drop expose at / for b.vm) and
// a plain proxied listener with a public URL, the first of the expose.
func serveListeners(t *testing.T, connMax int) *listenEnv {
	t.Helper()
	root := t.TempDir()
	e := &listenEnv{user: newSigner(t), shared: freePort(t), plain: freePort(t), pins: map[string]string{}}
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
root: %s
listen:
  intake:
    addr: %s
    host: [a.vm]
    tls: {mode: self, cert: tls/a.crt, key: tls/a.key, host: a.vm}
  download:
    addr: %s
    host: [B.vm]
    tls: {mode: self, algorithm: ecdsa-p256, cert: tls/b.crt, key: tls/b.key, host: b.vm}
  proxied:
    addr: %s
    host: [drop.example.com]
    public: https://drop.example.com
limits: {conn: {max: %d}}
auth:
  keys: [{name: robert.socha, key: "%s"}]
endpoint:
  up: {listen: intake, endpoint: /up, path: q/up, allow: [robert.socha], respond: url, storage: drop}
pipeline:
  drop: {endpoint: [up], steps: [{store: drop}]}
storage:
  drop: {type: local, base: s/drop, path: "{{ .Random }}", expose: drop}
expose:
  drop: {listen: [proxied, download], path: /}
`, root, e.shared, e.shared, e.plain, connMax, pubLine(e.user.PublicKey()))))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"intake", "download"} {
		l := cfg.Listen[n]
		pin, err := tlsself.Generate(l.TLS.Cert, l.TLS.Key, l.TLS.Host, l.TLS.Algorithm)
		if err != nil {
			t.Fatal(err)
		}
		e.pins[n] = pin
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 2)
	go func() { done <- Receive(ctx, cfg, slog.New(slog.DiscardHandler)) }()
	go func() { done <- Process(ctx, cfg, slog.New(slog.DiscardHandler)) }()
	t.Cleanup(func() {
		cancel()
		for range 2 {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	})
	for _, a := range []string{e.shared, e.plain} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			c, err := net.Dial("tcp", a)
			if err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s not listening", a)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	e.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	t.Cleanup(e.client.CloseIdleConnections)
	return e
}

func peerPin(t *testing.T, addr, serverName string) string {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return tlsself.Pin(c.ConnectionState().PeerCertificates[0])
}

func TestListenersSNI(t *testing.T) {
	e := serveListeners(t, 16)
	for name, want := range map[string]string{"a.vm": e.pins["intake"], "b.vm": e.pins["download"], "B.VM": e.pins["download"], "": e.pins["download"], "c.vm": e.pins["download"]} {
		if got := peerPin(t, e.shared, name); got != want {
			t.Errorf("sni %q: pin %s, want %s", name, got, want)
		}
	}
}

func TestListenersRouting(t *testing.T) {
	e := serveListeners(t, 16)
	get := func(base, host, path string) (int, string) {
		t.Helper()
		r, _ := http.NewRequest(http.MethodGet, base+path, nil)
		r.Host = host
		resp, err := e.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	tlsBase, plainBase := "https://"+e.shared, "http://"+e.plain

	resp, err := e.client.Do(signedPut(t, e.user, tlsBase, "a.vm:443", "/up", []byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	var out wire.Receipt
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload %d %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	name, ok := strings.CutPrefix(out.URL, "https://drop.example.com/")
	if !ok || len(name) != 32 {
		t.Fatalf("url %q", out.URL)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if code, body := get(plainBase, "drop.example.com", "/"+name); code == 200 && body == "hello" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not published on the proxied listener")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, c := range []struct {
		base, host, path string
		code             int
	}{
		{tlsBase, "b.vm", "/" + name, 200},
		{tlsBase, "B.VM:8443", "/" + name, 200},
		{tlsBase, "a.vm", "/" + name, 404},
		{tlsBase, "a.vm", "/up", 405},
		{tlsBase, "c.vm", "/" + name, 421},
		{plainBase, "b.vm", "/" + name, 421},
		{plainBase, "Drop.Example.com:80", "/" + name, 200},
	} {
		if code, body := get(c.base, c.host, c.path); code != c.code {
			t.Errorf("%s %s%s: %d %s, want %d", c.base, c.host, c.path, code, body, c.code)
		}
	}
	// An upload to a listener without endpoints (405 there), and one
	// replayed towards another host of the same server, are refused.
	for _, c := range []struct {
		base, signed, sent string
		code               int
	}{
		{tlsBase, "b.vm", "b.vm", 405},
		{plainBase, "a.vm", "a.vm", 421},
		{tlsBase, "a.vm", "b.vm", 405},
	} {
		r := signedPut(t, e.user, c.base, c.signed, "/up", []byte("x"))
		r.Host = c.sent
		resp, err := e.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.code {
			t.Errorf("put signed %s sent %s to %s: %d, want %d", c.signed, c.sent, c.base, resp.StatusCode, c.code)
		}
	}
}

func TestListenersConnLimitPerAddress(t *testing.T) {
	e := serveListeners(t, 1)
	// retry until the slot of the readiness probe is released
	retry := func(fn func() error) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := fn()
			if err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	var held *tls.Conn
	retry(func() (err error) {
		held, err = tls.Dial("tcp", e.shared, &tls.Config{ServerName: "a.vm", InsecureSkipVerify: true})
		return err
	})
	defer held.Close()
	// Another address has its own limit.
	retry(func() error {
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + e.plain + "/x")
		if err == nil {
			resp.Body.Close()
		}
		return err
	})
	c, err := net.DialTimeout("tcp", e.shared, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("second connection to the shared address not closed: %d %v", n, err)
	}
}

func TestHostCheckAfterSignature(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		return strings.Replace(s, `main: {addr: "127.0.0.1:0",`, `main: {addr: "127.0.0.1:0", host: [a.vm],`, 1)
	})
	body := []byte("abcd")
	// A second listener for b.vm with the same endpoints: a request signed
	// for a.vm replayed there fails even though the signature verifies.
	other := &listener{cfg: &config.Listen{Name: "other", Host: config.StringList{"b.vm"}}, byPath: f.srv.cur().listeners["main"].byPath}
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", host: "a.vm", meta: fileMeta(body, "prod"), body: body,
		via: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.srv.serveHTTP(w, r, f.srv.cur(), other) })})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "not served by listen other") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", host: "A.vm:8443", meta: fileMeta(body, "prod"), body: body})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("own host: %d %s", rec.Code, rec.Body)
	}
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", host: "b.vm", meta: fileMeta(body, "prod"), body: body})
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("unknown host: %d %s", rec.Code, rec.Body)
	}
}

func TestPublicURLInCreated(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, `listen: {main: {addr: "127.0.0.1:0", public: "https://lukd.vm:8443"}}`,
			"listen:\n  main: {addr: \"127.0.0.1:0\"}\n  pub: {addr: \"127.0.0.1:1\", host: [x.vm], tls: {mode: self, cert: c, key: k, host: x.vm}}\n  web: {addr: \"127.0.0.1:2\", public: \"https://files.example.com/\"}", 1)
		return strings.Replace(s, "drop: {listen: main, path: /d/}", "drop: {listen: [web, pub], path: /d/}", 1)
	})
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, File: "a b.txt", Source: wire.SourceStdin}, body: []byte("x"), chunked: true})
	out := receipt(t, rec, http.StatusCreated)
	if u, err := url.Parse(out.URL); err != nil || u.Scheme != "https" || u.Host != "files.example.com" || !strings.HasPrefix(u.Path, "/d/") {
		t.Fatalf("url %q", out.URL)
	}
	if got := f.srv.config().Listen["pub"].Public; got != "https://x.vm:1" {
		t.Fatalf("derived public %q", got)
	}
}

func TestHandshakeErrorLogLevel(t *testing.T) {
	for _, level := range []string{"info", "debug"} {
		cfg, err := config.Parse([]byte(fmt.Sprintf(`
root: %s
listen:
  main: {addr: %s, tls: {mode: self, cert: tls/a.crt, key: tls/a.key, host: a.vm}}
log: {level: %s}
`, t.TempDir(), freePort(t), level)))
		if err != nil {
			t.Fatal(err)
		}
		l := cfg.Listen["main"]
		if _, err := tlsself.Generate(l.TLS.Cert, l.TLS.Key, l.TLS.Host, l.TLS.Algorithm); err != nil {
			t.Fatal(err)
		}
		if err := prepareDirs(cfg, true); err != nil {
			t.Fatal(err)
		}
		logs := &syncBuf{}
		s := New(cfg, NewLogger(logs, cfg))
		certs, err := loadCerts(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		servers, err := s.listen(cfg, certs, make(chan error, 1))
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("tcp", l.Addr)
		if err != nil {
			t.Fatal(err)
		}
		// Not a TLS record: the handshake fails, is logged and the
		// connection closed, so the read ends after the log line.
		_, _ = c.Write([]byte("garbage\r\n\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(io.Discard, c)
		c.Close()
		for _, srv := range servers {
			srv.Close()
		}
		shown := strings.Contains(logs.String(), `level=DEBUG msg="http: TLS handshake error from `)
		if shown != (level == "debug") || strings.Contains(logs.String(), "level=INFO msg=\"http:") {
			t.Errorf("%s: %s", level, logs)
		}
	}
}

func TestHTTPErrorsPanicIsError(t *testing.T) {
	var logs bytes.Buffer
	httpErrors{slog.New(slog.NewTextHandler(&logs, nil))}.Write([]byte("http: panic serving 192.0.2.1:1234: boom\n"))
	if !strings.Contains(logs.String(), `level=ERROR msg="http: panic serving 192.0.2.1:1234: boom"`) {
		t.Fatal(logs.String())
	}
}

// A plain listener answers HTTP/2 with prior knowledge, as a proxy ending
// TLS on a TCP route sends it.
func TestPlainListenerH2C(t *testing.T) {
	e := serveListeners(t, 16)
	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	defer tr.CloseIdleConnections()
	r, _ := http.NewRequest(http.MethodGet, "http://"+e.plain+"/nothing", nil)
	r.Host = "drop.example.com"
	resp, err := (&http.Client{Transport: tr}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("%s %d", resp.Proto, resp.StatusCode)
	}
}

// The server announces MaxStreams as its SETTINGS_MAX_CONCURRENT_STREAMS:
// an HTTP/2 connection runs at most that many requests at once.
func TestH2CMaxStreams(t *testing.T) {
	e := serveListeners(t, 16)
	c, err := net.Dial("tcp", e.plain)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// The client preface and an empty SETTINGS frame.
	if _, err := c.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[3] != 0x4 {
		t.Fatalf("first frame type %d", hdr[3])
	}
	payload := make([]byte, int(hdr[0])<<16|int(hdr[1])<<8|int(hdr[2]))
	if _, err := io.ReadFull(c, payload); err != nil {
		t.Fatal(err)
	}
	for i := 0; i+6 <= len(payload); i += 6 {
		id := int(payload[i])<<8 | int(payload[i+1])
		v := int(payload[i+2])<<24 | int(payload[i+3])<<16 | int(payload[i+4])<<8 | int(payload[i+5])
		if id == 0x3 {
			if v != MaxStreams {
				t.Fatalf("max concurrent streams %d", v)
			}
			return
		}
	}
	t.Fatalf("no max concurrent streams in %x", payload)
}

// deadlineRecorder records the write deadlines set through a
// ResponseController.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

// A download leaves its write deadline on the connection for the final
// flush; every request clears it first, so a long upload on the same
// keep-alive connection can still write its answer.
func TestRequestClearsWriteDeadline(t *testing.T) {
	f := newFixture(t)
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	f.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443/nothing", nil))
	if len(w.deadlines) == 0 || !w.deadlines[0].IsZero() {
		t.Fatalf("deadlines %v", w.deadlines)
	}
}
