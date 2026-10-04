package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/config"
	"luk/internal/sshsig"
	"luk/internal/store"
	"luk/internal/tlsself"
	"luk/internal/wire"
)

// privateFixture is the fixture with a second identity (other), the
// listener secure (tls mode self, host secure.vm) and the expose secure on
// it with auth.ssh allow ["*"], the protect expose of the drop storage;
// /drop accepts both private modes and the link remove and list. mod
// rewrites the config text further.
type privateFixture struct {
	*fixture
	other ssh.Signer
	pin   string
}

func newPrivateFixture(t *testing.T, mod func(string) string) *privateFixture {
	t.Helper()
	other := newSigner(t)
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "s.crt"), filepath.Join(dir, "s.key")
	pin, err := tlsself.Generate(crt, key, "secure.vm", tlsself.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, `public: "https://lukd.vm:8443"}}`,
			`public: "https://lukd.vm:8443"}, secure: {addr: "127.0.0.1:443", host: [secure.vm], tls: {mode: self, cert: `+crt+`, key: `+key+`, host: secure.vm}}}`, 1)
		s = strings.Replace(s, `keys: [{name: robert.socha, key: "`, `keys: [{name: other, key: "`+pubLine(other.PublicKey())+`"}, {name: robert.socha, key: "`, 1)
		s = strings.Replace(s, `allow: [robert.socha], respond: url, storage: drop}`,
			`allow: [robert.socha, other, "hosts:*"], respond: url, storage: drop, private: {owner: ['*'], any: ['*']}, link: {remove: ['*'], list: ['*']}}`, 1)
		s = strings.Replace(s, `expose: drop}`, `expose: drop, protect: secure}`, 1)
		s = strings.Replace(s, `drop: {listen: main, path: /d/}`, `drop: {listen: main, path: /d/}
  secure: {listen: secure, path: /, auth: {ssh: {allow: ["*"]}}}`, 1)
		if mod != nil {
			s = mod(s)
		}
		return s
	})
	return &privateFixture{fixture: f, other: other, pin: pin}
}

// getReq is a signed GET (or HEAD) of a luk:// URL on the secure listener.
type getReq struct {
	signer ssh.Signer
	link   string
	method string // default GET
	signAs string // the method signed, default method
	nonce  string
	// ns signs under another namespace; upload signs an upload canonical
	// text instead; unsigned sends no signature headers.
	ns       string
	upload   bool
	unsigned bool
	// host is the Host of the request (default the host of link); the
	// address of the secure listener serves secure.vm, the first address
	// any other.
	host string
}

func (f *privateFixture) get(t *testing.T, r getReq) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(r.link)
	if err != nil {
		t.Fatal(err)
	}
	if r.method == "" {
		r.method = http.MethodGet
	}
	if r.nonce == "" {
		r.nonce = wire.NewNonce()
	}
	if r.signAs == "" {
		r.signAs = r.method
	}
	if r.ns == "" {
		r.ns = wire.GetNamespace
	}
	if r.host == "" {
		r.host = u.Host
	}
	addr := "127.0.0.1:443"
	if r.host != "secure.vm" {
		addr = f.srv.config().Addrs()[0].Addr
	}
	hr := httptest.NewRequest(r.method, "https://"+r.host+u.EscapedPath(), nil)
	hr.Host = r.host
	if !r.unsigned {
		ts := time.Now().UTC().Format(time.RFC3339)
		text := wire.GetCanonicalText(r.signAs, r.host, u.EscapedPath(), ts, r.nonce)
		if r.upload {
			text = wire.CanonicalText(r.host, u.EscapedPath(), ts, r.nonce, "e30")
		}
		sig, err := sshsig.Sign(r.signer, r.ns, text)
		if err != nil {
			t.Fatal(err)
		}
		hr.Header.Set(wire.HeaderTimestamp, ts)
		hr.Header.Set(wire.HeaderNonce, r.nonce)
		hr.Header.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
	}
	rec := httptest.NewRecorder()
	f.srv.Handler(addr).ServeHTTP(rec, hr)
	return rec
}

// sidecar is the sidecar of the drop file a link URL names.
func (f *privateFixture) sidecar(t *testing.T, link string) store.Sidecar {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return sidecarOf(t, filepath.Join(f.root, "s/drop"), filepath.Base(u.Path))
}

func wantStatus(t *testing.T, what string, rec *httptest.ResponseRecorder, code int) {
	t.Helper()
	if rec.Code != code {
		t.Errorf("%s: %d %s, want %d", what, rec.Code, rec.Body, code)
	}
}

func TestPrivateUploadURL(t *testing.T) {
	f := newPrivateFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{File: "a.txt", Access: wire.AccessPrivate}, "secret")
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "luk" || u.Host != "secure.vm" || strings.Count(u.Path, "/") != 1 || u.Fragment != f.pin {
		t.Fatalf("url %s, want luk://secure.vm/<name>#%s", link, f.pin)
	}
	sc := f.sidecar(t, link)
	if sc.Client.Access != wire.AccessPrivate || sc.OwnerKey != "key:robert.socha" {
		t.Fatalf("sidecar access %q owner key %q", sc.Client.Access, sc.OwnerKey)
	}
	public := f.drop(t, f.user, wire.Meta{File: "b.txt"}, "open")
	if !strings.HasPrefix(public, "https://lukd.vm:8443/d/") {
		t.Fatalf("public url %s", public)
	}
}

func TestPrivateURLWithoutPin(t *testing.T) {
	for _, c := range []struct{ name, listen string }{
		{"proxied", `secure: {addr: "127.0.0.1:443", host: [secure.vm], public: "https://secure.vm"}`},
		{"acme", `secure: {addr: "127.0.0.1:443", host: [secure.example.com], tls: {mode: acme}}, web: {addr: "127.0.0.1:80", acme: true}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newPrivateFixture(t, func(s string) string {
				i := strings.Index(s, "secure: {addr:")
				j := strings.Index(s[i:], "}}}") + i + 2
				return s[:i] + c.listen + s[j:]
			})
			link := f.drop(t, f.user, wire.Meta{Access: wire.AccessAny}, "x")
			u, err := url.Parse(link)
			if err != nil || u.Scheme != "luk" || u.Fragment != "" {
				t.Fatalf("url %s, want luk:// without a pin", link)
			}
		})
	}
}

func TestPrivateGetOwner(t *testing.T) {
	f := newPrivateFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{File: "a.txt", Access: wire.AccessPrivate}, "secret")
	rec := f.get(t, getReq{signer: f.user, link: link})
	if rec.Code != http.StatusOK || rec.Body.String() != "secret" {
		t.Fatalf("owner: %d %q", rec.Code, rec.Body)
	}
	h := rec.Header()
	if h.Get("Content-Disposition") != `attachment; filename="a.txt"` || h.Get("ETag") != `"`+fileMeta([]byte("secret")).SHA256+`"` ||
		!strings.HasPrefix(h.Get("Content-Type"), "text/plain") || h.Get("Content-Length") != "6" {
		t.Fatalf("headers %v", h)
	}
	if rec := f.get(t, getReq{signer: f.user, link: link, method: http.MethodHead}); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("head: %d %q", rec.Code, rec.Body)
	}
	wantStatus(t, "other identity", f.get(t, getReq{signer: f.other, link: link}), http.StatusNotFound)
	wantStatus(t, "certificate", f.get(t, getReq{signer: f.certSigner(t, "web1"), link: link}), http.StatusNotFound)
	wantStatus(t, "unknown key", f.get(t, getReq{signer: newSigner(t), link: link}), http.StatusUnauthorized)
	wantStatus(t, "unsigned", f.get(t, getReq{link: link, unsigned: true}), http.StatusNotFound)
	missing := strings.Replace(link, "secure.vm/", "secure.vm/nothere", 1)
	wantStatus(t, "missing", f.get(t, getReq{signer: f.user, link: missing}), http.StatusNotFound)
	// A HEAD signature is no GET signature.
	wantStatus(t, "get signed as head", f.get(t, getReq{signer: f.user, link: link, signAs: http.MethodHead}), http.StatusUnauthorized)
}

func TestPrivateGetAny(t *testing.T) {
	f := newPrivateFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{Access: wire.AccessAny}, "shared")
	for _, s := range []struct {
		name   string
		signer ssh.Signer
	}{{"owner", f.user}, {"other", f.other}, {"certificate", f.certSigner(t, "web1")}} {
		if rec := f.get(t, getReq{signer: s.signer, link: link}); rec.Code != http.StatusOK || rec.Body.String() != "shared" {
			t.Errorf("%s: %d %q", s.name, rec.Code, rec.Body)
		}
	}
	wantStatus(t, "unknown key", f.get(t, getReq{signer: newSigner(t), link: link}), http.StatusUnauthorized)

	// An allow list without other: other gets the same 404 as for a
	// missing file, the owner too (allow counts for any files).
	g := newPrivateFixture(t, func(s string) string {
		return strings.Replace(s, `allow: ["*"]`, `allow: ["hosts:*"]`, 1)
	})
	link = g.drop(t, g.user, wire.Meta{Access: wire.AccessAny}, "shared")
	wantStatus(t, "not allowed", g.get(t, getReq{signer: g.other, link: link}), http.StatusNotFound)
	wantStatus(t, "owner not allowed", g.get(t, getReq{signer: g.user, link: link}), http.StatusNotFound)
	wantStatus(t, "certificate allowed", g.get(t, getReq{signer: g.certSigner(t, "web2"), link: link}), http.StatusOK)
	// Owner-only files ignore allow.
	own := g.drop(t, g.user, wire.Meta{Access: wire.AccessPrivate}, "mine")
	wantStatus(t, "owner of a private file", g.get(t, getReq{signer: g.user, link: own}), http.StatusOK)
}

func TestPrivatePublicSeparation(t *testing.T) {
	f := newPrivateFixture(t, nil)
	priv := f.drop(t, f.user, wire.Meta{Access: wire.AccessPrivate}, "secret")
	name := filepath.Base(mustURL(t, priv).Path)
	if code, _ := f.fetch(t, "https://lukd.vm:8443/d/"+name); code != http.StatusNotFound {
		t.Fatalf("public expose served a private file: %d", code)
	}
	public := f.drop(t, f.user, wire.Meta{}, "open")
	pubName := filepath.Base(mustURL(t, public).Path)
	wantStatus(t, "public file on the secure expose", f.get(t, getReq{signer: f.user, link: "luk://secure.vm/" + pubName}), http.StatusNotFound)
	if code, body := f.fetch(t, public); code != http.StatusOK || body != "open" {
		t.Fatalf("public: %d %q", code, body)
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestPrivateGetReplay(t *testing.T) {
	f := newPrivateFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{Access: wire.AccessPrivate}, "secret")
	nonce := wire.NewNonce()
	wantStatus(t, "first", f.get(t, getReq{signer: f.user, link: link, nonce: nonce}), http.StatusOK)
	rec := f.get(t, getReq{signer: f.user, link: link, nonce: nonce})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "replayed nonce") {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body)
	}
}

func TestGetNamespaces(t *testing.T) {
	f := newPrivateFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{Access: wire.AccessPrivate}, "secret")
	for _, r := range []getReq{
		{signer: f.user, link: link, ns: wire.Namespace},
		{signer: f.user, link: link, ns: wire.LinkNamespace},
		{signer: f.user, link: link, ns: wire.Namespace, upload: true},
	} {
		if rec := f.get(t, r); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "namespace") {
			t.Errorf("ns %s upload %v: %d %s", r.ns, r.upload, rec.Code, rec.Body)
		}
	}
	// A get signature never verifies as an upload.
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, chunked: true,
		tamper: func(hr *http.Request) {
			sig, err := sshsig.Sign(f.user, wire.GetNamespace, wire.CanonicalText("lukd.test", "/drop", hr.Header.Get(wire.HeaderTimestamp), hr.Header.Get(wire.HeaderNonce), hr.Header.Get(wire.HeaderMeta)))
			if err != nil {
				t.Fatal(err)
			}
			hr.Header.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
		}})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "namespace") {
		t.Fatalf("upload signed as get: %d %s", rec.Code, rec.Body)
	}
}

func TestPrivateGetOnce(t *testing.T) {
	f := newPrivateFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{Access: wire.AccessPrivate, Once: true}, "once")
	wantStatus(t, "head", f.get(t, getReq{signer: f.user, link: link, method: http.MethodHead}), http.StatusOK)
	wantStatus(t, "not owner", f.get(t, getReq{signer: f.other, link: link}), http.StatusNotFound)
	if rec := f.get(t, getReq{signer: f.user, link: link}); rec.Code != http.StatusOK || rec.Body.String() != "once" {
		t.Fatalf("first: %d %q", rec.Code, rec.Body)
	}
	wantStatus(t, "second", f.get(t, getReq{signer: f.user, link: link}), http.StatusNotFound)
}

func TestPrivateModes(t *testing.T) {
	f := newPrivateFixture(t, func(s string) string {
		return strings.Replace(s, `private: {owner: ['*'], any: ['*']}`, `private: {owner: ['*']}`, 1)
	})
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Access: wire.AccessAny}, chunked: true})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "private.any") {
		t.Fatalf("any: %d %s", rec.Code, rec.Body)
	}
	f.drop(t, f.user, wire.Meta{Access: wire.AccessPrivate}, "x")

	g := newPrivateFixture(t, func(s string) string {
		return strings.Replace(s, `, private: {owner: ['*'], any: ['*']}`, ``, 1)
	})
	rec, _ = g.do(t, req{signer: g.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Access: wire.AccessPrivate}, chunked: true})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "private.owner") {
		t.Fatalf("private: %d %s", rec.Code, rec.Body)
	}
	// The meta refuses a portal with access.
	m := wire.Meta{Portal: wire.PortalReveal, Source: wire.SourceStdin, Access: wire.AccessPrivate}
	if err := m.Validate(); err == nil {
		t.Fatal("access with a portal validated")
	}
}

func TestPrivateLinks(t *testing.T) {
	f := newPrivateFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{File: "a.txt", Access: wire.AccessAny}, "secret")
	f.drop(t, f.user, wire.Meta{File: "b.txt"}, "open")
	rec := f.link(t, linkReq{signer: f.user, action: wire.LinkList})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"url": "`+link+`"`) || !strings.Contains(rec.Body.String(), `"access": "any"`) ||
		!strings.Contains(rec.Body.String(), `"url": "https://lukd.vm:8443/d/`) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	wantNoLink(t, "other owner", f.link(t, linkReq{signer: f.other, action: wire.LinkRemove, link: link}))
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: link}), http.StatusOK)
	wantStatus(t, "removed", f.get(t, getReq{signer: f.user, link: link}), http.StatusNotFound)
}

func TestPrivateReplaceKeepsAccess(t *testing.T) {
	f := newPrivateFixture(t, func(s string) string {
		s = strings.Replace(s, `link: {remove: ['*'], list: ['*']}`, `link: {replace: ['*']}`, 1)
		return strings.Replace(s, `drop: {endpoint: [drop], steps: [{store: drop}]}`, `drop: {endpoint: [drop], steps: [{store: [drop, archive]}]}`, 1)
	})
	link := f.drop(t, f.user, wire.Meta{File: "a.txt", Access: wire.AccessPrivate, Mutable: true}, "v1")
	body := []byte("v2")
	m := fileMeta(body)
	m.File = "c.txt"
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: link, meta: &m, body: body}), http.StatusAccepted)
	f.settle(t)
	if rec := f.get(t, getReq{signer: f.user, link: link}); rec.Code != http.StatusOK || rec.Body.String() != "v2" {
		t.Fatalf("replaced: %d %q", rec.Code, rec.Body)
	}
	if sc := sidecarOf(t, filepath.Join(f.root, "s/archive"), "c.txt"); sc.Client.Access != wire.AccessPrivate {
		t.Fatalf("archive copy of the replace has access %q", sc.Client.Access)
	}
}

func TestAllowAllHotReload(t *testing.T) {
	f := newPrivateFixture(t, func(s string) string {
		return strings.Replace(s, `allow: [robert.socha, other, "hosts:*"], respond: url`, `allow: ["*"], respond: url`, 1)
	})
	link := f.drop(t, f.certSigner(t, "web1"), wire.Meta{Access: wire.AccessAny}, "x")
	f.drop(t, f.other, wire.Meta{}, "y")
	late := newSigner(t)
	rec, _ := f.do(t, req{signer: late, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, chunked: true})
	wantStatus(t, "unknown key before the reload", rec, http.StatusUnauthorized)
	wantStatus(t, "unknown key get before the reload", f.get(t, getReq{signer: late, link: link}), http.StatusUnauthorized)

	next := *f.srv.config()
	next.Auth.Keys = append(append([]config.Key(nil), next.Auth.Keys...), config.Key{Name: "late", Key: pubLine(late.PublicKey())})
	text, err := reparse(&next)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.apply(text)
	wantStatus(t, "new key gets an any file", f.get(t, getReq{signer: late, link: link}), http.StatusOK)
	f.drop(t, late, wire.Meta{}, "z")
}

// reparse validates a copy of a configuration again, as a reload does.
func reparse(c *config.Config) (*config.Config, error) {
	for i := range c.Auth.Keys {
		c.Auth.Keys[i].Parsed = nil
	}
	return c, c.Validate()
}
