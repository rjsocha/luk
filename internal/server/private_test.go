package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
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
	// target is the request target signed (default that of link).
	target string
	// user and pass send a basic Authorization header when user is set.
	user, pass string
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
	if r.target == "" {
		r.target = wire.GetTarget(u.EscapedPath(), u.RawQuery)
	}
	hr := httptest.NewRequest(r.method, "https://"+r.host+u.RequestURI(), nil)
	hr.Host = r.host
	if r.user != "" {
		hr.SetBasicAuth(r.user, r.pass)
	}
	if !r.unsigned {
		ts := time.Now().UTC().Format(time.RFC3339)
		text := wire.GetCanonicalText(r.signAs, r.host, r.target, ts, r.nonce)
		if r.upload {
			text = wire.CanonicalText(r.host, u.EscapedPath(), ts, r.nonce, "e30", nil)
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
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin},
		tamper: func(hr *http.Request) {
			sig, err := sshsig.Sign(f.user, wire.GetNamespace, wire.CanonicalText("lukd.test", "/drop", hr.Header.Get(wire.HeaderTimestamp), hr.Header.Get(wire.HeaderNonce), hr.Header.Get(wire.HeaderMeta), nil))
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
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Access: wire.AccessAny}})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "private.any") {
		t.Fatalf("any: %d %s", rec.Code, rec.Body)
	}
	f.drop(t, f.user, wire.Meta{Access: wire.AccessPrivate}, "x")

	g := newPrivateFixture(t, func(s string) string {
		return strings.Replace(s, `, private: {owner: ['*'], any: ['*']}`, ``, 1)
	})
	rec, _ = g.do(t, req{signer: g.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Access: wire.AccessPrivate}})
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

// privateListFixture is the private fixture where /drop also offers link
// ttl and replace, and private.list admits robert.socha only; mod rewrites
// the config text further.
func privateListFixture(t *testing.T, mod func(string) string) *privateFixture {
	t.Helper()
	return newPrivateFixture(t, func(s string) string {
		s = strings.Replace(s, `private: {owner: ['*'], any: ['*']}, link: {remove: ['*'], list: ['*']}`,
			`private: {owner: ['*'], any: ['*'], list: [robert.socha]}, link: {remove: ['*'], ttl: ['*'], replace: ['*'], list: ['*']}`, 1)
		if mod != nil {
			s = mod(s)
		}
		return s
	})
}

// TestPrivateList: an identity of private.list gets the any files others
// sent through the endpoint it may download, marked shared, besides its
// own links; never the owner-only files of others, nor expired ones.
func TestPrivateList(t *testing.T) {
	f := privateListFixture(t, nil)
	own := f.drop(t, f.user, wire.Meta{File: "own.txt", Access: wire.AccessAny}, "mine")
	ownPublic := f.drop(t, f.user, wire.Meta{File: "pub.txt"}, "open")
	theirs := f.drop(t, f.other, wire.Meta{File: "any.txt", Access: wire.AccessAny, Mutable: true}, "theirs")
	f.drop(t, f.other, wire.Meta{File: "owner.txt", Access: wire.AccessPrivate}, "hidden")
	f.drop(t, f.other, wire.Meta{File: "public.txt"}, "public")
	expired := f.drop(t, f.other, wire.Meta{File: "old.txt", Access: wire.AccessAny, TTL: "1h"}, "old")
	f.setSidecar(t, mustURL(t, expired).Path, func(sc *store.Sidecar) { sc.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) })
	f.settle(t)

	a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList}))
	got := map[string]wire.LinkEntry{}
	for _, l := range a.Links {
		got[l.URL] = l
	}
	if len(a.Links) != 3 || got[theirs].File != "any.txt" || !got[theirs].Shared || got[theirs].Access != wire.AccessAny {
		t.Fatalf("list: %+v", a.Links)
	}
	if l, ok := got[own]; !ok || l.Shared {
		t.Errorf("own any file: %+v", l)
	}
	if l, ok := got[ownPublic]; !ok || l.Shared {
		t.Errorf("own public file: %+v", l)
	}
	if rec := f.link(t, linkReq{signer: f.user, action: wire.LinkList}); !strings.Contains(rec.Body.String(), `"shared": true`) {
		t.Errorf("answer: %s", rec.Body)
	}

	// The shared entry stays read-only: no remove, ttl or replace.
	m := wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}
	wantNoLink(t, "remove shared", f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: theirs}))
	wantNoLink(t, "ttl shared", f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, link: theirs, ttl: "1d"}))
	wantNoLink(t, "replace shared", f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: theirs, meta: &m, body: []byte("new")}))
	if rec := f.get(t, getReq{signer: f.other, link: theirs}); rec.Code != http.StatusOK || rec.Body.String() != "theirs" {
		t.Fatalf("after: %d %q", rec.Code, rec.Body)
	}

	// Not on private.list: its own links only.
	a = listAnswer(t, f.link(t, linkReq{signer: f.other, action: wire.LinkList}))
	for _, l := range a.Links {
		if l.Shared || l.URL == own || l.URL == ownPublic {
			t.Errorf("other: %+v", l)
		}
	}
	if len(a.Links) != 3 {
		t.Errorf("other: %d links: %+v", len(a.Links), a.Links)
	}
}

// TestPrivateListProtectAllow: an any file is listed to an identity of
// private.list only when the protect expose admits it.
func TestPrivateListProtectAllow(t *testing.T) {
	f := privateListFixture(t, func(s string) string {
		return strings.Replace(s, `auth: {ssh: {allow: ["*"]}}`, `auth: {ssh: {allow: [other]}}`, 1)
	})
	own := f.drop(t, f.user, wire.Meta{Access: wire.AccessAny}, "mine")
	f.drop(t, f.other, wire.Meta{Access: wire.AccessAny}, "theirs")
	f.settle(t)
	if a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList})); len(a.Links) != 1 || a.Links[0].URL != own || a.Links[0].Shared {
		t.Fatalf("list: %+v", a.Links)
	}
}

// TestPrivateListOnce: a once file of another identity is never listed
// as shared, so a viewer cannot claim a file meant for someone else.
func TestPrivateListOnce(t *testing.T) {
	f := privateListFixture(t, nil)
	f.drop(t, f.other, wire.Meta{Access: wire.AccessAny, Once: true}, "once")
	theirs := f.drop(t, f.other, wire.Meta{Access: wire.AccessAny}, "theirs")
	own := f.drop(t, f.user, wire.Meta{Access: wire.AccessAny, Once: true}, "mine")
	f.settle(t)
	a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList}))
	got := map[string]bool{}
	for _, l := range a.Links {
		got[l.URL] = l.Shared
	}
	if len(a.Links) != 2 || !got[theirs] || got[own] {
		t.Fatalf("list: %+v", a.Links)
	}
	if _, ok := got[own]; !ok {
		t.Fatalf("own once file: %+v", a.Links)
	}
}

// TestPrivateListSecret: shared entries come from the respond storage
// only, never from the secret storage.
func TestPrivateListSecret(t *testing.T) {
	vol := filepath.Join(t.TempDir(), "volatile")
	f := privateListFixture(t, func(s string) string {
		return strings.NewReplacer(
			`storage: drop, private:`, `storage: drop, secret: {allow: ['*'], path: `+vol+`/queue, storage: volatile}, private:`,
			"storage:\n", "storage:\n  volatile: {type: local, base: "+vol+"/storage, path: \"{{ .Random }}\", expose: volatile, protect: vsecure, ttl: {user: true}}\n",
			"  drop: {listen: main, path: /d/}\n", "  drop: {listen: main, path: /d/}\n  volatile: {listen: main, path: /d/volatile/}\n  vsecure: {listen: secure, path: /v/, auth: {ssh: {allow: [\"*\"]}}}\n",
		).Replace(s)
	})
	rec, _ := f.do(t, req{signer: f.other, path: "/drop", meta: secretMeta("s"), body: []byte("s")})
	sec := receipt(t, rec, http.StatusCreated).URL
	f.settle(t)
	// A secret of another identity made of access any by hand.
	name := path.Base(mustURL(t, sec).Path)
	sc := sidecarOf(t, filepath.Join(vol, "storage"), name)
	sc.Client.Access = wire.AccessAny
	b, _ := json.Marshal(sc)
	if err := os.WriteFile(filepath.Join(vol, "storage", ".db", "meta", name+".json"), b, 0o640); err != nil {
		t.Fatal(err)
	}
	theirs := f.drop(t, f.other, wire.Meta{Access: wire.AccessAny}, "theirs")
	f.settle(t)
	a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList}))
	if len(a.Links) != 1 || a.Links[0].URL != theirs || !a.Links[0].Shared {
		t.Fatalf("list: %+v", a.Links)
	}
}

// TestPrivateListCap: the cap keeps the own links first, the shared
// entries fill the remainder.
func TestPrivateListCap(t *testing.T) {
	f := privateListFixture(t, nil)
	own := f.drop(t, f.user, wire.Meta{Access: wire.AccessAny}, "mine")
	older := f.drop(t, f.other, wire.Meta{Access: wire.AccessAny}, "older")
	f.drop(t, f.other, wire.Meta{Access: wire.AccessAny}, "newer")
	f.settle(t)
	defer func(m int) { maxLinkList = m }(maxLinkList)
	maxLinkList = 1
	if a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList})); len(a.Links) != 1 || a.Links[0].URL != own || !a.Truncated {
		t.Fatalf("cap 1: %+v", a)
	}
	maxLinkList = 2
	a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList}))
	if len(a.Links) != 2 || !a.Truncated || a.Links[1].URL != own || !a.Links[0].Shared || a.Links[0].URL == older {
		t.Fatalf("cap 2: %+v", a)
	}
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
	rec, _ := f.do(t, req{signer: late, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}})
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

// newSignedFixture is the private fixture with the drop storage exposed by
// vault (/v/ on the secure listener, auth.ssh allow [robert.socha]) and
// still protected by secure.
func newSignedFixture(t *testing.T) *privateFixture {
	return newPrivateFixture(t, func(s string) string {
		s = strings.Replace(s, `expose: drop, protect: secure}`, `expose: vault, protect: secure}`, 1)
		return strings.Replace(s, `  secure: {listen: secure, path: /,`, `  vault: {listen: secure, path: /v/, auth: {ssh: {allow: [robert.socha]}}}
  secure: {listen: secure, path: /,`, 1)
	})
}

func TestSignedExposeGet(t *testing.T) {
	f := newSignedFixture(t)
	link := f.drop(t, f.user, wire.Meta{File: "a.txt"}, "open")
	u := mustURL(t, link)
	if u.Scheme != "luk" || u.Host != "secure.vm" || !strings.HasPrefix(u.Path, "/v/") || u.Fragment != f.pin {
		t.Fatalf("url %s, want luk://secure.vm/v/<name>#%s", link, f.pin)
	}
	if rec := f.get(t, getReq{signer: f.user, link: link}); rec.Code != http.StatusOK || rec.Body.String() != "open" {
		t.Fatalf("allowed: %d %q", rec.Code, rec.Body)
	}
	wantStatus(t, "not allowed", f.get(t, getReq{signer: f.other, link: link}), http.StatusNotFound)
	wantStatus(t, "unsigned", f.get(t, getReq{link: link, unsigned: true}), http.StatusNotFound)
	wantStatus(t, "unknown key", f.get(t, getReq{signer: newSigner(t), link: link}), http.StatusUnauthorized)
	// Private files stay on the protect expose.
	priv := f.drop(t, f.user, wire.Meta{Access: wire.AccessPrivate}, "secret")
	if !strings.HasPrefix(priv, "luk://secure.vm/") || strings.HasPrefix(priv, "luk://secure.vm/v/") {
		t.Fatalf("private url %s", priv)
	}
	wantStatus(t, "private on the protect", f.get(t, getReq{signer: f.user, link: priv}), http.StatusOK)
	wantStatus(t, "private on the expose", f.get(t, getReq{signer: f.user, link: "luk://secure.vm/v/" + path.Base(mustURL(t, priv).Path)}), http.StatusNotFound)
}

func TestSignedListingServer(t *testing.T) {
	f := newSignedFixture(t)
	link := f.drop(t, f.user, wire.Meta{File: "a.txt"}, "open")
	f.drop(t, f.user, wire.Meta{Access: wire.AccessPrivate}, "secret")
	f.drop(t, f.user, wire.Meta{Once: true}, "once")
	for _, q := range []string{"", "?recursive=1"} {
		rec := f.get(t, getReq{signer: f.user, link: "luk://secure.vm/v/" + q})
		var ents []wire.ListEntry
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ents) != nil || len(ents) != 1 ||
			ents[0].Name != path.Base(mustURL(t, link).Path) || ents[0].SHA256 != fileMeta([]byte("open")).SHA256 {
			t.Errorf("listing %q: %d %s", q, rec.Code, rec.Body)
		}
	}
	wantStatus(t, "not allowed", f.get(t, getReq{signer: f.other, link: "luk://secure.vm/v/"}), http.StatusNotFound)
	// The query is signed: a signature of the path alone does not verify.
	wantStatus(t, "query not signed", f.get(t, getReq{signer: f.user, link: "luk://secure.vm/v/?recursive=1", target: "/v/"}), http.StatusUnauthorized)
}

// newDualFixture is the signed fixture whose vault also has auth.basic
// (dev:pw) and index.
func newDualFixture(t *testing.T) *privateFixture {
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return newPrivateFixture(t, func(s string) string {
		s = strings.Replace(s, `expose: drop, protect: secure}`, `expose: vault, protect: secure}`, 1)
		return strings.Replace(s, `  secure: {listen: secure, path: /,`, `  vault: {listen: secure, path: /v/, index: true, auth: {basic: ['dev:`+string(hash)+`'], ssh: {allow: [robert.socha]}}}
  secure: {listen: secure, path: /,`, 1)
	})
}

func TestDualAuthExposeGet(t *testing.T) {
	f := newDualFixture(t)
	link := f.drop(t, f.user, wire.Meta{File: "a.txt"}, "open")
	if u := mustURL(t, link); u.Scheme != "https" || u.Host != "secure.vm" || !strings.HasPrefix(u.Path, "/v/") || u.Fragment != f.pin {
		t.Fatalf("url %s, want https://secure.vm/v/<name>#%s", link, f.pin)
	}
	for name, r := range map[string]getReq{
		"basic":  {link: link, unsigned: true, user: "dev", pass: "pw"},
		"signed": {signer: f.user, link: link},
	} {
		if rec := f.get(t, r); rec.Code != http.StatusOK || rec.Body.String() != "open" {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Body)
		}
	}
	// A signed request never falls back to basic.
	rec := f.get(t, getReq{signer: newSigner(t), link: link, user: "dev", pass: "pw"})
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("unknown key with basic: %d %v", rec.Code, rec.Header())
	}
	// Some of the signature headers: a signed request, never basic.
	hr := httptest.NewRequest("GET", "https://secure.vm"+mustURL(t, link).Path, nil)
	hr.Host = "secure.vm"
	hr.Header.Set(wire.HeaderNonce, wire.NewNonce())
	hr.SetBasicAuth("dev", "pw")
	rec = httptest.NewRecorder()
	f.srv.Handler("127.0.0.1:443").ServeHTTP(rec, hr)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("partial headers with basic: %d %v", rec.Code, rec.Header())
	}
	wantStatus(t, "not allowed with basic", f.get(t, getReq{signer: f.other, link: link, user: "dev", pass: "pw"}), http.StatusNotFound)
	rec = f.get(t, getReq{link: link, unsigned: true})
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != `Basic realm="luk"` {
		t.Errorf("no auth: %d %v", rec.Code, rec.Header())
	}
	wantStatus(t, "wrong password", f.get(t, getReq{link: link, unsigned: true, user: "dev", pass: "bad"}), http.StatusUnauthorized)
	// Private files: never through basic, on the expose or the protect.
	priv := f.drop(t, f.user, wire.Meta{Access: wire.AccessAny}, "secret")
	name := path.Base(mustURL(t, priv).Path)
	wantStatus(t, "private via basic", f.get(t, getReq{link: "luk://secure.vm/v/" + name, unsigned: true, user: "dev", pass: "pw"}), http.StatusNotFound)
	wantStatus(t, "private via basic on the protect", f.get(t, getReq{link: priv, unsigned: true, user: "dev", pass: "pw"}), http.StatusNotFound)
	// The directory: HTML for basic, the signed listing for luk.
	rec = f.get(t, getReq{link: "luk://secure.vm/v/", unsigned: true, user: "dev", pass: "pw"})
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || !strings.Contains(rec.Body.String(), path.Base(mustURL(t, link).Path)) || strings.Contains(rec.Body.String(), name) {
		t.Errorf("html index: %d %v", rec.Code, rec.Header())
	}
	rec = f.get(t, getReq{signer: f.user, link: "luk://secure.vm/v/"})
	var ents []wire.ListEntry
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ents) != nil || len(ents) != 1 || ents[0].Name != path.Base(mustURL(t, link).Path) {
		t.Errorf("signed listing: %d %s", rec.Code, rec.Body)
	}
}
