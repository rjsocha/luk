package server

import (
	"bytes"
	"crypto/rand"
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

	"golang.org/x/crypto/ssh"

	"luk/internal/pipeline"
	"luk/internal/sshsig"
	"luk/internal/store"
	"luk/internal/wire"
)

const allLinks = `respond: url, storage: drop, link: {remove: ['*'], ttl: ['*'], replace: ['*']}}`

// linkFixture is the fixture with every link action on /drop; mod rewrites
// the config text further.
func linkFixture(t *testing.T, mod func(string) string) *fixture {
	t.Helper()
	return newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, `respond: url, storage: drop}`, allLinks, 1)
		if mod != nil {
			s = mod(s)
		}
		return s
	})
}

type linkReq struct {
	signer ssh.Signer
	path   string // default /drop
	method string // default the method of the action
	action string
	link   string
	ttl    string
	// meta, when set, is the upload meta of a replace; body its content.
	meta  *wire.Meta
	body  []byte
	nonce string
	// ns signs under another namespace; upload signs the upload canonical
	// text instead of the link one.
	ns     string
	upload bool
}

func (f *fixture) link(t *testing.T, r linkReq) *httptest.ResponseRecorder {
	t.Helper()
	const host = "lukd.test"
	if r.path == "" {
		r.path = "/drop"
	}
	if r.method == "" {
		r.method, _ = wire.LinkMethod(r.action)
	}
	if r.nonce == "" {
		r.nonce = wire.NewNonce()
	}
	if r.ns == "" {
		r.ns = wire.LinkNamespace
	}
	var metaS string
	var err error
	if r.meta != nil {
		metaS, err = wire.EncodeMeta(*r.meta)
	} else {
		metaS, err = wire.EncodeLinkMeta(wire.LinkMeta{TTL: r.ttl})
	}
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	text := wire.LinkCanonicalText(r.method, host, r.path, r.link, r.action, ts, r.nonce, metaS)
	if r.upload {
		text = wire.CanonicalText(host, r.path, ts, r.nonce, metaS)
	}
	sig, err := sshsig.Sign(r.signer, r.ns, text)
	if err != nil {
		t.Fatal(err)
	}
	hr := httptest.NewRequest(r.method, "http://"+host+r.path, bytes.NewReader(r.body))
	hr.Host = host
	hr.Header.Set(wire.HeaderLink, r.link)
	hr.Header.Set(wire.HeaderLinkAction, r.action)
	hr.Header.Set(wire.HeaderMeta, metaS)
	hr.Header.Set(wire.HeaderTimestamp, ts)
	hr.Header.Set(wire.HeaderNonce, r.nonce)
	hr.Header.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
	rec := httptest.NewRecorder()
	f.handler().ServeHTTP(rec, hr)
	return rec
}

func linkAnswer(t *testing.T, rec *httptest.ResponseRecorder, code int) wire.LinkAnswer {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("%d, want %d: %s", rec.Code, code, rec.Body)
	}
	var a wire.LinkAnswer
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		t.Fatalf("decode: %v: %s", err, rec.Body)
	}
	return a
}

// drop uploads body to /drop as signer and stores it; it returns the URL.
func (f *fixture) drop(t *testing.T, signer ssh.Signer, meta wire.Meta, body string) string {
	t.Helper()
	if meta.Portal == "" {
		meta.Portal = wire.PortalDirect
	}
	if meta.Source == "" {
		meta.Source = wire.SourceStdin
	}
	rec, _ := f.do(t, req{signer: signer, path: "/drop", meta: meta, body: []byte(body), chunked: true})
	out := receipt(t, rec, http.StatusCreated)
	f.settle(t)
	return out.URL
}

// fetch downloads a link from the fixture handler.
func (f *fixture) fetch(t *testing.T, link string) (int, string) {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443"+u.Path, nil))
	return rec.Code, rec.Body.String()
}

func (f *fixture) dropSidecar(t *testing.T, link string) store.Sidecar {
	t.Helper()
	return sidecarOf(t, filepath.Join(f.root, "s/drop"), path.Base(link))
}

func wantNoLink(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"link not found"`) {
		t.Errorf("%s: %d %s, want the generic 404", what, rec.Code, rec.Body)
	}
}

func TestLinkRemove(t *testing.T) {
	f := linkFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{File: "a.txt"}, "hello")
	if code, body := f.fetch(t, link); code != 200 || body != "hello" {
		t.Fatalf("before: %d %q", code, body)
	}
	if sc := f.dropSidecar(t, link); sc.OwnerKey != "key:robert.socha" || sc.Endpoint != "drop" {
		t.Fatalf("sidecar owner %q endpoint %q", sc.OwnerKey, sc.Endpoint)
	}
	a := linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: link}), http.StatusOK)
	if a.URL != link || !a.Removed {
		t.Fatalf("%+v", a)
	}
	if code, _ := f.fetch(t, link); code != 404 {
		t.Fatalf("after: %d", code)
	}
	name := path.Base(link)
	for _, p := range []string{filepath.Join(f.root, "s/drop/file", name), filepath.Join(f.root, "s/drop/.db/meta", name+".json")} {
		if exists(p) {
			t.Errorf("%s left", p)
		}
	}
	wantNoLink(t, "removed again", f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: link}))
}

func TestLinkRemoveClaimedAndExpired(t *testing.T) {
	f := linkFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{Once: true}, "x")
	if code, _ := f.fetch(t, link); code != 200 {
		t.Fatalf("download: %d", code)
	}
	wantNoLink(t, "claimed", f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: link}))

	link = f.drop(t, f.user, wire.Meta{TTL: "1h"}, "x")
	// Expired, not removed by the janitor yet.
	sc := f.dropSidecar(t, link)
	sc.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	b, _ := json.Marshal(sc)
	if err := os.WriteFile(filepath.Join(f.root, "s/drop/.db/meta", path.Base(link)+".json"), b, 0o640); err != nil {
		t.Fatal(err)
	}
	wantNoLink(t, "expired ttl", f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, ttl: "1d", link: link}))
	wantNoLink(t, "expired remove", f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: link}))
}

func TestLinkTTL(t *testing.T) {
	f := linkFixture(t, func(s string) string {
		return strings.Replace(s, `ttl: {user: true, max: 7d}`, `ttl: {user: true, min: 1h, max: 7d}`, 1)
	})
	link := f.drop(t, f.user, wire.Meta{TTL: "1h"}, "x")
	for _, c := range []struct {
		ask, ttl, note string
		d              time.Duration
	}{
		{"3d", "3d", "", 72 * time.Hour},
		{"30d", "7d", wire.TTLCapped, 7 * 24 * time.Hour},
		{"10m", "1h", wire.TTLRaised, time.Hour},
		{wire.TTLMax, "7d", "", 7 * 24 * time.Hour},
	} {
		before := time.Now()
		a := linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, ttl: c.ask, link: link}), http.StatusOK)
		if a.URL != link || a.TTL != c.ttl || a.TTLNote != c.note || a.TTLMin != "1h" || a.TTLMax != "7d" || a.Removed || a.ID != "" {
			t.Fatalf("%s: %+v", c.ask, a)
		}
		expiresAbout(t, c.ask, a.Expires, before, c.d)
		if sc := f.dropSidecar(t, link); sc.Expires != a.Expires {
			t.Fatalf("%s: sidecar expires %q, answer %q", c.ask, sc.Expires, a.Expires)
		}
	}
	if code, body := f.fetch(t, link); code != 200 || body != "x" {
		t.Fatalf("download: %d %q", code, body)
	}
	rec := f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, link: link})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("no ttl: %d %s", rec.Code, rec.Body)
	}
	f.srv.config().Storage["drop"].TTL.Max = 0
	a := linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, ttl: wire.TTLMax, link: link}), http.StatusOK)
	if a.Expires != "" || a.TTL != "" || a.TTLNote != "" || a.TTLMin != "1h" || a.TTLMax != "" {
		t.Fatalf("max without ttl.max: %+v", a)
	}
	if sc := f.dropSidecar(t, link); sc.Expires != "" {
		t.Fatalf("max without ttl.max: sidecar expires %q", sc.Expires)
	}
}

func TestLinkTTLUserFalse(t *testing.T) {
	f := linkFixture(t, func(s string) string {
		return strings.Replace(s, `ttl: {user: true, max: 7d}`, `ttl: {max: 7d}`, 1)
	})
	link := f.drop(t, f.user, wire.Meta{}, "x")
	rec := f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, ttl: "1d", link: link})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "storage ttl policy does not take client ttl") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestLinkReplaceKeepsNoOwner(t *testing.T) {
	f := linkFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{Mutable: true, NoOwner: true, Portal: wire.PortalDownload}, "old")
	body := []byte("new")
	m := fileMeta(body)
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: link, meta: &m, body: body}), http.StatusAccepted)
	f.settle(t)
	if sc := f.dropSidecar(t, link); sc.Owner != "" || !sc.Client.NoOwner || sc.Updated == "" {
		t.Fatalf("sidecar after replace %+v", sc)
	}
	if code, page := f.fetch(t, link); code != 200 || strings.Contains(page, "<dt>Sent by</dt>") {
		t.Fatalf("landing %d %s", code, page)
	}
}

func TestLinkReplace(t *testing.T) {
	f := linkFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{File: "a.txt", Mutable: true, Portal: wire.PortalDownload}, "old")
	before := f.dropSidecar(t, link)
	if !before.Client.Mutable || before.Updated != "" || before.Owner != "robert.socha" {
		t.Fatalf("sidecar %+v", before)
	}
	body := []byte("new content")
	m := fileMeta(body)
	m.File = "b.txt"
	a := linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: link, meta: &m, body: body}), http.StatusAccepted)
	if a.URL != link || a.ID == "" || a.ID == before.ID || a.Size == nil || *a.Size != int64(len(body)) || a.SHA256 != m.SHA256 {
		t.Fatalf("%+v", a)
	}
	f.settle(t)
	sc := f.dropSidecar(t, link)
	if sc.ID != before.ID || sc.Received != before.Received || sc.Expires != before.Expires || sc.OwnerKey != before.OwnerKey || sc.Owner != before.Owner ||
		!sc.Client.Mutable || sc.Client.Portal != wire.PortalDownload || sc.Size != int64(len(body)) || sc.SHA256 != m.SHA256 ||
		sc.Client.File != "b.txt" || sc.Updated == "" {
		t.Fatalf("sidecar after replace %+v", sc)
	}
	code, page := f.fetch(t, link)
	if code != 200 || !strings.Contains(page, "<dt>Updated</dt><dd><time datetime=\""+sc.Updated+"\"") || !strings.Contains(page, "b.txt") {
		t.Fatalf("landing %d %s", code, page)
	}
	u, _ := url.Parse(link)
	rec := httptest.NewRecorder()
	hr := httptest.NewRequest(http.MethodPost, "http://lukd.vm:8443"+u.Path+"/download", nil)
	f.handler().ServeHTTP(rec, hr)
	if rec.Code != 200 || rec.Body.String() != "new content" {
		t.Fatalf("download %d %q", rec.Code, rec.Body)
	}
	if e := entries(t, filepath.Join(f.root, "q/drop")); len(e) != 0 {
		t.Fatalf("queue left %v", e)
	}
}

func TestLinkReplaceNotMutable(t *testing.T) {
	f := linkFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{}, "old")
	body := []byte("new")
	m := fileMeta(body)
	rec := f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: link, meta: &m, body: body})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "link is not mutable") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if _, body := f.fetch(t, link); body != "old" {
		t.Fatalf("content %q", body)
	}
}

func TestLinkReplaceMeta(t *testing.T) {
	f := linkFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{Mutable: true}, "old")
	body := []byte("new")
	m := fileMeta(body)
	m.TTL = "1d"
	rec := f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: link, meta: &m, body: body})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "ttl") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// copyFixture is the link fixture whose drop pipelines also store into
// the storage copy at path, with conflict reject; pipes rewrites the
// pipelines line.
func copyFixture(t *testing.T, path, pipes string) *fixture {
	t.Helper()
	return linkFixture(t, func(s string) string {
		s = strings.Replace(s, "  drop: {endpoint: [drop], steps: [{store: drop}]}\n", pipes, 1)
		return strings.Replace(s, "expose:\n", "  copy: {type: local, base: s/copy, path: \""+path+"\", conflict: reject}\nexpose:\n", 1)
	})
}

// A store that fails in another storage of a replace keeps the old content
// of the link and puts nothing new anywhere: after a store step into the
// link storage, and in another pipeline.
func TestLinkReplaceFailureKeepsOld(t *testing.T) {
	for name, pipes := range map[string]string{
		"second step":     "  drop: {endpoint: [drop], steps: [{store: drop}, {store: copy}]}\n",
		"second pipeline": "  drop: {endpoint: [drop], steps: [{store: drop}]}\n  copy: {endpoint: [drop], steps: [{store: copy}]}\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := copyFixture(t, "fixed", pipes)
			link := f.drop(t, f.user, wire.Meta{Mutable: true}, "old")
			before := f.dropSidecar(t, link)
			body := []byte("new")
			m := fileMeta(body)
			linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: link, meta: &m, body: body}), http.StatusAccepted)
			f.settle(t)
			if code, body := f.fetch(t, link); code != 200 || body != "old" {
				t.Fatalf("after a failed replace: %d %q", code, body)
			}
			if sc := f.dropSidecar(t, link); sc.SHA256 != before.SHA256 || sc.Updated != "" {
				t.Fatalf("sidecar changed: %+v", sc)
			}
			if v := visible(t, filepath.Join(f.root, "s/copy/file")); len(v) != 1 {
				t.Fatalf("copy holds %v", v)
			}
			if b, err := os.ReadFile(filepath.Join(f.root, "s/copy/file/fixed")); err != nil || string(b) != "old" {
				t.Fatalf("copy %q %v", b, err)
			}
			failed, err := pipeline.ListFailed(f.srv.config())
			if err != nil || len(failed) != 1 {
				t.Fatalf("failed %+v %v", failed, err)
			}
			ps := failed[0].Pipelines
			if len(ps) == 0 || !strings.Contains(ps[0].Error+ps[len(ps)-1].Error, "store copy") {
				t.Fatalf("failures %+v", ps)
			}
			for _, o := range ps {
				if o.State != pipeline.StateFailed || len(o.Stored) != 0 {
					t.Fatalf("failures %+v", ps)
				}
			}
		})
	}
}

// A replace that fails at the link after the stores into the other
// storages were placed removes them again.
func TestLinkReplaceFailureRemovesOtherStores(t *testing.T) {
	f := copyFixture(t, "{{ .Random }}", "  drop: {endpoint: [drop], steps: [{store: [copy, drop]}]}\n")
	link := f.drop(t, f.user, wire.Meta{Mutable: true}, "old")
	body := []byte("new")
	m := fileMeta(body)
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: link, meta: &m, body: body}), http.StatusAccepted)
	// The link is not mutable any more when the replace runs.
	sc := f.dropSidecar(t, link)
	sc.Client.Mutable = false
	b, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	l := store.FromConfig(f.srv.config().Storage["drop"])
	if err := os.WriteFile(l.SidecarPath(path.Base(link)), b, 0o640); err != nil {
		t.Fatal(err)
	}
	f.settle(t)
	if code, body := f.fetch(t, link); code != 200 || body != "old" {
		t.Fatalf("after a failed replace: %d %q", code, body)
	}
	v := visible(t, filepath.Join(f.root, "s/copy/file"))
	if len(v) != 1 {
		t.Fatalf("copy holds %v", v)
	}
	if b, err := os.ReadFile(filepath.Join(f.root, "s/copy/file", v[0])); err != nil || string(b) != "old" {
		t.Fatalf("copy %q %v", b, err)
	}
}

func TestLinkReplaceRemovedMeanwhile(t *testing.T) {
	f := linkFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{Mutable: true}, "old")
	body := []byte("new")
	m := fileMeta(body)
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: link, meta: &m, body: body}), http.StatusAccepted)
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: link}), http.StatusOK)
	f.settle(t)
	if code, _ := f.fetch(t, link); code != 404 {
		t.Fatalf("a replace brought a removed link back: %d", code)
	}
}

func TestMutableNeedsReplace(t *testing.T) {
	f := newFixture(t)
	var read int
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Mutable: true}, body: []byte("x"), chunked: true, tamper: countBody(&read)})
	if rec.Code != http.StatusUnprocessableEntity || read != 0 || !strings.Contains(rec.Body.String(), "link.replace") {
		t.Fatalf("%d read %d %s", rec.Code, read, rec.Body)
	}
}

func TestLinkActionDisabled(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		return strings.Replace(s, `respond: url, storage: drop}`, `respond: url, storage: drop, link: {remove: ['*']}}`, 1)
	})
	link := f.drop(t, f.user, wire.Meta{}, "x")
	rec := f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, ttl: "1d", link: link})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "does not allow link ttl (link.ttl)") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Disabled before the link is looked up: the same for any link.
	rec = f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, ttl: "1d", link: "https://lukd.vm:8443/d/nothing"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown link: %d %s", rec.Code, rec.Body)
	}
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: link}), http.StatusOK)
}

func TestLinkNotOwner(t *testing.T) {
	other := newSigner(t)
	f := linkFixture(t, func(s string) string {
		s = strings.Replace(s, `keys: [{name: robert.socha, key: "`, `keys: [{name: other, key: "`+pubLine(other.PublicKey())+`"}, {name: robert.socha, key: "`, 1)
		return strings.Replace(s, `allow: [robert.socha], respond: url`, `allow: [robert.socha, other], respond: url`, 1)
	})
	link := f.drop(t, f.user, wire.Meta{Mutable: true}, "x")
	wantNoLink(t, "remove", f.link(t, linkReq{signer: other, action: wire.LinkRemove, link: link}))
	wantNoLink(t, "ttl", f.link(t, linkReq{signer: other, action: wire.LinkTTL, ttl: "1d", link: link}))
	body := []byte("y")
	m := fileMeta(body)
	wantNoLink(t, "replace", f.link(t, linkReq{signer: other, action: wire.LinkReplace, link: link, meta: &m, body: body}))
	wantNoLink(t, "unknown", f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: "https://lukd.vm:8443/d/AAAAAAAAAAAAAAAAAAAAAA"}))
	wantNoLink(t, "no expose", f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: "https://lukd.vm:8443/x/" + path.Base(link)}))
	if code, body := f.fetch(t, link); code != 200 || body != "x" {
		t.Fatalf("after: %d %q", code, body)
	}
	// A stranger not in allow is refused before anything.
	stranger := newSigner(t)
	if rec := f.link(t, linkReq{signer: stranger, action: wire.LinkRemove, link: link}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stranger: %d %s", rec.Code, rec.Body)
	}
}

func TestLinkOwnerKeyDir(t *testing.T) {
	second := newSigner(t)
	f := newFixtureDir(t, func(s string) string {
		s = strings.Replace(s, `respond: url, storage: drop}`, allLinks, 1)
		// robert.socha moves to ssh.d, with a second key.
		i := strings.Index(s, "  keys: [")
		j := strings.Index(s[i:], "\n")
		return s[:i] + s[i+j+1:]
	}, func(dir string, user ssh.Signer) {
		kd := filepath.Join(dir, "ssh.d")
		if err := os.Mkdir(kd, 0o750); err != nil {
			t.Fatal(err)
		}
		lines := pubLine(user.PublicKey()) + "\n" + pubLine(second.PublicKey()) + "\n"
		if err := os.WriteFile(filepath.Join(kd, "robert.socha.pub"), []byte(lines), 0o640); err != nil {
			t.Fatal(err)
		}
	})
	link := f.drop(t, f.user, wire.Meta{}, "x")
	a := linkAnswer(t, f.link(t, linkReq{signer: second, action: wire.LinkTTL, ttl: "1d", link: link}), http.StatusOK)
	if a.TTL != "1d" {
		t.Fatalf("%+v", a)
	}
	linkAnswer(t, f.link(t, linkReq{signer: second, action: wire.LinkRemove, link: link}), http.StatusOK)
}

// certSigner is a host certificate of the fixture CA for a new key.
func (f *fixture) certSigner(t *testing.T, keyID string) ssh.Signer {
	t.Helper()
	host := newSigner(t)
	c := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, KeyId: keyID, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, f.hostCA); err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(c, host)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestLinkCertOwner(t *testing.T) {
	f := linkFixture(t, func(s string) string {
		return strings.Replace(s, `allow: [robert.socha], respond: url`, `allow: [robert.socha, "hosts:*"], respond: url`, 1)
	})
	link := f.drop(t, f.certSigner(t, "web1"), wire.Meta{}, "x")
	if sc := f.dropSidecar(t, link); sc.OwnerKey != "cert:hosts:web1" {
		t.Fatalf("owner key %q", sc.OwnerKey)
	}
	wantNoLink(t, "other key id", f.link(t, linkReq{signer: f.certSigner(t, "web2"), action: wire.LinkRemove, link: link}))
	wantNoLink(t, "plain key", f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: link}))
	// A new certificate, for another key, with the same CA and Key ID.
	linkAnswer(t, f.link(t, linkReq{signer: f.certSigner(t, "web1"), action: wire.LinkRemove, link: link}), http.StatusOK)
}

func TestLinkOtherEndpoint(t *testing.T) {
	f := linkFixture(t, func(s string) string {
		s = strings.Replace(s, `pipeline:`, `pipeline:
  drop2: {endpoint: [drop2], steps: [{store: drop}]}`, 1)
		return strings.Replace(s, `endpoint:
  backup:`, `endpoint:
  drop2: {listen: main, endpoint: /drop2, path: q/drop2, allow: [robert.socha], `+allLinks+`
  backup:`, 1)
	})
	link := f.drop(t, f.user, wire.Meta{Mutable: true}, "x")
	wantNoLink(t, "remove", f.link(t, linkReq{signer: f.user, path: "/drop2", action: wire.LinkRemove, link: link}))
	linkAnswer(t, f.link(t, linkReq{signer: f.user, path: "/drop", action: wire.LinkRemove, link: link}), http.StatusOK)
}

func TestLinkNamespaces(t *testing.T) {
	f := linkFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{}, "x")
	// The link canonical text signed under the upload namespace.
	rec := f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: link, ns: wire.Namespace})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "namespace") {
		t.Fatalf("upload namespace: %d %s", rec.Code, rec.Body)
	}
	// An upload signature (namespace and canonical text) with link headers.
	rec = f.link(t, linkReq{signer: f.user, action: wire.LinkReplace, link: link, ns: wire.Namespace, upload: true, meta: &wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("upload signature as a link: %d %s", rec.Code, rec.Body)
	}
	// A link signature on an upload: no link headers, luk-link@v1.
	rec, _ = f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, body: []byte("x"), chunked: true,
		tamper: func(r *http.Request) {
			ts, nonce, metaS := r.Header.Get(wire.HeaderTimestamp), r.Header.Get(wire.HeaderNonce), r.Header.Get(wire.HeaderMeta)
			for _, text := range [][]byte{
				wire.CanonicalText(r.Host, r.URL.Path, ts, nonce, metaS),
				wire.LinkCanonicalText(http.MethodPut, r.Host, r.URL.Path, "", "", ts, nonce, metaS),
			} {
				sig, err := sshsig.Sign(f.user, wire.LinkNamespace, text)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
			}
		}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("link namespace on an upload: %d %s", rec.Code, rec.Body)
	}
	if code, _ := f.fetch(t, link); code != 200 {
		t.Fatalf("link gone: %d", code)
	}
}

func TestLinkReplayedNonce(t *testing.T) {
	f := linkFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{}, "x")
	nonce := wire.NewNonce()
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, ttl: "1d", link: link, nonce: nonce}), http.StatusOK)
	rec := f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, ttl: "1d", link: link, nonce: nonce})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "replayed nonce") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestLinkRequestShape(t *testing.T) {
	f := linkFixture(t, nil)
	link := f.drop(t, f.user, wire.Meta{}, "x")
	for _, c := range []struct {
		what string
		r    linkReq
		code int
		want string
	}{
		{"bad url", linkReq{action: wire.LinkRemove, link: "lukd.vm/d/x"}, http.StatusUnprocessableEntity, "bad link URL"},
		{"wrong method", linkReq{action: wire.LinkRemove, method: http.MethodPatch, link: link}, http.StatusMethodNotAllowed, "needs method DELETE"},
		{"unknown action", linkReq{action: "rename", method: http.MethodPost, link: link}, http.StatusBadRequest, "unknown link action"},
		{"remove with ttl", linkReq{action: wire.LinkRemove, ttl: "1d", link: link}, http.StatusUnprocessableEntity, "no ttl"},
	} {
		c.r.signer = f.user
		rec := f.link(t, c.r)
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d %s", c.what, rec.Code, rec.Body)
		}
		if c.code == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodDelete {
			t.Errorf("%s: Allow %q", c.what, rec.Header().Get("Allow"))
		}
	}
	// A listener without a host list answers for any host; the scheme
	// and port of the link are ignored.
	u, _ := url.Parse(link)
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: "http://lukd.vm" + u.Path}), http.StatusOK)
}

func TestLinkHostMatch(t *testing.T) {
	f := linkFixture(t, func(s string) string {
		return strings.Replace(s, `main: {addr: "127.0.0.1:0", public:`, `main: {addr: "127.0.0.1:0", host: [lukd.test], public:`, 1)
	})
	link := f.drop(t, f.user, wire.Meta{}, "x")
	name := path.Base(link)
	wantNoLink(t, "other host", f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: "https://elsewhere.example/d/" + name}))
	// The host of the listener's public URL and its host list both count.
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, ttl: "1d", link: "https://LUKD.VM/d/" + name}), http.StatusOK)
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: "http://lukd.test:8080/d/" + name}), http.StatusOK)
}

const listLinks = `respond: url, storage: drop, link: {replace: ['*'], list: ['*']}}`

// listFixture has link list on /drop and on /drop2 (storing into the same
// storage), and a second identity other allowed on both.
func listFixture(t *testing.T, other ssh.Signer) *fixture {
	t.Helper()
	return newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, `keys: [{name: robert.socha, key: "`, `keys: [{name: other, key: "`+pubLine(other.PublicKey())+`"}, {name: robert.socha, key: "`, 1)
		s = strings.Replace(s, `allow: [robert.socha], respond: url, storage: drop}`, `allow: [robert.socha, other], `+listLinks, 1)
		s = strings.Replace(s, `pipeline:`, `pipeline:
  drop2: {endpoint: [drop2], steps: [{store: drop}]}`, 1)
		return strings.Replace(s, `endpoint:
  backup:`, `endpoint:
  drop2: {listen: main, endpoint: /drop2, path: q/drop2, allow: [robert.socha], `+listLinks+`
  backup:`, 1)
	})
}

func listAnswer(t *testing.T, rec *httptest.ResponseRecorder) wire.LinkListAnswer {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("%d: %s", rec.Code, rec.Body)
	}
	var a wire.LinkListAnswer
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		t.Fatalf("decode: %v: %s", err, rec.Body)
	}
	return a
}

// setSidecar rewrites the sidecar of a link with fn.
func (f *fixture) setSidecar(t *testing.T, link string, fn func(*store.Sidecar)) {
	t.Helper()
	sc := f.dropSidecar(t, link)
	fn(&sc)
	b, _ := json.Marshal(sc)
	if err := os.WriteFile(filepath.Join(f.root, "s/drop/.db/meta", path.Base(link)+".json"), b, 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestLinkList(t *testing.T) {
	other := newSigner(t)
	f := listFixture(t, other)
	if a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList})); a.Links == nil || len(a.Links) != 0 || a.Truncated {
		t.Fatalf("empty: %+v", a)
	}
	older := f.drop(t, f.user, wire.Meta{File: "a.txt", Mutable: true}, "hello")
	received := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	f.setSidecar(t, older, func(sc *store.Sidecar) { sc.Received = received })
	newer := f.drop(t, f.user, wire.Meta{Once: true, Portal: wire.PortalDownload}, "x")
	claimed := f.drop(t, f.user, wire.Meta{Once: true}, "c")
	if code, _ := f.fetch(t, claimed); code != 200 {
		t.Fatalf("claim: %d", code)
	}
	expired := f.drop(t, f.user, wire.Meta{TTL: "1h"}, "e")
	f.setSidecar(t, expired, func(sc *store.Sidecar) { sc.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) })
	f.drop(t, other, wire.Meta{}, "o")
	rec, _ := f.do(t, req{signer: f.user, path: "/drop2", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, body: []byte("2"), chunked: true})
	viaDrop2 := receipt(t, rec, http.StatusCreated).URL
	f.settle(t)

	a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList}))
	if len(a.Links) != 2 || a.Truncated {
		t.Fatalf("%+v", a)
	}
	n, o := a.Links[0], a.Links[1]
	if n.URL != newer || !n.Once || n.Mutable || n.Portal != wire.PortalDownload || n.Size != 1 || n.Expires == "" {
		t.Errorf("newer: %+v", n)
	}
	if o.URL != older || o.File != "a.txt" || o.Size != 5 || !o.Mutable || o.Once || o.Portal != wire.PortalDirect || o.Received != received {
		t.Errorf("older: %+v", o)
	}
	// Other identity: its own only; drop2: only what came through it.
	if a := listAnswer(t, f.link(t, linkReq{signer: other, action: wire.LinkList})); len(a.Links) != 1 || a.Links[0].Size != 1 || a.Links[0].URL == newer {
		t.Errorf("other: %+v", a)
	}
	if a := listAnswer(t, f.link(t, linkReq{signer: f.user, path: "/drop2", action: wire.LinkList})); len(a.Links) != 1 || a.Links[0].URL != viaDrop2 {
		t.Errorf("drop2: %+v", a)
	}

	defer func(m int) { maxLinkList = m }(maxLinkList)
	maxLinkList = 1
	if a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList})); len(a.Links) != 1 || a.Links[0].URL != newer || !a.Truncated {
		t.Errorf("truncated: %+v", a)
	}
}

func TestLinkListDisabled(t *testing.T) {
	f := linkFixture(t, nil)
	rec := f.link(t, linkReq{signer: f.user, action: wire.LinkList})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "does not allow link list (link.list)") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestLinkListRequest(t *testing.T) {
	f := listFixture(t, newSigner(t))
	link := f.drop(t, f.user, wire.Meta{}, "x")
	for _, c := range []struct {
		what string
		r    linkReq
		code int
		want string
	}{
		{"with a link", linkReq{action: wire.LinkList, link: link}, http.StatusBadRequest, "link list takes an empty Luk-Link"},
		{"wrong method", linkReq{action: wire.LinkList, method: http.MethodDelete}, http.StatusMethodNotAllowed, "needs method GET"},
		{"with ttl", linkReq{action: wire.LinkList, ttl: "1d"}, http.StatusUnprocessableEntity, "list takes no ttl"},
		{"remove without a link", linkReq{action: wire.LinkRemove}, http.StatusBadRequest, "go together"},
		{"upload namespace", linkReq{action: wire.LinkList, ns: wire.Namespace}, http.StatusUnauthorized, "namespace"},
		{"stranger", linkReq{action: wire.LinkList, signer: newSigner(t)}, http.StatusUnauthorized, ""},
	} {
		if c.r.signer == nil {
			c.r.signer = f.user
		}
		rec := f.link(t, c.r)
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d %s", c.what, rec.Code, rec.Body)
		}
		if c.code == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodGet {
			t.Errorf("%s: Allow %q", c.what, rec.Header().Get("Allow"))
		}
	}
	nonce := wire.NewNonce()
	listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList, nonce: nonce}))
	if rec := f.link(t, linkReq{signer: f.user, action: wire.LinkList, nonce: nonce}); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "replayed nonce") {
		t.Fatalf("replayed: %d %s", rec.Code, rec.Body)
	}
}
