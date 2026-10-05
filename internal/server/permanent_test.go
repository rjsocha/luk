package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/store"
	"luk/internal/wire"
)

const permanentBlock = `respond: url, storage: drop, link: {remove: ['*'], ttl: ['*'], list: ['*']},
    permanent: {names: {"rev/hosts.krl": {allow: [robert.socha]}, "builds/*": {allow: [robert.socha], max: 1}, "certs/*": {allow: ["hosts:*"]}}}}`

func permanentFixture(t *testing.T) (*fixture, *time.Time) {
	t.Helper()
	f := newFixtureWith(t, func(s string) string {
		return strings.Replace(s, `respond: url, storage: drop}`, permanentBlock, 1)
	})
	// Every upload a second later than the one before, so the newest is
	// clear.
	clock := time.Now()
	f.srv.SetClock(func() time.Time { return clock })
	return f, &clock
}

func permMeta(name string, body []byte) wire.Meta {
	m := fileMeta(body)
	m.Permanent = name
	return m
}

func (f *fixture) sendPermanent(t *testing.T, clock *time.Time, name, body string) wire.Receipt {
	t.Helper()
	*clock = clock.Add(time.Second)
	out := f.queuePermanent(t, name, body)
	f.settle(t)
	return out
}

// queuePermanent sends a version of name and leaves it in the queue.
func (f *fixture) queuePermanent(t *testing.T, name, body string) wire.Receipt {
	t.Helper()
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: permMeta(name, []byte(body)), body: []byte(body)})
	return receipt(t, rec, http.StatusCreated)
}

func TestPermanentUploadServesLast(t *testing.T) {
	f, clock := permanentFixture(t)
	const perm = "https://lukd.vm:8443/d/permanent/rev/hosts.krl"
	if code, _ := f.fetch(t, perm); code != http.StatusNotFound {
		t.Fatalf("before: %d", code)
	}
	v1 := f.sendPermanent(t, clock, "rev/hosts.krl", "one")
	if v1.URL != perm || v1.Permanent != "rev/hosts.krl" || !strings.HasPrefix(v1.VersionURL, "https://lukd.vm:8443/d/") || v1.VersionURL == perm {
		t.Fatalf("answer %+v", v1)
	}
	if code, body := f.fetch(t, perm); code != 200 || body != "one" {
		t.Fatalf("v1: %d %q", code, body)
	}
	if code, body := f.fetch(t, v1.VersionURL); code != 200 || body != "one" {
		t.Fatalf("v1 version: %d %q", code, body)
	}
	if sc := f.dropSidecar(t, v1.VersionURL); sc.Client.Permanent != "rev/hosts.krl" || sc.PermanentPath != "permanent" || sc.Accepted == 0 {
		t.Fatalf("sidecar %+v", sc)
	}
	v2 := f.sendPermanent(t, clock, "rev/hosts.krl", "two")
	rec := httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443/d/permanent/rev/hosts.krl", nil))
	if rec.Code != 200 || rec.Body.String() != "two" || rec.Header().Get("ETag") != `"`+fileMeta([]byte("two")).SHA256+`"` ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), `filename="f"`) {
		t.Fatalf("v2: %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	// The new version removed the previous one.
	if code, _ := f.fetch(t, v1.VersionURL); code != http.StatusNotFound {
		t.Fatalf("v1 after v2: %d", code)
	}
	v3 := f.sendPermanent(t, clock, "rev/hosts.krl", "three")
	if code, body := f.fetch(t, perm); code != 200 || body != "three" {
		t.Fatalf("v3: %d %q", code, body)
	}
	if code, _ := f.fetch(t, v2.VersionURL); code != http.StatusNotFound {
		t.Fatalf("v2 after v3: %d", code)
	}
	// Listed per version, with the permanent name and URL.
	a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList}))
	if len(a.Links) != 1 || a.Links[0].URL != v3.VersionURL || a.Links[0].Permanent != "rev/hosts.krl" || a.Links[0].PermanentURL != perm {
		t.Fatalf("list %+v", a.Links)
	}
	// A version that is not the current one is listed as a plain link.
	cur := filepath.Join(f.root, "s/drop/.db/permanent/permanent/rev/hosts.krl/current")
	if err := os.Rename(cur, cur+".away"); err != nil {
		t.Fatal(err)
	}
	a = listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList}))
	if len(a.Links) != 1 || a.Links[0].URL != v3.VersionURL || a.Links[0].Permanent != "" || a.Links[0].PermanentURL != "" {
		t.Fatalf("list without current %+v", a.Links)
	}
	if err := os.Rename(cur+".away", cur); err != nil {
		t.Fatal(err)
	}
	// A link action takes the version URL; the permanent URL is no link.
	wantNoLink(t, "permanent url", f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: perm}))
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: v3.VersionURL}), http.StatusOK)
	// No fallback: the name is empty.
	if code, _ := f.fetch(t, perm); code != http.StatusNotFound {
		t.Fatalf("after removing v3: %d", code)
	}
	if got := entries(t, filepath.Join(f.root, "s/drop/.db/permanent/permanent/rev/hosts.krl")); len(got) != 0 {
		t.Fatalf("permanent directory %v", got)
	}
	f.sendPermanent(t, clock, "rev/hosts.krl", "four")
	if code, body := f.fetch(t, perm); code != 200 || body != "four" {
		t.Fatalf("v4: %d %q", code, body)
	}
}

// TestPermanentCommitOrder: the version committed last is current, also
// when it was received earlier, and whatever the order the queue entries
// of one second are processed in.
func TestPermanentCommitOrder(t *testing.T) {
	f, clock := permanentFixture(t)
	const perm = "https://lukd.vm:8443/d/permanent/rev/hosts.krl"
	start := *clock
	*clock = start.Add(10 * time.Second)
	f.queuePermanent(t, "rev/hosts.krl", "received-later")
	// Received earlier (a request started before), committed after.
	*clock = start
	last := f.queuePermanent(t, "rev/hosts.krl", "committed-last")
	f.settle(t)
	if code, body := f.fetch(t, perm); code != 200 || body != "committed-last" {
		t.Fatalf("current: %d %q", code, body)
	}
	if a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList})); len(a.Links) != 1 || a.Links[0].URL != last.VersionURL {
		t.Fatalf("list %+v", a.Links)
	}
	// Many uploads in one second, processed at once in any order.
	*clock = start.Add(20 * time.Second)
	var want wire.Receipt
	for i := range 8 {
		want = f.queuePermanent(t, "rev/hosts.krl", fmt.Sprint("same-second-", i))
	}
	f.settle(t)
	if code, body := f.fetch(t, perm); code != 200 || body != "same-second-7" {
		t.Fatalf("same second: %d %q", code, body)
	}
	if a := listAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkList})); len(a.Links) != 1 || a.Links[0].URL != want.VersionURL {
		t.Fatalf("list after the same second %+v", a.Links)
	}
}

func TestPermanentGate(t *testing.T) {
	f, clock := permanentFixture(t)
	send := func(m wire.Meta, body string) *httptest.ResponseRecorder {
		t.Helper()
		rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: m, body: []byte(body)})
		return rec
	}
	want := func(what string, rec *httptest.ResponseRecorder, code int, msg string) {
		t.Helper()
		if rec.Code != code || !strings.Contains(rec.Body.String(), msg) {
			t.Errorf("%s: %d %s, want %d %q", what, rec.Code, rec.Body, code, msg)
		}
	}
	body := []byte("x")
	for what, mod := range map[string]func(*wire.Meta){
		"once":       func(m *wire.Meta) { m.Once = true },
		"portal":     func(m *wire.Meta) { m.Portal = wire.PortalDownload },
		"secret":     func(m *wire.Meta) { m.Portal = wire.PortalReveal },
		"private":    func(m *wire.Meta) { m.Access = wire.AccessPrivate },
		"mutable":    func(m *wire.Meta) { m.Mutable = true },
		"pretty_url": func(m *wire.Meta) { m.PrettyURL = true },
	} {
		m := permMeta("builds/a", body)
		mod(&m)
		want(what, send(m, "x"), http.StatusUnprocessableEntity, "permanent excludes")
	}
	want("invalid", send(permMeta("builds/../x", body), "x"), http.StatusUnprocessableEntity, `is not a name`)
	want("reserved", send(permMeta("builds/current", body), "x"), http.StatusUnprocessableEntity, "reserved")
	// Not covered and covered but not granted answer alike.
	want("uncovered", send(permMeta("nope", body), "x"), http.StatusForbidden, `permanent name \"nope\" not allowed for this key`)
	want("not granted", send(permMeta("certs/a", body), "x"), http.StatusForbidden, `permanent name \"certs/a\" not allowed for this key`)
	want("pattern element", send(permMeta("builds/a/b", body), "x"), http.StatusForbidden, "not allowed for this key")
	// max 1 of builds/*.
	f.sendPermanent(t, clock, "builds/a", "a1")
	f.sendPermanent(t, clock, "builds/a", "a2")
	want("max", send(permMeta("builds/b", body), "x"), http.StatusConflict, "limit of 1 permanent names of this pattern reached")
	// A host of hosts:* may publish certs/*, nothing else.
	host := f.hostCert(t)
	rec, _ := f.do(t, req{signer: host, path: "/drop", meta: permMeta("certs/a", body), body: body})
	want("host not in drop allow", rec, http.StatusForbidden, "may not upload to drop")
	// The dry run answers the permanent URL.
	m := permMeta("builds/a", body)
	m.DryRun = true
	rec, out := f.do(t, req{signer: f.user, path: "/drop", meta: m, chunked: true})
	if rec.Code != 200 || out.Respond.URL != "https://lukd.vm:8443/d/permanent/builds/a" || out.Client.Permanent != "builds/a" {
		t.Errorf("dry run: %d %+v", rec.Code, out)
	}
	// Stored names under the path are refused before the body.
	g := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, `respond: url, storage: drop}`, permanentBlock, 1)
		return strings.Replace(s, `path: "{{ .Random }}", expose: drop`, `path: "{{ .File }}", expose: drop`, 1)
	})
	m = wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, File: "permanent"}
	rec, _ = g.do(t, req{signer: g.user, path: "/drop", meta: m, body: body, chunked: true})
	want("stored at the path", rec, http.StatusUnprocessableEntity, "reserved for the permanent names under permanent/")
}

func TestPermanentNotOffered(t *testing.T) {
	f := newFixture(t)
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: permMeta("x", []byte("x")), body: []byte("x")})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "endpoint drop does not offer permanent names") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for _, e := range decodeList(t, f.list(t, listReq{signer: f.user})).Endpoints {
		if e.Permanent {
			t.Fatalf("listed permanent on %s", e.Name)
		}
	}
	g, _ := permanentFixture(t)
	for _, e := range decodeList(t, g.list(t, listReq{signer: g.user})).Endpoints {
		if e.Permanent != (e.Name == "drop") {
			t.Fatalf("permanent %v on %s", e.Permanent, e.Name)
		}
	}
	// An endpoint granting the signer no entry answers as one without
	// permanent names.
	h := newFixtureWith(t, func(s string) string {
		return strings.Replace(s, `respond: url, storage: drop}`, `respond: url, storage: drop, permanent: {names: {"x": {allow: ["hosts:*"]}}}}`, 1)
	})
	rec, _ = h.do(t, req{signer: h.user, path: "/drop", meta: permMeta("x", []byte("x")), body: []byte("x")})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "does not offer permanent names") {
		t.Fatalf("no entry for the signer: %d %s", rec.Code, rec.Body)
	}
	for _, e := range decodeList(t, h.list(t, listReq{signer: h.user})).Endpoints {
		if e.Permanent {
			t.Fatalf("listed permanent on %s for a signer without an entry", e.Name)
		}
	}
}

func TestPermanentExpiredVersionIs404(t *testing.T) {
	f, clock := permanentFixture(t)
	const perm = "https://lukd.vm:8443/d/permanent/rev/hosts.krl"
	f.sendPermanent(t, clock, "rev/hosts.krl", "old")
	v2 := f.sendPermanent(t, clock, "rev/hosts.krl", "new")
	f.setSidecar(t, v2.VersionURL, func(sc *store.Sidecar) { sc.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) })
	// The published copy still holds the old expiry: the request checks
	// the version itself.
	expired := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	meta := filepath.Join(f.root, "s/drop/.db/permanent/permanent/rev/hosts.krl/current/meta.json")
	b, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	var sc store.Sidecar
	if err := json.Unmarshal(b, &sc); err != nil {
		t.Fatal(err)
	}
	sc.Expires = expired
	if b, err = json.Marshal(sc); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meta, b, 0o640); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.fetch(t, perm); code != http.StatusNotFound {
		t.Fatalf("expired before maintenance: %d", code)
	}
	// The maintenance pass unpublishes it: no fallback to an older one.
	if err := store.FromConfig(f.srv.config().Storage["drop"]).Reconcile(); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.fetch(t, perm); code != http.StatusNotFound {
		t.Fatalf("after expiry: %d", code)
	}
}
