package server

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/sshsig"
	"luk/internal/wire"
)

// listReq is a request of the endpoint listing.
type listReq struct {
	signer ssh.Signer
	method string // default GET
	host   string // default lukd.test
	path   string // default wire.EndpointsPath
	ns     string // default wire.ListNamespace
	nonce  string
	ts     time.Time
	// unsigned sends no signature headers.
	unsigned bool
	via      http.Handler
}

func (f *fixture) list(t *testing.T, r listReq) *httptest.ResponseRecorder {
	t.Helper()
	if r.method == "" {
		r.method = http.MethodGet
	}
	if r.host == "" {
		r.host = "lukd.test"
	}
	if r.path == "" {
		r.path = wire.EndpointsPath
	}
	if r.ns == "" {
		r.ns = wire.ListNamespace
	}
	if r.nonce == "" {
		r.nonce = wire.NewNonce()
	}
	if r.ts.IsZero() {
		r.ts = time.Now()
	}
	hr := httptest.NewRequest(r.method, "https://"+r.host+r.path, nil)
	hr.Host = r.host
	if !r.unsigned {
		ts := r.ts.UTC().Format(time.RFC3339)
		sig, err := sshsig.Sign(r.signer, r.ns, wire.ListCanonicalText(r.method, r.host, r.path, ts, r.nonce))
		if err != nil {
			t.Fatal(err)
		}
		hr.Header.Set(wire.HeaderTimestamp, ts)
		hr.Header.Set(wire.HeaderNonce, r.nonce)
		hr.Header.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
	}
	rec := httptest.NewRecorder()
	h := r.via
	if h == nil {
		h = f.handler()
	}
	h.ServeHTTP(rec, hr)
	return rec
}

func decodeList(t *testing.T, rec *httptest.ResponseRecorder) wire.EndpointList {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("%d: %s", rec.Code, rec.Body)
	}
	var out wire.EndpointList
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEndpointList(t *testing.T) {
	f := newPrivateFixture(t, func(s string) string {
		return strings.Replace(s, `link: {remove: ['*'], list: ['*']}}`, `link: {replace: ['*'], list: ['*']}, pretty: {allow: ['*']}}`, 1)
	})
	got := decodeList(t, f.list(t, listReq{signer: f.user}))
	want := wire.EndpointList{Endpoints: []wire.EndpointInfo{
		{Name: "backup", Path: "/backup", URL: "https://lukd.test/backup", Respond: "accept"},
		{Name: "drop", Path: "/drop", URL: "https://lukd.test/drop", Respond: "url", Pretty: true,
			Private: wire.PrivateModes{Owner: true, Any: true}, Link: wire.LinkActions{Replace: true, List: true},
			TTL: &wire.TTLPolicy{User: true, Max: "7d", Default: "7d"}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	// The allow of backup does not admit other.
	got = decodeList(t, f.list(t, listReq{signer: f.other, host: "lukd.test:8443"}))
	if len(got.Endpoints) != 1 || got.Endpoints[0].Name != "drop" || got.Endpoints[0].URL != "https://lukd.test:8443/drop" {
		t.Fatalf("other: %+v", got)
	}
	got = decodeList(t, f.list(t, listReq{signer: f.hostCert(t)}))
	if len(got.Endpoints) != 2 {
		t.Fatalf("host: %+v", got)
	}
}

func TestEndpointListSecretTTL(t *testing.T) {
	f := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, `respond: url, storage: drop}`, `respond: url, storage: drop, secret: {allow: ['*'], path: q/secret, storage: volatile}}`, 1)
		s = strings.Replace(s, "expose: drop}\n", "expose: drop}\n  volatile: {type: local, base: s/volatile, ttl: {user: true, min: 1h, max: 1d}, path: \"{{ .Random }}\", expose: volatile}\n", 1)
		return strings.Replace(s, "drop: {listen: main, path: /d/}", "drop: {listen: main, path: /d/}\n  volatile: {listen: main, path: /v/}", 1)
	})
	got := decodeList(t, f.list(t, listReq{signer: f.user}))
	d := got.Endpoints[1]
	if !d.Secret || d.SecretTTL == nil || *d.SecretTTL != (wire.TTLPolicy{User: true, Min: "1h", Max: "1d", Default: "1d"}) {
		t.Fatalf("%+v", d)
	}
}

func TestEndpointListRejected(t *testing.T) {
	f := newFixture(t)
	nonce := wire.NewNonce()
	if rec := f.list(t, listReq{signer: f.user, nonce: nonce}); rec.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rec.Code, rec.Body)
	}
	for name, c := range map[string]struct {
		r    listReq
		code int
		msg  string
	}{
		"unsigned":    {listReq{unsigned: true}, 401, "missing signature headers"},
		"unknown key": {listReq{signer: newSigner(t)}, 401, "unknown key"},
		"get ns":      {listReq{signer: f.user, ns: wire.GetNamespace}, 401, "namespace"},
		"link ns":     {listReq{signer: f.user, ns: wire.LinkNamespace}, 401, "namespace"},
		"old":         {listReq{signer: f.user, ts: time.Now().Add(-time.Hour)}, 401, wire.ErrTimestampWindow},
		"replay":      {listReq{signer: f.user, nonce: nonce}, 401, "replayed nonce"},
		"method":      {listReq{signer: f.user, method: http.MethodPut}, 405, "use GET"},
	} {
		rec := f.list(t, c.r)
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.msg) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if c.code == 405 && rec.Header().Get("Allow") != http.MethodGet {
			t.Errorf("%s: Allow %q", name, rec.Header().Get("Allow"))
		}
	}
	// A list signature is no get and no upload.
	pf := newPrivateFixture(t, nil)
	link := pf.drop(t, pf.user, wire.Meta{Access: wire.AccessPrivate}, "secret")
	if rec := pf.get(t, getReq{signer: pf.user, link: link, ns: wire.ListNamespace}); rec.Code != http.StatusUnauthorized {
		t.Errorf("get signed as list: %d %s", rec.Code, rec.Body)
	}
}

// The listing is per listener, also on one without endpoints whose
// expose serves /, and leaves the rest of /.well-known to the expose.
func TestEndpointListPerListener(t *testing.T) {
	f := newPrivateFixture(t, nil)
	secure := f.srv.Handler("127.0.0.1:443")
	got := decodeList(t, f.list(t, listReq{signer: f.user, host: "secure.vm", via: secure}))
	if len(got.Endpoints) != 0 {
		t.Fatalf("secure: %+v", got)
	}
	if rec := f.list(t, listReq{unsigned: true, host: "secure.vm", via: secure}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("secure unsigned: %d %s", rec.Code, rec.Body)
	}
	if rec := f.list(t, listReq{unsigned: true, host: "secure.vm", path: "/.well-known/other", via: secure}); rec.Code != http.StatusNotFound {
		t.Fatalf("other well-known: %d %s", rec.Code, rec.Body)
	}
}

// The acme: true listener keeps answering the challenges and redirects
// the listing to https like any other path.
func TestEndpointListACME(t *testing.T) {
	cfg := acmeTestConfig(t, t.TempDir(), "https://ca.example.com/dir", "0.0.0.0:8443", "127.0.0.1:8080")
	s := New(cfg, slog.New(slog.DiscardHandler))
	s.acme = newACME(cfg, slog.New(slog.DiscardHandler), nil)
	for _, c := range []struct {
		addr, path string
		code       int
	}{
		{"127.0.0.1:8080", wire.EndpointsPath, http.StatusPermanentRedirect},
		{"127.0.0.1:8080", "/.well-known/acme-challenge/tok", http.StatusNotFound},
		{"0.0.0.0:8443", wire.EndpointsPath, http.StatusUnauthorized},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, c.path, nil)
		r.Host = "drop.example.com"
		s.Handler(c.addr).ServeHTTP(w, r)
		if w.Code != c.code {
			t.Errorf("%s %s: %d %s", c.addr, c.path, w.Code, w.Body)
		}
	}
}
