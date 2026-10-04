package gpgkeys_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"luk/internal/gpgkeys"
	"luk/internal/gpgkeys/gpgtest"
)

func TestHashVectors(t *testing.T) {
	cases := map[string]string{
		"Joe.Doe": "iy9q119eutrkn8s1mk4r39qejnbu3n5q",
		"joe.doe": "iy9q119eutrkn8s1mk4r39qejnbu3n5q",
	}
	for in, want := range cases {
		if got := gpgkeys.Hash(in); got != want {
			t.Errorf("Hash(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestURLs(t *testing.T) {
	a, err := gpgkeys.AdvancedURL("Joe.Doe@Example.ORG")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"; a != want {
		t.Errorf("advanced %s", a)
	}
	d, err := gpgkeys.DirectURL("Joe.Doe@Example.ORG")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"; d != want {
		t.Errorf("direct %s", d)
	}
	if _, err := gpgkeys.DirectURL("nodomain"); err == nil {
		t.Error("address without domain accepted")
	}
}

func TestUsable(t *testing.T) {
	now := time.Now()
	const a = "a@example.org"
	if err := gpgkeys.Usable(gpgtest.New(t, a), a, now); err != nil {
		t.Errorf("good key: %v", err)
	}
	for name, e := range map[string]*openpgp.Entity{
		"expired":   gpgtest.Expired(t, a),
		"revoked":   gpgtest.Revoked(t, a),
		"other uid": gpgtest.New(t, "b@example.org"),
	} {
		if err := gpgkeys.Usable(e, a, now); err == nil {
			t.Errorf("%s: usable", name)
		}
	}
}

func writeKeys(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestKeyDir(t *testing.T) {
	dir := t.TempDir()
	good := gpgtest.New(t, "Matt@Example.com")
	writeKeys(t, dir, "matt.asc", gpgtest.Armored(t, good))
	writeKeys(t, dir, "old.asc", gpgtest.Armored(t, gpgtest.Expired(t, "old@example.com")))
	writeKeys(t, dir, "broken.asc", []byte("garbage"))
	writeKeys(t, dir, "ignored.txt", gpgtest.Armored(t, gpgtest.New(t, "txt@example.com")))
	bin := gpgtest.New(t, "bin@example.com")
	writeKeys(t, dir, "bin.gpg", gpgtest.Public(t, bin))
	writeKeys(t, dir, "noext@example.com", gpgtest.Armored(t, gpgtest.New(t, "noext@example.com")))
	r := &gpgkeys.Resolver{Dir: dir}

	rc, err := r.Key("matt@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if fp := rc.Fingerprints(); len(fp) != 1 || fp[0] != gpgkeys.Fingerprint(good) || fp[0] != strings.ToUpper(fp[0]) {
		t.Fatalf("fingerprints %v", fp)
	}
	if len(rc.Notes) != 1 || !strings.Contains(rc.Notes[0], "broken.asc") {
		t.Errorf("notes %v", rc.Notes)
	}
	if _, err := r.Key("old@example.com"); err == nil || !strings.Contains(err.Error(), "no usable key") {
		t.Errorf("expired: %v", err)
	}
	if _, err := r.Key("txt@example.com"); err == nil || !strings.Contains(err.Error(), "no key with user id") {
		t.Errorf("non-key file read: %v", err)
	}
	if _, err := r.Key("noext@example.com"); err == nil || !strings.Contains(err.Error(), "no key with user id") {
		t.Errorf("file without extension read: %v", err)
	}
	if rc, err := r.Key("bin@example.com"); err != nil || len(rc.Fingerprints()) != 1 || rc.Fingerprints()[0] != gpgkeys.Fingerprint(bin) {
		t.Errorf("binary .gpg: %v %v", rc, err)
	}
}

type wkdServer struct {
	srv      *httptest.Server
	hits     atomic.Int32
	status   atomic.Int32
	path     atomic.Value
	host     atomic.Value
	body     []byte
	advanced bool
}

// newWKD serves body for example.com; with advanced false the host
// openpgpkey.example.com does not answer.
func newWKD(t *testing.T, body []byte, advanced bool) *wkdServer {
	t.Helper()
	w := &wkdServer{body: body, advanced: advanced}
	w.status.Store(200)
	w.srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.hits.Add(1)
		if st := int(w.status.Load()); st != 200 {
			http.Error(rw, "no", st)
			return
		}
		w.host.Store(r.Host)
		w.path.Store(r.URL.String())
		rw.Write(w.body)
	}))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *wkdServer) resolver(t *testing.T, now func() time.Time) *gpgkeys.Resolver {
	tr := w.srv.Client().Transport.(*http.Transport).Clone()
	addr := w.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, a string) (net.Conn, error) {
		if a == "openpgpkey.example.com:443" && !w.advanced || a != "openpgpkey.example.com:443" && a != "example.com:443" {
			return nil, errors.New("no such host")
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return &gpgkeys.Resolver{Cache: t.TempDir(), Client: &http.Client{Transport: tr}, Now: now}
}

const joe = "joe.doe@example.com"

func TestWKDAdvancedAndDirect(t *testing.T) {
	e := gpgtest.New(t, joe)
	for _, advanced := range []bool{true, false} {
		w := newWKD(t, gpgtest.Public(t, e), advanced)
		r := w.resolver(t, nil)
		rc, err := r.WKD(context.Background(), joe)
		if err != nil {
			t.Fatalf("advanced %v: %v", advanced, err)
		}
		if len(rc.Entities) != 1 {
			t.Fatalf("entities %d", len(rc.Entities))
		}
		host, want := "example.com", "/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe"
		if advanced {
			host, want = "openpgpkey.example.com", "/.well-known/openpgpkey/example.com/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe"
		}
		if got := w.path.Load(); got != want || w.host.Load() != host {
			t.Errorf("advanced %v: %v %v, want %s %s", advanced, w.host.Load(), got, host, want)
		}
		if _, err := os.Stat(filepath.Join(r.Cache, joe+".pgp")); err != nil {
			t.Errorf("not cached: %v", err)
		}
	}
}

func TestWKDBaseURL(t *testing.T) {
	w := newWKD(t, gpgtest.Public(t, gpgtest.New(t, joe)), true)
	r := &gpgkeys.Resolver{Cache: t.TempDir(), Client: w.srv.Client(), BaseURL: w.srv.URL}
	if _, err := r.WKD(context.Background(), joe); err != nil {
		t.Fatal(err)
	}
	if got := w.path.Load(); got != "/.well-known/openpgpkey/example.com/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe" {
		t.Errorf("path %v", got)
	}
}

func TestWKDCacheFreshness(t *testing.T) {
	w := newWKD(t, gpgtest.Public(t, gpgtest.New(t, joe)), true)
	now := time.Now()
	r := w.resolver(t, func() time.Time { return now })
	r.Fresh = time.Hour
	for range 2 {
		if _, err := r.WKD(context.Background(), joe); err != nil {
			t.Fatal(err)
		}
	}
	if n := w.hits.Load(); n != 1 {
		t.Fatalf("fresh cache: %d requests", n)
	}
	now = now.Add(2 * time.Hour)
	if _, err := r.WKD(context.Background(), joe); err != nil {
		t.Fatal(err)
	}
	if n := w.hits.Load(); n != 2 {
		t.Fatalf("stale cache not refetched: %d requests", n)
	}
	fi, err := os.Stat(filepath.Join(r.Cache, joe+".pgp"))
	if err != nil || !fi.ModTime().Equal(now.Truncate(time.Second)) && !fi.ModTime().Equal(now) {
		t.Errorf("cache mtime %v, want %v (%v)", fi.ModTime(), now, err)
	}
}

func TestWKDStaleOnError(t *testing.T) {
	w := newWKD(t, gpgtest.Public(t, gpgtest.New(t, joe)), true)
	now := time.Now()
	r := w.resolver(t, func() time.Time { return now })
	if _, err := r.WKD(context.Background(), joe); err != nil {
		t.Fatal(err)
	}
	now = now.Add(48 * time.Hour)
	w.status.Store(503)
	rc, err := r.WKD(context.Background(), joe)
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.Entities) != 1 || len(rc.Notes) != 1 || !strings.Contains(rc.Notes[0], "using the cached key") {
		t.Fatalf("stale: %d entities, notes %v", len(rc.Entities), rc.Notes)
	}
	w.srv.Close()
	if rc, err := r.WKD(context.Background(), joe); err != nil || len(rc.Notes) != 1 {
		t.Fatalf("server gone: %v %v", err, rc.Notes)
	}
}

func TestWKDNoCacheFailure(t *testing.T) {
	w := newWKD(t, nil, true)
	w.status.Store(503)
	if _, err := w.resolver(t, nil).WKD(context.Background(), "x@example.com"); err == nil {
		t.Fatal("fetch failure without cache accepted")
	}
}

func TestWKD404(t *testing.T) {
	w := newWKD(t, gpgtest.Public(t, gpgtest.New(t, joe)), true)
	now := time.Now()
	r := w.resolver(t, func() time.Time { return now })
	if _, err := r.WKD(context.Background(), joe); err != nil {
		t.Fatal(err)
	}
	now = now.Add(48 * time.Hour)
	w.status.Store(404)
	if _, err := r.WKD(context.Background(), joe); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404 with a stale cache: %v", err)
	}
	if _, err := r.WKD(context.Background(), "other@example.com"); err == nil {
		t.Fatal("404 accepted")
	}
}

func TestWKDOversize(t *testing.T) {
	w := newWKD(t, make([]byte, gpgkeys.MaxBody+1), true)
	if _, err := w.resolver(t, nil).WKD(context.Background(), joe); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversize: %v", err)
	}
}

func TestWKDUnusableKey(t *testing.T) {
	w := newWKD(t, gpgtest.Public(t, gpgtest.Revoked(t, joe), gpgtest.New(t, "someone@example.org")), true)
	if _, err := w.resolver(t, nil).WKD(context.Background(), joe); err == nil {
		t.Fatal("revoked key usable")
	}
}
