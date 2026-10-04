package expose

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/auth"
	"luk/internal/config"
	"luk/internal/store"
	"luk/internal/wire"
)

// newSignedEnv is an env whose storage drop is exposed by pub with
// auth.ssh allow [alice], and protected by sec (auth.ssh allow ["*"]) on
// the same listener. The verifier takes the identity from the header
// X-Id: none is unsigned, "bad" a signature that does not verify.
func newSignedEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, func(x *config.Expose) { x.Auth.SSH = &config.SSHAuth{Allow: []string{"alice"}} })
	e.cfg.Storage["drop"].Protect = "sec"
	e.cfg.Expose["sec"] = &config.Expose{Listen: config.StringList{"l"}, Path: "/s/", Auth: config.ExposeAuth{SSH: &config.SSHAuth{Allow: []string{auth.AllowAll}}}}
	e.h = New(e.cfg, e.log(), func() time.Time { return e.now }, "l", fakeVerify)
	return e
}

func fakeVerify(r *http.Request) (*wire.Identity, error) {
	switch n := r.Header.Get("X-Id"); n {
	case "":
		return nil, ErrUnsigned
	case "bad":
		return nil, errors.New("signature does not verify")
	default:
		return &wire.Identity{Name: n, Type: "key"}, nil
	}
}

func as(id string) map[string]string { return map[string]string{"X-Id": id} }

func TestSignedExposeServes(t *testing.T) {
	e := newSignedEnv(t)
	e.put(t, "pub.txt", "hello", store.Sidecar{})
	e.put(t, "reveal", "secret", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	e.put(t, "own", "mine", store.Sidecar{Client: wire.Meta{Access: wire.AccessPrivate}, OwnerKey: "key:alice"})
	e.put(t, "any", "shared", store.Sidecar{Client: wire.Meta{Access: wire.AccessAny}})
	e.put(t, "once", "one", store.Sidecar{Client: wire.Meta{Once: true}})
	if w := e.do(t, "GET", "/d/pub.txt", as("alice")); w.Code != 200 || w.Body.String() != "hello" || w.Header().Get("ETag") == "" {
		t.Fatalf("alice: %d %q", w.Code, w.Body)
	}
	for name, h := range map[string]map[string]string{"unsigned": nil, "not allowed": as("bob")} {
		if w := e.do(t, "GET", "/d/pub.txt", h); w.Code != 404 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if w := e.do(t, "GET", "/d/pub.txt", as("bad")); w.Code != 401 {
		t.Errorf("bad signature: %d", w.Code)
	}
	// A portal upload: the content itself, never a landing page; the
	// action URLs do not exist.
	if w := e.do(t, "GET", "/d/reveal", as("alice")); w.Code != 200 || w.Body.String() != "secret" || w.Header().Get("Content-Disposition") == "" {
		t.Errorf("reveal: %d %q", w.Code, w.Body)
	}
	for _, m := range []string{"GET", "POST"} {
		if w := e.do(t, m, "/d/reveal/get", as("alice")); w.Code != 404 && w.Code != 405 {
			t.Errorf("%s action: %d", m, w.Code)
		}
	}
	if w := e.do(t, "POST", "/d/reveal/reveal", as("alice")); w.Code != 405 {
		t.Errorf("POST action: %d", w.Code)
	}
	// Private files belong to the protect expose.
	for _, n := range []string{"own", "any"} {
		if w := e.do(t, "GET", "/d/"+n, as("alice")); w.Code != 404 {
			t.Errorf("%s on the expose: %d", n, w.Code)
		}
		if w := e.do(t, "GET", "/s/"+n, as("alice")); w.Code != 200 {
			t.Errorf("%s on the protect: %d", n, w.Code)
		}
	}
	if w := e.do(t, "GET", "/s/pub.txt", as("alice")); w.Code != 404 {
		t.Errorf("public file on the protect: %d", w.Code)
	}
	// once: HEAD announces, GET claims.
	if w := e.do(t, "HEAD", "/d/once", as("alice")); w.Code != 200 || w.Header().Get(wire.HeaderOnce) != "true" {
		t.Errorf("once head: %d %v", w.Code, w.Header())
	}
	if w := e.do(t, "GET", "/d/once", as("alice")); w.Code != 200 || w.Body.String() != "one" {
		t.Errorf("once: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/once", as("alice")); w.Code != 404 {
		t.Errorf("once again: %d", w.Code)
	}
}

// signedList GETs the listing at p as alice and decodes it.
func (e *env) signedList(t *testing.T, p string) []wire.ListEntry {
	t.Helper()
	w := e.do(t, "GET", p, as("alice"))
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s: %d %v %s", p, w.Code, w.Header(), w.Body)
	}
	var out []wire.ListEntry
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return out
}

func names(ents []wire.ListEntry) string {
	var s []string
	for _, e := range ents {
		s = append(s, e.Name)
	}
	return strings.Join(s, " ")
}

func TestSignedListing(t *testing.T) {
	e := newSignedEnv(t)
	if got := e.signedList(t, "/d/"); got == nil || len(got) != 0 {
		t.Fatalf("empty root: %v", got)
	}
	e.fill(t)
	if err := os.WriteFile(filepath.Join(e.base, store.DataDir, "bare"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pub.txt", filepath.Join(e.base, store.DataDir, "lf")); err != nil {
		t.Fatal(err)
	}
	got := e.signedList(t, "/d/")
	if n := names(got); n != `.cfg/ b/ C/ .bashrc odd <&>"' %name pub.txt Readme readme` {
		t.Fatalf("root: %s", n)
	}
	if !got[0].Dir || got[0].Size != nil || got[0].SHA256 != "" {
		t.Errorf("dir entry %+v", got[0])
	}
	pub := got[5]
	if pub.Dir || pub.Size == nil || *pub.Size != 5 || pub.Received != "2026-09-30T10:15:00Z" || len(pub.SHA256) != 64 {
		t.Errorf("file entry %+v", pub)
	}
	w := e.do(t, "GET", "/d/", as("alice"))
	if !strings.HasPrefix(w.Body.String(), `[{"name":".cfg/","dir":true},`) || !strings.Contains(w.Body.String(), `{"name":"pub.txt","size":5,"received":"2026-09-30T10:15:00Z","sha256":"`) {
		t.Errorf("wire form %s", w.Body)
	}
	if n := names(e.signedList(t, "/d/b/")); n != "c/" {
		t.Errorf("b/: %s", n)
	}
	if n := names(e.signedList(t, "/d/?recursive=1")); n != `.bashrc .cfg/rc b/c/deep C/x odd <&>"' %name pub.txt Readme readme` {
		t.Errorf("recursive: %s", n)
	}
	if n := names(e.signedList(t, "/d/b/?recursive=1")); n != "c/deep" {
		t.Errorf("recursive b/: %s", n)
	}
	if w := e.do(t, "HEAD", "/d/", as("alice")); w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") == "" {
		t.Errorf("HEAD: %d %q", w.Code, w.Body)
	}
	// Nothing listable, unknown, not allowed or unsigned: 404.
	for _, p := range []string{"/d/secret/", "/d/gone/", "/d/missing/", "/d/pub.txt/", "/d/secret/?recursive=1", "/d/lf/"} {
		if w := e.do(t, "GET", p, as("alice")); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	for _, h := range []map[string]string{nil, as("bob")} {
		for _, p := range []string{"/d/", "/d/b/", "/d/?recursive=1"} {
			if w := e.do(t, "GET", p, h); w.Code != 404 {
				t.Errorf("%v %s: %d", h, p, w.Code)
			}
		}
	}
	if w := e.do(t, "GET", "/d/", as("bad")); w.Code != 401 {
		t.Errorf("bad signature: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/?recursive=yes", as("alice")); w.Code != 400 {
		t.Errorf("unknown query: %d", w.Code)
	}
	// Without the slash a directory is a missing file; the protect has no
	// listing.
	for _, p := range []string{"/d/b", "/d", "/s/", "/s/b/"} {
		if w := e.do(t, "GET", p, as("alice")); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := e.do(t, "POST", "/d/", as("alice")); w.Code != 405 {
		t.Errorf("POST: %d", w.Code)
	}
}

func TestSignedListingSharded(t *testing.T) {
	e := newSignedEnv(t)
	e.cfg.Storage["drop"].Shard = 1
	e.st.Shard = 1
	e.h = New(e.cfg, e.log(), func() time.Time { return e.now }, "l", fakeVerify)
	e.put(t, "f", "x", store.Sidecar{})
	if w := e.do(t, "GET", "/d/f", as("alice")); w.Code != 200 {
		t.Errorf("file: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/", as("alice")); w.Code != 404 {
		t.Errorf("listing: %d", w.Code)
	}
}
