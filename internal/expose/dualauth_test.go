package expose

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"luk/internal/store"
	"luk/internal/wire"
)

// newDualEnv is the signed env whose expose pub also has auth.basic
// (alice:pw) and index, logging at info.
func newDualEnv(t *testing.T) *env {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	e := newSignedEnv(t)
	x := e.cfg.Expose["pub"]
	x.Auth.Basic, x.Index = []string{"alice:" + string(hash)}, true
	e.cfg.Storage["drop"].Catalog, e.st.Catalog = true, true
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	e.h = New(e.cfg, log, func() time.Time { return e.now }, "l", fakeVerify)
	return e
}

// basic adds the Authorization header of user:pass to h.
func basic(h map[string]string, user, pass string) map[string]string {
	out := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))}
	for k, v := range h {
		out[k] = v
	}
	return out
}

func TestDualAuthDownload(t *testing.T) {
	e := newDualEnv(t)
	e.put(t, "pub.txt", "hello", store.Sidecar{})
	for name, h := range map[string]map[string]string{
		"basic":  basic(nil, "alice", "pw"),
		"signed": as("alice"),
		"both":   basic(as("alice"), "alice", "pw"),
	} {
		if w := e.do(t, "GET", "/d/pub.txt", h); w.Code != 200 || w.Body.String() != "hello" {
			t.Errorf("%s: %d %q", name, w.Code, w.Body)
		}
	}
	// A signed request is judged by its signature alone.
	if w := e.do(t, "GET", "/d/pub.txt", basic(as("bad"), "alice", "pw")); w.Code != 401 || w.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("bad signature with basic: %d %v", w.Code, w.Header())
	}
	if w := e.do(t, "GET", "/d/pub.txt", basic(as("bob"), "alice", "pw")); w.Code != 404 {
		t.Errorf("signer not allowed with basic: %d", w.Code)
	}
	for name, h := range map[string]map[string]string{"none": nil, "wrong password": basic(nil, "alice", "bad")} {
		if w := e.do(t, "GET", "/d/pub.txt", h); w.Code != 401 || w.Header().Get("WWW-Authenticate") != `Basic realm="luk"` {
			t.Errorf("%s: %d %v", name, w.Code, w.Header())
		}
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "auth=ssh") || !strings.Contains(logs, "auth=basic") || !strings.Contains(logs, "user=alice") {
		t.Errorf("logs:\n%s", logs)
	}
}

func TestDualAuthPrivateAndPortal(t *testing.T) {
	e := newDualEnv(t)
	e.put(t, "reveal", "secret", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	e.put(t, "own", "mine", store.Sidecar{Client: wire.Meta{Access: wire.AccessPrivate}, OwnerKey: "key:alice"})
	e.put(t, "any", "shared", store.Sidecar{Client: wire.Meta{Access: wire.AccessAny}})
	for _, n := range []string{"own", "any"} {
		if w := e.do(t, "GET", "/d/"+n, basic(nil, "alice", "pw")); w.Code != 404 {
			t.Errorf("%s via basic: %d", n, w.Code)
		}
		if w := e.do(t, "GET", "/s/"+n, basic(nil, "alice", "pw")); w.Code != 404 {
			t.Errorf("%s via basic on the protect: %d", n, w.Code)
		}
	}
	// basic gets the portal, a signed request the content.
	if w := e.do(t, "GET", "/d/reveal", basic(nil, "alice", "pw")); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "<!doctype html>") {
		t.Errorf("landing via basic: %d %q", w.Code, w.Body)
	}
	if w := e.do(t, "GET", "/d/reveal/get", basic(nil, "alice", "pw")); w.Code != 200 || w.Body.String() != "secret" {
		t.Errorf("get via basic: %d %q", w.Code, w.Body)
	}
	if w := e.do(t, "GET", "/d/reveal/get", as("alice")); w.Code != 404 {
		t.Errorf("signed action: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/reveal", as("alice")); w.Code != 200 || w.Body.String() != "secret" {
		t.Errorf("signed: %d %q", w.Code, w.Body)
	}
	// No expose with auth.ssh serves the catalog.
	if err := e.st.RebuildCatalog(); err != nil {
		t.Fatal(err)
	}
	if w := e.do(t, "GET", "/d/"+store.CatalogName, basic(nil, "alice", "pw")); w.Code != 404 {
		t.Errorf("catalog via basic: %d", w.Code)
	}
}

func TestDualAuthListing(t *testing.T) {
	e := newDualEnv(t)
	e.put(t, "pub.txt", "hello", store.Sidecar{})
	e.put(t, "b/f", "x", store.Sidecar{})
	e.put(t, "any", "shared", store.Sidecar{Client: wire.Meta{Access: wire.AccessAny}})
	w := e.do(t, "GET", "/d/", basic(nil, "alice", "pw"))
	if got := links(w.Body.String()); w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || len(got) != 2 || got[0][0] != "./b/" || got[1][0] != "./pub.txt" {
		t.Errorf("html index: %d %v %v", w.Code, w.Header(), got)
	}
	if w := e.do(t, "GET", "/d", basic(nil, "alice", "pw")); w.Code/100 != 3 {
		t.Errorf("index without slash: %d", w.Code)
	}
	if got := names(e.signedList(t, "/d/")); got != "b/ pub.txt" {
		t.Errorf("signed listing: %q", got)
	}
	if w := e.do(t, "GET", "/d/", nil); w.Code != 401 {
		t.Errorf("index without auth: %d", w.Code)
	}
	var ents []wire.ListEntry
	if w := e.do(t, "GET", "/d/b/", as("alice")); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ents) != nil || names(ents) != "f" {
		t.Errorf("signed sub listing: %d %s", w.Code, w.Body)
	}
}

func TestDualAuthSigned(t *testing.T) {
	e := newDualEnv(t)
	e.put(t, "b/f", "x", store.Sidecar{})
	e.put(t, "reveal", "secret", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	e.put(t, "o", "one", store.Sidecar{Client: wire.Meta{Once: true}})
	// A directory name without its slash: the index redirect is for
	// unsigned requests only, a signer gets 404 whoever it is.
	for _, id := range []string{"alice", "bob"} {
		if w := e.do(t, "GET", "/d/b", as(id)); w.Code != 404 {
			t.Errorf("%s: /d/b %d", id, w.Code)
		}
	}
	if w := e.do(t, "GET", "/d/b", basic(nil, "alice", "pw")); w.Code != 301 {
		t.Errorf("basic: /d/b %d", w.Code)
	}
	for _, p := range []string{"/d/reveal/reveal", "/d/reveal/get", "/d/o/download"} {
		if w := e.do(t, "POST", p, as("alice")); w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("signed POST %s: %d %v", p, w.Code, w.Header())
		}
	}
	if w := e.do(t, "GET", "/d/o", as("alice")); w.Code != 200 || w.Body.String() != "one" {
		t.Errorf("once: %d %q", w.Code, w.Body)
	}
	if w := e.do(t, "GET", "/d/o", as("alice")); w.Code != 404 {
		t.Errorf("once again: %d", w.Code)
	}
}

func TestDualAuthBasicOnceAndLog(t *testing.T) {
	e := newDualEnv(t)
	e.put(t, "dl", "one", store.Sidecar{Client: wire.Meta{Once: true, Portal: wire.PortalDownload}})
	e.put(t, "pub.txt", "hello", store.Sidecar{})
	for _, m := range []string{"GET", "HEAD"} {
		if w := e.do(t, m, "/d/dl", basic(nil, "alice", "pw")); w.Code != 200 {
			t.Errorf("%s landing: %d", m, w.Code)
		}
	}
	if w := e.do(t, "HEAD", "/d/pub.txt", basic(nil, "alice", "pw")); w.Code != 200 {
		t.Errorf("head: %d", w.Code)
	}
	if strings.Contains(e.logs.String(), "download") {
		t.Errorf("landing pages and HEAD logged as downloads:\n%s", e.logs)
	}
	if w := e.do(t, "POST", "/d/dl/download", basic(nil, "alice", "pw")); w.Code != 200 || w.Body.String() != "one" {
		t.Errorf("download: %d %q", w.Code, w.Body)
	}
	if w := e.do(t, "POST", "/d/dl/download", basic(nil, "alice", "pw")); w.Code != 404 {
		t.Errorf("download again: %d", w.Code)
	}
	if logs := e.logs.String(); strings.Count(logs, "auth=basic") != 1 || !strings.Contains(logs, "action=download") {
		t.Errorf("logs:\n%s", logs)
	}
}

// A basic download is logged only when content goes out: not for a 304,
// a 416 or a once file claimed by another request meanwhile.
func TestDualAuthBasicLogOnlySent(t *testing.T) {
	e := newDualEnv(t)
	e.put(t, "pub.txt", "hello", store.Sidecar{SHA256: sumHex("hello")})
	e.put(t, "o", "one", store.Sidecar{Client: wire.Meta{Once: true}})
	if w := e.do(t, "GET", "/d/pub.txt", basic(map[string]string{"If-None-Match": `"` + sumHex("hello") + `"`}, "alice", "pw")); w.Code != 304 {
		t.Errorf("if-none-match: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/pub.txt", basic(map[string]string{"Range": "bytes=100-"}, "alice", "pw")); w.Code != 416 {
		t.Errorf("range: %d", w.Code)
	}
	orig := beforeClaim
	defer func() { beforeClaim = orig }()
	beforeClaim = func() {
		beforeClaim = func() {}
		if w := e.do(t, "GET", "/d/o", as("alice")); w.Code != 200 {
			t.Errorf("other claim: %d", w.Code)
		}
	}
	if w := e.do(t, "GET", "/d/o", basic(nil, "alice", "pw")); w.Code != 404 {
		t.Errorf("claimed meanwhile: %d", w.Code)
	}
	if logs := e.logs.String(); strings.Contains(logs, "auth=basic") {
		t.Errorf("logged without content:\n%s", logs)
	}
	if w := e.do(t, "GET", "/d/pub.txt", basic(map[string]string{"Range": "bytes=1-2"}, "alice", "pw")); w.Code != 206 || w.Body.String() != "el" {
		t.Errorf("partial: %d %q", w.Code, w.Body)
	}
	if logs := e.logs.String(); strings.Count(logs, "auth=basic") != 1 {
		t.Errorf("partial content not logged once:\n%s", logs)
	}
}

func sumHex(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}
