package expose

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/store"
	"luk/internal/wire"
)

func newCatalogEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, nil)
	e.cfg.Storage["drop"].Catalog = true
	e.st.Catalog = true
	e.h = New(e.cfg, e.log(), func() time.Time { return e.now }, "l", nil)
	return e
}

func aliasSidecar(alias string, received time.Time, expires string) store.Sidecar {
	return store.Sidecar{Received: received.UTC().Format(time.RFC3339), Expires: expires,
		Meta: json.RawMessage(`{"alias":"` + alias + `"}`)}
}

func TestCatalogServed(t *testing.T) {
	e := newCatalogEnv(t)
	e.put(t, "a/f", "hello", store.Sidecar{})
	w := e.do(t, "GET", "/d/catalog.json", nil)
	if w.Code != 200 {
		t.Fatalf("code %d", w.Code)
	}
	for k, v := range map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q", k, got)
		}
	}
	var c struct {
		Files []struct{ Name string } `json:"files"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || len(c.Files) != 1 || c.Files[0].Name != "a/f" {
		t.Fatalf("%s %v", w.Body, err)
	}
	if w := e.do(t, "HEAD", "/d/catalog.json", nil); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("head %d", w.Code)
	}
	if w := e.do(t, "POST", "/d/catalog.json", nil); w.Code != 405 {
		t.Fatalf("post %d", w.Code)
	}
}

func TestCatalogDisabledIsAFile(t *testing.T) {
	e := newEnv(t, nil)
	if w := e.do(t, "GET", "/d/catalog.json", nil); w.Code != 404 {
		t.Fatalf("missing %d", w.Code)
	}
	e.put(t, "catalog.json", "plain", store.Sidecar{})
	if w := e.do(t, "GET", "/d/catalog.json", nil); w.Code != 200 || w.Body.String() != "plain" {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
}

func TestAliasDownload(t *testing.T) {
	e := newCatalogEnv(t)
	sc := aliasSidecar("latest", t0.Add(-time.Hour), "")
	sc.Client.File = "db.sql"
	e.put(t, "d1/x", "one", sc)
	e.put(t, "d2/dump", "two", aliasSidecar("latest", t0, ""))
	w := e.do(t, "GET", "/d/latest", nil)
	if w.Code != 200 || w.Body.String() != "two" || w.Header().Get("Content-Disposition") != `attachment; filename="dump"` {
		t.Fatalf("%d %q %q", w.Code, w.Body, w.Header().Get("Content-Disposition"))
	}
	if err := e.st.Remove("d2/dump"); err != nil {
		t.Fatal(err)
	}
	w = e.do(t, "GET", "/d/latest", nil)
	if w.Code != 200 || w.Body.String() != "one" || w.Header().Get("Content-Disposition") != `attachment; filename="db.sql"` {
		t.Fatalf("%d %q %q", w.Code, w.Body, w.Header().Get("Content-Disposition"))
	}
}

func TestJanitorRepairsAlias(t *testing.T) {
	e := newCatalogEnv(t)
	e.put(t, "d1", "one", aliasSidecar("latest", t0.Add(-time.Hour), ""))
	e.put(t, "d2", "two", aliasSidecar("latest", t0, ""))
	os.Remove(filepath.Join(e.base, store.DataDir, "d2"))
	os.Remove(e.st.SidecarPath("d2"))
	sweep(e.cfg, e.log(), t0)
	if w := e.do(t, "GET", "/d/latest", nil); w.Code != 200 || w.Body.String() != "one" {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	if w := e.do(t, "GET", "/d/catalog.json", nil); !strings.Contains(w.Body.String(), `"latest":{"latest":"d1"}`) {
		t.Fatalf("catalog %s", w.Body)
	}
}

func TestJanitorExpiryRepointsAlias(t *testing.T) {
	for _, alias := range []string{"latest", "a"} {
		t.Run(alias, func(t *testing.T) { testJanitorExpiryRepointsAlias(t, alias) })
	}
}

func testJanitorExpiryRepointsAlias(t *testing.T, alias string) {
	e := newCatalogEnv(t)
	e.put(t, "d1", "one", aliasSidecar(alias, t0.Add(-2*time.Hour), t0.Add(time.Hour).Format(time.RFC3339)))
	e.put(t, "d2", "two", aliasSidecar(alias, t0.Add(-time.Hour), t0.Add(-time.Minute).Format(time.RFC3339)))
	if w := e.do(t, "GET", "/d/"+alias, nil); w.Code != 404 {
		t.Fatalf("alias of an expired target: %d", w.Code)
	}
	sweep(e.cfg, e.log(), t0)
	if exists(filepath.Join(e.base, store.DataDir, "d2")) {
		t.Fatal("expired target kept")
	}
	if w := e.do(t, "GET", "/d/"+alias, nil); w.Code != 200 || w.Body.String() != "one" {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
	sweep(e.cfg, e.log(), t0.Add(2*time.Hour))
	if exists(filepath.Join(e.base, store.DataDir, alias)) || exists(e.st.SidecarPath(alias)) {
		t.Fatal("alias kept after its last target")
	}
	if e.logs.Len() != 0 {
		t.Fatalf("logs: %s", e.logs)
	}
}

func TestJanitorBuildsCatalog(t *testing.T) {
	e := newCatalogEnv(t)
	sweep(e.cfg, e.log(), t0)
	b, err := os.ReadFile(filepath.Join(e.base, ".db", "catalog.json"))
	if err != nil || !strings.Contains(string(b), `"files":[]`) {
		t.Fatalf("%s %v", b, err)
	}
}

func TestExpiryRebuildsCatalog(t *testing.T) {
	e := newCatalogEnv(t)
	e.put(t, "gone", "one", store.Sidecar{Received: t0.Add(-time.Hour).Format(time.RFC3339), Expires: t0.Add(-time.Minute).Format(time.RFC3339)})
	e.put(t, "kept", "two", store.Sidecar{Received: t0.Format(time.RFC3339)})
	expire(e.cfg, e.log(), t0)
	w := e.do(t, "GET", "/d/catalog.json", nil)
	if strings.Contains(w.Body.String(), `"gone"`) || !strings.Contains(w.Body.String(), `"kept"`) {
		t.Fatalf("catalog after expiry %s", w.Body)
	}
}

// catalogNames GETs the catalog at p with h and returns the names it lists.
func (e *env) catalogNames(t *testing.T, p string, h map[string]string) string {
	t.Helper()
	w := e.do(t, "GET", p, h)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s: %d %v %s", p, w.Code, w.Header(), w.Body)
	}
	var c struct {
		Files []struct{ Name string } `json:"files"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	var out []string
	for _, f := range c.Files {
		out = append(out, f.Name)
	}
	return strings.Join(out, " ")
}

// fillCatalog stores a public and two private files and rebuilds the
// catalog.
func (e *env) fillCatalog(t *testing.T) {
	t.Helper()
	e.put(t, "pub.txt", "hello", store.Sidecar{})
	e.put(t, "own", "mine", store.Sidecar{Client: wire.Meta{Access: wire.AccessPrivate}, OwnerKey: "key:alice"})
	e.put(t, "any", "shared", store.Sidecar{Client: wire.Meta{Access: wire.AccessAny}})
	if err := e.st.RebuildCatalog(); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogSigned(t *testing.T) {
	e := newSignedEnv(t)
	e.cfg.Storage["drop"].Catalog, e.st.Catalog = true, true
	e.h = New(e.cfg, e.log(), func() time.Time { return e.now }, "l", fakeVerify)
	e.fillCatalog(t)
	if got := e.catalogNames(t, "/d/"+store.CatalogName, as("alice")); got != "pub.txt" {
		t.Errorf("signed catalog: %q", got)
	}
	if w := e.do(t, "HEAD", "/d/"+store.CatalogName, as("alice")); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("signed head: %d", w.Code)
	}
	for name, h := range map[string]map[string]string{"unsigned": nil, "not allowed": as("bob")} {
		if w := e.do(t, "GET", "/d/"+store.CatalogName, h); w.Code != 404 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if w := e.do(t, "GET", "/d/"+store.CatalogName, as("bad")); w.Code != 401 {
		t.Errorf("bad signature: %d", w.Code)
	}
	if w := e.do(t, "POST", "/d/"+store.CatalogName, as("alice")); w.Code != 405 {
		t.Errorf("signed post: %d", w.Code)
	}
	// A protect never serves the catalog.
	if w := e.do(t, "GET", "/s/"+store.CatalogName, as("alice")); w.Code != 404 {
		t.Errorf("catalog on the protect: %d", w.Code)
	}
}

func TestCatalogDualAuth(t *testing.T) {
	e := newDualEnv(t)
	e.fillCatalog(t)
	if got := e.catalogNames(t, "/d/"+store.CatalogName, basic(nil, "alice", "pw")); got != "pub.txt" {
		t.Errorf("catalog via basic: %q", got)
	}
	if got := e.catalogNames(t, "/d/"+store.CatalogName, as("alice")); got != "pub.txt" {
		t.Errorf("signed catalog: %q", got)
	}
	for name, h := range map[string]map[string]string{"none": nil, "wrong password": basic(nil, "alice", "bad")} {
		if w := e.do(t, "GET", "/d/"+store.CatalogName, h); w.Code != 401 || w.Header().Get("WWW-Authenticate") != `Basic realm="luk"` {
			t.Errorf("%s: %d %v", name, w.Code, w.Header())
		}
	}
	if w := e.do(t, "GET", "/d/"+store.CatalogName, basic(as("bob"), "alice", "pw")); w.Code != 404 {
		t.Errorf("signer not allowed with basic: %d", w.Code)
	}
	if w := e.do(t, "GET", "/s/"+store.CatalogName, basic(nil, "alice", "pw")); w.Code != 404 {
		t.Errorf("catalog via basic on the protect: %d", w.Code)
	}
}
