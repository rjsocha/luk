package expose

import (
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"luk/internal/config"
	"luk/internal/store"
	"luk/internal/wire"
)

var hrefRe = regexp.MustCompile(`<td class="name"><a href="([^"]*)">([^<]*)</a>`)

// links are the href and the shown name of every line of a listing.
func links(body string) [][2]string {
	var out [][2]string
	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		out = append(out, [2]string{html.UnescapeString(m[1]), html.UnescapeString(m[2])})
	}
	return out
}

func newIndexEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, func(x *config.Expose) { x.Index = true })
	e.cfg.Storage["drop"].Catalog, e.st.Catalog = true, true
	e.h = New(e.cfg, e.log(), func() time.Time { return e.now }, "l", nil)
	return e
}

// fill stores one file of every kind: only pub, b/c/deep, the dot names,
// the mixed case names and odd names are listed.
func (e *env) fill(t *testing.T) {
	t.Helper()
	e.put(t, "pub.txt", "hello", store.Sidecar{Received: "2026-09-30T10:15:00Z"})
	e.put(t, ".bashrc", "x", store.Sidecar{})
	e.put(t, ".cfg/rc", "x", store.Sidecar{})
	e.put(t, "Readme", "x", store.Sidecar{})
	e.put(t, "readme", "x", store.Sidecar{})
	e.put(t, "C/x", "x", store.Sidecar{})
	e.put(t, "b/c/deep", "deep", store.Sidecar{})
	e.put(t, `odd <&>"' %name`, "x", store.Sidecar{})
	e.put(t, "once", "x", store.Sidecar{Client: wire.Meta{Once: true}})
	e.put(t, "reveal", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	e.put(t, "portal", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload}})
	e.put(t, "private", "x", store.Sidecar{Client: wire.Meta{Access: wire.AccessPrivate}})
	e.put(t, "any", "x", store.Sidecar{Client: wire.Meta{Access: wire.AccessAny}})
	e.put(t, "expired", "x", store.Sidecar{Expires: t0.Add(-time.Second).Format(time.RFC3339)})
	e.put(t, "secret/only", "x", store.Sidecar{Client: wire.Meta{Once: true}})
	e.put(t, "gone/f", "x", store.Sidecar{Expires: t0.Add(-time.Second).Format(time.RFC3339)})
	if err := e.st.RebuildCatalog(); err != nil {
		t.Fatal(err)
	}
}

func TestIndexListing(t *testing.T) {
	e := newIndexEnv(t)
	e.fill(t)
	// A data file without a sidecar is not served, so not listed.
	if err := os.WriteFile(filepath.Join(e.base, store.DataDir, "bare"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	w := e.do(t, "GET", "/d/", nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	checkPortalHeaders(t, w, body)
	got := links(body)
	// Case is ignored, ties go by bytes: C/ after b/, Readme after
	// pub.txt and before readme.
	want := [][2]string{{"./.cfg/", ".cfg/"}, {"./b/", "b/"}, {"./C/", "C/"}, {"./.bashrc", ".bashrc"},
		{`./odd%20%3C&%3E%22%27%20%25name`, `odd <&>"' %name`}, {"./pub.txt", "pub.txt"}, {"./Readme", "Readme"}, {"./readme", "readme"}}
	if len(got) != len(want) {
		t.Fatalf("%v\n%s", got, body)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d %v, want %v", i, got[i], want[i])
		}
	}
	for _, s := range []string{"Index of /d/", "max-width: 80rem", "5 bytes", `<time datetime="2026-09-30T10:15:00Z" title="2026-09-30 10:15 UTC">2026-09-30 10:15 UTC</time>`, "Powered by", `href="../"`} {
		if strings.Contains(body, s) != (s != `href="../"`) {
			t.Errorf("%q: %s", s, body)
		}
	}
	for _, s := range []string{"once", "reveal", "portal", "private", "any", "expired", "secret", "gone", "catalog.json", ".luk", "bare", "<script>alert"} {
		if strings.Contains(body, ">"+s) {
			t.Errorf("%s listed", s)
		}
	}
	// Every listed name downloads; the directories list in turn.
	for _, l := range got {
		u, err := url.Parse("http://x/d/" + strings.TrimPrefix(l[0], "./"))
		if err != nil {
			t.Fatal(err)
		}
		if w := e.do(t, "GET", u.String(), nil); w.Code != 200 {
			t.Errorf("%s: %d", l[0], w.Code)
		}
	}
	w = e.do(t, "GET", "/d/b/", nil)
	if got := links(w.Body.String()); w.Code != 200 || len(got) != 2 || got[0] != [2]string{"../", "../"} || got[1] != [2]string{"./c/", "c/"} {
		t.Errorf("b/: %d %v", w.Code, got)
	}
	w = e.do(t, "GET", "/d/b/c/", nil)
	if got := links(w.Body.String()); w.Code != 200 || len(got) != 2 || got[1] != [2]string{"./deep", "deep"} {
		t.Errorf("b/c/: %d %v", w.Code, got)
	}
	if w := e.do(t, "HEAD", "/d/b/", nil); w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("HEAD: %d", w.Code)
	}
	// Directories holding nothing listed are as hidden as missing ones.
	for _, p := range []string{"/d/secret/", "/d/gone/", "/d/missing/", "/d/secret", "/d/missing", "/d/b/../", "/d/.luk/", "/d/a//"} {
		if w := e.do(t, "GET", p, nil); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	for p, loc := range map[string]string{"/d": "./d/", "/d/b": "./b/", "/d/b/c": "./c/"} {
		if w := e.do(t, "GET", p, nil); w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != loc {
			t.Errorf("%s: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := e.do(t, "POST", "/d/", nil); w.Code != 405 {
		t.Errorf("POST: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/catalog.json", nil); w.Code != 200 {
		t.Errorf("catalog: %d", w.Code)
	}
}

func TestIndexEmptyAndDisabled(t *testing.T) {
	e := newIndexEnv(t)
	w := e.do(t, "GET", "/d/", nil)
	if w.Code != 200 || len(links(w.Body.String())) != 0 || !strings.Contains(w.Body.String(), "No files.") {
		t.Fatalf("empty: %d %s", w.Code, w.Body)
	}
	e = newEnv(t, nil)
	e.fill(t)
	for _, p := range []string{"/d/", "/d", "/d/b/", "/d/b"} {
		if w := e.do(t, "GET", p, nil); w.Code != 404 {
			t.Errorf("without index %s: %d", p, w.Code)
		}
	}
}

func TestIndexBasicAuth(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(x *config.Expose) { x.Index, x.Auth.Basic = true, []string{"alice:" + string(hash)} })
	e.put(t, "b/f", "x", store.Sidecar{})
	for _, p := range []string{"/d/", "/d", "/d/b/", "/d/b"} {
		if w := e.do(t, "GET", p, nil); w.Code != 401 {
			t.Errorf("%s without auth: %d", p, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/d/", nil)
	r.SetBasicAuth("alice", "pw")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if got := links(w.Body.String()); w.Code != 200 || len(got) != 1 || got[0][0] != "./b/" {
		t.Errorf("with auth: %d %v", w.Code, got)
	}
}

func TestIndexSymlinks(t *testing.T) {
	e := newIndexEnv(t)
	e.put(t, "real/f", "x", store.Sidecar{})
	e.put(t, "f", "x", store.Sidecar{})
	if err := os.Symlink("real", filepath.Join(e.base, store.DataDir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(e.base, store.DataDir, "lf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f.json", filepath.Join(e.base, ".db", "meta", "lf.json")); err != nil {
		t.Fatal(err)
	}
	got := links(e.do(t, "GET", "/d/", nil).Body.String())
	if len(got) != 2 || got[0][0] != "./real/" || got[1][0] != "./f" {
		t.Errorf("%v", got)
	}
	for _, p := range []string{"/d/link/", "/d/link"} {
		if w := e.do(t, "GET", p, nil); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}

// TestIndexNested: the directory of a nested expose is never listed by the
// outer one, and the nested expose lists its own storage.
func TestIndexNested(t *testing.T) {
	outer, inner := t.TempDir(), t.TempDir()
	cfg, err := config.Parse([]byte(`
root: ` + t.TempDir() + `
listen:
  l: {addr: "127.0.0.1:1", public: "http://l.vm"}
  m: {addr: "127.0.0.1:2", public: "http://m.vm"}
storage:
  outer: {type: local, base: ` + outer + `, path: x, expose: outer}
  inner: {type: local, base: ` + inner + `, path: x, expose: inner}
expose:
  outer: {listen: [l, m], path: /, index: true}
  inner: {listen: l, path: /v/, index: true}
`))
	if err != nil {
		t.Fatal(err)
	}
	put := func(base, rel string) {
		src := filepath.Join(t.TempDir(), "src")
		if err := os.WriteFile(src, []byte(rel), 0o640); err != nil {
			t.Fatal(err)
		}
		sc := store.Sidecar{ID: rel, Size: int64(len(rel)), Client: wire.Meta{Portal: wire.PortalDirect}}
		if _, err := (store.Local{Base: base, Conflict: "version"}).Put(src, rel, sc); err != nil {
			t.Fatal(err)
		}
	}
	put(outer, "a")
	put(outer, "v/b")
	put(inner, "b")
	for _, c := range []struct {
		listen, path string
		code         int
		names        []string
	}{
		{"l", "/", 200, []string{"a"}},
		{"m", "/", 200, []string{"a"}},
		{"l", "/v/", 200, []string{"b"}},
		{"m", "/v/", 404, nil},
		{"m", "/v", 404, nil},
	} {
		w := httptest.NewRecorder()
		New(cfg, slog.New(slog.DiscardHandler), time.Now, c.listen, nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.path, nil))
		var names []string
		for _, l := range links(w.Body.String()) {
			if l[0] != "../" {
				names = append(names, l[1])
			}
		}
		if w.Code != c.code || strings.Join(names, ",") != strings.Join(c.names, ",") {
			t.Errorf("%s %s: %d %v", c.listen, c.path, w.Code, names)
		}
	}
	w := httptest.NewRecorder()
	New(cfg, slog.New(slog.DiscardHandler), time.Now, "l", nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v", nil))
	if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "./v/" {
		t.Errorf("/v: %d %q", w.Code, w.Header().Get("Location"))
	}
}
