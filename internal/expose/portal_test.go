package expose

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"luk/internal/config"
	"luk/internal/store"
	"luk/internal/wire"
)

var nonceRe = regexp.MustCompile(`^default-src 'none'; img-src data:; connect-src 'self'; style-src 'nonce-([A-Za-z0-9_-]{16,})'; script-src 'nonce-([A-Za-z0-9_-]{16,})'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'$`)

func checkPortalHeaders(t *testing.T, w interface{ Header() http.Header }, body string) {
	t.Helper()
	h := w.Header()
	for k, v := range map[string]string{
		"Content-Type":           "text/html; charset=utf-8",
		"X-Robots-Tag":           "noindex",
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if h.Get("Content-Disposition") != "" {
		t.Errorf("Content-Disposition on a portal page: %q", h.Get("Content-Disposition"))
	}
	m := nonceRe.FindStringSubmatch(h.Get("Content-Security-Policy"))
	if m == nil || m[1] != m[2] {
		t.Fatalf("CSP %q", h.Get("Content-Security-Policy"))
	}
	if !strings.Contains(body, `<style nonce="`+m[1]+`">`) {
		t.Errorf("style tag without the nonce")
	}
	if strings.Contains(body, "<script") && !strings.Contains(body, `<script nonce="`+m[1]+`">`) {
		t.Errorf("script tag without the nonce")
	}
	if n := strings.Count(body, "<style") + strings.Count(body, "<script"); n != strings.Count(body, `nonce="`+m[1]+`"`) {
		t.Errorf("tags without the nonce: %s", body)
	}
}

const secret = "s3cr3t <script>alert(1)</script> & \"q\""

func TestPortalLanding(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r", secret, store.Sidecar{Expires: "2026-10-01T12:00:00Z", Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "dir/d", secret, store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload, File: "report <1>.pdf", Once: true}})
	sum := sha256.Sum256([]byte(secret))
	for _, c := range []struct{ path, action, name, ctype string }{
		{"/d/r", `action="./r/reveal"`, "r", "<dd>secret</dd>"},
		{"/d/dir/d", `action="./d/download"`, "report &lt;1&gt;.pdf", "application/pdf"},
	} {
		w := e.do(t, "GET", c.path, nil)
		body := w.Body.String()
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", c.path, w.Code, body)
		}
		checkPortalHeaders(t, w, body)
		for _, want := range []string{c.action, `method="post"`, "<button", c.name, c.ctype, "38"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q in %s", c.path, want, body)
			}
		}
		// A secret never shows its hash; a download page does.
		if hasSum := strings.Contains(body, hex.EncodeToString(sum[:])); hasSum == (c.path == "/d/r") {
			t.Errorf("%s: sha256 shown %v", c.path, hasSum)
		}
		if strings.Contains(body, "s3cr3t") {
			t.Errorf("%s: landing shows the content", c.path)
		}
		if w.Header().Get("Content-Security-Policy") == e.do(t, "GET", c.path, nil).Header().Get("Content-Security-Policy") {
			t.Errorf("%s: nonce reused", c.path)
		}
	}
	e.now = t0.Add(12*time.Minute + 30*time.Second)
	body := e.do(t, "GET", "/d/r", nil).Body.String()
	for _, want := range []string{
		`<dt>Published</dt><dd><time datetime="2026-09-30T12:00:00Z" title="2026-09-30 12:00 UTC (12 min ago)">2026-09-30 12:00 UTC (12 min ago)</time></dd>`,
		`<dt>Expires</dt><dd><time datetime="2026-10-01T12:00:00Z" title="2026-10-01 12:00 UTC (in 23h 47m)">2026-10-01 12:00 UTC (in 23h 47m)</time></dd>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}
	if body := e.do(t, "GET", "/d/dir/d", nil).Body.String(); !strings.Contains(body, "<dt>Expires</dt><dd>never</dd>") {
		t.Errorf("no TTL: %s", body)
	}
	e.put(t, "a:b", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload}})
	if body := e.do(t, "GET", "/d/a:b", nil).Body.String(); !strings.Contains(body, `action="./a:b/download"`) {
		t.Errorf("colon name action: %s", body)
	}
	if w := e.do(t, "HEAD", "/d/r", nil); w.Code != 200 {
		t.Errorf("HEAD landing: %d", w.Code)
	}
	if !exists(filepath.Join(e.base, store.DataDir, "r")) || !exists(filepath.Join(e.base, store.DataDir, "dir/d")) {
		t.Fatal("landing consumed a once upload")
	}
}

func TestPortalReveal(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r", secret, store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "keep", "again", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})

	for _, m := range []string{"GET", "HEAD"} {
		w := e.do(t, m, "/d/r/reveal", nil)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
			t.Errorf("%s reveal: %d allow %q", m, w.Code, w.Header().Get("Allow"))
		}
	}
	w := e.do(t, "POST", "/d/r", nil)
	if w.Code != http.StatusMethodNotAllowed || strings.Contains(w.Header().Get("Allow"), "POST") {
		t.Errorf("POST name: %d allow %q", w.Code, w.Header().Get("Allow"))
	}
	if w := e.do(t, "POST", "/d/r/download", nil); w.Code != 404 {
		t.Errorf("download on a reveal portal: %d", w.Code)
	}
	if !exists(filepath.Join(e.base, store.DataDir, "r")) {
		t.Fatal("consumed before the reveal POST")
	}

	w = e.do(t, "POST", "/d/r/reveal", nil)
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("reveal: %d %s", w.Code, body)
	}
	checkPortalHeaders(t, w, body)
	if strings.Contains(body, "<script>alert") || !strings.Contains(body, "s3cr3t &lt;script&gt;alert(1)&lt;/script&gt; &amp; &#34;q&#34;") {
		t.Errorf("content not escaped: %s", body)
	}
	if !regexp.MustCompile(`<textarea[^>]*readonly`).MatchString(body) || !strings.Contains(body, "navigator.clipboard") || !strings.Contains(body, ".select()") || !strings.Contains(body, `id="copy"`) {
		t.Errorf("no read-only field or copy button: %s", body)
	}
	if exists(filepath.Join(e.base, store.DataDir, "r")) {
		t.Error("once not consumed by the reveal")
	}
	if w := e.do(t, "POST", "/d/r/reveal", nil); w.Code != 404 {
		t.Errorf("second reveal: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/r", nil); w.Code != 404 {
		t.Errorf("landing after reveal: %d", w.Code)
	}
	for range 2 {
		if w := e.do(t, "POST", "/d/keep/reveal", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "again") {
			t.Errorf("non-once reveal: %d", w.Code)
		}
	}
}

func TestPortalRevealTooLarge(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "big", strings.Repeat("a", MaxReveal+1), store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "max", strings.Repeat("b", MaxReveal), store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	w := e.do(t, "POST", "/d/big/reveal", nil)
	if w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "aaaa") {
		t.Errorf("big: %d", w.Code)
	}
	checkPortalHeaders(t, w, w.Body.String())
	if !exists(filepath.Join(e.base, store.DataDir, "big")) {
		t.Error("too large reveal consumed the upload")
	}
	if w := e.do(t, "POST", "/d/max/reveal", nil); w.Code != 200 || !strings.Contains(w.Body.String(), strings.Repeat("b", MaxReveal)) {
		t.Errorf("max: %d", w.Code)
	}
}

func TestPortalDownload(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "d", secret, store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload, File: "s.txt", Once: true}})
	e.put(t, "k", "keep", store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload}})
	if w := e.do(t, "GET", "/d/d/download", nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
		t.Errorf("GET download: %d allow %q", w.Code, w.Header().Get("Allow"))
	}
	if w := e.do(t, "POST", "/d/d/reveal", nil); w.Code != 404 {
		t.Errorf("reveal on a download portal: %d", w.Code)
	}
	w := e.do(t, "POST", "/d/d/download", nil)
	if w.Code != 200 || w.Body.String() != secret {
		t.Fatalf("download: %d %q", w.Code, w.Body.String())
	}
	for k, v := range map[string]string{
		"Content-Disposition":     `attachment; filename="s.txt"`,
		"Content-Security-Policy": "sandbox",
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           "no-store",
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("type %q", w.Header().Get("Content-Type"))
	}
	if exists(filepath.Join(e.base, store.DataDir, "d")) {
		t.Error("once not consumed")
	}
	if w := e.do(t, "POST", "/d/d/download", nil); w.Code != 404 {
		t.Errorf("second download: %d", w.Code)
	}
	for range 2 {
		if w := e.do(t, "POST", "/d/k/download", nil); w.Code != 200 || w.Body.String() != "keep" {
			t.Errorf("non-once download: %d", w.Code)
		}
	}
}

func TestPortalDirectUpload(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "x", "plain", store.Sidecar{Client: wire.Meta{Once: true}})
	e.put(t, "tree/reveal", "file named reveal", store.Sidecar{})
	for _, p := range []string{"/d/x/reveal", "/d/x/download"} {
		if w := e.do(t, "POST", p, nil); w.Code != 404 {
			t.Errorf("POST %s: %d", p, w.Code)
		}
		if w := e.do(t, "GET", p, nil); w.Code != 404 {
			t.Errorf("GET %s: %d", p, w.Code)
		}
	}
	if w := e.do(t, "POST", "/d/x", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST direct: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/tree/reveal", nil); w.Code != 200 || w.Body.String() != "file named reveal" {
		t.Errorf("direct file named reveal: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/x", nil); w.Code != 200 || w.Body.String() != "plain" {
		t.Errorf("direct once: %d", w.Code)
	}
}

func TestPortalExpiredAndAuth(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(x *config.Expose) { x.Auth.Basic = []string{"alice:" + string(hash)} })
	e.put(t, "r", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "old", "x", store.Sidecar{Expires: "2026-09-30T11:00:00Z", Client: wire.Meta{Portal: wire.PortalReveal}})
	for _, c := range []struct{ method, path string }{{"GET", "/d/r"}, {"POST", "/d/r/reveal"}, {"GET", "/d/r/reveal"}} {
		if w := e.do(t, c.method, c.path, nil); w.Code != 401 {
			t.Errorf("%s %s without auth: %d", c.method, c.path, w.Code)
		}
	}
	if !exists(filepath.Join(e.base, store.DataDir, "r")) {
		t.Fatal("consumed without auth")
	}
	auth := func(method, p string) int {
		r := httptest.NewRequest(method, p, nil)
		r.SetBasicAuth("alice", "pw")
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		return w.Code
	}
	if c := auth("POST", "/d/old/reveal"); c != 404 {
		t.Errorf("expired reveal: %d", c)
	}
	if c := auth("GET", "/d/old"); c != 404 {
		t.Errorf("expired landing: %d", c)
	}
	if c := auth("POST", "/d/r/reveal"); c != 200 {
		t.Errorf("reveal with auth: %d", c)
	}
}

func TestProducedName(t *testing.T) {
	e := newEnv(t, nil)
	client := wire.Meta{File: "dump.sql", Type: "application/sql"}
	e.put(t, "p", "x", store.Sidecar{Produced: "dump.sql.gz", Client: client})
	client.Portal = wire.PortalDownload
	e.put(t, "l", "x", store.Sidecar{Produced: "notes.txt", Client: client})
	w := e.do(t, "GET", "/d/p", nil)
	if got := w.Header().Get("Content-Disposition"); got != `attachment; filename="dump.sql.gz"` {
		t.Errorf("disposition %q", got)
	}
	if got := w.Header().Get("Content-Type"); got == "application/sql" {
		t.Errorf("client type on a produced file: %q", got)
	}
	body := e.do(t, "GET", "/d/l", nil).Body.String()
	if !strings.Contains(body, "<h1>notes.txt</h1>") || !strings.Contains(body, "text/plain") || strings.Contains(body, "dump.sql") {
		t.Errorf("landing of a produced file: %s", body)
	}
	w = e.do(t, "POST", "/d/l/download", nil)
	if got := w.Header().Get("Content-Disposition"); got != `attachment; filename="notes.txt"` {
		t.Errorf("download disposition %q", got)
	}
}

func TestPortalCrossOrigin(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "d", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload, Once: true}})
	for _, p := range []string{"/d/r/reveal", "/d/d/download"} {
		if w := e.do(t, "POST", p, map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != http.StatusForbidden {
			t.Errorf("%s cross-site: %d", p, w.Code)
		}
		if w := e.do(t, "POST", p, map[string]string{"Origin": "https://evil.example"}); w.Code != http.StatusForbidden {
			t.Errorf("%s cross origin: %d", p, w.Code)
		}
	}
	if !exists(filepath.Join(e.base, store.DataDir, "r")) || !exists(filepath.Join(e.base, store.DataDir, "d")) {
		t.Fatal("cross-origin POST consumed a once upload")
	}
	if w := e.do(t, "POST", "/d/r/reveal", map[string]string{"Sec-Fetch-Site": "same-origin"}); w.Code != 200 {
		t.Errorf("same-origin reveal: %d", w.Code)
	}
	if w := e.do(t, "POST", "/d/d/download", nil); w.Code != 200 {
		t.Errorf("header-less download: %d", w.Code)
	}
}

func TestPortalActionNoStore(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "k", "keep", store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload}})
	if w := e.do(t, "POST", "/d/k/download", nil); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("non-once download: %d cache %q", w.Code, w.Header().Get("Cache-Control"))
	}
}

func TestRevealReadFailureKeepsClaimed(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	orig := readReveal
	defer func() { readReveal = orig }()
	readReveal = func(io.Reader) ([]byte, error) { return nil, errors.New("disk error") }
	w := e.do(t, "POST", "/d/r/reveal", nil)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), e.base) {
		t.Errorf("read failure: %d %q", w.Code, w.Body.String())
	}
	claimed, err := os.ReadDir(filepath.Join(e.base, store.ClaimedDir))
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claimed file not kept: %v %v", claimed, err)
	}
}

func checkTextHeaders(t *testing.T, w *httptest.ResponseRecorder, size int) {
	t.Helper()
	for k, v := range map[string]string{
		"Content-Type":            "text/plain; charset=utf-8",
		"Content-Length":          strconv.Itoa(size),
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "sandbox",
		"Referrer-Policy":         "no-referrer",
		"Content-Disposition":     "",
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestPortalGet(t *testing.T) {
	e := newEnv(t, nil)
	const raw = secret + "\n\x00tail"
	e.put(t, "k", raw, store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	e.put(t, "nonl", "abc", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	for _, m := range []string{"GET", "POST"} {
		for range 2 {
			w := e.do(t, m, "/d/k/get", nil)
			if w.Code != 200 || w.Body.String() != raw {
				t.Fatalf("%s get: %d %q", m, w.Code, w.Body.String())
			}
			checkTextHeaders(t, w, len(raw))
		}
	}
	if w := e.do(t, "GET", "/d/nonl/get", nil); w.Body.String() != "abc" {
		t.Errorf("trailing bytes added: %q", w.Body.String())
	}
	w := e.do(t, "HEAD", "/d/k/get", nil)
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("HEAD get: %d %q", w.Code, w.Body.String())
	}
	checkTextHeaders(t, w, len(raw))
	for _, m := range []string{"PUT", "DELETE"} {
		w := e.do(t, m, "/d/k/get", nil)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD, POST" {
			t.Errorf("%s get: %d allow %q", m, w.Code, w.Header().Get("Allow"))
		}
	}
}

func TestPortalGetDownload(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "k", secret, store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload, File: "s.txt"}})
	for _, m := range []string{"GET", "POST", "HEAD"} {
		w := e.do(t, m, "/d/k/get", nil)
		want := secret
		if m == "HEAD" {
			want = ""
		}
		if w.Code != 200 || w.Body.String() != want {
			t.Fatalf("%s get: %d %q", m, w.Code, w.Body.String())
		}
		for k, v := range map[string]string{
			"Content-Disposition":     `attachment; filename="s.txt"`,
			"Content-Security-Policy": "sandbox",
			"X-Content-Type-Options":  "nosniff",
			"Cache-Control":           "no-store",
			"Content-Length":          strconv.Itoa(len(secret)),
		} {
			if got := w.Header().Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", m, k, got, v)
			}
		}
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
			t.Errorf("%s: type %q", m, w.Header().Get("Content-Type"))
		}
	}
}

func TestPortalGetOnce(t *testing.T) {
	for _, portal := range []string{wire.PortalReveal, wire.PortalDownload} {
		for _, m := range []string{"GET", "POST"} {
			e := newEnv(t, nil)
			e.put(t, "r", secret, store.Sidecar{Client: wire.Meta{Portal: portal, Once: true}})
			for range 2 {
				if w := e.do(t, "HEAD", "/d/r/get", nil); w.Code != 200 || w.Header().Get("Content-Length") != strconv.Itoa(len(secret)) {
					t.Errorf("%s HEAD get: %d", portal, w.Code)
				}
			}
			if !exists(filepath.Join(e.base, store.DataDir, "r")) {
				t.Fatalf("%s: HEAD consumed a once upload", portal)
			}
			if w := e.do(t, m, "/d/r/get", nil); w.Code != 200 || w.Body.String() != secret {
				t.Fatalf("%s %s get: %d %q", portal, m, w.Code, w.Body.String())
			}
			if exists(filepath.Join(e.base, store.DataDir, "r")) {
				t.Errorf("%s %s get did not consume the once upload", portal, m)
			}
			for _, c := range []struct{ method, path string }{{"GET", "/d/r/get"}, {"POST", "/d/r/get"}, {"HEAD", "/d/r/get"}, {"POST", "/d/r/" + portal}, {"GET", "/d/r"}} {
				if w := e.do(t, c.method, c.path, nil); w.Code != 404 {
					t.Errorf("%s after %s get: %s %s: %d", portal, m, c.method, c.path, w.Code)
				}
			}
		}
	}
}

func TestPortalGetLimits(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "big", strings.Repeat("a", MaxReveal+1), store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "max", strings.Repeat("b", MaxReveal), store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	e.put(t, "bigdl", strings.Repeat("c", MaxReveal+1), store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload}})
	e.put(t, "old", "x", store.Sidecar{Expires: "2026-09-30T11:00:00Z", Client: wire.Meta{Portal: wire.PortalReveal}})
	e.put(t, "olddl", "x", store.Sidecar{Expires: "2026-09-30T11:00:00Z", Client: wire.Meta{Portal: wire.PortalDownload}})
	for _, m := range []string{"GET", "POST", "HEAD"} {
		if w := e.do(t, m, "/d/big/get", nil); w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "aaaa") {
			t.Errorf("%s big: %d", m, w.Code)
		}
		for _, p := range []string{"/d/old/get", "/d/olddl/get"} {
			if w := e.do(t, m, p, nil); w.Code != 404 {
				t.Errorf("%s %s expired: %d", m, p, w.Code)
			}
		}
	}
	if !exists(filepath.Join(e.base, store.DataDir, "big")) {
		t.Error("too large get consumed the upload")
	}
	if w := e.do(t, "GET", "/d/max/get", nil); w.Code != 200 || w.Body.String() != strings.Repeat("b", MaxReveal) {
		t.Errorf("max: %d", w.Code)
	}
	if w := e.do(t, "GET", "/d/bigdl/get", nil); w.Code != 200 || w.Body.Len() != MaxReveal+1 {
		t.Errorf("large download: %d", w.Code)
	}
}

func TestPortalGetPlainFile(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "x", "x", store.Sidecar{Client: wire.Meta{Once: true}})
	e.put(t, "tree/get", "file named get", store.Sidecar{})
	for _, m := range []string{"GET", "HEAD", "POST"} {
		if w := e.do(t, m, "/d/x/get", nil); w.Code != 404 {
			t.Errorf("%s /d/x/get: %d", m, w.Code)
		}
	}
	if !exists(filepath.Join(e.base, store.DataDir, "x")) {
		t.Fatal("get consumed a plain upload")
	}
	if w := e.do(t, "GET", "/d/tree/get", nil); w.Code != 200 || w.Body.String() != "file named get" {
		t.Errorf("direct file named get: %d", w.Code)
	}
}

func TestPortalGetCrossOrigin(t *testing.T) {
	for _, portal := range []string{wire.PortalReveal, wire.PortalDownload} {
		e := newEnv(t, nil)
		e.put(t, "r", "x", store.Sidecar{Client: wire.Meta{Portal: portal, Once: true}})
		for _, hdr := range []map[string]string{{"Sec-Fetch-Site": "cross-site"}, {"Origin": "https://evil.example"}} {
			if w := e.do(t, "POST", "/d/r/get", hdr); w.Code != http.StatusForbidden {
				t.Errorf("%s cross-origin POST get %v: %d", portal, hdr, w.Code)
			}
		}
		if !exists(filepath.Join(e.base, store.DataDir, "r")) {
			t.Fatalf("%s: cross-origin POST consumed a once upload", portal)
		}
		if w := e.do(t, "POST", "/d/r/get", map[string]string{"Sec-Fetch-Site": "same-origin"}); w.Code != 200 || w.Body.String() != "x" {
			t.Errorf("%s same-origin POST get: %d", portal, w.Code)
		}
	}
}

func TestPortalTextGone(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	for _, m := range []string{"GET", "HEAD"} {
		if w := e.do(t, m, "/d/r/text", nil); w.Code != 404 {
			t.Errorf("%s text: %d", m, w.Code)
		}
	}
	if w := e.do(t, "POST", "/d/r/text", nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST text: %d allow %q", w.Code, w.Header().Get("Allow"))
	}
	if !exists(filepath.Join(e.base, store.DataDir, "r")) {
		t.Fatal("text consumed a once upload")
	}
}

func TestPortalRevealAccept(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "k", secret, store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	e.put(t, "big", strings.Repeat("a", MaxReveal+1), store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	for _, accept := range []string{"text/plain", "text/plain, */*;q=0.1", "text/html;q=0.5, text/plain"} {
		w := e.do(t, "POST", "/d/k/reveal", map[string]string{"Accept": accept})
		if w.Code != 200 || w.Body.String() != secret || w.Header().Get("Vary") != "Accept" {
			t.Errorf("Accept %q: %d vary %q %q", accept, w.Code, w.Header().Get("Vary"), w.Body.String())
		}
		checkTextHeaders(t, w, len(secret))
		if w := e.do(t, "POST", "/d/big/reveal", map[string]string{"Accept": accept}); w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "<html") {
			t.Errorf("Accept %q big: %d %q", accept, w.Code, w.Body.String())
		}
	}
	for _, accept := range []string{"", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "*/*", "text/plain;q=0.5, text/html", "text/plain, text/html"} {
		hdr := map[string]string{}
		if accept != "" {
			hdr["Accept"] = accept
		}
		w := e.do(t, "POST", "/d/k/reveal", hdr)
		if w.Code != 200 || w.Header().Get("Vary") != "Accept" {
			t.Errorf("Accept %q: %d vary %q", accept, w.Code, w.Header().Get("Vary"))
		}
		checkPortalHeaders(t, w, w.Body.String())
		if !strings.Contains(w.Body.String(), "s3cr3t &lt;script&gt;") || regexp.MustCompile(`/(get|text)\b`).MatchString(w.Body.String()) {
			t.Errorf("Accept %q: reveal page %s", accept, w.Body.String())
		}
	}
}

func TestPortalNoContentOnGet(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r", secret, store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "k", secret, store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	for _, p := range []string{"/d/r", "/d/r/reveal", "/d/k", "/d/k/reveal"} {
		for _, m := range []string{"GET", "HEAD"} {
			if w := e.do(t, m, p, nil); strings.Contains(w.Body.String(), "s3cr3t") {
				t.Errorf("%s %s shows the content", m, p)
			}
		}
	}
	if !exists(filepath.Join(e.base, store.DataDir, "r")) {
		t.Fatal("GET consumed a once upload")
	}
}

func TestHumanTime(t *testing.T) {
	now := time.Date(2026, 10, 2, 17, 52, 30, 0, time.UTC)
	for _, c := range []struct {
		at   time.Time
		want string
	}{
		{now, "2026-10-02 17:52 UTC (just now)"},
		{now.Add(-59 * time.Second), "2026-10-02 17:51 UTC (just now)"},
		{now.Add(-time.Minute), "2026-10-02 17:51 UTC (1 min ago)"},
		{now.Add(-12*time.Minute - 30*time.Second), "2026-10-02 17:40 UTC (12 min ago)"},
		{now.Add(time.Second), "2026-10-02 17:52 UTC (in under a minute)"},
		{now.Add(59 * time.Minute), "2026-10-02 18:51 UTC (in 59 min)"},
		{now.Add(23*time.Hour + 48*time.Minute + 30*time.Second), "2026-10-03 17:41 UTC (in 23h 48m)"},
		{now.Add(-3 * time.Hour), "2026-10-02 14:52 UTC (3h ago)"},
		{now.Add(2*24*time.Hour + 5*time.Hour + 59*time.Minute), "2026-10-04 23:51 UTC (in 2d 5h)"},
		{now.Add(-7 * 24 * time.Hour), "2026-09-25 17:52 UTC (7d ago)"},
	} {
		if got := humanTime(c.at.Format(time.RFC3339), now); got != c.want {
			t.Errorf("%v: %q, want %q", c.at, got, c.want)
		}
	}
	if got := humanTime("2026-10-02T19:40:00+02:00", now); got != "2026-10-02 17:40 UTC (12 min ago)" {
		t.Errorf("offset: %q", got)
	}
	if got := humanTime("bogus", now); got != "bogus" {
		t.Errorf("unparsable: %q", got)
	}
}

type unreadable struct{ t *testing.T }

func (u unreadable) Read([]byte) (int, error) {
	u.t.Error("action body read")
	return 0, io.EOF
}

func TestPortalActionBodyLimit(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "d", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload, Once: true}})
	for _, p := range []string{"/d/r/reveal", "/d/r/get", "/d/d/get", "/d/d/download", "/d/missing/reveal"} {
		for _, n := range []int64{2000, -1} {
			r := httptest.NewRequest("POST", p, unreadable{t})
			r.ContentLength = n
			w := httptest.NewRecorder()
			e.h.ServeHTTP(w, r)
			if w.Code != http.StatusRequestEntityTooLarge || w.Header().Get("Connection") != "close" {
				t.Errorf("%s length %d: %d connection %q", p, n, w.Code, w.Header().Get("Connection"))
			}
		}
	}
	if !exists(filepath.Join(e.base, store.DataDir, "r")) || !exists(filepath.Join(e.base, store.DataDir, "d")) {
		t.Fatal("an oversized POST consumed a once upload")
	}
	r := httptest.NewRequest("POST", "/d/r/get", strings.NewReader(strings.Repeat("a", maxActionBody)))
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "x" {
		t.Errorf("body at the limit: %d", w.Code)
	}
}

func TestPortalLandingFetch(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r", secret, store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "d", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload}})
	w := e.do(t, "GET", "/d/r", nil)
	body := w.Body.String()
	checkPortalHeaders(t, w, body)
	nonce := nonceRe.FindStringSubmatch(w.Header().Get("Content-Security-Policy"))[1]
	for _, want := range []string{
		`<form method="post" action="./r/reveal" id="action">`,
		`<script nonce="` + nonce + `">`,
		`fetch(form.getAttribute("action"), { method: "POST", headers: { "Accept": "text/plain" }, credentials: "same-origin"`,
		`<textarea id="content" readonly`, `id="copy"`, deletedNotice,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}
	if strings.Contains(body, "s3cr3t") || regexp.MustCompile(`<[^>]+ on[a-z]+=`).MatchString(body) {
		t.Errorf("content or an inline handler on the landing page: %s", body)
	}
	if regexp.MustCompile(`/(get|text)\b`).MatchString(body) || strings.Contains(body, "curl") {
		t.Errorf("landing page names /get, /text or curl: %s", body)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Errorf("CSP without connect-src: %q", w.Header().Get("Content-Security-Policy"))
	}
	// The request the script sends: a same-origin POST without a body,
	// asking for text/plain.
	script := map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com", "Accept": "text/plain"}
	if w := e.do(t, "POST", "/d/r/reveal", script); w.Code != 200 || w.Body.String() != secret {
		t.Errorf("same-origin fetch of reveal: %d %q", w.Code, w.Body.String())
	}
	if w := e.do(t, "POST", "/d/r/reveal", script); w.Code != 404 {
		t.Errorf("second fetch of a once reveal: %d", w.Code)
	}
	body = e.do(t, "GET", "/d/d", nil).Body.String()
	if strings.Contains(body, "fetch(") || regexp.MustCompile(`/(get|text)\b`).MatchString(body) || !strings.Contains(body, `action="./d/download"`) {
		t.Errorf("download landing: %s", body)
	}
}

func TestPortalPoweredBy(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "p", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload}})
	body := e.do(t, "GET", "/d/p", nil).Body.String()
	if !strings.Contains(body, `<footer>Powered by <a href="https://github.com/rjsocha/luk" rel="noopener noreferrer">LUK</a></footer>`) {
		t.Fatalf("no footer: %s", body)
	}
}

const (
	secretNotice   = `<p class="notice" id="once"><strong>One-time secret.</strong><br><b>It will be deleted as soon as it is revealed.</b></p>`
	downloadNotice = `<p class="notice" id="once"><strong>One-time download.</strong><br><b>It will be deleted as soon as it is downloaded.</b></p>`
	deletedNotice  = `<p class="notice"><strong>Deleted.</strong><br><b>This page is the only copy.</b></p>`
)

func TestPortalOnceNotices(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "ro", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "r", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	e.put(t, "do", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload, Once: true}})
	e.put(t, "d", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalDownload}})
	for _, c := range []struct {
		path, button string
		want, absent []string
	}{
		{"/d/ro", "Reveal and delete", []string{secretNotice, deletedNotice}, []string{downloadNotice}},
		{"/d/r", "Reveal", nil, []string{`class="notice"`, "and delete"}},
		{"/d/do", "Download and delete", []string{downloadNotice}, []string{secretNotice, deletedNotice}},
		{"/d/d", "Download", nil, []string{`class="notice"`, "and delete"}},
	} {
		body := e.do(t, "GET", c.path, nil).Body.String()
		button := `<button type="submit">` + c.button + `</button>`
		if strings.HasSuffix(c.button, "and delete") {
			button = `<button type="submit" class="danger">` + c.button + `</button>`
		}
		for _, want := range append(c.want, button) {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q in %s", c.path, want, body)
			}
		}
		for _, no := range c.absent {
			if strings.Contains(body, no) {
				t.Errorf("%s: unexpected %q in %s", c.path, no, body)
			}
		}
		if strings.Contains(body, `class="note"`) {
			t.Errorf("%s: old gray note in %s", c.path, body)
		}
	}
	if body := e.do(t, "POST", "/d/ro/reveal", nil).Body.String(); !strings.Contains(body, deletedNotice) {
		t.Errorf("once reveal page without the deleted notice: %s", body)
	}
	if body := e.do(t, "POST", "/d/r/reveal", nil).Body.String(); strings.Contains(body, `class="notice"`) {
		t.Errorf("non-once reveal page with a notice: %s", body)
	}
}

func TestPortalRevealBinary(t *testing.T) {
	e := newEnv(t, nil)
	bin := "\x00\x01\xff\xfekey"
	e.put(t, "b", bin, store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, Once: true}})
	e.put(t, "c", "a\x07b", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	text := "line\tone\r\nzażółć ☃\n"
	e.put(t, "t", text, store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})

	w := e.do(t, "POST", "/d/b/reveal", nil)
	body := w.Body.String()
	checkPortalHeaders(t, w, body)
	for _, want := range []string{
		`<label for="content">Base64</label>`,
		">\n" + base64.StdEncoding.EncodeToString([]byte(bin)) + "</textarea>",
		deletedNotice,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("binary reveal: missing %q in %s", want, body)
		}
	}
	if body := e.do(t, "POST", "/d/c/reveal", nil).Body.String(); !strings.Contains(body, `<label for="content">Base64</label>`) || !strings.Contains(body, base64.StdEncoding.EncodeToString([]byte("a\x07b"))) {
		t.Errorf("control character not shown as binary: %s", body)
	}
	body = e.do(t, "POST", "/d/t/reveal", nil).Body.String()
	if strings.Contains(body, ">Base64</label>") || !strings.Contains(body, ">\n"+text+"</textarea>") {
		t.Errorf("text reveal changed: %s", body)
	}
	// /get answers the raw bytes whatever they are.
	e.put(t, "g", bin, store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	if w := e.do(t, "GET", "/d/g/get", nil); w.Code != 200 || w.Body.String() != bin {
		t.Errorf("get of binary content: %d %q", w.Code, w.Body.String())
	}
}

func TestPortalLandingBinaryScript(t *testing.T) {
	e := newEnv(t, nil)
	e.put(t, "r", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal}})
	e.put(t, "f", "x", store.Sidecar{Client: wire.Meta{Portal: wire.PortalReveal, File: "id <rsa>"}})
	w := e.do(t, "GET", "/d/r", nil)
	body := w.Body.String()
	// The CSP stays as it is: saving through an <a download> of a blob:
	// URL is a download, not a fetch, so no directive is needed for it.
	checkPortalHeaders(t, w, body)
	for _, want := range []string{
		"res.arrayBuffer().then(show)",
		`new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })`,
		`/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/`,
		`new Blob([bytes]`, "URL.createObjectURL(", "a.download = ", "btoa(",
		`<button type="button" id="save" data-name="r.bin">Save binary</button>`,
		`<label for="content">Base64</label>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}
	if body := e.do(t, "GET", "/d/f", nil).Body.String(); !strings.Contains(body, `data-name="id &lt;rsa&gt;"`) {
		t.Errorf("save name of a named upload: %s", body)
	}
}
