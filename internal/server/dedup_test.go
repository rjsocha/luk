package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"luk/internal/wire"
)

// dedupFixture has a second key anna allowed on /drop besides the fixture
// key; mod rewrites the config further.
func dedupFixture(t *testing.T, mod func(string) string) (*fixture, ssh.Signer) {
	t.Helper()
	anna := newSigner(t)
	f := newFixtureWith(t, func(s string) string {
		s = strings.Replace(s, `"}]
  ca:`, `"}, {name: anna, key: "`+pubLine(anna.PublicKey())+`"}]
  ca:`, 1)
		s = strings.Replace(s, `allow: [robert.socha], respond: url`, `allow: [robert.socha, anna], respond: url`, 1)
		if mod != nil {
			s = mod(s)
		}
		return s
	})
	return f, anna
}

// put uploads body to /drop as signer with the meta m and returns the
// answer and the body bytes the server read.
func (f *fixture) put(t *testing.T, signer ssh.Signer, m wire.Meta, body []byte) (wire.Receipt, int) {
	t.Helper()
	n := 0
	rec, _ := f.do(t, req{signer: signer, path: "/drop", meta: m, body: body, tamper: countBody(&n)})
	return receipt(t, rec, http.StatusCreated), n
}

// dropFile is the path of the stored file of a /drop URL.
func (f *fixture) dropFile(t *testing.T, u string) string {
	t.Helper()
	pu, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(f.root, "s/drop/file", strings.TrimPrefix(pu.Path, "/d/"))
}

func (f *fixture) download(t *testing.T, u string) (int, string) {
	t.Helper()
	pu, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	f.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://lukd.vm:8443"+pu.Path, nil))
	return rec.Code, rec.Body.String()
}

func shared(t *testing.T, a, b string) bool {
	t.Helper()
	fa, err := os.Lstat(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := os.Lstat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(fa, fb)
}

func TestDedupSameOwnerReadsNoBody(t *testing.T) {
	f, _ := dedupFixture(t, nil)
	body := []byte("the same content")
	first, n := f.put(t, f.user, fileMeta(body), body)
	if n != len(body) || first.Deduplicated {
		t.Fatalf("first read %d: %+v", n, first)
	}
	f.settle(t)
	second, n := f.put(t, f.user, fileMeta(body), body)
	if n != 0 || !second.Deduplicated || second.URL == first.URL || second.ID == first.ID ||
		second.Size != int64(len(body)) || second.SHA256 != fileMeta(body).SHA256 {
		t.Fatalf("second read %d: %+v", n, second)
	}
	f.settle(t)
	for _, u := range []string{first.URL, second.URL} {
		if code, got := f.download(t, u); code != 200 || got != string(body) {
			t.Fatalf("%s: %d %q", u, code, got)
		}
	}
	if !shared(t, f.dropFile(t, first.URL), f.dropFile(t, second.URL)) {
		t.Fatal("the two links do not share the content")
	}
	if e := entries(t, filepath.Join(f.root, "q/drop")); len(e) != 0 {
		t.Fatalf("queue left %v", e)
	}
	// A stream sent again carries the size and sha256 of the first answer.
	m := wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Size: &second.Size, SHA256: second.SHA256}
	third, n := f.put(t, f.user, m, body)
	if n != 0 || !third.Deduplicated {
		t.Fatalf("stream read %d: %+v", n, third)
	}
}

func TestDedupBeforeFirstStored(t *testing.T) {
	f, anna := dedupFixture(t, nil)
	body := []byte("queued content")
	first, _ := f.put(t, f.user, fileMeta(body), body)
	// Not stored yet: the committed queue entry of the same sender holds it.
	second, n := f.put(t, f.user, fileMeta(body), body)
	if n != 0 || !second.Deduplicated {
		t.Fatalf("read %d: %+v", n, second)
	}
	// Never from the queue entry of another sender.
	if other, n := f.put(t, anna, fileMeta(body), body); n != len(body) || other.Deduplicated {
		t.Fatalf("other sender read %d: %+v", n, other)
	}
	f.settle(t)
	if !shared(t, f.dropFile(t, first.URL), f.dropFile(t, second.URL)) {
		t.Fatal("not shared")
	}
}

func TestDedupNeverAcrossOwners(t *testing.T) {
	f, anna := dedupFixture(t, nil)
	body := []byte("robert's content")
	first, _ := f.put(t, f.user, fileMeta(body), body)
	f.settle(t)
	other, n := f.put(t, anna, fileMeta(body), body)
	if n != len(body) || other.Deduplicated {
		t.Fatalf("other owner read %d: %+v", n, other)
	}
	f.settle(t)
	// The space is shared all the same.
	if !shared(t, f.dropFile(t, first.URL), f.dropFile(t, other.URL)) {
		t.Fatal("not shared at store")
	}
	// Now anna has a name with it too.
	if again, n := f.put(t, anna, fileMeta(body), body); n != 0 || !again.Deduplicated {
		t.Fatalf("anna again read %d: %+v", n, again)
	}
	// A claimed hash of content the sender never had reads the body.
	other2 := []byte("other content")
	m := fileMeta(other2)
	if r, n := f.put(t, f.user, m, other2); n != len(other2) || r.Deduplicated {
		t.Fatalf("unknown content read %d: %+v", n, r)
	}
}

func TestDedupNotWithRunStep(t *testing.T) {
	f, _ := dedupFixture(t, func(s string) string {
		return strings.Replace(s, `drop: {endpoint: [drop], steps: [{store: drop}]}`, `drop: {endpoint: [drop], steps: [{run: /bin/true}, {store: drop}]}`, 1)
	})
	body := []byte("transformed")
	f.put(t, f.user, fileMeta(body), body)
	if r, n := f.put(t, f.user, fileMeta(body), body); n != len(body) || r.Deduplicated {
		t.Fatalf("run pipeline read %d: %+v", n, r)
	}
}

func TestDedupNotWithoutHardlink(t *testing.T) {
	f, _ := dedupFixture(t, func(s string) string {
		return strings.Replace(s, `drop: {type: local, base: s/drop,`, `drop: {type: local, hardlink: false, base: s/drop,`, 1)
	})
	body := []byte("separate")
	first, _ := f.put(t, f.user, fileMeta(body), body)
	f.settle(t)
	second, n := f.put(t, f.user, fileMeta(body), body)
	if n != len(body) || second.Deduplicated {
		t.Fatalf("read %d: %+v", n, second)
	}
	f.settle(t)
	if shared(t, f.dropFile(t, first.URL), f.dropFile(t, second.URL)) {
		t.Fatal("shared without hardlink")
	}
}

func TestDedupEveryStorage(t *testing.T) {
	f, _ := dedupFixture(t, func(s string) string {
		s = strings.Replace(s, `drop: {endpoint: [drop], steps: [{store: drop}]}`, `drop: {endpoint: [drop], steps: [{store: drop}]}
  copy: {endpoint: [drop], tags: [copy], steps: [{store: archive}]}`, 1)
		return s
	})
	body := []byte("fan out")
	f.put(t, f.user, fileMeta(body), body)
	f.settle(t)
	// The archive storage does not hold it for robert.socha.
	if r, n := f.put(t, f.user, fileMeta(body, "copy"), body); n != len(body) || r.Deduplicated {
		t.Fatalf("read %d: %+v", n, r)
	}
	f.settle(t)
	if r, n := f.put(t, f.user, fileMeta(body, "copy"), body); n != 0 || !r.Deduplicated {
		t.Fatalf("both storages hold it, read %d: %+v", n, r)
	}
}
