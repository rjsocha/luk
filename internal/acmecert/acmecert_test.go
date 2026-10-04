package acmecert

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"luk/internal/acmecert/acmetest"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// setup starts a CA and a manager for a.example.com and b.example.com
// whose challenge handler the CA reaches.
func setup(t *testing.T, eab *acme.ExternalAccountBinding) (*acmetest.CA, *Manager, *syncBuffer) {
	t.Helper()
	ca := acmetest.New(t)
	logs := &syncBuffer{}
	m := New(Options{
		Directory: ca.Directory(), CacheDir: t.TempDir(), Email: "ops@example.com", EAB: eab,
		Hosts: []string{"a.example.com", "b.example.com"}, Log: slog.New(slog.NewTextHandler(logs, nil)),
		HTTPClient: ca.Client(),
	})
	srv := httptest.NewServer(m.HTTPHandler())
	t.Cleanup(srv.Close)
	ca.SetHTTP01(srv.Listener.Addr().String())
	return ca, m, logs
}

func verify(t *testing.T, ca *acmetest.CA, c *tls.Certificate, host string) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
		t.Fatal(err)
	}
}

func TestObtainCacheAndReuse(t *testing.T) {
	ca, m, logs := setup(t, nil)
	c, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "A.example.com."})
	if err != nil {
		t.Fatal(err)
	}
	verify(t, ca, c, "a.example.com")
	if len(ca.Registrations) != 1 || ca.Registrations[0].Contact[0] != "mailto:ops@example.com" || ca.Registrations[0].EAB {
		t.Fatalf("registrations %+v", ca.Registrations)
	}
	for _, f := range []string{"account.key", "a.example.com.pem"} {
		fi, err := os.Stat(filepath.Join(m.o.CacheDir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi, err)
		}
	}
	if !strings.Contains(logs.String(), "acme certificate obtained") || !strings.Contains(logs.String(), "host=a.example.com") {
		t.Fatalf("logs %s", logs)
	}
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"}); err != nil || ca.Count() != 1 {
		t.Fatalf("second handshake: %v, issued %d", err, ca.Count())
	}
	// A new process on the same cache serves the stored certificate.
	m2 := New(m.o)
	c2, err := m2.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil || ca.Count() != 1 || !bytes.Equal(c2.Certificate[0], c.Certificate[0]) {
		t.Fatalf("from cache: %v, issued %d", err, ca.Count())
	}
	// The same account key: the CA knows it.
	srv := httptest.NewServer(m2.HTTPHandler())
	defer srv.Close()
	ca.SetHTTP01(srv.Listener.Addr().String())
	if _, err := m2.GetCertificate(&tls.ClientHelloInfo{ServerName: "b.example.com"}); err != nil || ca.Count() != 2 {
		t.Fatalf("b: %v, issued %d", err, ca.Count())
	}
	if n := len(ca.Registrations); n != 2 {
		t.Fatalf("registrations %d", n)
	}
	if leaf, err := m2.Leaf("b.example.com"); err != nil || leaf == nil {
		t.Fatalf("leaf %v %v", leaf, err)
	}
	if leaf, err := m2.Leaf("c.example.com"); err != nil || leaf != nil {
		t.Fatalf("leaf of an unknown name %v %v", leaf, err)
	}
}

func TestUnknownName(t *testing.T) {
	ca, m, _ := setup(t, nil)
	for _, n := range []string{"c.example.com", "", "127.0.0.1"} {
		if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: n}); err == nil {
			t.Errorf("%q: served", n)
		}
	}
	if ca.Count() != 0 || len(ca.Registrations) != 0 {
		t.Fatalf("CA asked for an unknown name")
	}
}

func TestEAB(t *testing.T) {
	ca, m, _ := setup(t, &acme.ExternalAccountBinding{KID: "kid-1", Key: []byte("0123456789abcdef0123456789abcdef")})
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(ca.Registrations) != 1 || !ca.Registrations[0].EAB {
		t.Fatalf("registrations %+v", ca.Registrations)
	}
}

func TestFailedChallengeHoldsOff(t *testing.T) {
	ca, m, _ := setup(t, nil)
	nothing := httptest.NewServer(http.NotFoundHandler())
	defer nothing.Close()
	ca.SetHTTP01(nothing.Listener.Addr().String())
	_, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err == nil || !strings.Contains(err.Error(), "challenge") {
		t.Fatalf("got %v", err)
	}
	if _, err2 := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"}); err2 != err {
		t.Fatalf("retried at once: %v", err2)
	}
	if _, err := os.Stat(m.certFile("a.example.com")); !os.IsNotExist(err) {
		t.Fatalf("cached after a failure: %v", err)
	}
	m.now = func() time.Time { return time.Now().Add(retryAfter) }
	srv := httptest.NewServer(m.HTTPHandler())
	defer srv.Close()
	ca.SetHTTP01(srv.Listener.Addr().String())
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"}); err != nil {
		t.Fatalf("after retryAfter: %v", err)
	}
}

func TestRenewal(t *testing.T) {
	ca, m, _ := setup(t, nil)
	ca.SetLifetime(time.Hour)
	c, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	m.check(ctx, "a.example.com", false)
	if ca.Count() != 1 {
		t.Fatalf("renewed too early: %d", ca.Count())
	}
	// Within the last third of the lifetime.
	m.now = func() time.Time { return c.Leaf.NotAfter.Add(-15 * time.Minute) }
	m.check(ctx, "a.example.com", false)
	if ca.Count() != 2 {
		t.Fatalf("not renewed: %d", ca.Count())
	}
	c2, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil || bytes.Equal(c2.Certificate[0], c.Certificate[0]) {
		t.Fatalf("still the old certificate: %v", err)
	}
	// An expired certificate is never served: the handshake obtains a new one.
	m.now = func() time.Time { return c2.Leaf.NotAfter.Add(time.Minute) }
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"}); err != nil || ca.Count() != 3 {
		t.Fatalf("expired: %v, issued %d", err, ca.Count())
	}
}

func TestRunPrefetches(t *testing.T) {
	ca, m, logs := setup(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	// The CA counts a certificate when it signs it, before the manager
	// has fetched and cached it: wait for the cache files.
	cached := func() bool {
		for _, h := range m.o.Hosts {
			if _, err := LoadLeaf(m.o.CacheDir, h); err != nil {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(10 * time.Second)
	for !cached() {
		if time.Now().After(deadline) {
			t.Fatalf("not prefetched: %s", logs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	// A second start finds both valid and only logs them.
	m2 := New(m.o)
	logs2 := &syncBuffer{}
	m2.o.Log = slog.New(slog.NewTextHandler(logs2, nil))
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	m2.Run(ctx)
	if ca.Count() != 2 || strings.Count(logs2.String(), "msg=\"acme certificate\"") != 2 {
		t.Fatalf("issued %d, logs %s", ca.Count(), logs2)
	}
}

func TestChallengeHandler(t *testing.T) {
	_, m, _ := setup(t, nil)
	m.tokens[ChallengePrefix+"tok"] = "tok.thumb"
	h := m.HTTPHandler()
	for _, c := range []struct {
		method, path string
		code         int
	}{
		{http.MethodGet, ChallengePrefix + "tok", 200},
		{http.MethodHead, ChallengePrefix + "tok", 200},
		{http.MethodPost, ChallengePrefix + "tok", 404},
		{http.MethodGet, ChallengePrefix + "other", 404},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(c.method, c.path, nil))
		if w.Code != c.code || c.code == 200 && c.method == http.MethodGet && w.Body.String() != "tok.thumb" {
			t.Errorf("%s %s: %d %q", c.method, c.path, w.Code, w.Body.String())
		}
	}
}

// TestRenewRequest renews through a request file in the cache directory
// while Run runs and records the result under its nonce.
func TestRenewRequest(t *testing.T) {
	ca, m, logs := setup(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	result := func(nonce string) *RequestResult {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			if st, err := ReadStatus(m.o.CacheDir); err == nil && st != nil && st.Requests[nonce] != nil {
				return st.Requests[nonce]
			}
			if time.Now().After(deadline) {
				t.Fatalf("no result for %s: %s", nonce, logs)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// The CA counts a certificate when it signs it, before the manager
	// has fetched and cached it: wait for the cache files.
	cached := func() bool {
		for _, h := range m.o.Hosts {
			if _, err := LoadLeaf(m.o.CacheDir, h); err != nil {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(10 * time.Second)
	for !cached() {
		if time.Now().After(deadline) {
			t.Fatalf("not prefetched: %s", logs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	before, err := m.Leaf("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := WriteRequest(m.o.CacheDir, "a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	r := result(nonce)
	c, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil || r.Error != "" || r.Host != "a.example.com" || r.Serial == Serial(before) || r.Serial != Serial(c.Leaf) || ca.Count() != 3 {
		t.Fatalf("renewal %+v %v, issued %d", r, err, ca.Count())
	}
	if _, err := os.Stat(RequestFile(m.o.CacheDir, "a.example.com")); !os.IsNotExist(err) {
		t.Fatalf("request left: %v", err)
	}
	st, _ := ReadStatus(m.o.CacheDir)
	if h := st.Hosts["a.example.com"]; h.Serial != r.Serial || h.LastSuccess.IsZero() || h.LastError != "" {
		t.Fatalf("host status %+v", h)
	}
	nonce, err = WriteRequest(m.o.CacheDir, "c.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if r := result(nonce); !strings.Contains(r.Error, "c.example.com is not a name of") || ca.Count() != 3 {
		t.Fatalf("unknown name %+v", r)
	}
}

// TestRequestsPolled takes requests on a scan, as the poll without
// inotify and the hourly check do.
func TestRequestsPolled(t *testing.T) {
	ca, m, _ := setup(t, nil)
	nonce, err := WriteRequest(m.o.CacheDir, "b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	m.requests(context.Background(), &wg)
	wg.Wait()
	st, err := ReadStatus(m.o.CacheDir)
	if err != nil || st == nil || st.Requests[nonce] == nil || st.Requests[nonce].Error != "" || ca.Count() != 1 {
		t.Fatalf("status %+v %v, issued %d", st, err, ca.Count())
	}
}
