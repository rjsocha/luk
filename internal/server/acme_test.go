package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"luk/internal/acmecert"
	"luk/internal/acmecert/acmetest"
	"luk/internal/config"
	"luk/internal/tlsself"
)

// acmeTestConfig has an acme listener download (drop.example.com,
// get.example.com) on dl, a second one on 443 and the acme: true
// listener http on plain.
func acmeTestConfig(t *testing.T, root, directory, dl, plain string) *config.Config {
	t.Helper()
	cfg, err := config.Parse(fmt.Appendf(nil, `
root: %s
listen:
  download:
    addr: %s
    host: [drop.example.com, get.example.com]
    tls: {mode: acme, email: ops@example.com, directory: '%s'}
  main:
    addr: 0.0.0.0:443
    host: [main.example.com]
    tls: {mode: acme, email: ops@example.com, directory: '%s'}
  http:
    addr: %s
    acme: true
`, root, dl, directory, directory, plain))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestACMEHTTPListener(t *testing.T) {
	cfg := acmeTestConfig(t, t.TempDir(), "https://ca.example.com/dir", "0.0.0.0:8443", "127.0.0.1:8080")
	s := New(cfg, slog.New(slog.DiscardHandler))
	s.acme = newACME(cfg, slog.New(slog.DiscardHandler), nil)
	h := s.Handler("127.0.0.1:8080")
	for _, c := range []struct {
		method, host, path string
		code               int
		location           string
	}{
		{http.MethodGet, "drop.example.com", "/x/y?z=1", 308, "https://drop.example.com:8443/x/y?z=1"},
		{http.MethodPut, "Get.Example.com:80", "/up", 308, "https://get.example.com:8443/up"},
		{http.MethodGet, "main.example.com", "/", 308, "https://main.example.com/"},
		{http.MethodGet, "other.example.com", "/", 421, ""},
		{http.MethodGet, "other.example.com", acmecert.ChallengePrefix + "tok", 421, ""},
		// No challenge in flight: the manager answers 404.
		{http.MethodGet, "drop.example.com", acmecert.ChallengePrefix + "tok", 404, ""},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(c.method, c.path, nil)
		r.Host = c.host
		h.ServeHTTP(w, r)
		if w.Code != c.code || w.Header().Get("Location") != c.location {
			t.Errorf("%s %s%s: %d %q", c.method, c.host, c.path, w.Code, w.Header().Get("Location"))
		}
	}
	// Without the managers (outside Receive) nothing is answered.
	s.acme = nil
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "drop.example.com"
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("no acme: %d", w.Code)
	}
}

func TestACMEManagersPerDirectory(t *testing.T) {
	cfg := acmeTestConfig(t, t.TempDir(), "https://ca.example.com/dir", "0.0.0.0:8443", "127.0.0.1:8080")
	a := newACME(cfg, slog.New(slog.DiscardHandler), nil)
	if len(a.managers) != 1 || a.listen["download"] != a.listen["main"] {
		t.Fatalf("one directory, %d managers", len(a.managers))
	}
	if got := a.managers[0].Hosts(); strings.Join(got, ",") != "drop.example.com,get.example.com,main.example.com" {
		t.Fatalf("hosts %v", got)
	}
	cfg.Listen["main"].TLS.Directory = "https://staging.example.com/dir"
	if a = newACME(cfg, slog.New(slog.DiscardHandler), nil); len(a.managers) != 2 || a.listen["download"] == a.listen["main"] {
		t.Fatalf("two directories, %d managers", len(a.managers))
	}
}

// fakeSource records the server names it is asked for.
type fakeSource struct {
	cert  *tls.Certificate
	names []string
}

func (f *fakeSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.names = append(f.names, hello.ServerName)
	return f.cert, nil
}

func TestACMEListenerSNI(t *testing.T) {
	root := t.TempDir()
	cfg, err := config.Parse(fmt.Appendf(nil, `
root: %s
listen:
  a-self:
    addr: 127.0.0.1:8443
    host: [self.vm]
    tls: {mode: self, cert: tls/s.crt, key: tls/s.key, host: self.vm}
  b-acme:
    addr: 127.0.0.1:8443
    host: [drop.example.com, get.example.com]
    tls: {mode: acme}
  c-acme:
    addr: 127.0.0.1:9443
    host: [solo.example.com]
    tls: {mode: acme}
  http:
    addr: 127.0.0.1:8080
    acme: true
`, root))
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Listen["a-self"].TLS
	if _, err := tlsself.Generate(l.Cert, l.Key, l.Host, l.Algorithm); err != nil {
		t.Fatal(err)
	}
	fake := &fakeSource{cert: &tls.Certificate{}}
	a := newACME(cfg, slog.New(slog.DiscardHandler), nil)
	a.listen["b-acme"], a.listen["c-acme"] = fake, fake
	certs, err := loadCerts(cfg, a)
	if err != nil {
		t.Fatal(err)
	}
	groups := cfg.Addrs()
	shared, solo := tlsConfig(groups[0], certs), tlsConfig(groups[1], certs)
	selfCert := certs["a-self"].cur.Load()
	for _, c := range []struct {
		cfg        *tls.Config
		sni, asked string
		want       *tls.Certificate
	}{
		{shared, "self.vm", "", selfCert},
		{shared, "GET.example.com", "GET.example.com", fake.cert},
		{shared, "", "", selfCert},
		{shared, "other.example.com", "", selfCert},
		{solo, "solo.example.com", "solo.example.com", fake.cert},
		// The first listener of an address is acme: its first name.
		{solo, "", "solo.example.com", fake.cert},
		{solo, "other.example.com", "solo.example.com", fake.cert},
	} {
		fake.names = nil
		got, err := c.cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: c.sni})
		if err != nil || got != c.want {
			t.Errorf("sni %q: %v", c.sni, err)
		}
		if c.asked != "" && (len(fake.names) != 1 || fake.names[0] != c.asked) {
			t.Errorf("sni %q: acme asked for %v, want %s", c.sni, fake.names, c.asked)
		}
	}
	// SIGHUP leaves acme listeners alone.
	reloadCerts(certs, slog.New(slog.DiscardHandler))
	if certs["b-acme"].cur.Load() != nil {
		t.Fatal("acme slot got a file certificate")
	}
}

func TestACMECacheDir(t *testing.T) {
	root := t.TempDir()
	cfg := acmeTestConfig(t, root, "https://ca.example.com:14000/dir", "0.0.0.0:8443", "127.0.0.1:8080")
	if err := os.MkdirAll(filepath.Join(root, "data", "acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := prepareDirs(cfg, "receive"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(root, "data", "acme"), filepath.Join(root, "data", "acme", "ca.example.com_14000_dir")} {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", d, fi, err)
		}
	}
	// The process role does not touch it.
	other := acmeTestConfig(t, t.TempDir(), "https://ca.example.com/dir", "0.0.0.0:8443", "127.0.0.1:8080")
	if err := prepareDirs(other, "process"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(other.DataDir(), "acme")); !os.IsNotExist(err) {
		t.Fatalf("process role created the acme cache: %v", err)
	}
}

// TestReceiveACME runs the receive role against a local CA: the
// certificates are obtained at start through the acme: true listener,
// served by SNI and logged on SIGHUP.
func TestReceiveACME(t *testing.T) {
	ca := acmetest.New(t)
	ACMEHTTPClient = ca.Client()
	t.Cleanup(func() { ACMEHTTPClient = nil })
	dl, plain := freePort(t), freePort(t)
	ca.SetHTTP01(plain)
	root := t.TempDir()
	cfg := acmeTestConfig(t, root, ca.Directory(), dl, plain)
	// main is on 443, which a test cannot bind; keep download and http.
	delete(cfg.Listen, "main")
	var logs syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Receive(ctx, cfg, slog.New(slog.NewTextHandler(&logs, nil))) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	cache := cfg.ACMECacheDir(ca.Directory())
	waitFor(t, "certificates", func() bool {
		for _, h := range []string{"drop.example.com", "get.example.com"} {
			if _, err := os.Stat(filepath.Join(cache, h+".pem")); err != nil {
				return false
			}
		}
		return true
	})
	if n := ca.Count(); n != 2 {
		t.Fatalf("issued %d", n)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	for _, sni := range []string{"drop.example.com", "get.example.com"} {
		c, err := tls.Dial("tcp", dl, &tls.Config{ServerName: sni, RootCAs: roots})
		if err != nil {
			t.Fatalf("%s: %v", sni, err)
		}
		c.Close()
	}
	// No SNI: the certificate of the first name, as for other modes.
	c, err := tls.Dial("tcp", dl, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.ConnectionState().PeerCertificates[0].DNSNames; len(got) != 1 || got[0] != "drop.example.com" {
		t.Fatalf("no sni: %v", got)
	}
	c.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, "http://"+plain+"/file?x=1", nil)
	req.Host = "drop.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	_, port, _ := net.SplitHostPort(dl)
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "https://drop.example.com:"+port+"/file?x=1" {
		t.Fatalf("redirect %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !strings.Contains(logs.String(), "acme certificate obtained") {
		t.Fatalf("logs %s", logs.String())
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tls acme log", func() bool {
		return strings.Contains(logs.String(), `msg="tls acme" listen=download host=get.example.com`)
	})
}
