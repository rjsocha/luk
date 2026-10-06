package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"luk/internal/acmecert"
	"luk/internal/acmecert/acmetest"
	"luk/internal/config"
	"luk/internal/server"
)

const stagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// acmeCacheConfig has the acme listeners prod (a and b on the default
// directory) and stage (s on staging), and cache directories with:
// production a (in use) and gone (unused), staging s (in use), and a
// directory no listener uses with x. Each has an account key; production
// and the unused one have a status.json.
func acmeCacheConfig(t *testing.T) (string, *config.Config) {
	t.Helper()
	root := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	text := fmt.Sprintf(`root: %s
listen:
  prod:
    addr: 127.0.0.1:18443
    host: [a.example.com, b.example.com]
    tls: {mode: acme}
  stage:
    addr: 127.0.0.1:18444
    host: [s.example.com]
    tls: {mode: acme, directory: '%s'}
  http:
    addr: 127.0.0.1:18080
    acme: true
`, root, stagingDirectory)
	if err := os.WriteFile(cfgPath, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	prod, stage := cfg.ACMECacheDir(config.DefaultACMEDirectory), cfg.ACMECacheDir(stagingDirectory)
	other := filepath.Join(root, "acme", "ca.example.com_14000_dir")
	issuer := testIssuer(t)
	for dir, names := range map[string][]string{prod: {"a.example.com", "gone.example.com"}, stage: {"s.example.com"}, other: {"x.example.com"}} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, acmecert.AccountFile), []byte("key"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			writeTestCert(t, issuer, dir, n, 10*24*time.Hour+time.Hour)
		}
	}
	retry := time.Date(2026, 10, 2, 13, 0, 0, 0, time.UTC)
	writeStatus(t, prod, acmecert.Status{Directory: config.DefaultACMEDirectory, Hosts: map[string]*acmecert.HostStatus{
		"a.example.com": {LastError: "rate limited", NextRetry: retry},
	}})
	writeStatus(t, other, acmecert.Status{Directory: "https://ca.example.com:14000/dir"})
	return cfgPath, cfg
}

type issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func testIssuer(t *testing.T) issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Issuer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return issuer{c, key}
}

// writeTestCert writes <dir>/<name>.pem, valid from an hour ago for life.
func writeTestCert(t *testing.T, is issuer, dir, name string, life time.Duration) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(life)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, is.cert, key.Public(), is.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	data := append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := os.WriteFile(acmecert.CertFile(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeStatus(t *testing.T, dir string, st acmecert.Status) {
	t.Helper()
	data, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(dir, acmecert.StatusFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// holdReceive takes the lock of the receive role as a running lukd does.
func holdReceive(t *testing.T, root string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(root, ".lukd-receive.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
}

// acmeLines maps the name of each ls row to its columns.
func acmeLines(t *testing.T, out string) map[string][]string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if !strings.HasPrefix(lines[0], "NAME") || !strings.Contains(lines[0], "LAST ERROR") {
		t.Fatalf("header:\n%s", out)
	}
	rows := map[string][]string{}
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		rows[f[0]] = f
	}
	return rows
}

func TestACMELs(t *testing.T) {
	cfgPath, cfg := acmeCacheConfig(t)
	out, err := runLukd(t, "tls", "acme", "ls", "-c", cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rows := acmeLines(t, out)
	// NAME LISTEN DIRECTORY ISSUER(2 words) NOT-BEFORE NOT-AFTER DAYS RENEW-AT ERROR RETRY
	for name, want := range map[string][3]string{
		"a.example.com":    {"prod", "acme-v02.api.letsencrypt.org"},
		"gone.example.com": {"unused", "acme-v02.api.letsencrypt.org"},
		"s.example.com":    {"stage", "acme-staging-v02.api.letsencrypt.org"},
		// No listener and the daemon is not running: the host from the
		// directory name.
		"x.example.com": {"unused", "ca.example.com"},
	} {
		f := rows[name]
		if len(f) != 11 || f[1] != want[0] || f[2] != want[1] || f[3]+" "+f[4] != "Test Issuer" || f[7] != "10" || f[9] != "-" || f[10] != "-" {
			t.Errorf("%s: %q", name, f)
		}
	}
	if len(rows) != 4 {
		t.Fatalf("rows:\n%s", out)
	}

	// With the receive role running the status columns come from its
	// status.json.
	holdReceive(t, cfg.Root)
	out, err = runLukd(t, "tls", "acme", "ls", "-c", cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rows = acmeLines(t, out)
	if f := rows["a.example.com"]; len(f) != 12 || f[9]+" "+f[10] != "rate limited" || f[11] != "2026-10-02T13:00:00Z" {
		t.Errorf("a with status: %q", f)
	}
	if f := rows["x.example.com"]; f[2] != "ca.example.com:14000" {
		t.Errorf("x with status: %q", f)
	}

	out, err = runLukd(t, "tls", "acme", "ls", "--json", "-c", cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var list []acmeRow
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	byName := map[string]acmeRow{}
	for _, r := range list {
		byName[r.Name] = r
	}
	a, s, g := byName["a.example.com"], byName["s.example.com"], byName["gone.example.com"]
	if a.Unused || len(a.Listen) != 1 || a.Directory != config.DefaultACMEDirectory || a.Daemon == nil || a.Daemon.LastError != "rate limited" ||
		a.Issuer != "Test Issuer" || a.DaysLeft != 10 || !a.RenewAt.Equal(a.NotAfter.Add(-a.NotAfter.Sub(a.NotBefore)/3)) {
		t.Errorf("a: %+v", a)
	}
	if s.Unused || s.Directory != stagingDirectory || s.DirectoryHost != "acme-staging-v02.api.letsencrypt.org" {
		t.Errorf("s: %+v", s)
	}
	if !g.Unused || len(g.Listen) != 0 || !strings.Contains(out, `"listen": []`) {
		t.Errorf("gone: %+v", g)
	}
}

func TestACMEPrune(t *testing.T) {
	cfgPath, cfg := acmeCacheConfig(t)
	prod, stage := cfg.ACMECacheDir(config.DefaultACMEDirectory), cfg.ACMECacheDir(stagingDirectory)
	other := filepath.Join(cfg.Root, "acme", "ca.example.com_14000_dir")
	gone, x := acmecert.CertFile(prod, "gone.example.com"), acmecert.CertFile(other, "x.example.com")
	out, err := runLukd(t, "tls", "acme", "prune", "--dry-run", "-c", cfgPath)
	if err != nil || out != "would remove "+gone+"\nwould remove "+x+"\n" {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	for _, p := range []string{gone, x} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("dry run removed %s", p)
		}
	}
	out, err = runLukd(t, "tls", "acme", "prune", "-c", cfgPath)
	if err != nil || out != "removed "+gone+"\nremoved "+x+"\n" {
		t.Fatalf("prune: %v\n%s", err, out)
	}
	for _, p := range []string{gone, x} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s kept: %v", p, err)
		}
	}
	for _, p := range []string{acmecert.CertFile(prod, "a.example.com"), acmecert.CertFile(stage, "s.example.com"),
		filepath.Join(prod, acmecert.AccountFile), filepath.Join(other, acmecert.AccountFile)} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed: %v", p, err)
		}
	}
	if out, err := runLukd(t, "tls", "acme", "prune", "-c", cfgPath); err != nil || out != "nothing to prune\n" {
		t.Fatalf("second prune: %v %q", err, out)
	}
}

// TestACMEAsOwner covers the decision of the acme commands for the
// calling uid against the owner of <root>/acme.
func TestACMEAsOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	cfgPath, cfg := acmeCacheConfig(t)
	var gotUID uint32
	called := false
	geteuid, reexecAs = func() int { return 0 }, func(uid, gid uint32, groups []uint32) error {
		called, gotUID = true, uid
		return exitCode(3)
	}
	t.Cleanup(func() { geteuid, reexecAs = os.Geteuid, reexec })
	// Root runs it again as the owner of the cache.
	_, err := runLukd(t, "tls", "acme", "ls", "-c", cfgPath)
	var code exitCode
	if !errors.As(err, &code) || code != 3 || !called || gotUID != uint32(os.Getuid()) {
		t.Fatalf("root: %v called %v uid %d", err, called, gotUID)
	}
	// The second run as root (the owner is not root) is refused.
	t.Setenv(reexecEnv, "1")
	called = false
	name := strconv.Itoa(os.Getuid())
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	want := "lukd tls acme must run as root or as " + name + " (owner of " + filepath.Join(cfg.Root, "acme") + ")"
	if _, err := runLukd(t, "tls", "acme", "prune", "-c", cfgPath); err == nil || err.Error() != want || called {
		t.Fatalf("reexeced root: %v", err)
	}
	// Another user is refused.
	t.Setenv(reexecEnv, "")
	geteuid = func() int { return os.Getuid() + 1 }
	if _, err := runLukd(t, "tls", "acme", "ls", "-c", cfgPath); err == nil || err.Error() != want || called {
		t.Fatalf("other user: %v", err)
	}
	// The owner runs it.
	geteuid = os.Geteuid
	if _, err := runLukd(t, "tls", "acme", "ls", "-c", cfgPath); err != nil || called {
		t.Fatalf("owner: %v", err)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// servedSerial is the serial of the certificate dl serves for sni.
func servedSerial(t *testing.T, ca *acmetest.CA, dl, sni string) string {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ca.Root)
	c, err := tls.Dial("tcp", dl, &tls.Config{ServerName: sni, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0].SerialNumber.Text(16)
}

func runLukdIn(t *testing.T, in string, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := rootCmd()
	cmd.SetArgs(args)
	cmd.SetIn(strings.NewReader(in))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

// TestACMERenewRevoke runs the receive role against a local CA: renew
// and revoke through the cache directory swap the served certificate
// without a restart.
func TestACMERenewRevoke(t *testing.T) {
	ca := acmetest.New(t)
	server.ACMEHTTPClient, acmeClient = ca.Client(), ca.Client()
	t.Cleanup(func() { server.ACMEHTTPClient, acmeClient = nil, nil })
	dl, plain := freeAddr(t), freeAddr(t)
	ca.SetHTTP01(plain)
	root := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	text := fmt.Sprintf(`root: %s
listen:
  download:
    addr: %s
    host: [drop.example.com]
    tls: {mode: acme, directory: '%s'}
  http:
    addr: %s
    acme: true
`, root, dl, ca.Directory(), plain)
	if err := os.WriteFile(cfgPath, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	writeIdentity(t, cfgPath)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cache := cfg.ACMECacheDir(ca.Directory())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Receive(ctx, cfg, slog.New(slog.DiscardHandler)) }()
	stop := func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	defer func() {
		if ctx.Err() == nil {
			stop()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(acmecert.CertFile(cache, "drop.example.com")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no certificate")
		}
		time.Sleep(10 * time.Millisecond)
	}
	first := servedSerial(t, ca, dl, "drop.example.com")

	out, err := runLukd(t, "tls", "acme", "renew", "--host", "drop.example.com", "--timeout", "20s", "-c", cfgPath)
	if err != nil {
		t.Fatalf("renew: %v %s", err, out)
	}
	second := servedSerial(t, ca, dl, "drop.example.com")
	if second == first || !strings.HasPrefix(out, "drop.example.com: renewed, serial "+second+", not after ") {
		t.Fatalf("renew: %s (served %s, before %s)", out, second, first)
	}
	if _, err := os.Stat(acmecert.RequestFile(cache, "drop.example.com")); !os.IsNotExist(err) {
		t.Fatalf("request file left: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(cache, acmecert.StatusFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("status.json: %v %v", fi, err)
	}
	st, err := acmecert.ReadStatus(cache)
	if err != nil || st.Hosts["drop.example.com"].Serial != second || st.Directory != ca.Directory() || len(st.Requests) != 1 {
		t.Fatalf("status %+v %v", st, err)
	}
	if _, err := runLukd(t, "tls", "acme", "renew", "--host", "other.example.com", "-c", cfgPath); err == nil ||
		err.Error() != "other.example.com is not a host of any acme listener" {
		t.Fatalf("unknown host: %v", err)
	}

	ls, err := runLukd(t, "tls", "acme", "ls", "-c", cfgPath)
	if f := acmeLines(t, ls)["drop.example.com"]; err != nil || len(f) < 3 || f[1] != "download" || f[2] != strings.TrimPrefix(ca.Srv.URL, "https://") {
		t.Fatalf("ls: %v\n%s", err, ls)
	}

	// Revoke: refused without a terminal, declined on one.
	isTerm := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = isTerm })
	stdinIsTerminal = func() bool { return false }
	if _, _, err := runLukdIn(t, "", "tls", "acme", "revoke", "--host", "drop.example.com", "-c", cfgPath); err == nil || !strings.Contains(err.Error(), "without --yes") {
		t.Fatalf("no terminal: %v", err)
	}
	stdinIsTerminal = func() bool { return true }
	if _, prompt, err := runLukdIn(t, "n\n", "tls", "acme", "revoke", "--host", "drop.example.com", "-c", cfgPath); err == nil || err.Error() != "not revoked" ||
		!strings.Contains(prompt, "Revoke the certificate of drop.example.com (serial "+second) {
		t.Fatalf("declined: %v %q", err, prompt)
	}
	if n := len(ca.Revoked()); n != 0 {
		t.Fatalf("revoked %d", n)
	}
	out, _, err = runLukdIn(t, "yes\n", "tls", "acme", "revoke", "--host", "drop.example.com", "--reason", "superseded", "--timeout", "20s", "-c", cfgPath)
	if err != nil {
		t.Fatalf("revoke: %v %s", err, out)
	}
	if r := ca.Revoked(); len(r) != 1 || r[0].Serial != second || r[0].Reason != 4 {
		t.Fatalf("revocations %+v", r)
	}
	third := servedSerial(t, ca, dl, "drop.example.com")
	if third == second || out != "drop.example.com: revoked serial "+second+"\n"+
		"drop.example.com: removed "+acmecert.CertFile(cache, "drop.example.com")+"\n"+
		"drop.example.com: renewed, serial "+third+", not after "+mustLeaf(t, cache).NotAfter.UTC().Format(time.RFC3339)+"\n" {
		t.Fatalf("revoke output:\n%s(served %s)", out, third)
	}
	if _, err := runLukd(t, "tls", "acme", "revoke", "--host", "drop.example.com", "--reason", "bogus", "--yes", "-c", cfgPath); err == nil || !strings.Contains(err.Error(), "--reason") {
		t.Fatalf("bad reason: %v", err)
	}

	stop()
	if _, err := runLukd(t, "tls", "acme", "renew", "--host", "drop.example.com", "-c", cfgPath); err == nil || err.Error() != "lukd receive is not running" {
		t.Fatalf("not running: %v", err)
	}
	if _, err := os.Stat(acmecert.RequestFile(cache, "drop.example.com")); !os.IsNotExist(err) {
		t.Fatalf("request written without a daemon: %v", err)
	}
}

func mustLeaf(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	leaf, err := acmecert.LoadLeaf(dir, "drop.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// TestACMEPruneOnlyCertificates keeps a file named like a certificate that
// does not load as one, and refuses an acme directory that is a symlink.
func TestACMEPruneOnlyCertificates(t *testing.T) {
	cfgPath, cfg := acmeCacheConfig(t)
	prod := cfg.ACMECacheDir(config.DefaultACMEDirectory)
	junk := acmecert.CertFile(prod, "junk.example.com")
	if err := os.WriteFile(junk, []byte("not even a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runLukd(t, "tls", "acme", "prune", "-c", cfgPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(junk); err != nil {
		t.Fatalf("junk removed: %v", err)
	}

	victim := t.TempDir()
	if err := os.MkdirAll(filepath.Join(victim, "live"), 0o755); err != nil {
		t.Fatal(err)
	}
	pem := filepath.Join(victim, "live", "privkey.pem")
	if err := os.WriteFile(pem, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	acme := filepath.Join(cfg.Root, "acme")
	if err := os.RemoveAll(acme); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, acme); err != nil {
		t.Fatal(err)
	}
	if _, err := runLukd(t, "tls", "acme", "prune", "-c", cfgPath); err == nil || !strings.Contains(err.Error(), "is a symlink") {
		t.Fatalf("symlink: %v", err)
	}
	if err := pruneACME(cfg, false, io.Discard); err == nil {
		t.Fatal("pruneACME through a symlink")
	}
	if _, err := os.Stat(pem); err != nil {
		t.Fatalf("victim removed: %v", err)
	}
}

// Without <root>/acme, root still runs the acme commands as the owner of
// root: it never creates or writes anything in a directory the service
// user could put back as a symlink.
func TestACMEAsOwnerWithoutCache(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	cfgPath, cfg := acmeCacheConfig(t)
	if err := os.RemoveAll(filepath.Join(cfg.Root, "acme")); err != nil {
		t.Fatal(err)
	}
	var gotUID uint32
	called := false
	geteuid, reexecAs = func() int { return 0 }, func(uid, gid uint32, groups []uint32) error {
		called, gotUID = true, uid
		return exitCode(0)
	}
	t.Cleanup(func() { geteuid, reexecAs = os.Geteuid, reexec })
	for _, args := range [][]string{{"ls"}, {"renew", "--host", "a.example.com"}} {
		called = false
		_, err := runLukd(t, append(append([]string{"tls", "acme"}, args...), "-c", cfgPath)...)
		var code exitCode
		if !errors.As(err, &code) || code != 0 || !called || gotUID != uint32(os.Getuid()) {
			t.Fatalf("%v: %v called %v uid %d", args, err, called, gotUID)
		}
	}
	if _, err := os.Lstat(filepath.Join(cfg.Root, "acme")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("acme created as root: %v", err)
	}
}
