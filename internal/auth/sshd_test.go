package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/config"
)

// An identity of ssh.d with two keys resolves, and is allowed, with each.
func TestKeyDIdentity(t *testing.T) {
	laptop, desktop, stranger := signer(t), signer(t), signer(t)
	line := func(s ssh.Signer) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) }
	dir := t.TempDir()
	cfg := "listen:\n  main: {addr: 127.0.0.1:8080}\n" +
		"endpoint:\n  backup: {listen: main, endpoint: /backup, path: /queue/backup, allow: [jan.kowalski]}\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "ssh.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	pub := "# Jan Kowalski\n" + line(laptop) + " laptop\n" + line(desktop) + " desktop\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh.d", "jan.kowalski.pub"), []byte(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	a := New(c.Auth)
	for _, k := range []ssh.Signer{laptop, desktop} {
		id, err := a.Resolve(k.PublicKey(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if id.Name != "jan.kowalski" || id.Type != "key" || id.Fingerprint != ssh.FingerprintSHA256(k.PublicKey()) {
			t.Fatalf("%+v", id)
		}
		if !Allowed(id, c.Endpoint["backup"].Allow) {
			t.Fatal("not allowed")
		}
	}
	if _, err := a.Resolve(stranger.PublicKey(), time.Now()); err == nil {
		t.Fatal("unknown key resolved")
	}
}

// CAs of ssh.d/ca authenticate certificates of their type only, with every
// key of a rotation, and take revocations from a keyless auth.ca entry.
func TestKeyDCA(t *testing.T) {
	hostOld, hostNew, userCA := signer(t), signer(t), signer(t)
	line := func(s ssh.Signer) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) }
	dir := t.TempDir()
	cfg := "listen:\n  main: {addr: 127.0.0.1:8080}\n" +
		"auth:\n  ca:\n    - {name: hosts, revoked: {key_ids: [old.host], serials: [13]}}\n" +
		"endpoint:\n  backup: {listen: main, endpoint: /backup, path: /queue/backup, allow: [\"hosts:*\", \"people:*\"]}\n"
	files := map[string]string{
		"config.yaml":              cfg,
		"ssh.d/ca/host/hosts.pub":  "# CA/SSH rotation\n" + line(hostOld) + " 2025\n" + line(hostNew) + " 2026\n",
		"ssh.d/ca/user/people.pub": line(userCA) + "\n",
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := config.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	a := New(c.Auth)
	now := time.Now()
	for _, tc := range []struct {
		ca     ssh.Signer
		typ    uint32
		wantCA string
	}{{hostOld, ssh.HostCert, "hosts"}, {hostNew, ssh.HostCert, "hosts"}, {userCA, ssh.UserCert, "people"}} {
		id, err := a.Resolve(cert(t, tc.ca, tc.typ, "ping.example", 5, nil, ssh.CertTimeInfinity), now)
		if err != nil {
			t.Fatal(err)
		}
		if id.Type != "certificate" || id.CA != tc.wantCA || id.Name != tc.wantCA+":ping.example" || !Allowed(id, c.Endpoint["backup"].Allow) {
			t.Fatalf("%+v", id)
		}
	}
	bad := map[string]*ssh.Certificate{
		"user cert of host CA": cert(t, hostNew, ssh.UserCert, "ping.example", 5, nil, ssh.CertTimeInfinity),
		"host cert of user CA": cert(t, userCA, ssh.HostCert, "ping.example", 5, nil, ssh.CertTimeInfinity),
		"revoked key id":       cert(t, hostOld, ssh.HostCert, "old.host", 5, nil, ssh.CertTimeInfinity),
		"revoked serial":       cert(t, hostNew, ssh.HostCert, "ping.example", 13, nil, ssh.CertTimeInfinity),
		"unknown CA":           cert(t, signer(t), ssh.HostCert, "ping.example", 5, nil, ssh.CertTimeInfinity),
	}
	for name, crt := range bad {
		if id, err := a.Resolve(crt, now); err == nil {
			t.Errorf("%s: resolved %+v", name, id)
		}
	}
}
