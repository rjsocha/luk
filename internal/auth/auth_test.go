package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/config"
	"luk/internal/wire"
)

func signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cert(t *testing.T, ca ssh.Signer, typ uint32, keyID string, serial uint64, principals []string, before uint64) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{
		Key: signer(t).PublicKey(), CertType: typ, KeyId: keyID, Serial: serial,
		ValidPrincipals: principals, ValidBefore: before,
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func setup(t *testing.T) (*Authenticator, ssh.Signer, ssh.Signer, ssh.Signer) {
	user := signer(t)
	hostCA := signer(t)
	userCA := signer(t)
	a := config.Auth{
		Keys: []config.Key{{Name: "robert.socha", Parsed: []ssh.PublicKey{user.PublicKey()}}},
		CA: []config.CA{
			{Name: "hosts", Type: "host", Parsed: []ssh.PublicKey{hostCA.PublicKey()}, Revoked: config.Revoked{KeyIDs: []string{"gone"}, Serials: []uint64{13}}},
			{Name: "people", Type: "user", Parsed: []ssh.PublicKey{userCA.PublicKey()}},
		},
	}
	return New(a), user, hostCA, userCA
}

func TestResolveKey(t *testing.T) {
	a, user, _, _ := setup(t)
	id, err := a.Resolve(user.PublicKey(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "robert.socha" || id.Type != "key" || !strings.HasPrefix(id.Fingerprint, "SHA256:") {
		t.Fatalf("%+v", id)
	}
	if _, err := a.Resolve(signer(t).PublicKey(), time.Now()); err == nil {
		t.Fatal("unknown key resolved")
	}
}

func TestResolveCert(t *testing.T) {
	a, _, hostCA, userCA := setup(t)
	now := time.Now()
	c := cert(t, hostCA, ssh.HostCert, "ping.example", 5, nil, ssh.CertTimeInfinity)
	id, err := a.Resolve(c, now)
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "hosts:ping.example" || id.CA != "hosts" || id.KeyID != "ping.example" || id.Serial != 5 || id.Type != "certificate" {
		t.Fatalf("%+v", id)
	}

	withP := cert(t, hostCA, ssh.HostCert, "db1", 6, []string{"db1.example.net"}, ssh.CertTimeInfinity)
	if id, err := a.Resolve(withP, now); err != nil || id.Principals[0] != "db1.example.net" {
		t.Fatalf("principals: %v %+v", err, id)
	}

	bad := map[string]*ssh.Certificate{
		"revoked key id":       cert(t, hostCA, ssh.HostCert, "gone", 1, nil, ssh.CertTimeInfinity),
		"revoked serial":       cert(t, hostCA, ssh.HostCert, "x", 13, nil, ssh.CertTimeInfinity),
		"expired":              cert(t, hostCA, ssh.HostCert, "x", 1, nil, uint64(now.Add(-time.Hour).Unix())),
		"user cert of host CA": cert(t, hostCA, ssh.UserCert, "x", 1, nil, ssh.CertTimeInfinity),
		"host cert of user CA": cert(t, userCA, ssh.HostCert, "x", 1, nil, ssh.CertTimeInfinity),
		"unknown CA":           cert(t, signer(t), ssh.HostCert, "x", 1, nil, ssh.CertTimeInfinity),
	}
	for name, c := range bad {
		if _, err := a.Resolve(c, now); err == nil {
			t.Errorf("%s: resolved", name)
		}
	}
	if id, err := a.Resolve(cert(t, userCA, ssh.UserCert, "robert", 2, []string{"robert"}, ssh.CertTimeInfinity), now); err != nil || id.Name != "people:robert" {
		t.Fatalf("user cert: %v %+v", err, id)
	}
}

func TestAllowed(t *testing.T) {
	key := &wire.Identity{Name: "robert.socha", Type: "key"}
	bare := &wire.Identity{Name: "hosts:ping.example", Type: "certificate", CA: "hosts", KeyID: "ping.example"}
	prin := &wire.Identity{Name: "hosts:db1", Type: "certificate", CA: "hosts", KeyID: "db1", Principals: []string{"db1.example.net"}}
	cases := []struct {
		id    *wire.Identity
		allow []string
		ok    bool
	}{
		{key, []string{"robert.socha"}, true},
		{key, []string{"hosts:*"}, false},
		{bare, []string{"hosts:*"}, true},
		{bare, []string{"hosts:*.example.net"}, false},
		{bare, []string{"people:*"}, false},
		{prin, []string{"hosts:*.example.net"}, true},
		{prin, []string{"hosts:*.example.com"}, false},
		{bare, []string{"ping.example"}, false},
		{key, []string{"*"}, true},
		{bare, []string{"*"}, true},
		{prin, []string{"robert.socha", "*"}, true},
		{key, nil, false},
		// Key ID globs, for certificates without principals.
		{bare, []string{"hosts#ping.*"}, true},
		{bare, []string{"hosts#*"}, true},
		{bare, []string{"hosts#db*"}, false},
		{prin, []string{"hosts#db1"}, true},
		{prin, []string{"hosts#db1.example.net"}, false},
		{bare, []string{"people#ping.*"}, false},
		{key, []string{"hosts#*"}, false},
	}
	for i, c := range cases {
		if got := Allowed(c.id, c.allow); got != c.ok {
			t.Errorf("case %d: %v", i, got)
		}
	}
}

func TestNonceCache(t *testing.T) {
	c := NewNonceCache(time.Minute)
	now := time.Now()
	if !c.Check("a", now) {
		t.Fatal("fresh nonce refused")
	}
	if c.Check("a", now.Add(30*time.Second)) {
		t.Fatal("replay accepted")
	}
	if !c.Check("a", now.Add(2*time.Minute)) {
		t.Fatal("expired nonce still remembered")
	}
}

func TestNonceCacheSweep(t *testing.T) {
	c := NewNonceCache(time.Minute)
	now := time.Now()
	c.Check("a", now)
	c.Check("b", now)
	if !c.Check("c", now.Add(2*time.Minute)) {
		t.Fatal("fresh nonce refused")
	}
	if len(c.seen) != 1 {
		t.Fatalf("expired entries not swept: %d", len(c.seen))
	}
}

func TestResolveCertSameKeyTwoCAs(t *testing.T) {
	ca := signer(t)
	a := New(config.Auth{CA: []config.CA{
		{Name: "hosts", Type: "host", Parsed: []ssh.PublicKey{ca.PublicKey()}},
		{Name: "people", Type: "user", Parsed: []ssh.PublicKey{ca.PublicKey()}},
	}})
	now := time.Now()
	id, err := a.Resolve(cert(t, ca, ssh.UserCert, "bob", 1, []string{"bob"}, uint64(now.Add(time.Hour).Unix())), now)
	if err != nil || id.CA != "people" {
		t.Fatalf("%+v %v", id, err)
	}
	id, err = a.Resolve(cert(t, ca, ssh.HostCert, "h", 2, []string{"h"}, uint64(now.Add(time.Hour).Unix())), now)
	if err != nil || id.CA != "hosts" {
		t.Fatalf("%+v %v", id, err)
	}
}

func TestResolveCertTypeMismatch(t *testing.T) {
	a, _, hostCA, _ := setup(t)
	now := time.Now()
	_, err := a.Resolve(cert(t, hostCA, ssh.UserCert, "x", 1, nil, uint64(now.Add(time.Hour).Unix())), now)
	if err == nil || !strings.Contains(err.Error(), "not a host certificate") {
		t.Fatalf("%v", err)
	}
}

func TestNonceCacheExtend(t *testing.T) {
	c := NewNonceCache(time.Minute)
	t0 := time.Now()
	if !c.Check("n", t0) {
		t.Fatal("first use rejected")
	}
	c.Extend(30 * time.Second)
	c.Extend(2 * time.Minute)
	if c.Check("n", t0.Add(90*time.Second)) {
		t.Fatal("replay accepted within the extended ttl")
	}
}

// A persisted cache refuses after a restart the nonces seen before it,
// drops the expired ones and skips a torn last line.
func TestNonceCachePersist(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Unix(1_790_000_000, 0)
	c := NewNonceCache(2 * time.Minute)
	if err := c.Persist(dir, t0, func(err error) { t.Error(err) }); err != nil {
		t.Fatal(err)
	}
	old, kept := wire.NewNonce(), wire.NewNonce()
	if !c.Check(old, t0) || !c.Check(kept, t0.Add(90*time.Second)) {
		t.Fatal("fresh nonce refused")
	}
	p := filepath.Join(dir, NonceFile)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("garbage line\n" + wire.NewNonce() + " 17")
	f.Close()

	// The restart: a new cache on the same directory, after old expired.
	now := t0.Add(150 * time.Second)
	r := NewNonceCache(2 * time.Minute)
	if err := r.Persist(dir, now, func(err error) { t.Error(err) }); err != nil {
		t.Fatal(err)
	}
	if len(r.seen) != 1 {
		t.Fatalf("loaded %v", r.seen)
	}
	if r.Check(kept, now) {
		t.Fatal("replay accepted after a restart")
	}
	if !r.Check(old, now) {
		t.Fatal("expired nonce still refused")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"); len(lines) != 2 || strings.Contains(string(b), "garbage") {
		t.Fatalf("file not compacted:\n%s", b)
	}
	if err := NewNonceCache(time.Minute).Persist(filepath.Join(dir, "missing"), now, nil); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing dir: %v", err)
	}
}

// The sweep rewrites the file with the live nonces only.
func TestNonceCachePersistCompacts(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Unix(1_790_000_000, 0)
	c := NewNonceCache(time.Minute)
	if err := c.Persist(dir, t0, func(err error) { t.Error(err) }); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		c.Check(wire.NewNonce(), t0)
	}
	c.Check(wire.NewNonce(), t0.Add(2*time.Minute))
	b, err := os.ReadFile(filepath.Join(dir, NonceFile))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n != 1 {
		t.Fatalf("%d lines:\n%s", n, b)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("dir holds %v", ents)
	}
}
