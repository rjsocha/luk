package tlsself

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAndPin(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "sub", "tls.crt"), filepath.Join(dir, "sub", "tls.key")
	pin, err := Generate(c, k, "lukd.vm", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pin, "sha256//") {
		t.Fatalf("pin %q", pin)
	}
	again, err := PinFile(c)
	if err != nil || again != pin {
		t.Fatalf("PinFile %q %v", again, err)
	}
	if _, err := tls.LoadX509KeyPair(c, k); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(c, k, "lukd.vm", ""); err == nil {
		t.Fatal("overwrote an existing certificate")
	}
}

func TestGenerateSamePath(t *testing.T) {
	dir := t.TempDir()
	for _, pair := range [][2]string{
		{filepath.Join(dir, "a"), filepath.Join(dir, "a")},
		{filepath.Join(dir, "a"), dir + "/./a"},
	} {
		if _, err := Generate(pair[0], pair[1], "lukd.vm", ""); err == nil {
			t.Errorf("%s %s: accepted", pair[0], pair[1])
		}
		if _, err := os.Stat(pair[0]); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s written: %v", pair[0], err)
		}
	}
}

func TestGenerateKeepsExistingKey(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(k, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(c, k, "lukd.vm", ""); err == nil {
		t.Fatal("overwrote an existing key")
	}
	if b, _ := os.ReadFile(k); string(b) != "old" {
		t.Fatalf("key changed: %q", b)
	}
	if _, err := os.Stat(c); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cert written: %v", err)
	}
}

func TestGenerateCertExistsRemovesNewKey(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(c, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(c, k, "lukd.vm", ""); err == nil {
		t.Fatal("overwrote an existing certificate")
	}
	if _, err := os.Stat(k); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key left behind: %v", err)
	}
}

func TestGenerateAlgorithms(t *testing.T) {
	for algo, want := range map[string]x509.PublicKeyAlgorithm{
		"":        x509.Ed25519,
		Ed25519:   x509.Ed25519,
		ECDSAP256: x509.ECDSA,
	} {
		dir := t.TempDir()
		c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
		pin, err := Generate(c, k, "127.0.0.1", algo)
		if err != nil {
			t.Fatalf("%q: %v", algo, err)
		}
		pair, err := tls.LoadX509KeyPair(c, k)
		if err != nil {
			t.Fatalf("%q: %v", algo, err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if leaf.PublicKeyAlgorithm != want || Pin(leaf) != pin {
			t.Fatalf("%q: key %v pin %s", algo, leaf.PublicKeyAlgorithm, pin)
		}
		if leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.IPAddresses) != 1 {
			t.Fatalf("%q: usage %v %v %v", algo, leaf.KeyUsage, leaf.ExtKeyUsage, leaf.IPAddresses)
		}
		_, isEC := pair.PrivateKey.(*ecdsa.PrivateKey)
		_, isEd := pair.PrivateKey.(ed25519.PrivateKey)
		if isEC != (want == x509.ECDSA) || isEd != (want == x509.Ed25519) {
			t.Fatalf("%q: private key %T", algo, pair.PrivateKey)
		}
	}
}

func TestGenerateUnknownAlgorithm(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if _, err := Generate(c, k, "lukd.vm", "rsa"); err == nil {
		t.Fatal("accepted rsa")
	}
	if _, err := os.Stat(k); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key written: %v", err)
	}
}

func TestECDSAHandshakeBrowserSchemes(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if _, err := Generate(c, k, "lukd.vm", ECDSAP256); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- conn.(*tls.Conn).Handshake()
	}()
	cfg := &tls.Config{
		RootCAs:      pool,
		ServerName:   "lukd.vm",
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
