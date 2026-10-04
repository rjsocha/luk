package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/config"
)

// sha1Signer hides AlgorithmSigner, so an RSA key signs ssh-rsa (SHA-1).
type sha1Signer struct{ s ssh.Signer }

func (s sha1Signer) PublicKey() ssh.PublicKey { return s.s.PublicKey() }
func (s sha1Signer) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return s.s.Sign(r, data)
}

func rsaKey(t *testing.T, bits int) ssh.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestResolveCertWeak refuses a certificate signed in the ssh-rsa (SHA-1)
// format and one certifying a short RSA key; rsa-sha2-512 by the same CA
// gives the identity.
func TestResolveCertWeak(t *testing.T) {
	ca := rsaKey(t, 2048)
	a := New(config.Auth{CA: []config.CA{{Name: "people", Type: "user", Parsed: []ssh.PublicKey{ca.PublicKey()}}}})
	mk := func(key ssh.PublicKey, s ssh.Signer) *ssh.Certificate {
		c := &ssh.Certificate{Key: key, CertType: ssh.UserCert, KeyId: "u", ValidBefore: ssh.CertTimeInfinity}
		if err := c.SignCert(rand.Reader, s); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := mk(signer(t).PublicKey(), sha1Signer{ca})
	if c.Signature.Format != ssh.KeyAlgoRSA {
		t.Fatalf("format %s", c.Signature.Format)
	}
	if _, err := a.Resolve(c, time.Now()); err == nil || !strings.Contains(err.Error(), "signature format ssh-rsa (SHA-1) is not accepted") {
		t.Fatalf("ssh-rsa: %v", err)
	}
	if _, err := a.Resolve(mk(rsaKey(t, 1024).PublicKey(), ca), time.Now()); err == nil || !strings.Contains(err.Error(), "RSA key of 1024 bits") {
		t.Fatalf("weak certified key: %v", err)
	}
	if id, err := a.Resolve(mk(signer(t).PublicKey(), ca), time.Now()); err != nil || id.Name != "people:u" {
		t.Fatalf("rsa-sha2-512: %v %+v", err, id)
	}
}
