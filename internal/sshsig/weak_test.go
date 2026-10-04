package sshsig

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func rsaSigner(t *testing.T, bits int) ssh.Signer {
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

// signAs signs message with the format given, as an older client would.
func signAs(t *testing.T, s ssh.Signer, format string, message []byte) *Signature {
	t.Helper()
	var sig *ssh.Signature
	var err error
	if format == "" {
		sig, err = s.Sign(rand.Reader, signedData("ns@v1", message))
	} else {
		sig, err = s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, signedData("ns@v1", message), format)
	}
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBlob((&Signature{Key: s.PublicKey(), Namespace: "ns@v1", Sig: sig}).Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestVerifyRefusesSHA1(t *testing.T) {
	s := rsaSigner(t, 2048)
	m := []byte("m")
	if err := signAs(t, s, ssh.KeyAlgoRSA, m).Verify("ns@v1", m); err == nil || !strings.Contains(err.Error(), "signature format ssh-rsa (SHA-1) is not accepted") {
		t.Fatalf("ssh-rsa: %v", err)
	}
	for _, f := range []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512} {
		if err := signAs(t, s, f, m).Verify("ns@v1", m); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func TestVerifyRefusesWeakKeys(t *testing.T) {
	m := []byte("m")
	err := signAs(t, rsaSigner(t, 1024), ssh.KeyAlgoRSASHA512, m).Verify("ns@v1", m)
	if err == nil || !strings.Contains(err.Error(), "RSA key of 1024 bits, at least 2048 required") {
		t.Fatalf("rsa 1024: %v", err)
	}
	var priv dsa.PrivateKey
	if err := dsa.GenerateParameters(&priv.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	if err := dsa.GenerateKey(&priv, rand.Reader); err != nil {
		t.Fatal(err)
	}
	ds, err := ssh.NewSignerFromKey(&priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckKey(ds.PublicKey()); err == nil || err.Error() != "ssh-dss keys are not accepted" {
		t.Fatalf("dsa key: %v", err)
	}
	if err := signAs(t, ds, "", m).Verify("ns@v1", m); err == nil {
		t.Fatal("dsa signature verified")
	}
	// A certificate is judged by its certified key.
	c := &ssh.Certificate{Key: rsaSigner(t, 1024).PublicKey(), CertType: ssh.UserCert, KeyId: "weak", ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, ed25519Signer(t)); err != nil {
		t.Fatal(err)
	}
	if err := CheckKey(c); err == nil {
		t.Fatal("certificate of a 1024-bit key accepted")
	}
}
