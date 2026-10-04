package sshsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func ed25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	s := ed25519Signer(t)
	msg := []byte("hello")
	sig, err := Sign(s, "ns@v1", msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBlob(sig.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify("ns@v1", msg); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := got.Verify("other@v1", msg); err == nil {
		t.Fatal("wrong namespace verified")
	}
	if err := got.Verify("ns@v1", []byte("hellO")); err == nil {
		t.Fatal("tampered message verified")
	}
	armored, err := Parse(sig.Armor())
	if err != nil {
		t.Fatal(err)
	}
	if err := armored.Verify("ns@v1", msg); err != nil {
		t.Fatalf("armored verify: %v", err)
	}
}

func TestRSAUsesSHA512(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(s, "ns@v1", []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if sig.Sig.Format != ssh.KeyAlgoRSASHA512 {
		t.Fatalf("format %q", sig.Sig.Format)
	}
	if err := sig.Verify("ns@v1", []byte("m")); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateSigner(t *testing.T) {
	ca := ed25519Signer(t)
	host := ed25519Signer(t)
	cert := &ssh.Certificate{
		Key:         host.PublicKey(),
		CertType:    ssh.HostCert,
		KeyId:       "h1",
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(cs, "ns@v1", []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBlob(sig.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	c, ok := got.Key.(*ssh.Certificate)
	if !ok {
		t.Fatalf("embedded key is %T, want certificate", got.Key)
	}
	if c.KeyId != "h1" {
		t.Fatalf("key id %q", c.KeyId)
	}
	if err := got.Verify("ns@v1", []byte("m")); err != nil {
		t.Fatal(err)
	}
}

// ssh-keygen must accept what we produce.
func TestSSHKeygenInterop(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not found")
	}
	s := ed25519Signer(t)
	dir := t.TempDir()
	msg := []byte("interop")
	sig, err := Sign(s, "ns@v1", msg)
	if err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "msg.sig")
	allowed := filepath.Join(dir, "allowed")
	if err := os.WriteFile(sigPath, sig.Armor(), 0o600); err != nil {
		t.Fatal(err)
	}
	line := "me " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + "\n"
	if err := os.WriteFile(allowed, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(keygen, "-Y", "verify", "-f", allowed, "-I", "me", "-n", "ns@v1", "-s", sigPath)
	cmd.Stdin = strings.NewReader(string(msg))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen verify: %v\n%s", err, out)
	}
}
