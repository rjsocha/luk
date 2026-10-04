package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func startAgent(t *testing.T) agent.Agent {
	t.Helper()
	dir := t.TempDir()
	l, err := net.Listen("unix", filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	kr := agent.NewKeyring()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				agent.ServeAgent(kr, c)
			}()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(dir, "agent.sock"))
	return kr
}

func TestUploadWithAgent(t *testing.T) {
	kr := startAgent(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: "agent key"}); err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	pubFile := filepath.Join(t.TempDir(), "id_ed25519.pub")
	if err := os.WriteFile(pubFile, ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	ts, _ := testServer(t, pub, false)
	for _, arg := range []string{"", pubFile} {
		s, err := LoadSigner(arg)
		if err != nil {
			t.Fatalf("%q: %v", arg, err)
		}
		o := fileOpts(t, ts.URL+"/backup", s, []byte("from the agent"))
		o.Meta.DryRun = true
		resp, err := Upload(context.Background(), o)
		if err != nil {
			t.Fatalf("%q: %v", arg, err)
		}
		if resp.Debug.Identity.Name != "robert.socha" {
			t.Fatalf("%q: %+v", arg, resp)
		}
	}
	otherFile := filepath.Join(t.TempDir(), "other.pub")
	if err := os.WriteFile(otherFile, ssh.MarshalAuthorizedKey(newSigner(t).PublicKey()), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(otherFile); err == nil || !strings.Contains(err.Error(), "not in the SSH agent") {
		t.Fatalf("key missing from the agent: %v", err)
	}
}

func addAgentKey(t *testing.T, kr agent.Agent) ssh.PublicKey {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := kr.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestLoadSignerFingerprint(t *testing.T) {
	kr := startAgent(t)
	addAgentKey(t, kr)
	second := addAgentKey(t, kr)
	fp := ssh.FingerprintSHA256(second)
	s, err := LoadSigner(fp)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(s.PublicKey()) != fp {
		t.Fatalf("got %s, want %s", ssh.FingerprintSHA256(s.PublicKey()), fp)
	}
	absent := ssh.FingerprintSHA256(newSigner(t).PublicKey())
	if _, err := LoadSigner(absent); err == nil || !strings.Contains(err.Error(), absent) || !strings.Contains(err.Error(), "not in the SSH agent") {
		t.Fatalf("absent fingerprint: %v", err)
	}
	if _, err := LoadSigner("SHA256:short"); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("malformed fingerprint: %v", err)
	}
}

func TestLoadSignerFingerprintNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	fp := ssh.FingerprintSHA256(newSigner(t).PublicKey())
	if _, err := LoadSigner(fp); err == nil || !strings.Contains(err.Error(), "agent") {
		t.Fatalf("%v", err)
	}
}

func TestFirstAgentSignerCountsKeys(t *testing.T) {
	kr := startAgent(t)
	first := addAgentKey(t, kr)
	addAgentKey(t, kr)
	addAgentKey(t, kr)
	s, n, err := FirstAgentSigner()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || !bytes.Equal(s.PublicKey().Marshal(), first.Marshal()) {
		t.Fatalf("n=%d key %s", n, ssh.FingerprintSHA256(s.PublicKey()))
	}
}

func TestValidateFingerprint(t *testing.T) {
	good := ssh.FingerprintSHA256(newSigner(t).PublicKey())
	if err := ValidateFingerprint(good); err != nil {
		t.Fatalf("%s: %v", good, err)
	}
	for _, bad := range []string{"SHA256:", "SHA256:abc", good + "=", good[:len(good)-1] + "!", "MD5:" + good[7:], good + "A"} {
		if err := ValidateFingerprint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
