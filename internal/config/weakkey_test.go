package config

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func weakLines(t *testing.T) map[string]string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rpub, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var d dsa.PrivateKey
	if err := dsa.GenerateParameters(&d.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	if err := dsa.GenerateKey(&d, rand.Reader); err != nil {
		t.Fatal(err)
	}
	dpub, err := ssh.NewPublicKey(&d.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	line := func(p ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p))) }
	return map[string]string{
		"RSA key of 1024 bits, at least 2048 required": line(rpub),
		"ssh-dss keys are not accepted":                line(dpub),
	}
}

// TestWeakKeys refuses DSA and short RSA keys as identities and as CA
// keys, inline and in ssh.d.
func TestWeakKeys(t *testing.T) {
	for want, line := range weakLines(t) {
		inline := strings.Replace(good, "  ca:\n", "    - name: weak\n      key: \""+line+"\"\n  ca:\n", 1)
		if _, err := Parse([]byte(inline)); err == nil || !strings.Contains(err.Error(), "auth.keys weak: "+want) {
			t.Errorf("inline key: %v", err)
		}
		ca := strings.Replace(good, "  ca:\n", "  ca:\n    - name: weakca\n      type: user\n      key: \""+line+"\"\n", 1)
		if _, err := Parse([]byte(ca)); err == nil || !strings.Contains(err.Error(), "auth.ca weakca: "+want) {
			t.Errorf("inline ca: %v", err)
		}
		_, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "ssh.d/weak.pub": s(line + "\n")})
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "auth.keys weak: "+want) {
			t.Errorf("ssh.d key: %v", err)
		}
		_, p = writeTree(t, map[string]*string{"config.yaml": s(baseMain), "ssh.d/ca/user/weakca.pub": s(line + "\n")})
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "auth.ca weakca: "+want) {
			t.Errorf("ssh.d ca: %v", err)
		}
	}
}
