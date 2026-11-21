package config

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
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
	line := func(p ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p))) }
	return map[string]string{
		"RSA key of 1024 bits, at least 2048 required": line(rpub),
		`ssh: unknown key algorithm: "ssh-dss"`:        dssLine(t),
	}
}

// dssLine is an ssh-dss authorized_keys line, marshalled by hand: x/crypto
// no longer builds a DSA key, and its parser refuses the algorithm. luk
// refuses the type on its own as well, in sshsig.CheckKey, which no parsed
// key can reach any more.
func dssLine(t *testing.T) string {
	t.Helper()
	var d dsa.PrivateKey
	if err := dsa.GenerateParameters(&d.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	if err := dsa.GenerateKey(&d, rand.Reader); err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Name       string
		P, Q, G, Y *big.Int
	}{ssh.KeyAlgoDSA, d.P, d.Q, d.G, d.Y})
	return ssh.KeyAlgoDSA + " " + base64.StdEncoding.EncodeToString(blob)
}

// TestWeakKeys refuses DSA and short RSA keys as identities and as CA
// keys, inline and in ssh.d. The DSA line dies in the x/crypto parser,
// the RSA one in luk's own check; the message of both is reported with
// the name of the field it came from.
func TestWeakKeys(t *testing.T) {
	for want, line := range weakLines(t) {
		inline := strings.Replace(good, "  ca:\n", "    weak: \""+line+"\"\n  ca:\n", 1)
		if _, err := Parse([]byte(inline)); err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "auth.keys weak: ") {
			t.Errorf("inline key: %v", err)
		}
		ca := strings.Replace(good, "  ca:\n", "  ca:\n    weakca:\n      type: user\n      key: \""+line+"\"\n", 1)
		if _, err := Parse([]byte(ca)); err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "auth.ca weakca: ") {
			t.Errorf("inline ca: %v", err)
		}
		// A key of ssh.d dies in the parser before it gets a field
		// name, and is reported with its file and line instead.
		_, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "ssh.d/weak.pub": s(line + "\n")})
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "weak") {
			t.Errorf("ssh.d key: %v", err)
		}
		_, p = writeTree(t, map[string]*string{"config.yaml": s(baseMain), "ssh.d/ca/user/weakca.pub": s(line + "\n")})
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "weakca") {
			t.Errorf("ssh.d ca: %v", err)
		}
	}
}
