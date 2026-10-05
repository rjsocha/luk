package channel

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyRoundTrip(t *testing.T) {
	k, err := GenerateKey()
	if err != nil || len(k.Private) != 32 || len(k.Public) != 32 {
		t.Fatalf("generate: %v", err)
	}
	p := filepath.Join(t.TempDir(), "identity.key")
	if err := WriteKey(p, k); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode: %v %v", fi.Mode(), err)
	}
	got, err := LoadKey(p)
	if err != nil || !bytes.Equal(got.Private, k.Private) || !bytes.Equal(got.Public, k.Public) {
		t.Fatalf("load: %v", err)
	}
	if !strings.HasPrefix(string(k.Marshal()), "-----BEGIN LUK IDENTITY KEY-----\n") {
		t.Fatalf("armor %q", k.Marshal())
	}

	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(p); err == nil || !strings.Contains(err.Error(), "0644") {
		t.Fatalf("0644 accepted: %v", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		strings.Replace(string(k.Marshal()), "BEGIN LUK", "BEGIN LUX", 1),
		strings.Replace(string(k.Marshal()), "-----END LUK IDENTITY KEY-----\n", "", 1),
		"-----BEGIN LUK IDENTITY KEY-----\nAAAA\n-----END LUK IDENTITY KEY-----\n",
		"-----BEGIN LUK IDENTITY KEY-----\n!!!!\n-----END LUK IDENTITY KEY-----\n",
	} {
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKey(p); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestFormatPin(t *testing.T) {
	k, _ := GenerateKey()
	if s, err := FormatPin(k.Public, "words"); err != nil || s != Words(k.Public) {
		t.Fatalf("words: %q %v", s, err)
	}
	if s, err := FormatPin(k.Public, "key"); err != nil || s != KeyString(k.Public) {
		t.Fatalf("key: %q %v", s, err)
	}
	if _, err := FormatPin(k.Public, "hex"); err == nil {
		t.Fatal("hex accepted")
	}
}
