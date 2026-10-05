package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestEncryptInsecure(t *testing.T) {
	c, err := Parse([]byte(encryptConfig("", "      - encrypt:\n          wkd: [a@b.example]\n"+
		"          insecure:\n            symmetric: [client-a, other.b]\n"+
		"            openssl:\n              key: client-a\n              files: ['*-latest.sql.zst', 'x?.tar']\n")))
	if err != nil {
		t.Fatal(err)
	}
	in := c.Pipeline["drop"].Steps[0].Encrypt.Insecure
	if in == nil || strings.Join(in.Symmetric, ",") != "client-a,other.b" || in.OpenSSL == nil ||
		in.OpenSSL.Key != "client-a" || strings.Join(in.OpenSSL.Files, ",") != "*-latest.sql.zst,x?.tar" {
		t.Fatalf("insecure %+v", in)
	}
	if got := c.PasswordNames(); !slices.Equal(got, []string{"client-a", "other.b"}) {
		t.Fatalf("names %v", got)
	}
	if m := in.OpenSSL.Match("db-latest.sql.zst"); !m {
		t.Fatal("no match")
	}
	if m := in.OpenSSL.Match("db.sql.zst"); m {
		t.Fatal("match")
	}

	c, err = Parse([]byte(encryptConfig("", "      - encrypt: {wkd: [a@b.example], insecure: {openssl: {key: x, files: [a]}}}\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.PasswordNames(); !slices.Equal(got, []string{"x"}) {
		t.Fatalf("names %v", got)
	}
}

func TestEncryptInsecureValidation(t *testing.T) {
	cases := map[string]string{
		"empty insecure":        "      - encrypt: {wkd: [a@b.example], insecure: {}}\n",
		"no recipient":          "      - encrypt: {insecure: {symmetric: [a]}}\n",
		"bad symmetric name":    "      - encrypt: {wkd: [a@b.example], insecure: {symmetric: [../a]}}\n",
		"upper symmetric name":  "      - encrypt: {wkd: [a@b.example], insecure: {symmetric: [A]}}\n",
		"duplicate symmetric":   "      - encrypt: {wkd: [a@b.example], insecure: {symmetric: [a, a]}}\n",
		"openssl without key":   "      - encrypt: {wkd: [a@b.example], insecure: {openssl: {files: [a]}}}\n",
		"openssl bad key":       "      - encrypt: {wkd: [a@b.example], insecure: {openssl: {key: .a, files: [a]}}}\n",
		"openssl without files": "      - encrypt: {wkd: [a@b.example], insecure: {openssl: {key: a}}}\n",
		"openssl empty files":   "      - encrypt: {wkd: [a@b.example], insecure: {openssl: {key: a, files: []}}}\n",
		"openssl bad glob":      "      - encrypt: {wkd: [a@b.example], insecure: {openssl: {key: a, files: ['[a']}}}\n",
		"openssl empty glob":    "      - encrypt: {wkd: [a@b.example], insecure: {openssl: {key: a, files: ['']}}}\n",
		"openssl unknown key":   "      - encrypt: {wkd: [a@b.example], insecure: {openssl: {key: a, files: [a], bogus: 1}}}\n",
		"unknown insecure key":  "      - encrypt: {wkd: [a@b.example], insecure: {bogus: 1}}\n",
	}
	for name, step := range cases {
		if _, err := Parse([]byte(encryptConfig("", step))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPasswordDirNextToMainFile(t *testing.T) {
	main := baseMain
	dir, p := writeTree(t, map[string]*string{"config.yaml": &main})
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "password.d"); c.PasswordDir != want {
		t.Fatalf("%q", c.PasswordDir)
	}
}

func TestReadPassword(t *testing.T) {
	dir := t.TempDir()
	for n, body := range map[string]string{
		"plain":   "secret",
		"newline": "secret\n",
		"two":     "secret\n\n",
		"crlf":    " sec ret\r\n",
		"crlf2":   "a\r\nb\r\n",
		"empty":   "",
		"only":    "\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	for n, want := range map[string]string{"plain": "secret", "newline": "secret"} {
		got, err := ReadPassword(dir, n)
		if err != nil || string(got) != want {
			t.Errorf("%s: %q %v", n, got, err)
		}
	}
	for _, n := range []string{"empty", "only", "missing", "two", "crlf", "crlf2"} {
		if _, err := ReadPassword(dir, n); err == nil || !strings.Contains(err.Error(), filepath.Join(dir, n)) {
			t.Errorf("%s: %v", n, err)
		}
	}
	if _, err := ReadPassword("", "plain"); err == nil {
		t.Error("no directory accepted")
	}
	big := strings.Repeat("x", maxPassword+1)
	if err := os.WriteFile(filepath.Join(dir, "big"), []byte(big), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPassword(dir, "big"); err == nil {
		t.Error("oversized password accepted")
	}
}

func TestReadOpenSSLPassword(t *testing.T) {
	dir := t.TempDir()
	for n, l := range map[string]int{"ok": maxOpenSSLPassword, "long": maxOpenSSLPassword + 1} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(strings.Repeat("x", l)+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReadOpenSSLPassword(dir, "ok"); err != nil {
		t.Error(err)
	}
	_, err := ReadOpenSSLPassword(dir, "long")
	if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, "long")) || !strings.Contains(err.Error(), "1023") {
		t.Errorf("long: %v", err)
	}
	if _, err := ReadPassword(dir, "long"); err != nil {
		t.Errorf("gpg password limit: %v", err)
	}
}
