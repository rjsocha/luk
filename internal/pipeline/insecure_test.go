package pipeline

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"luk/internal/gpgkeys"
	"luk/internal/gpgkeys/gpgtest"
)

// passwords writes the password files into a password.d of the env.
func (g *gpgEnv) passwords(t *testing.T, pw map[string]string) string {
	t.Helper()
	dir := filepath.Join(g.root, "password.d")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for n, p := range pw {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(p+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	g.cfg.PasswordDir = dir
	return dir
}

type insecureMeta struct {
	encMeta
	Passwords []string `json:"passwords"`
}

// decryptPassword decrypts an OpenPGP message with a password only.
func decryptPassword(t *testing.T, msg []byte, password string) ([]byte, error) {
	t.Helper()
	tries := 0
	prompt := func([]openpgp.Key, bool) ([]byte, error) {
		if tries++; tries > 1 {
			return nil, errors.New("wrong password")
		}
		return []byte(password), nil
	}
	md, err := openpgp.ReadMessage(bytes.NewReader(msg), openpgp.EntityList{}, prompt, nil)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func TestEncryptSymmetricPasswords(t *testing.T) {
	k := gpgtest.New(t, "matt@example.com")
	g := newGPGEnv(t, `    steps:
      - encrypt:
          key: [matt@example.com]
          insecure:
            symmetric: [pw-a, pw-b]
      - store: a
`, map[string][]byte{"k.asc": gpgtest.Armored(t, k)}, nil)
	g.passwords(t, map[string]string{"pw-a": "first secret", "pw-b": "second secret"})
	g.run(t, "id1")
	if find(g.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", g.logs.records(t))
	}
	msg := g.raw(t, "a/file/robert.socha/f.txt.gpg")
	for _, pw := range []string{"first secret", "second secret"} {
		got, err := decryptPassword(t, msg, pw)
		if err != nil || string(got) != "data-id1" {
			t.Fatalf("password %q: %q %v", pw, got, err)
		}
	}
	if got, err := decryptPassword(t, msg, "first secret\n"); err == nil {
		t.Fatalf("decrypted with the newline kept: %q", got)
	}
	if got := string(gpgtest.Decrypt(t, msg, k)); got != "data-id1" {
		t.Fatalf("key decrypted %q", got)
	}
	var m insecureMeta
	if err := json.Unmarshal(g.sidecar(t, "a/.db/meta/robert.socha/f.txt.gpg.json").Meta, &m); err != nil {
		t.Fatal(err)
	}
	if m.Encryption != "gpg" || !slices.Equal(m.Recipients, []string{gpgkeys.Fingerprint(k)}) ||
		!slices.Equal(m.Passwords, []string{"pw-a", "pw-b"}) || m.Plain.Name != "f.txt" {
		t.Fatalf("meta %+v", m)
	}
}

func TestEncryptWithoutPasswordsHasNoPasswordMeta(t *testing.T) {
	k := gpgtest.New(t, "matt@example.com")
	g := newGPGEnv(t, "    steps:\n      - encrypt: {key: [matt@example.com]}\n      - store: a\n",
		map[string][]byte{"k.asc": gpgtest.Armored(t, k)}, nil)
	g.run(t, "id1")
	var m map[string]any
	if err := json.Unmarshal(g.sidecar(t, "a/.db/meta/robert.socha/f.txt.gpg.json").Meta, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["passwords"]; ok {
		t.Fatalf("meta %v", m)
	}
}

func TestEncryptMissingPassword(t *testing.T) {
	k := gpgtest.New(t, "matt@example.com")
	for name, step := range map[string]string{
		"symmetric": "{key: [matt@example.com], insecure: {symmetric: [gone]}}",
		"openssl":   "{key: [matt@example.com], insecure: {openssl: {key: gone, files: ['*']}}}",
	} {
		g := newGPGEnv(t, "    steps:\n      - encrypt: "+step+"\n      - store: a\n",
			map[string][]byte{"k.asc": gpgtest.Armored(t, k)}, nil)
		g.passwords(t, map[string]string{"empty": ""})
		g.run(t, "id1")
		r := find(g.logs.records(t), "pipeline failed", "p")
		if r == nil || !strings.Contains(fmt.Sprint(r["error"]), filepath.Join(g.cfg.PasswordDir, "gone")) {
			t.Fatalf("%s: logs %v", name, g.logs.records(t))
		}
		if entries, _ := os.ReadDir(filepath.Join(g.root, "a", "file", "robert.socha")); len(entries) > 0 {
			t.Fatalf("%s: stored %v", name, entries)
		}
	}
}

// opensslDecrypt reads the openssl enc -aes-256-cbc -pbkdf2 format.
func opensslDecrypt(t *testing.T, data []byte, password string) []byte {
	t.Helper()
	if len(data) < 32 || string(data[:8]) != "Salted__" || (len(data)-16)%16 != 0 {
		t.Fatalf("not the openssl format: %d bytes", len(data))
	}
	km, err := pbkdf2.Key(sha256.New, password, data[8:16], 10000, 48)
	if err != nil {
		t.Fatal(err)
	}
	b, err := aes.NewCipher(km[:32])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(data)-16)
	cipher.NewCBCDecrypter(b, km[32:]).CryptBlocks(out, data[16:])
	pad := int(out[len(out)-1])
	if pad < 1 || pad > 16 || !bytes.Equal(out[len(out)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		t.Fatalf("bad padding %d", pad)
	}
	return out[:len(out)-pad]
}

// opensslBinary decrypts data with the openssl binary, or skips.
func opensslBinary(t *testing.T, data []byte, password string) []byte {
	t.Helper()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl binary")
	}
	dir := t.TempDir()
	in, pw, out := filepath.Join(dir, "x.enc"), filepath.Join(dir, "pw"), filepath.Join(dir, "x")
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pw, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command(bin, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-in", in, "-out", out, "-pass", "file:"+pw).CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v\n%s", err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEncryptOpenSSL(t *testing.T) {
	s1 := script(t, `set -e
printf dump > "$LUK_OUT/db-latest.sql.zst"
printf '{"kind": "dump"}' > "$LUK_OUT/db-latest.sql.zst.meta.json"
printf other > "$LUK_OUT/db-2026.sql.zst"
`)
	k := gpgtest.New(t, "matt@example.com")
	g := newGPGEnv(t, fmt.Sprintf(`    steps:
      - run: %s
      - encrypt:
          key: [matt@example.com]
          insecure:
            symmetric: [pw-a]
            openssl:
              key: pw-b
              files: ['*-latest.sql.zst']
      - store: a
`, s1), map[string][]byte{"k.asc": gpgtest.Armored(t, k)}, nil)
	g.passwords(t, map[string]string{"pw-a": "first secret", "pw-b": "second secret"})
	g.run(t, "id1")
	if find(g.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", g.logs.records(t))
	}
	dir := filepath.Join(g.root, "a", "file", "robert.socha")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"db-2026.sql.zst.gpg", "db-latest.sql.zst.enc"}) {
		t.Fatalf("stored %v", names)
	}
	enc := g.raw(t, "a/file/robert.socha/db-latest.sql.zst.enc")
	if got := string(opensslDecrypt(t, enc, "second secret")); got != "dump" {
		t.Fatalf("openssl decrypted %q", got)
	}
	gpgMsg := g.raw(t, "a/file/robert.socha/db-2026.sql.zst.gpg")
	if got, err := decryptPassword(t, gpgMsg, "first secret"); err != nil || string(got) != "other" {
		t.Fatalf("gpg: %q %v", got, err)
	}

	sc := g.sidecar(t, "a/.db/meta/robert.socha/db-latest.sql.zst.enc.json")
	if sc.Produced != "db-latest.sql.zst.enc" || sc.Size != int64(len(enc)) || sc.SHA256 != sha(string(enc)) {
		t.Fatalf("sidecar %+v", sc)
	}
	var m insecureMeta
	if err := json.Unmarshal(sc.Meta, &m); err != nil {
		t.Fatal(err)
	}
	if m.Kind != "dump" || m.Encryption != "openssl" || m.Recipients != nil || !slices.Equal(m.Passwords, []string{"pw-b"}) ||
		m.Plain.Name != "db-latest.sql.zst" || m.Plain.Size != 4 || m.Plain.SHA256 != sha("dump") {
		t.Fatalf("meta %s", sc.Meta)
	}
	if err := json.Unmarshal(g.sidecar(t, "a/.db/meta/robert.socha/db-2026.sql.zst.gpg.json").Meta, &m); err != nil {
		t.Fatal(err)
	}
	if m.Encryption != "gpg" || !slices.Equal(m.Passwords, []string{"pw-a"}) || len(m.Recipients) != 1 {
		t.Fatalf("gpg meta %+v", m)
	}

	t.Run("openssl binary", func(t *testing.T) {
		if got := string(opensslBinary(t, enc, "second secret")); got != "dump" {
			t.Fatalf("openssl binary decrypted %q", got)
		}
	})
}

// TestEncryptOpenSSLOnlyNeedsNoRecipient: a set that goes to the openssl
// format alone does not look up the recipients.
func TestEncryptOpenSSLOnlyNeedsNoRecipient(t *testing.T) {
	g := newGPGEnv(t, "    steps:\n      - encrypt: {wkd: [nobody@example.net], insecure: {openssl: {key: pw, files: ['*.txt']}}}\n      - store: a\n", nil, nil)
	g.passwords(t, map[string]string{"pw": "secret"})
	g.run(t, "id1")
	if find(g.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", g.logs.records(t))
	}
	if got := string(opensslDecrypt(t, g.raw(t, "a/file/robert.socha/f.txt.enc"), "secret")); got != "data-id1" {
		t.Fatalf("decrypted %q", got)
	}
}

// opensslVector is openssl enc -aes-256-cbc -pbkdf2 -S 0001020304050607
// -pass file:pw (pw holding "vector password") of the 43 bytes
// "luk openssl test vector, not block aligned.", by OpenSSL 3.5.7; it
// prints no header with -S, so the header is prepended here.
const opensslVector = "53616c7465645f5f0001020304050607" +
	"b0e373caba07fbc1ad771d287c74f3957c9609b2bb0f0dc798a7323c4f6c4824187618200ab98248fa1269f03c0c374b"

func TestOpenSSLVector(t *testing.T) {
	old := opensslSalt
	t.Cleanup(func() { opensslSalt = old })
	opensslSalt = func(b []byte) error {
		for i := range b {
			b[i] = byte(i)
		}
		return nil
	}
	var buf bytes.Buffer
	w, err := newOpenSSLWriter(&buf, []byte("vector password"))
	if err != nil {
		t.Fatal(err)
	}
	plain := "luk openssl test vector, not block aligned."
	for _, part := range []string{plain[:5], plain[5:21], plain[21:]} {
		if _, err := io.WriteString(w, part); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(buf.Bytes()); got != opensslVector {
		t.Fatalf("got  %s\nwant %s", got, opensslVector)
	}
}

func TestOpenSSLWriterSizes(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 17, 32, 100000} {
		plain := bytes.Repeat([]byte{'x'}, n)
		var buf bytes.Buffer
		w, err := newOpenSSLWriter(&buf, []byte("pw"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, bytes.NewReader(plain)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if want := 16 + (n/16+1)*16; buf.Len() != want {
			t.Fatalf("%d: %d bytes, want %d", n, buf.Len(), want)
		}
		if got := opensslDecrypt(t, buf.Bytes(), "pw"); !bytes.Equal(got, plain) {
			t.Fatalf("%d: round trip", n)
		}
		t.Run(fmt.Sprintf("openssl binary %d", n), func(t *testing.T) {
			if got := opensslBinary(t, buf.Bytes(), "pw"); !bytes.Equal(got, plain) {
				t.Fatalf("%d: openssl binary", n)
			}
		})
	}
}
