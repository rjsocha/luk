// Package ringtest makes GnuPG keyrings for tests.
package ringtest

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"luk/internal/gpgkeys"
	"luk/internal/gpgkeys/gpgtest"
)

type Entity = openpgp.Entity

// Home makes a GnuPG home holding the public keys of valid, with ultimate
// ownertrust, and of unknown, with none, and points GNUPGHOME at it. The
// test is skipped without gpg.
func Home(t testing.TB, valid, unknown []*Entity) string {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("no gpg in PATH")
	}
	home, err := os.MkdirTemp("", "luk-gnupg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", home)
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
		os.RemoveAll(home)
	})
	run := func(stdin []byte, args ...string) {
		t.Helper()
		cmd := exec.Command("gpg", append([]string{"--batch", "--no-tty", "--quiet"}, args...)...)
		cmd.Stdin = bytes.NewReader(stdin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("gpg %v: %v: %s", args, err, out)
		}
	}
	run(gpgtest.Public(t, append(append([]*Entity{}, valid...), unknown...)...), "--import")
	var trust bytes.Buffer
	for _, e := range valid {
		trust.WriteString(gpgkeys.Fingerprint(e) + ":6:\n")
	}
	run(trust.Bytes(), "--import-ownertrust")
	run(nil, "--check-trustdb")
	return home
}
