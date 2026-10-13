package gpgring

import (
	"context"
	"strings"
	"testing"

	"luk/internal/gpgkeys"
	"luk/internal/gpgkeys/gpgtest"
	"luk/internal/gpgring/ringtest"
)

const (
	fprA = "7EC80CF896481018FFA9C82280A127F359F9A844"
	fprB = "1111111111111111111111111111111111111111"
)

// listing is one key of gpg --list-keys --with-colons: the validity of the
// key and of its user id, and the capabilities.
func listing(fpr, validity, caps, uid string) string {
	return "pub:" + validity + ":255:22:" + fpr[24:] + ":1624610951:1814400017::-:::" + caps + ":::::ed25519::1790667733:4:\n" +
		"fpr:::::::::" + fpr + ":\n" +
		"uid:" + validity + "::::1782975990::0EE297A38ECA8618C459956F8BC46B9BB0A76489::" + uid + ":::::::::1790667733:4 https\\x3a//openpgpkey.example.net:\n" +
		"sub:" + validity + ":4096:1:032945AFF1CDEBFC:1624644458:1814400003:::::e::::::23:\n" +
		"fpr:::::::::B1C01B67893E71A8435808CE032945AFF1CDEBFC:\n"
}

func TestParseColons(t *testing.T) {
	keys := parseColons([]byte("tru::1:1791797833:1801440080:3:1:5\n" +
		listing(fprA, "f", "cESCA", "Anna Test <Anna@Example.net>") +
		listing(fprB, "-", "cESC", "a\\x3ab <b@example.net>")))
	if len(keys) != 2 {
		t.Fatalf("keys %+v", keys)
	}
	a, b := keys[0], keys[1]
	if a.fingerprint != fprA || a.validity != "f" || a.caps != "cESCA" || len(a.uids) != 1 || a.uids[0] != (uid{"f", "anna@example.net"}) {
		t.Fatalf("first key %+v", a)
	}
	if b.fingerprint != fprB || b.validity != "-" || b.uids[0] != (uid{"-", "b@example.net"}) {
		t.Fatalf("second key %+v", b)
	}
}

func TestPick(t *testing.T) {
	for _, c := range []struct {
		name, list, who string
		want, err       string
	}{
		{"full", listing(fprA, "f", "cESCA", "A <a@example.net>"), "a@example.net", fprA, ""},
		{"ultimate", listing(fprA, "u", "cESCA", "A <a@example.net>"), "a@example.net", fprA, ""},
		{"fingerprint", listing(fprA, "f", "cESCA", "A <a@example.net>"), fprA, fprA, ""},
		{"unknown validity", listing(fprA, "-", "cESCA", "A <a@example.net>"), "a@example.net", "", fprA + ": validity unknown"},
		{"marginal", listing(fprA, "m", "cESCA", "A <a@example.net>"), "a@example.net", "", fprA + ": validity marginal"},
		{"revoked", listing(fprA, "r", "cSCA", "A <a@example.net>"), "a@example.net", "", fprA + ": validity revoked"},
		{"fingerprint not valid", listing(fprA, "q", "cESCA", "A <a@example.net>"), fprA, "", fprA + ": validity undefined"},
		{"disabled", listing(fprA, "f", "cESCAD", "A <a@example.net>"), "a@example.net", "", fprA + ": disabled"},
		{"no encryption key", listing(fprA, "f", "cSCA", "A <a@example.net>"), "a@example.net", "", fprA + ": no encryption key"},
		{"other address", listing(fprA, "f", "cESCA", "A <aa@example.net>"), "a@example.net", "", "no key of a@example.net"},
		{"none", "", "a@example.net", "", "no key of a@example.net"},
		{"one valid of two", listing(fprA, "f", "cESCA", "A <a@example.net>") + listing(fprB, "-", "cESCA", "A <a@example.net>"), "a@example.net", fprA, ""},
		{"two valid", listing(fprA, "f", "cESCA", "A <a@example.net>") + listing(fprB, "u", "cESCA", "A <a@example.net>"), "a@example.net", "", "2 valid keys of a@example.net"},
	} {
		got, err := pick(parseColons([]byte(c.list)), c.who)
		switch {
		case c.err == "" && (err != nil || got != c.want):
			t.Errorf("%s: %q, %v", c.name, got, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error %v, want %q", c.name, err, c.err)
		}
	}
}

func TestFind(t *testing.T) {
	valid, other := gpgtest.New(t, "valid@example.net"), gpgtest.New(t, "other@example.net")
	ringtest.Home(t, []*ringtest.Entity{valid}, []*ringtest.Entity{other})
	ctx := context.Background()
	for _, who := range []string{"valid@example.net", "Valid@Example.NET", gpgkeys.Fingerprint(valid), "0x" + strings.ToLower(gpgkeys.Fingerprint(valid))} {
		e, err := Find(ctx, who)
		if err != nil || gpgkeys.Fingerprint(e) != gpgkeys.Fingerprint(valid) {
			t.Fatalf("%s: %v", who, err)
		}
	}
	for who, want := range map[string]string{
		"other@example.net":            gpgkeys.Fingerprint(other) + ": validity unknown",
		gpgkeys.Fingerprint(other):     gpgkeys.Fingerprint(other) + ": validity unknown",
		"nobody@example.net":           "no key of nobody@example.net",
		"alid@example.net":             "no key of alid@example.net",
		"--export-secret-keys":         "not an e-mail address or a fingerprint",
		"Valid <valid@example.net>":    "not an e-mail address or a fingerprint",
		strings.Repeat("0", 40) + "zz": "not an e-mail address or a fingerprint",
	} {
		if _, err := Find(ctx, who); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want %q", who, err, want)
		}
	}
}

func TestFindNoGPG(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := Find(context.Background(), "a@example.net"); err == nil || !strings.Contains(err.Error(), "gpg not found") {
		t.Fatalf("error %v", err)
	}
}

func TestRecipients(t *testing.T) {
	got := recipients(parseColons([]byte(
		listing(fprA, "f", "cESCA", "A <a@example.net>") +
			listing(fprB, "u", "cESCA", "Two <two@example.net>") +
			listing(fprA, "f", "cESCA", "Two <two@example.net>") +
			listing(fprB, "-", "cESCA", "Unknown <unknown@example.net>") +
			listing(fprB, "f", "cESCAD", "Disabled <disabled@example.net>") +
			listing(fprB, "f", "cSCA", "Sign <sign@example.net>") +
			listing(fprB, "f", "cESCA", "No address"))))
	want := []Recipient{{fprB, "two@example.net"}, {fprA, "two@example.net"}, {Name: "a@example.net"}}
	if len(got) != len(want) {
		t.Fatalf("recipients %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("recipients %+v", got)
		}
	}
}

func TestRecipientsOfKeyring(t *testing.T) {
	valid, other := gpgtest.New(t, "valid@example.net"), gpgtest.New(t, "other@example.net")
	ringtest.Home(t, []*ringtest.Entity{valid}, []*ringtest.Entity{other})
	got, err := Recipients(context.Background())
	if err != nil || len(got) != 1 || got[0] != (Recipient{Name: "valid@example.net"}) {
		t.Fatalf("recipients %+v, %v", got, err)
	}
	if !Available() {
		t.Fatal("gpg not available")
	}
	t.Setenv("PATH", t.TempDir())
	if Available() {
		t.Fatal("gpg available without PATH")
	}
}
