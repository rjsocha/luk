package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"luk/internal/gpgkeys"
	"luk/internal/gpgkeys/gpgtest"
	"luk/internal/gpgring"
	"luk/internal/gpgring/ringtest"
	"luk/internal/wire"
)

func TestSendGPGFile(t *testing.T) {
	e := newSendEnv(t)
	to := gpgtest.New(t, "to@example.net")
	ringtest.Home(t, []*ringtest.Entity{to}, nil)
	if code, _, errs := e.send(t, "--gpg", "to@example.net", "--file", namedFile(t, "a.txt", "plain body")); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if got := gpgtest.Decrypt(t, e.body, to); string(got) != "plain body" {
		t.Fatalf("decrypted %q", got)
	}
	sum := sha256.Sum256(e.body)
	if e.meta.File != "a.txt.gpg" || e.meta.Type != "application/pgp-encrypted" || e.meta.Source != wire.SourceFile ||
		e.meta.Size == nil || *e.meta.Size != int64(len(e.body)) || e.meta.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("meta %+v", e.meta)
	}
}

func TestSendGPGRecipients(t *testing.T) {
	e := newSendEnv(t)
	a, b := gpgtest.New(t, "a@example.net"), gpgtest.New(t, "b@example.net")
	ringtest.Home(t, []*ringtest.Entity{a, b}, nil)
	if code, _, errs := e.send(t, "--gpg", "a@example.net", "--gpg", gpgkeys.Fingerprint(b), "--name", "q3.pdf", "--type", "application/x-test", "--file", namedFile(t, "a.txt", "for two")); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, key := range []*ringtest.Entity{a, b} {
		if got := gpgtest.Decrypt(t, e.body, key); string(got) != "for two" {
			t.Fatalf("decrypted %q", got)
		}
	}
	if e.meta.File != "q3.pdf.gpg" || e.meta.Type != "application/x-test" {
		t.Fatalf("meta %+v", e.meta)
	}
}

func TestSendGPGStdin(t *testing.T) {
	e := newSendEnv(t)
	to := gpgtest.New(t, "to@example.net")
	ringtest.Home(t, []*ringtest.Entity{to}, nil)
	defer stdinFrom(t, "streamed body")()
	if code, _, errs := e.send(t, "--gpg", "to@example.net", "--stdin", "--name", "dump.sql"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if got := gpgtest.Decrypt(t, e.body, to); string(got) != "streamed body" {
		t.Fatalf("decrypted %q", got)
	}
	if e.meta.File != "dump.sql.gpg" || e.meta.Source != wire.SourceStdin || e.meta.Size != nil {
		t.Fatalf("meta %+v", e.meta)
	}
}

func TestSendGPGNotValid(t *testing.T) {
	e := newSendEnv(t)
	to, unknown := gpgtest.New(t, "to@example.net"), gpgtest.New(t, "unknown@example.net")
	ringtest.Home(t, []*ringtest.Entity{to}, []*ringtest.Entity{unknown})
	code, _, errs := e.send(t, "--gpg", "to@example.net", "--gpg", "unknown@example.net", "--file", namedFile(t, "a.txt", "plain body"))
	if code != 1 || !strings.Contains(errs, gpgkeys.Fingerprint(unknown)+": validity unknown") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if e.body != nil || e.meta.Source != "" {
		t.Fatalf("sent %q, meta %+v", e.body, e.meta)
	}
}

func TestSendGPGUsage(t *testing.T) {
	tempConfig(t)
	for _, args := range [][]string{
		{"send", "--gpg", "a@example.net", "--secret"},
		{"send", "--gpg", "a@example.net", "--secret", "--stdin"},
		{"send", "--gpg", "", "--stdin"},
	} {
		if code, _, _ := runLuk(t, args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
}

func TestSendGPGLinks(t *testing.T) {
	e := newLukdEnv(t)
	to := gpgtest.New(t, "to@example.net")
	ringtest.Home(t, []*ringtest.Entity{to}, nil)
	out := mustRun(t, "send", "-e", "drop", "-k", e.key, "--gpg", "to@example.net", "--links", "2", "--file", namedFile(t, "a.txt", "one body"))
	urls := lines(out)
	if len(urls) != 2 || !distinct(urls) {
		t.Fatalf("urls %q", out)
	}
	for _, u := range urls {
		var body string
		waitUntil(t, u+" is served", func() bool {
			var code int
			code, body = httpGet(t, u)
			return code == 200
		})
		if got := gpgtest.Decrypt(t, []byte(body), to); string(got) != "one body" {
			t.Fatalf("%s: decrypted %q", u, got)
		}
	}
	if a, d := e.logs.count("upload accepted"), e.logs.count("upload deduplicated"); a != 1 || d != 1 {
		t.Fatalf("%d bodies received, %d deduplicated", a, d)
	}
}

func TestCompleteGPG(t *testing.T) {
	tempConfig(t)
	a, b, unknown := gpgtest.New(t, "a@example.net"), gpgtest.New(t, "b@example.net"), gpgtest.New(t, "unknown@example.net")
	ringtest.Home(t, []*ringtest.Entity{a, b}, []*ringtest.Entity{unknown})
	want := []string{"a@example.net", "b@example.net"}
	wantCompletion(t, []string{"send", "--gpg", ""}, want, ":4")
	wantCompletion(t, []string{"put", "--gpg", "b"}, want[1:], ":4")
	wantCompletion(t, []string{"send", "--gpg", "u"}, nil, ":4")
}

func TestSendGPGNeedsGPG(t *testing.T) {
	tempConfig(t)
	if !gpgring.Available() {
		t.Skip("no gpg in PATH")
	}
	if _, out, _ := runLuk(t, "send", "--help"); !strings.Contains(out, "--gpg") {
		t.Fatalf("help with gpg: %s", out)
	}
	t.Setenv("PATH", t.TempDir())
	if _, out, _ := runLuk(t, "send", "--help"); strings.Contains(out, "gpg") {
		t.Fatalf("help without gpg: %s", out)
	}
	if _, out, _ := runLuk(t, "__complete", "send", "--g"); strings.Contains(out, "--gpg") {
		t.Fatalf("completion without gpg: %s", out)
	}
	wantCompletion(t, []string{"send", "--gpg", ""}, nil, ":4")
	if code, _, errs := runLuk(t, "send", "--gpg", "a@example.net", "--stdin"); code != 1 || !strings.Contains(errs, "--gpg: gpg not found in PATH") {
		t.Fatalf("exit %d: %s", code, errs)
	}
}
