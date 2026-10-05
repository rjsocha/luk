package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/wire"
)

func TestSendPermanent(t *testing.T) {
	e := newSendEnv(t)
	e.url = true
	e.ttl = `,"permanent":"revocation/hosts.krl","version_url":"https://lukd.test/d/abc123"`
	p := filepath.Join(t.TempDir(), "hosts.krl")
	if err := os.WriteFile(p, []byte("krl"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runLuk(t, "send", "-e", "t", "-k", e.key, "--file", p, "--permanent", "revocation/hosts.krl")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if e.meta.Permanent != "revocation/hosts.krl" || e.meta.File != "hosts.krl" || out != "https://lukd.test/d/xyz\n" {
		t.Fatalf("meta %+v out %q", e.meta, out)
	}
	// --name keeps its meaning: the file name in the meta.
	code, out, errs = runLuk(t, "send", "-e", "t", "-k", e.key, "--file", p, "--permanent", "revocation/hosts.krl", "--name", "keys.krl", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var r wire.Receipt
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if e.meta.File != "keys.krl" || r.URL != "https://lukd.test/d/xyz" || r.Permanent != "revocation/hosts.krl" || r.VersionURL != "https://lukd.test/d/abc123" {
		t.Fatalf("meta %+v answer %+v", e.meta, r)
	}
}

func TestSendPermanentUsage(t *testing.T) {
	e := newSendEnv(t)
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		msg  string
	}{
		{[]string{"--once"}, "--permanent takes no --once"},
		{[]string{"--secret"}, "--permanent takes no --secret"},
		{[]string{"--portal"}, "--permanent takes no --portal"},
		{[]string{"--private"}, "--permanent takes no --private"},
		{[]string{"--mutable"}, "--permanent takes no --mutable"},
		{[]string{"--pretty-url"}, "--permanent takes no --pretty-url"},
		{[]string{"--links", "2"}, "--permanent takes no --links above 1"},
		{[]string{"--once", "--mutable"}, "--permanent takes no --once, --mutable"},
	} {
		code, _, errs := runLuk(t, append([]string{"send", "-e", "t", "-k", e.key, "--file", p, "--permanent", "x"}, c.args...)...)
		if code != 1 || !strings.Contains(errs, c.msg) {
			t.Errorf("%v: exit %d %q, want %q", c.args, code, errs, c.msg)
		}
	}
	for name, msg := range map[string]string{
		"":          "empty permanent name",
		"/x":        "is absolute",
		"a/../b":    `element ".." is not a name`,
		"a//b":      "empty element",
		"a/current": `element "current" is reserved`,
		"a\nb":      "control character",
	} {
		code, _, errs := runLuk(t, "send", "-e", "t", "-k", e.key, "--file", p, "--permanent", name)
		if code != 1 || !strings.Contains(errs, msg) {
			t.Errorf("%q: exit %d %q, want %q", name, code, errs, msg)
		}
	}
	if e.meta.Permanent != "" || e.body != nil {
		t.Fatalf("sent %+v", e.meta)
	}
}

func TestPrintLinksPermanent(t *testing.T) {
	var b strings.Builder
	err := printLinks(&b, []wire.LinkEntry{
		{URL: "https://d.example/d/v3", File: "hosts.krl", Size: 3, Received: "2026-10-02T10:00:00Z", Portal: wire.PortalDirect,
			Permanent: "rev/hosts.krl", PermanentURL: "https://d.example/d/permanent/rev/hosts.krl"},
		{URL: "https://d.example/d/other", File: "a", Size: 1, Received: "2026-10-01T12:00:00Z", Portal: wire.PortalDirect},
		{URL: "https://d.example/d/v2", File: "hosts.krl", Size: 3, Received: "2026-10-01T10:00:00Z", Portal: wire.PortalDirect,
			Permanent: "rev/hosts.krl", PermanentURL: "https://d.example/d/permanent/rev/hosts.krl"},
	}, time.UTC)
	want := "NAME       SIZE  SENT              EXPIRES  FLAGS      URL\n" +
		"hosts.krl  3 B   2026-10-02 10:00  never    permanent  https://d.example/d/v3\n" +
		"a          1 B   2026-10-01 12:00  never    -          https://d.example/d/other\n" +
		"hosts.krl  3 B   2026-10-01 10:00  never    permanent  https://d.example/d/v2\n" +
		"\n" +
		"PERMANENT      SENT              URL\n" +
		"rev/hosts.krl  2026-10-02 10:00  https://d.example/d/permanent/rev/hosts.krl\n"
	if err != nil || b.String() != want {
		t.Fatalf("%v\n%s\nwant\n%s", err, b.String(), want)
	}
}
