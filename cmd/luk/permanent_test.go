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
	a := &wire.LinkListAnswer{Links: []wire.LinkEntry{
		{URL: "https://d.example/d/v3", File: "hosts.krl", Size: 3, Received: "2026-10-02T10:00:00Z", Portal: wire.PortalDirect,
			Permanent: "rev/hosts.krl", PermanentURL: "https://d.example/d/permanent/rev/hosts.krl"},
		{URL: "https://d.example/d/other", File: "a", Size: 1, Received: "2026-10-01T12:00:00Z", Portal: wire.PortalDirect},
		{URL: "https://d.example/d/b1", File: "b", Size: 2, Received: "2026-10-01T11:00:00Z", Portal: wire.PortalDirect,
			Permanent: "builds/b", PermanentURL: "https://d.example/d/permanent/builds/b"},
		// An older version listed as one of the same name is a plain link.
		{URL: "https://d.example/d/v2", File: "hosts.krl", Size: 3, Received: "2026-10-01T10:00:00Z", Portal: wire.PortalDirect,
			Permanent: "rev/hosts.krl", PermanentURL: "https://d.example/d/permanent/rev/hosts.krl"},
	}}
	ls := newLinkList(a)
	var b strings.Builder
	err := printLinks(&b, ls, time.UTC, false)
	want := "NAME       SIZE  SENT              EXPIRES  FLAGS      URL\n" +
		"hosts.krl  3 B   2026-10-02 10:00  never    permanent  https://d.example/d/v3\n" +
		"a          1 B   2026-10-01 12:00  never    -          https://d.example/d/other\n" +
		"b          2 B   2026-10-01 11:00  never    permanent  https://d.example/d/b1\n" +
		"hosts.krl  3 B   2026-10-01 10:00  never    -          https://d.example/d/v2\n" +
		"\n" +
		"permanent builds/b\n" +
		"  url      https://d.example/d/permanent/builds/b\n" +
		"  version  https://d.example/d/b1\n" +
		"\n" +
		"permanent rev/hosts.krl\n" +
		"  url      https://d.example/d/permanent/rev/hosts.krl\n" +
		"  version  https://d.example/d/v3\n"
	if err != nil || b.String() != want {
		t.Fatalf("%v\n%s\nwant\n%s", err, b.String(), want)
	}

	raw, err := json.Marshal(ls)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `{"links":[` +
		`{"name":"hosts.krl","size":3,"sent":"2026-10-02T10:00:00Z","flags":["permanent"],"url":"https://d.example/d/v3","permanent":"rev/hosts.krl","cursor":""},` +
		`{"name":"a","size":1,"sent":"2026-10-01T12:00:00Z","flags":[],"url":"https://d.example/d/other","cursor":""},` +
		`{"name":"b","size":2,"sent":"2026-10-01T11:00:00Z","flags":["permanent"],"url":"https://d.example/d/b1","permanent":"builds/b","cursor":""},` +
		`{"name":"hosts.krl","size":3,"sent":"2026-10-01T10:00:00Z","flags":[],"url":"https://d.example/d/v2","cursor":""}],` +
		`"permanent":[` +
		`{"name":"builds/b","url":"https://d.example/d/permanent/builds/b","version_url":"https://d.example/d/b1"},` +
		`{"name":"rev/hosts.krl","url":"https://d.example/d/permanent/rev/hosts.krl","version_url":"https://d.example/d/v3"}]}`
	if string(raw) != wantJSON {
		t.Fatalf("json\n%s\nwant\n%s", raw, wantJSON)
	}
	// Each permanent name joins the link of its current version.
	for _, pm := range ls.Permanent {
		n := 0
		for _, l := range ls.Links {
			if l.URL == pm.VersionURL && l.Permanent == pm.Name {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: %d links", pm.Name, n)
		}
	}
}

// The permanent blocks escape the control characters a server sends.
func TestPrintLinksPermanentEscapes(t *testing.T) {
	var b strings.Builder
	err := printLinks(&b, newLinkList(&wire.LinkListAnswer{Links: []wire.LinkEntry{
		{URL: "https://d.example/d/v\x1b", Size: 1, Received: "2026-10-02T10:00:00Z", Permanent: "a\nb", PermanentURL: "https://d.example/p/a\x07"},
	}}), time.UTC, false)
	want := "\npermanent " + `a\nb` + "\n  url      " + `https://d.example/p/a\a` + "\n  version  " + `https://d.example/d/v\x1b` + "\n"
	if err != nil || !strings.HasSuffix(b.String(), want) {
		t.Fatalf("%v\n%q\nwant suffix %q", err, b.String(), want)
	}
}
