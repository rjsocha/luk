package wire

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func size(n int64) *int64 { return &n }

func TestNormalizeTags(t *testing.T) {
	m := Meta{Portal: PortalDirect, Source: "stdin", Tags: []string{"DevDump", "prod", "devdump", " prod "}}
	if err := m.Normalize(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.Tags, ",") != "devdump,prod" {
		t.Fatalf("tags %v", m.Tags)
	}
	bad := Meta{Portal: PortalDirect, Source: "stdin", Tags: []string{"a b"}}
	if err := bad.Normalize(); err == nil {
		t.Fatal("tag with space accepted")
	}
}

func TestValidate(t *testing.T) {
	sha := strings.Repeat("a", 64)
	cases := []struct {
		name string
		m    Meta
		ok   bool
	}{
		{"no source", Meta{Portal: PortalDirect}, false},
		{"bad source", Meta{Portal: PortalDirect, Source: "net"}, false},
		{"source file", Meta{Portal: PortalDirect, File: "a.gz", Source: "file", Size: size(3), SHA256: sha}, true},
		{"source file zero size", Meta{Portal: PortalDirect, Source: "file", Size: size(0), SHA256: sha}, true},
		{"source file without size", Meta{Portal: PortalDirect, Source: "file"}, false},
		{"source file size only", Meta{Portal: PortalDirect, Source: "file", Size: size(3)}, false},
		{"source file sha only", Meta{Portal: PortalDirect, Source: "file", SHA256: sha}, false},
		{"source pipe", Meta{Portal: PortalDirect, Source: "pipe"}, true},
		{"source stdin", Meta{Portal: PortalDirect, Source: "stdin", File: "x.tar"}, true},
		{"source terminal", Meta{Portal: PortalDirect, Source: "terminal", Size: size(3), SHA256: sha}, true},
		{"terminal without size", Meta{Portal: PortalDirect, Source: "terminal"}, false},
		{"dry run", Meta{Portal: PortalDirect, Source: "stdin", DryRun: true}, true},
		{"pipe with size and sha", Meta{Portal: PortalDirect, Source: "pipe", Size: size(3), SHA256: sha}, true},
		{"stdin with size and sha", Meta{Portal: PortalDirect, Source: "stdin", Size: size(3), SHA256: sha}, true},
		{"stdin size only", Meta{Portal: PortalDirect, Source: "stdin", Size: size(3)}, false},
		{"pipe sha only", Meta{Portal: PortalDirect, Source: "pipe", SHA256: sha}, false},
		{"bad sha", Meta{Portal: PortalDirect, Source: "file", Size: size(1), SHA256: "xyz"}, false},
		{"negative", Meta{Portal: PortalDirect, Source: "file", Size: size(-1), SHA256: sha}, false},
		{"ttl and once", Meta{Portal: PortalDirect, Source: "stdin", TTL: "1h", Once: true}, true},
		{"ttl days", Meta{Portal: PortalDirect, Source: "stdin", TTL: "2d"}, true},
		{"bad ttl", Meta{Portal: PortalDirect, Source: "stdin", TTL: "soon"}, false},
		{"zero ttl", Meta{Portal: PortalDirect, Source: "stdin", TTL: "0s"}, false},
		{"unsorted tags", Meta{Portal: PortalDirect, Source: "stdin", Tags: []string{"b", "a"}}, false},
		{"file slash", Meta{Portal: PortalDirect, Source: "stdin", File: "a/b"}, false},
		{"file nul", Meta{Portal: PortalDirect, Source: "stdin", File: "a\x00b"}, false},
		{"file newline", Meta{Portal: PortalDirect, Source: "stdin", File: "report.pdf\nsha256: 00"}, false},
		{"file escape", Meta{Portal: PortalDirect, Source: "stdin", File: "a\x1b]0;owned\a"}, false},
		{"file del", Meta{Portal: PortalDirect, Source: "stdin", File: "a\x7f"}, false},
		{"file c1", Meta{Portal: PortalDirect, Source: "stdin", File: "a\u009bb"}, false},
		{"file tab", Meta{Portal: PortalDirect, Source: "stdin", File: "a\tb"}, false},
		{"file unicode", Meta{Portal: PortalDirect, Source: "stdin", File: "zażółć gęślą.txt"}, true},
		{"file 255", Meta{Portal: PortalDirect, Source: "stdin", File: strings.Repeat("a", 255)}, true},
		{"file 256", Meta{Portal: PortalDirect, Source: "stdin", File: strings.Repeat("a", 256)}, false},
		{"backup host", Meta{Portal: PortalDirect, Source: "stdin", Backup: &Backup{Hostname: "db1.example.net", Path: "/x"}}, true},
		{"backup host slash", Meta{Portal: PortalDirect, Source: "stdin", Backup: &Backup{Hostname: "db1/../x", Path: "/x"}}, false},
		{"backup host dot", Meta{Portal: PortalDirect, Source: "stdin", Backup: &Backup{Hostname: ".hidden", Path: "/x"}}, false},
		{"backup host dotdot", Meta{Portal: PortalDirect, Source: "stdin", Backup: &Backup{Hostname: "..", Path: "/x"}}, false},
		{"backup host nul", Meta{Portal: PortalDirect, Source: "stdin", Backup: &Backup{Hostname: "a\x00b", Path: "/x"}}, false},
		{"backup host newline", Meta{Portal: PortalDirect, Source: "stdin", Backup: &Backup{Hostname: "db1\nx", Path: "/x"}}, false},
		{"backup host 256", Meta{Portal: PortalDirect, Source: "stdin", Backup: &Backup{Hostname: strings.Repeat("a", 256), Path: "/x"}}, false},
		{"type", Meta{Portal: PortalDirect, Source: "stdin", Type: "text/plain; charset=utf-8"}, true},
		{"bad type", Meta{Portal: PortalDirect, Source: "stdin", Type: "not a type"}, false},
		{"type crlf", Meta{Portal: PortalDirect, Source: "stdin", Type: "text/plain;\r\n x=y"}, false},
		{"type escape", Meta{Portal: PortalDirect, Source: "stdin", Type: "text/plain; x=\"\x1b[2J\""}, false},
		{"type too long", Meta{Portal: PortalDirect, Source: "stdin", Type: "text/plain; x=" + strings.Repeat("a", 250)}, false},
	}
	for _, c := range cases {
		err := c.m.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestMetaRoundTrip(t *testing.T) {
	in := Meta{Portal: PortalDirect, File: "x", Source: "file", Size: size(0), SHA256: strings.Repeat("b", 64), Tags: []string{"a"},
		Backup: &Backup{Hostname: "h", Path: "/x", Mtime: "2026-09-30T00:00:00Z"}}
	s, err := EncodeMeta(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(s, "+/=") {
		t.Fatalf("not raw base64url: %s", s)
	}
	out, err := DecodeMeta(s)
	if err != nil {
		t.Fatal(err)
	}
	if out.Size == nil || *out.Size != 0 || out.Backup.Hostname != "h" {
		t.Fatalf("round trip %+v", out)
	}
	if _, err := DecodeMeta("eyJ4IjoxfQ"); err == nil { // {"x":1}
		t.Fatal("unknown field accepted")
	}
}

func TestCanonicalText(t *testing.T) {
	h := []byte{0xfb, 0xff, 0x01}
	for _, c := range []struct{ got, want string }{
		{string(CanonicalText("h:8080", "/backup", "T", "N", "M", h)), "luk-upload@v2\nPUT\nh:8080\n/backup\nT\nN\nM\n-_8B"},
		{string(ListCanonicalText("GET", "h", EndpointsPath, "T", "N", h)), "luk-list@v2\nGET\nh\n/.well-known/luk/endpoints\nT\nN\n-_8B"},
		{string(LinkCanonicalText("PATCH", "h:8080", "/drop", "https://d/x", "ttl", "T", "N", "M", h)), "luk-link@v2\nPATCH\nh:8080\n/drop\nhttps://d/x\nttl\nT\nN\nM\n-_8B"},
		{string(LinkCanonicalText("GET", "h", "/drop", "", "list", "T", "N", "M", h)), "luk-link@v2\nGET\nh\n/drop\n\nlist\nT\nN\nM\n-_8B"},
	} {
		if c.got != c.want {
			t.Errorf("%q, want %q", c.got, c.want)
		}
	}
	if Namespace != "luk-upload@v2" || ListNamespace != "luk-list@v2" || LinkNamespace != "luk-link@v2" || GetNamespace != "luk-get@v1" {
		t.Fatal("namespaces")
	}
}

func TestNonce(t *testing.T) {
	a, b := NewNonce(), NewNonce()
	if a == b || !ValidNonce(a) || len(a) != 22 {
		t.Fatalf("nonce %q %q", a, b)
	}
	if ValidNonce("short") {
		t.Fatal("short nonce valid")
	}
}

func TestParseDurationAndSize(t *testing.T) {
	if d, _ := ParseDuration("7d"); d != 7*24*time.Hour {
		t.Fatalf("7d = %v", d)
	}
	if d, _ := ParseDuration("90m"); d != 90*time.Minute {
		t.Fatalf("90m = %v", d)
	}
	if _, err := ParseDuration("xd"); err == nil {
		t.Fatal("xd parsed")
	}
	if _, err := ParseDuration("+5d"); err == nil {
		t.Fatal("+5d parsed")
	}
	if _, err := ParseDuration("999999999999d"); err == nil {
		t.Fatal("999999999999d parsed")
	}
	for in, want := range map[string]int64{"10": 10, "2K": 2048, "16k": 16 << 10, "1m": 1 << 20, "50G": 50 << 30, "1T": 1 << 40} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("%s = %d, %v", in, got, err)
		}
	}
	if _, err := ParseSize("-1"); err == nil {
		t.Fatal("negative size parsed")
	}
	if _, err := ParseSize("9999999T"); err == nil {
		t.Fatal("9999999T parsed")
	}
	if _, err := ParseSize("99999999999999999999"); err == nil {
		t.Fatal("99999999999999999999 parsed")
	}
}

func TestDecodeMetaSingleObject(t *testing.T) {
	for _, s := range []string{`{} trailing garbage`, `{"source":"stdin"} {"name":"ignored"}`, `null`, ``, `[]`} {
		if _, err := DecodeMeta(base64.RawURLEncoding.EncodeToString([]byte(s))); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	for _, s := range []string{`{"source":"stdin","portal":"direct"}`, ` {"source":"pipe","portal":"reveal"} `, "\n{\"file\":\"f\",\"source\":\"stdin\",\"portal\":\"download\",\"dry_run\":true}\t\r\n"} {
		if _, err := DecodeMeta(base64.RawURLEncoding.EncodeToString([]byte(s))); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}

func TestDecodeMetaRejectsName(t *testing.T) {
	s := base64.RawURLEncoding.EncodeToString([]byte(`{"name":"x","source":"stdin"}`))
	if _, err := DecodeMeta(s); err == nil {
		t.Fatal("old name field accepted")
	}
}

func TestPortalEnum(t *testing.T) {
	for _, p := range []string{PortalDirect, PortalReveal, PortalDownload} {
		if err := (Meta{Source: "stdin", Portal: p}).Validate(); err != nil {
			t.Errorf("portal %q: %v", p, err)
		}
	}
	for _, p := range []string{"", "true", "Reveal", "x"} {
		if err := (Meta{Source: "stdin", Portal: p}).Validate(); err == nil {
			t.Errorf("portal %q accepted", p)
		}
	}
	if _, err := DecodeMeta(base64.RawURLEncoding.EncodeToString([]byte(`{"source":"stdin","portal":true}`))); err == nil {
		t.Error("boolean portal accepted")
	}
}

func TestMetaNoCLIHint(t *testing.T) {
	s, err := EncodeMeta(Meta{Portal: PortalReveal, Source: SourceStdin})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := base64.RawURLEncoding.DecodeString(s); string(b) != `{"source":"stdin","portal":"reveal"}` {
		t.Fatalf("%s", b)
	}
	old := base64.RawURLEncoding.EncodeToString([]byte(`{"source":"stdin","portal":"reveal","cli_hint":true}`))
	if _, err := DecodeMeta(old); err == nil {
		t.Fatal("cli_hint accepted")
	}
}

func TestMetaNoOwner(t *testing.T) {
	for _, c := range []struct {
		hide bool
		want string
	}{
		{true, `{"source":"stdin","portal":"download","no_owner":true}`},
		{false, `{"source":"stdin","portal":"download"}`},
	} {
		s, err := EncodeMeta(Meta{Portal: PortalDownload, Source: SourceStdin, NoOwner: c.hide})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := base64.RawURLEncoding.DecodeString(s)
		if string(b) != c.want {
			t.Fatalf("%s", b)
		}
		if m, err := DecodeMeta(s); err != nil || m.NoOwner != c.hide {
			t.Fatalf("%+v %v", m, err)
		}
	}
}

func TestMetaPrettyURL(t *testing.T) {
	s, err := EncodeMeta(Meta{Portal: PortalDirect, Source: SourceStdin, PrettyURL: true})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := base64.RawURLEncoding.DecodeString(s)
	if string(b) != `{"source":"stdin","portal":"direct","pretty_url":true}` {
		t.Fatalf("%s", b)
	}
	if m, err := DecodeMeta(s); err != nil || !m.PrettyURL {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		21 * 24 * time.Hour: "21d",
		time.Hour:           "1h",
		90 * time.Minute:    "1h30m",
		25 * time.Hour:      "25h",
		30 * time.Second:    "30s",
		61 * time.Second:    "1m1s",
	} {
		got := FormatDuration(d)
		if got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
		if back, err := ParseDuration(got); err != nil || back != d {
			t.Errorf("%q parses to %v %v", got, back, err)
		}
	}
}

func TestLinkMethod(t *testing.T) {
	for action, method := range map[string]string{LinkRemove: "DELETE", LinkTTL: "PATCH", LinkReplace: "PUT"} {
		if m, ok := LinkMethod(action); !ok || m != method {
			t.Errorf("%s: %s %v", action, m, ok)
		}
	}
	if _, ok := LinkMethod("rename"); ok {
		t.Error("unknown action has a method")
	}
}

func TestLinkMeta(t *testing.T) {
	s, err := EncodeLinkMeta(LinkMeta{TTL: "3d"})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := DecodeLinkMeta(s); err != nil || m.TTL != "3d" {
		t.Fatalf("%+v %v", m, err)
	}
	if m, err := DecodeLinkMeta("e30"); err != nil || m.TTL != "" {
		t.Fatalf("{}: %+v %v", m, err)
	}
	for _, bad := range []string{`{"ttl":"-1h"}`, `{"ttl":"x"}`, `{"once":true}`, `[]`, `{} {}`} {
		if _, err := DecodeLinkMeta(base64.RawURLEncoding.EncodeToString([]byte(bad))); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// The list fields of a link meta round-trip; their values are checked by
// lukd after the signature.
func TestLinkMetaList(t *testing.T) {
	s, err := EncodeLinkMeta(LinkMeta{Limit: 50, After: "abc", Any: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.RawURLEncoding.EncodeToString([]byte(`{"limit":50,"after":"abc","any":true}`)); s != want {
		t.Fatalf("%s, want %s", s, want)
	}
	if m, err := DecodeLinkMeta(s); err != nil || m != (LinkMeta{Limit: 50, After: "abc", Any: true}) {
		t.Fatalf("%+v %v", m, err)
	}
}

// A cursor is base64url of the acceptance order, the key of the stored
// name and the id in hex; only the form Encode writes parses, and every
// id, also an empty or a long one or one of any bytes, round-trips.
func TestLinkCursor(t *testing.T) {
	key := LinkKey("drop", "a")
	if len(key) != 32 || key == LinkKey("drop", "b") || key == LinkKey("drop/a", "") {
		t.Fatalf("key %q", key)
	}
	const id = "20261006T120000Z-0a1b2c3d"
	c := LinkCursor{NS: 1791288000123456789, Seq: 3, Key: key, ID: id}
	s := c.Encode()
	if want := base64.RawURLEncoding.EncodeToString([]byte("1791288000123456789.3." + key + "." + hex.EncodeToString([]byte(id)))); s != want {
		t.Fatalf("%s, want %s", s, want)
	}
	for _, c := range []LinkCursor{c, {Key: key}, {NS: -5, Key: key, ID: "x.y\n\xff\x00"}, {Key: key, ID: strings.Repeat("é", 300)}} {
		if got, err := ParseLinkCursor(c.Encode()); err != nil || got != c {
			t.Errorf("%+v: %+v %v", c, got, err)
		}
	}
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, bad := range []string{
		"", "!!", b64("1.2."+key+".78") + "=", base64.StdEncoding.EncodeToString([]byte("1.2." + key + ".78>?")),
		b64("1.2.78"), b64("1.2." + key), b64("x.2." + key + ".78"), b64("1.x." + key + ".78"),
		b64("01.2." + key + ".78"), b64("+1.2." + key + ".78"), b64("1.-2." + key + ".78"),
		b64("1.2." + strings.ToUpper(key) + ".78"), b64("1.2." + key[1:] + ".78"),
		b64("1.2." + key + ".7"), b64("1.2." + key + ".7G"), b64("1.2." + key + ".7A"), b64("1.2." + key + ".78.79"),
	} {
		if c, err := ParseLinkCursor(bad); err == nil {
			t.Errorf("%q accepted: %+v", bad, c)
		}
	}
}

func TestValidateReplace(t *testing.T) {
	n := int64(1)
	ok := Meta{Portal: PortalDirect, Source: SourceFile, File: "a", Type: "text/plain", Size: &n, SHA256: strings.Repeat("0", 64)}
	if err := ok.ValidateReplace(); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]Meta{
		"ttl": {Portal: PortalDirect, TTL: "1d"}, "once": {Portal: PortalDirect, Once: true},
		"mutable": {Portal: PortalDirect, Mutable: true}, "tags": {Portal: PortalDirect, Tags: []string{"a"}},
		"portal": {Portal: PortalReveal}, "dry_run": {Portal: PortalDirect, DryRun: true},
		"no_owner": {Portal: PortalDirect, NoOwner: true},
	} {
		if err := m.ValidateReplace(); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTTLErrorNamesUnits(t *testing.T) {
	for ttl, want := range map[string]string{
		"90":  `invalid ttl "90": add a unit, e.g. 90m, 90h or 90d`,
		"1x":  `invalid ttl "1x": use a number with a unit (s, m, h, d), e.g. 90m, 12h or 7d, or max`,
		"-1h": `invalid ttl "-1h": use a number with a unit (s, m, h, d), e.g. 90m, 12h or 7d, or max`,
	} {
		m := Meta{Portal: PortalDirect, Source: SourceStdin, TTL: ttl}
		if err := m.Validate(); err == nil || err.Error() != want {
			t.Errorf("ttl %q: %v", ttl, err)
		}
	}
}

func TestTTLMax(t *testing.T) {
	if d, max, err := ParseTTL(TTLMax); d != 0 || !max || err != nil {
		t.Fatalf("max: %v %v %v", d, max, err)
	}
	if d, max, err := ParseTTL("2d"); d != 48*time.Hour || max || err != nil {
		t.Fatalf("2d: %v %v %v", d, max, err)
	}
	for _, bad := range []string{"MAX", "max1h", "0s", ""} {
		if err := CheckTTL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	m := Meta{Portal: PortalDirect, Source: SourceStdin, TTL: TTLMax}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	s, _ := EncodeLinkMeta(LinkMeta{TTL: TTLMax})
	if lm, err := DecodeLinkMeta(s); err != nil || lm.TTL != TTLMax {
		t.Fatalf("link meta: %+v %v", lm, err)
	}
}

func TestGetCanonicalText(t *testing.T) {
	got := string(GetCanonicalText("GET", "secure.vm:8443", "/a%20b/x7Kq", "T", "N"))
	if want := "luk-get@v1\nGET\nsecure.vm:8443\n/a%20b/x7Kq\nT\nN"; got != want {
		t.Fatalf("%q", got)
	}
	if got := GetTarget("/d/", ""); got != "/d/" {
		t.Fatalf("target without query %q", got)
	}
	if got := GetTarget("/d/", "recursive=1"); got != "/d/?recursive=1" {
		t.Fatalf("target with query %q", got)
	}
}

func TestMetaAccess(t *testing.T) {
	for _, c := range []struct {
		access, portal string
		ok             bool
	}{
		{"", PortalReveal, true}, {AccessPrivate, PortalDirect, true}, {AccessAny, PortalDirect, true},
		{"public", PortalDirect, false}, {AccessPrivate, PortalReveal, false}, {AccessAny, PortalDownload, false},
	} {
		m := Meta{Source: SourceStdin, Portal: c.portal, Access: c.access}
		if err := m.Validate(); (err == nil) != c.ok {
			t.Errorf("access %q portal %s: %v", c.access, c.portal, err)
		}
	}
	m := Meta{Source: SourceStdin, Portal: PortalDirect, Access: AccessAny}
	if err := m.ValidateReplace(); err == nil || !strings.Contains(err.Error(), "access") {
		t.Fatalf("replace with access: %v", err)
	}
}

func TestSizesAndRates(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 1000: "1000", 1024: "1K", 1536 << 20: "1536M", 10 << 30: "10G", 2 << 40: "2T"} {
		if got := FormatSize(n); got != want {
			t.Errorf("FormatSize(%d) = %q, want %q", n, got, want)
		}
		if back, err := ParseSize(FormatSize(n)); err != nil || back != n {
			t.Errorf("%d: back %d %v", n, back, err)
		}
	}
	for n, want := range map[int64]string{512: "512", 1024: "1K", 13421772800: "12.5G", 50 << 30: "50G"} {
		if got := HumanSize(n); got != want {
			t.Errorf("HumanSize(%d) = %q, want %q", n, got, want)
		}
	}
	size, per, err := ParseRate("10G/1d")
	if err != nil || size != 10<<30 || per != 24*time.Hour || FormatRate(size, per) != "10G/1d" {
		t.Fatalf("%d %s %v", size, per, err)
	}
	for _, bad := range []string{"10G", "/1d", "0/1d", "1G/0s", "1G/-1h", "x/1d", "1G/x"} {
		if _, _, err := ParseRate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
