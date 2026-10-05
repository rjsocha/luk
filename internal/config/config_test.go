package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"luk/internal/wire"
)

const good = `
listen:
  plain:
    addr: 127.0.0.1:8080
  main:
    addr: 127.0.0.1:8443
    tls: {mode: self, cert: /tmp/c.crt, key: /tmp/c.key, host: lukd.vm}
auth:
  keys:
    - name: robert.socha
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"
  ca:
    - name: hosts
      type: host
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n ca"
      revoked: {key_ids: [old], serials: [7]}
endpoint:
  backup:
    listen: main
    endpoint: /backup
    path: /queue/backup
    allow: [robert.socha, "hosts:*"]
    limits: {body: {size: 50G}}
  drop:
    listen: [main]
    endpoint: /drop
    path: /queue/drop
    allow: [robert.socha]
    respond: url
    storage: drop
pipeline:
  devdb:
    endpoint: [backup]
    tags: [prod, devdump]
    timeout: 2h
    steps:
      - store: [archive, drop]
      - run: /opt/luk/dbdump
      - store: archive
  drop:
    endpoint: [drop]
    steps:
      - store: drop
storage:
  archive: {type: local, base: /storage/archive, path: "{{ .Sender }}/{{ .File }}"}
  drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop}
expose:
  drop:
    listen: main
    path: /d/
`

func TestParseGood(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(c.Auth.ClockSkew) != time.Minute || c.Auth.Nonces != "/run/luk/nonces" {
		t.Fatalf("auth defaults %v %q", time.Duration(c.Auth.ClockSkew), c.Auth.Nonces)
	}
	if c.Endpoint["backup"].Name != "backup" || c.Endpoint["backup"].Respond != "accept" {
		t.Fatalf("endpoint %+v", c.Endpoint["backup"])
	}
	if c.Endpoint["backup"].Limits.Body.Size != 50<<30 {
		t.Fatalf("body size %d", c.Endpoint["backup"].Limits.Body.Size)
	}
	if q := c.Pipeline["drop"].Queue; q.Concurrency != 1 || q.Group != "" || q.Order != 0 {
		t.Fatal("concurrency default")
	}
	if time.Duration(c.Pipeline["drop"].Timeout) != time.Hour || time.Duration(c.Pipeline["devdb"].Timeout) != 2*time.Hour {
		t.Fatalf("pipeline timeout %v %v", time.Duration(c.Pipeline["drop"].Timeout), time.Duration(c.Pipeline["devdb"].Timeout))
	}
	if c.WorkDir() != "/var/lib/luk/work" {
		t.Fatalf("work dir %q", c.WorkDir())
	}
	if got := c.Pipeline["devdb"].Steps[0].Store; len(got) != 2 {
		t.Fatalf("store list %v", got)
	}
	if got := c.Pipeline["devdb"].Steps[2].Store; len(got) != 1 || got[0] != "archive" {
		t.Fatalf("store scalar %v", got)
	}
	if c.Auth.Keys[0].Parsed == nil || c.Auth.CA[0].Parsed == nil {
		t.Fatal("keys not parsed")
	}
	if time.Duration(c.Storage["drop"].TTL.Max) != 7*24*time.Hour || !c.Storage["drop"].TTL.User {
		t.Fatal("ttl max")
	}
}

func TestUnknownKey(t *testing.T) {
	_, err := Parse([]byte(good + "\nbogus: 1\n"))
	if err == nil {
		t.Fatal("unknown top-level key accepted")
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string][2]string{
		"pipeline without endpoint": {"    endpoint: [backup]\n    tags: [prod, devdump]", "    tags: [prod, devdump]"},
		"unknown endpoint":          {"    endpoint: [drop]\n    steps:", "    endpoint: [nope]\n    steps:"},
		"unknown allow key":         {"allow: [robert.socha, \"hosts:*\"]", "allow: [nobody]"},
		"unknown allow ca":          {"\"hosts:*\"", "\"other:*\""},
		"bad glob":                  {"\"hosts:*\"", "\"hosts:[\""},
		"unknown store":             {"      - run: /opt/luk/dbdump\n      - store: archive", "      - run: /opt/luk/dbdump\n      - store: nope"},
		"relative run":              {"run: /opt/luk/dbdump", "run: dbdump"},
		"pipeline timeout 7d":       {"timeout: 2h", "timeout: 7d"},
		"hidden pipeline name":      {"  devdb:\n    endpoint: [backup]", "  .devdb:\n    endpoint: [backup]"},
		"storage base in work":      {"base: /storage/archive", "base: /var/lib/luk/work/a"},
		"respond url no storage":    {"    respond: url\n    storage: drop", "    respond: url"},
		"bad respond":               {"respond: url", "respond: maybe"},
		"relative endpoint path":    {"endpoint: /backup", "endpoint: backup"},
		"tls acme unsupported":      {"mode: self", "mode: acme"},
		"tls files no key":          {"mode: self, cert: /tmp/c.crt, key: /tmp/c.key", "mode: files, cert: /tmp/c.crt"},
		"tls files algorithm":       {"mode: self", "mode: files, algorithm: ed25519"},
		"bad tls algorithm":         {"host: lukd.vm}", "host: lukd.vm, algorithm: rsa}"},
		"bad ca type":               {"type: host", "type: robot"},
		"bad key":                   {"key: \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha\"", "key: \"garbage\""},
		"key with options":          {"key: \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha\"", "key: 'from=\"10.0.0.0/8\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha'"},
		"ca key with options":       {"key: \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n ca\"", "key: 'cert-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n ca'"},
		"expose path no slash":      {"path: /d/", "path: /d"},
		"storage unexposed for url": {", expose: drop}\nexpose:", "}\nexpose:"},
		"exposed s3 storage":        {`drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop}`, `drop: {type: s3, bucket: b, expose: drop}`},
		"store to s3":               {"      - store: archive\n  drop:", "      - store: off\n  drop:"},
		"url storage not stored":    {"    endpoint: [drop]\n    steps:\n      - store: drop", "    endpoint: [drop]\n    steps:\n      - store: archive"},
	}
	for name, r := range cases {
		if !strings.Contains(good, r[0]) {
			t.Fatalf("%s: fixture does not contain %q", name, r[0])
		}
		src := good
		if name == "store to s3" {
			src = strings.Replace(src, "storage:\n", "storage:\n  off: {type: s3, bucket: b}\n", 1)
		}
		_, err := Parse([]byte(strings.Replace(src, r[0], r[1], 1)))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "store to s3" && !strings.Contains(err.Error(), "pipeline devdb: step 3: storage off: s3 storage is not implemented yet") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A pipeline name is a component of the work directory path lukd run
// checks: a name lukd run would refuse is a config error.
func TestPipelineNames(t *testing.T) {
	for _, n := range []string{"db_1.daily", "A-b", "_x", "9"} {
		if _, err := Parse([]byte(strings.Replace(good, "  devdb:\n", "  "+n+":\n", 1))); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	for _, n := range []string{`"Offsite DB"`, "-x", ".x", `"a%b"`, `"a$b"`, "ü", `"a\tb"`, `"a\nb"`, `"a\u0085b"`, `"a/b"`, `""`} {
		_, err := Parse([]byte(strings.Replace(good, "  devdb:\n", "  "+n+":\n", 1)))
		if err == nil || !strings.Contains(err.Error(), "the name must be of [A-Za-z0-9_.-]") {
			t.Errorf("%s: %v", n, err)
		}
	}
}

func TestTLSFilesMode(t *testing.T) {
	src := strings.Replace("root: /srv/luk\n"+good, "tls: {mode: self, cert: /tmp/c.crt, key: /tmp/c.key, host: lukd.vm}",
		"tls: {mode: files, cert: tls/c.crt, key: /etc/ssl/c.key}", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	tl := c.Listen["main"].TLS
	if tl.Mode != "files" || tl.Cert != "/srv/luk/tls/c.crt" || tl.Key != "/etc/ssl/c.key" || tl.Host != "" || tl.Algorithm != "" {
		t.Fatalf("%+v", tl)
	}
}

func TestWellKnownReserved(t *testing.T) {
	for _, r := range [][2]string{
		{"endpoint: /drop", "endpoint: /.well-known"},
		{"endpoint: /drop", "endpoint: /.well-known/luk/drop"},
		{"path: /d/", "path: /.well-known/"},
		{"path: /d/", "path: /.well-known/acme-challenge/"},
	} {
		_, err := Parse([]byte(strings.Replace(good, r[0], r[1], 1)))
		if err == nil || !strings.Contains(err.Error(), "which lukd reserves") {
			t.Errorf("%s: %v", r[1], err)
		}
	}
	for _, r := range [][2]string{{"endpoint: /drop", "endpoint: /.well-knownx"}, {"path: /d/", "path: /well-known/"}} {
		if _, err := Parse([]byte(strings.Replace(good, r[0], r[1], 1))); err != nil {
			t.Errorf("%s: %v", r[1], err)
		}
	}
}

func TestDuplicateEndpointPath(t *testing.T) {
	bad := strings.Replace(good, "endpoint: /drop", "endpoint: /backup", 1)
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("duplicate endpoint path accepted")
	}
}

func TestExampleConfig(t *testing.T) {
	if _, err := Load("../../lukd.example.yaml"); err != nil {
		t.Fatal(err)
	}
}

// The merged configuration example of doc/SPEC.md is valid once its auth
// placeholder holds the identities it refers to.
func TestSpecExampleConfig(t *testing.T) {
	b, err := os.ReadFile("../../doc/SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(b), "Example of the merged configuration:\n\n```yaml\n")
	ex, _, ok2 := strings.Cut(rest, "\n```\n")
	if !ok || !ok2 || !strings.Contains(ex, "auth: {...}") {
		t.Fatal("example not found")
	}
	ex = strings.Replace(ex, "auth: {...}", `auth:
  keys:
    - name: robert.socha
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"
  ca:
    - name: hosts
      type: host
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ca"`, 1)
	if _, err := Parse([]byte(ex)); err != nil {
		t.Fatal(err)
	}
}

func TestNullEntries(t *testing.T) {
	cases := map[string]string{
		"null endpoint": `
listen:
  plain: {addr: 127.0.0.1:8080}
auth:
  keys:
    - name: robert.socha
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"
endpoint:
  backup:
    listen: plain
    endpoint: /backup
    path: /queue/backup
    allow: [robert.socha]
  drop:
pipeline:
  devdb:
    endpoint: [backup]
    steps:
      - store: archive
storage:
  archive: {type: local, base: /storage/archive, path: "{{ .Sender }}/{{ .File }}"}
`,
		"null expose": `
listen:
  plain: {addr: 127.0.0.1:8080}
auth:
  keys:
    - name: robert.socha
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"
endpoint:
  backup:
    listen: plain
    endpoint: /backup
    path: /queue/backup
    allow: [robert.socha]
    respond: url
    storage: archive
pipeline:
  devdb:
    endpoint: [backup]
    steps:
      - store: archive
storage:
  archive: {type: local, base: /storage/archive, path: "{{ .Sender }}/{{ .File }}", expose: drop}
expose:
  drop:
`,
	}
	for name, yaml := range cases {
		_, err := Parse([]byte(yaml))
		if err == nil {
			t.Errorf("%s: accepted null entry", name)
		}
	}
}

func TestClockSkewLimits(t *testing.T) {
	for _, v := range []string{"-1s", "2000000h"} {
		if _, err := Parse([]byte(strings.Replace(good, "auth:\n", "auth:\n  clock_skew: "+v+"\n", 1))); err == nil || !strings.Contains(err.Error(), "clock_skew") {
			t.Errorf("clock_skew %s: %v", v, err)
		}
	}
	c, err := Parse([]byte(strings.Replace(good, "auth:\n", "auth:\n  clock_skew: 1h\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(c.Auth.ClockSkew) != time.Hour {
		t.Fatalf("%v", time.Duration(c.Auth.ClockSkew))
	}
}

func TestAuthNonces(t *testing.T) {
	if _, err := Parse([]byte(strings.Replace(good, "auth:\n", "auth:\n  nonces: run/nonces\n", 1))); err == nil || !strings.Contains(err.Error(), "auth.nonces") {
		t.Fatalf("relative: %v", err)
	}
	c, err := Parse([]byte(strings.Replace(good, "auth:\n", "auth:\n  nonces: /tmp/nonces\n", 1)))
	if err != nil || c.Auth.Nonces != "/tmp/nonces" {
		t.Fatalf("%v", err)
	}
	def, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if got := def.Restart().Changes(c.Restart()); !slices.Equal(got, []string{"auth.nonces"}) {
		t.Fatalf("changes %v", got)
	}
	old := def.Restart()
	old.Nonces = ""
	if got := old.Changes(c.Restart()); len(got) != 0 {
		t.Fatalf("running file without nonces: %v", got)
	}
}

func TestTLSCertKeySamePath(t *testing.T) {
	for _, key := range []string{"/tmp/c.crt", "/tmp/./c.crt", "/tmp//c.crt"} {
		if _, err := Parse([]byte(strings.Replace(good, "key: /tmp/c.key", "key: "+key, 1))); err == nil {
			t.Errorf("key %s: accepted", key)
		}
	}
}

const edKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n"

func TestDuplicateKeyMaterial(t *testing.T) {
	dup := strings.Replace(good, "  ca:\n", "    - name: alias\n      key: \""+edKey+" another comment\"\n  ca:\n", 1)
	_, err := Parse([]byte(dup))
	if err == nil || !strings.Contains(err.Error(), "robert.socha") || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("%v", err)
	}
}

func TestDuplicateCA(t *testing.T) {
	second := func(typ string) string {
		return strings.Replace(good, "endpoint:\n", "    - name: hosts2\n      type: "+typ+"\n      key: \""+edKey+" other\"\nendpoint:\n", 1)
	}
	_, err := Parse([]byte(second("host")))
	if err == nil || !strings.Contains(err.Error(), "hosts2") {
		t.Fatalf("same CA key and type: %v", err)
	}
	if _, err := Parse([]byte(second("user"))); err != nil {
		t.Fatalf("same CA key for host and user: %v", err)
	}
}

func TestRootDefaultAndRelative(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if c.Root != "/var/lib/luk" {
		t.Fatalf("root default %q", c.Root)
	}
	rel := strings.NewReplacer(
		"cert: /tmp/c.crt", "cert: tls/c.crt",
		"key: /tmp/c.key", "key: ./tls/../tls/c.key",
		"path: /queue/backup", "path: queue/backup",
		"base: /storage/archive", "base: storage/archive",
	).Replace("root: /srv/luk\n" + good)
	c, err = Parse([]byte(rel))
	if err != nil {
		t.Fatal(err)
	}
	tl := c.Listen["main"].TLS
	if tl.Cert != "/srv/luk/tls/c.crt" || tl.Key != "/srv/luk/tls/c.key" {
		t.Fatalf("tls %q %q", tl.Cert, tl.Key)
	}
	if got := c.Endpoint["backup"].Path; got != "/srv/luk/queue/backup" {
		t.Fatalf("endpoint path %q", got)
	}
	if got := c.Storage["archive"].Base; got != "/srv/luk/storage/archive" {
		t.Fatalf("base %q", got)
	}
	if got := c.Storage["drop"].Base; got != "/storage/drop" {
		t.Fatalf("absolute base changed: %q", got)
	}
	if got := c.Endpoint["drop"].Path; got != "/queue/drop" {
		t.Fatalf("absolute path changed: %q", got)
	}
}

func TestRootErrors(t *testing.T) {
	cases := map[string][3]string{
		"relative root":   {"root: srv\n" + good, "", "root"},
		"cert escape":     {good, "cert: /tmp/c.crt|cert: ../x", "tls.cert"},
		"path escape":     {good, "path: /queue/backup|path: ../x", "endpoint.backup.path"},
		"path nested esc": {good, "path: /queue/backup|path: queue/../../x", "endpoint.backup.path"},
		"base escape":     {good, "base: /storage/archive|base: ../x", "storage.archive.base"},
		"base nested esc": {good, "base: /storage/archive|base: queue/../../x", "storage.archive.base"},
		"cert eq key":     {good, "cert: /tmp/c.crt|cert: /var/lib/luk/tls/a\n      key: tls/a", "different files"},
	}
	for name, c := range cases {
		src := c[0]
		if c[1] != "" {
			old, repl, _ := strings.Cut(c[1], "|")
			if name == "cert eq key" {
				src = strings.Replace(src, "tls: {mode: self, cert: /tmp/c.crt, key: /tmp/c.key, host: lukd.vm}",
					"tls:\n      mode: self\n      cert: /var/lib/luk/tls/a\n      key: tls/a\n      host: lukd.vm", 1)
			} else {
				src = strings.Replace(src, old, repl, 1)
			}
		}
		_, err := Parse([]byte(src))
		if err == nil || !strings.Contains(err.Error(), c[2]) {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestLimitsDefaults(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	l := c.Limits
	if l.Conn.Max != 1024 || l.Conn.Idle != Duration(time.Minute) || l.Header.Timeout != Duration(10*time.Second) {
		t.Fatalf("%+v", l)
	}
	b := c.Endpoint["drop"].Limits.Body
	if b.Size != 0 || b.Idle != Duration(2*time.Minute) {
		t.Fatalf("%+v", b)
	}
	if ch := l.Channel; ch.Auth != Duration(time.Minute) || ch.Pending != 1024 || ch.Idle != Duration(2*time.Minute) {
		t.Fatalf("%+v", ch)
	}
	if u := l.Uploads; u.Total != 256 || u.Identity != 8 {
		t.Fatalf("%+v", u)
	}
	if b.BytesPerSecond() != 64<<10 {
		t.Fatalf("rate %d", b.BytesPerSecond())
	}
	if p := c.Endpoint["drop"].Parts; p.Size != 8<<20 || p.Parallel != 4 {
		t.Fatalf("%+v", p)
	}
}

func TestLimitsSet(t *testing.T) {
	c, err := Parse([]byte(good + "\nlimits: {conn: {max: 5, idle: 4s}, header: {timeout: 3s}, channel: {auth: 7s, pending: 1, idle: 8s}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	l := c.Limits
	if l.Conn.Max != 5 || l.Conn.Idle != Duration(4*time.Second) || l.Header.Timeout != Duration(3*time.Second) {
		t.Fatalf("%+v", l)
	}
	if ch := l.Channel; ch.Auth != Duration(7*time.Second) || ch.Pending != 1 || ch.Idle != Duration(8*time.Second) {
		t.Fatalf("%+v", ch)
	}
	c, err = Parse([]byte(strings.Replace(good, "limits: {body: {size: 50G}}", "limits: {body: {size: 1K, idle: 5s}}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	b := c.Endpoint["backup"].Limits.Body
	if b.Size != 1024 || b.Idle != Duration(5*time.Second) {
		t.Fatalf("%+v", b)
	}
	c, err = Parse([]byte(strings.Replace(good, "limits: {body: {size: 50G}}", "limits: {body: {rate: 0}}\n    parts: {size: 2097088K, parallel: 64}", 1) +
		"\nlimits: {uploads: {total: 3, identity: 2}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r := c.Endpoint["backup"].Limits.Body.BytesPerSecond(); r != 0 {
		t.Fatalf("rate %d", r)
	}
	if p := c.Endpoint["backup"].Parts; p.Size != 2<<30-64<<10 || p.Parallel != 64 {
		t.Fatalf("%+v", p)
	}
	if u := c.Limits.Uploads; u.Total != 3 || u.Identity != 2 {
		t.Fatalf("%+v", u)
	}
}

// TestBodyTimeoutUnknown: limits.body.timeout bounded the single upload
// request, which parts replaced; like any unknown key it is an error.
func TestBodyTimeoutUnknown(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(good, "limits: {body: {size: 50G}}", "limits: {body: {size: 50G, timeout: 1h}}", 1)))
	if err == nil || !strings.Contains(err.Error(), "field timeout not found") {
		t.Fatalf("got %v", err)
	}
}

func TestPartsInvalid(t *testing.T) {
	for _, p := range []string{"size: 32K", "size: 100K", "size: 2G", "parallel: 65", "parallel: -1"} {
		text := strings.Replace(good, "limits: {body: {size: 50G}}", "limits: {body: {size: 50G}}\n    parts: {"+p+"}", 1)
		if _, err := Parse([]byte(text)); err == nil || !strings.Contains(err.Error(), "parts.") {
			t.Fatalf("%s: %v", p, err)
		}
	}
}

func TestLimitsInvalid(t *testing.T) {
	for _, l := range []string{"conn: {max: -1}", "conn: {idle: -1s}", "header: {timeout: -1s}",
		"channel: {auth: -1s}", "channel: {idle: -1s}", "channel: {pending: -1}",
		"uploads: {total: -1}", "uploads: {identity: -1}"} {
		if _, err := Parse([]byte(good + "\nlimits: {" + l + "}\n")); err == nil || !strings.Contains(err.Error(), "limits.") {
			t.Fatalf("%s: %v", l, err)
		}
	}
	for _, b := range []string{"idle: -1s"} {
		text := strings.Replace(good, "limits: {body: {size: 50G}}", "limits: {body: {"+b+"}}", 1)
		if _, err := Parse([]byte(text)); err == nil || !strings.Contains(err.Error(), "limits.body.") {
			t.Fatalf("%s: %v", b, err)
		}
	}
}

func TestLogLevel(t *testing.T) {
	for text, want := range map[string]slog.Level{
		"": slog.LevelInfo, "log: {level: debug}": slog.LevelDebug, "log: {level: info}": slog.LevelInfo,
		"log: {level: warn}": slog.LevelWarn, "log: {level: error}": slog.LevelError,
	} {
		c, err := Parse([]byte(good + "\n" + text + "\n"))
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if got := c.LogLevel(); got != want {
			t.Errorf("%s: %v, want %v", text, got, want)
		}
	}
	for _, l := range []string{"trace", "DEBUG", "warning"} {
		if _, err := Parse([]byte(good + "\nlog: {level: " + l + "}\n")); err == nil || !strings.Contains(err.Error(), "log.level") {
			t.Errorf("%s: %v", l, err)
		}
	}
}

func TestLocalStoragePath(t *testing.T) {
	for name, repl := range map[string]string{
		"missing":      `drop: {type: local, base: /storage/drop, expose: drop}`,
		"bad template": `drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random", expose: drop}`,
	} {
		src := strings.Replace(good, `drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop}`, repl, 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "storage drop") {
			t.Errorf("%s: %v", name, err)
		}
	}
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage["archive"].PathTemplate() == nil || c.Storage["drop"].PathTemplate() == nil {
		t.Fatal("template not parsed")
	}
	var b strings.Builder
	if err := c.Storage["archive"].PathTemplate().Execute(&b, map[string]string{"Sender": "s", "File": "f"}); err != nil || b.String() != "s/f" {
		t.Fatalf("%q %v", b.String(), err)
	}
	if err := c.Storage["archive"].PathTemplate().Execute(&b, map[string]string{"Sender": "s"}); err == nil {
		t.Fatal("missing key not an error")
	}
}

func TestConflict(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage["archive"].Conflict != "version" {
		t.Fatalf("default %q", c.Storage["archive"].Conflict)
	}
	for _, v := range []string{"version", "reject", "replace"} {
		src := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", conflict: `+v+`}`, 1)
		c, err := Parse([]byte(src))
		if err != nil || c.Storage["archive"].Conflict != v {
			t.Errorf("%s: %v", v, err)
		}
	}
	src := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", conflict: merge}`, 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("bad conflict: %v", err)
	}
}

func TestCleanupAge(t *testing.T) {
	src := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", cleanup: {age: 14d}}`, 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(c.Storage["archive"].Cleanup.Age) != 14*24*time.Hour {
		t.Fatalf("%v", c.Storage["archive"].Cleanup.Age)
	}
	src = strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", cleanup: {policy: old}}`, 1)
	if _, err := Parse([]byte(src)); err == nil {
		t.Fatal("policy accepted")
	}
	for _, v := range []string{"cleanup: {age: -1h}", "ttl: {max: -1h}"} {
		src = strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", `+v+`}`, 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "must be positive") {
			t.Errorf("%s: %v", v, err)
		}
	}
}

func TestLifetimeNeedsLocal(t *testing.T) {
	for _, ttl := range []string{"{max: 1d}", "{user: true}"} {
		src := strings.Replace(good, "storage:\n", "storage:\n  off: {type: s3, bucket: b, ttl: "+ttl+"}\n", 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "storage off: ttl and cleanup.age need a local storage") {
			t.Errorf("%s: %v", ttl, err)
		}
	}
}

func TestTTLPolicyErrors(t *testing.T) {
	for ttl, want := range map[string]string{
		"{min: 1h, max: 7d}":             "storage drop: ttl.min needs ttl.user",
		"{user: true, min: 8d, max: 7d}": "storage drop: ttl.min must not exceed ttl.max",
		"{user: true, min: -1h}":         "storage drop: ttl.min must be positive",
	} {
		src := strings.Replace(good, "ttl: {user: true, max: 7d}", "ttl: "+ttl, 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", ttl, err)
		}
	}
	for _, ttl := range []string{"{user: true, min: 1h}", "{user: true, min: 7d, max: 7d}", "{user: true}", "{max: 21d}"} {
		src := strings.Replace(good, "ttl: {user: true, max: 7d}", "ttl: "+ttl, 1)
		if _, err := Parse([]byte(src)); err != nil {
			t.Errorf("%s: %v", ttl, err)
		}
	}
}

func TestStorageLifetime(t *testing.T) {
	const h, d = time.Hour, 24 * time.Hour
	policy := func(user bool, lo, hi time.Duration) *Storage {
		s := &Storage{}
		s.TTL.User, s.TTL.Min, s.TTL.Max = user, Duration(lo), Duration(hi)
		return s
	}
	for _, tc := range []struct {
		name   string
		st     *Storage
		client string
		want   time.Duration
		note   string
	}{
		{"inside", policy(true, h, 7*d), "2d", 2 * d, ""},
		{"above max", policy(true, h, 7*d), "60d", 7 * d, wire.TTLCapped},
		{"below min", policy(true, 3*d, 7*d), "1d", 3 * d, wire.TTLRaised},
		{"no client ttl", policy(true, h, 7*d), "", 7 * d, ""},
		{"no min", policy(true, 0, 7*d), "1m", time.Minute, ""},
		{"no max", policy(true, h, 0), "90d", 90 * d, ""},
		{"no bounds, no client ttl", policy(true, 0, 0), "", 0, ""},
		{"max", policy(true, h, 7*d), wire.TTLMax, 7 * d, ""},
		{"max, no max", policy(true, h, 0), wire.TTLMax, 0, ""},
		{"user false", policy(false, 0, 21*d), "1d", 21 * d, wire.TTLIgnored},
		{"user false, max", policy(false, 0, 21*d), wire.TTLMax, 21 * d, wire.TTLIgnored},
		{"user false, no client ttl", policy(false, 0, 21*d), "", 21 * d, ""},
		{"user false, no max", policy(false, 0, 0), "1d", 0, wire.TTLIgnored},
	} {
		if got, note := tc.st.Lifetime(tc.client); got != tc.want || note != tc.note {
			t.Errorf("%s: %v %q, want %v %q", tc.name, got, note, tc.want, tc.note)
		}
	}
}

func TestExposeLifetimeMoved(t *testing.T) {
	for _, tc := range []struct{ add, want string }{
		{"    ttl: {max: 7d}\n", "expose drop: ttl moved to storage.drop.ttl.max"},
		{"    cleanup: {age: 14d}\n", "expose drop: cleanup moved to storage.drop.cleanup.age"},
	} {
		src := strings.Replace(good, "    path: /d/\n", "    path: /d/\n"+tc.add, 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v", tc.add, err)
		}
	}
}

func TestPipelineQueue(t *testing.T) {
	devdb := "    timeout: 2h\n"
	c, err := Parse([]byte(strings.Replace(good, devdb, devdb+"    queue: {group: backup, order: 2, concurrency: 3}\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if q := c.Pipeline["devdb"].Queue; q != (Queue{Group: "backup", Order: 2, Concurrency: 3}) {
		t.Fatalf("%+v", q)
	}
	for _, tc := range []struct{ add, want string }{
		{"    concurrency: 1\n", "pipeline devdb: concurrency moved to queue.concurrency"},
		{"    queue: {concurrency: -1}\n", "pipeline devdb: negative queue.concurrency or timeout"},
		{"    queue: {group: backup, order: -1}\n", "pipeline devdb: queue.order must not be negative"},
		{"    queue: {order: 1}\n", "pipeline devdb: queue.order needs queue.group"},
		{"    queue: {group: .x}\n", "queue.group \".x\": the name must be of"},
		{"    queue: {group: a/b}\n", "queue.group \"a/b\": the name must be of"},
		{"    queue: {group: \"a\\nb\"}\n", "queue.group \"a\\nb\": the name must be of"},
	} {
		if _, err := Parse([]byte(strings.Replace(good, devdb, devdb+tc.add, 1))); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v", tc.add, err)
		}
	}
}

func TestQueueReserve(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits.Queue.Reserve != 1<<30 {
		t.Fatalf("default %d", c.Limits.Queue.Reserve)
	}
	c, err = Parse([]byte(good + "\nlimits: {queue: {reserve: 5M}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits.Queue.Reserve != 5<<20 {
		t.Fatalf("set %d", c.Limits.Queue.Reserve)
	}
}

func TestExposeHelpers(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	x, ok := c.ExposeOf("drop")
	if u, _ := c.ExposeURL("drop"); !ok || x.Path != "/d/" || u != "https://lukd.vm:8443/d/" {
		t.Fatalf("%+v %v %q", x, ok, u)
	}
	if _, ok := c.ExposeOf("archive"); ok {
		t.Fatal("archive is not exposed")
	}
	if _, ok := c.ExposeOf("nope"); ok {
		t.Fatal("unknown storage")
	}
	name, st, ok := c.StorageOfExpose("drop")
	if !ok || name != "drop" || st != c.Storage["drop"] {
		t.Fatalf("%q %v", name, ok)
	}
	if _, _, ok := c.StorageOfExpose("nope"); ok {
		t.Fatal("unknown expose")
	}
}

func TestTwoStoragesOneExpose(t *testing.T) {
	src := strings.Replace(good, `archive: {type: local, base: /storage/archive, path: "{{ .Sender }}/{{ .File }}"}`,
		`archive: {type: local, base: /storage/archive, path: "{{ .Sender }}/{{ .File }}", expose: drop}`, 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "expose drop") {
		t.Fatalf("%v", err)
	}
}

func TestWarnings(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("%v", w)
	}
	src := strings.Replace(good, "endpoint:\n  backup:", "endpoint:\n  test:\n    listen: main\n    endpoint: /test\n    path: /storage/test\n    allow: [robert.socha]\n  backup:", 1)
	c, err = Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	w := c.Warnings()
	if len(w) != 1 || w[0] != "endpoint test: no pipeline uses it" {
		t.Fatalf("%v", w)
	}
}

func TestWarningVersionWithoutUniqueName(t *testing.T) {
	src := strings.Replace(good, `path: "{{ .Random }}", expose: drop}`, `path: "{{ .File }}", expose: drop}`, 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	w := c.Warnings()
	if len(w) != 1 || !strings.Contains(w[0], "storage drop") || !strings.Contains(w[0], "conflict version") {
		t.Fatalf("%v", w)
	}
	for _, p := range []string{`{{ .Id }}/{{ .File }}`, `{{ .Random }}`} {
		s := strings.Replace(good, `path: "{{ .Random }}", expose: drop}`, `path: "`+p+`", expose: drop}`, 1)
		if c, err := Parse([]byte(s)); err != nil || len(c.Warnings()) != 0 {
			t.Errorf("%s: %v %v", p, err, c.Warnings())
		}
	}
	s := strings.Replace(src, `path: "{{ .File }}", expose: drop}`, `path: "{{ .File }}", conflict: reject, expose: drop}`, 1)
	if c, err := Parse([]byte(s)); err != nil || len(c.Warnings()) != 0 {
		t.Errorf("reject: %v %v", err, c.Warnings())
	}
}

// An expose with index never serves a sharded storage: its listings would
// read every hash directory.
func TestIndexShard(t *testing.T) {
	src := strings.Replace(good, "    path: /d/\n", "    path: /d/\n    index: true\n", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
	shard := strings.Replace(src, `path: "{{ .Random }}", expose: drop}`, `path: "{{ .Random }}", shard: 2, expose: drop}`, 1)
	if _, err := Parse([]byte(shard)); err == nil || !strings.Contains(err.Error(), "storage drop: shard on expose drop with index") {
		t.Fatalf("want shard error, got %v", err)
	}
	noIndex := strings.Replace(good, `path: "{{ .Random }}", expose: drop}`, `path: "{{ .Random }}", shard: 2, expose: drop}`, 1)
	if _, err := Parse([]byte(noIndex)); err != nil {
		t.Fatal(err)
	}
}

func TestExposeOverlapsEndpoint(t *testing.T) {
	for _, p := range []string{"/drop/", "/drop/x/", "/"} {
		src := strings.Replace(good, "path: /d/", "path: "+p, 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "overlaps") {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"/d/", "/dropx/"} {
		src := strings.Replace(good, "path: /d/", "path: "+p, 1)
		if _, err := Parse([]byte(src)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	src := strings.Replace(good, "    listen: main\n    path: /d/", "    listen: plain\n    path: /", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Errorf("root path on a listener without endpoints: %v", err)
	}
}

func TestPathTemplateUnknownKey(t *testing.T) {
	old := `path: "{{ .Sender }}/{{ .File }}"}`
	src := strings.Replace(good, old, `path: "{{ .Sendr }}/{{ .File }}"}`, 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "storage archive") || !strings.Contains(err.Error(), "path") {
		t.Fatalf("typo: %v", err)
	}
	all := `path: "{{ .Sender }}/{{ .Endpoint }}/{{ .Year }}/{{ .Month }}/{{ .Day }}/{{ .Hour }}{{ .Minute }}{{ .Seconds }}/{{ .Id }}/{{ .Random }}/{{ .File }}/{{ .Tags }}/{{ .Hostname }}/{{ .Origin }}"}`
	if _, err := Parse([]byte(strings.Replace(good, old, all, 1))); err != nil {
		t.Fatalf("valid keys: %v", err)
	}
}

func TestStorageOverlap(t *testing.T) {
	for name, c := range map[string]struct{ old, new, want string }{
		"same base":      {"base: /storage/drop,", "base: /storage/archive,", "storage archive and drop"},
		"nested base":    {"base: /storage/drop,", "base: /storage/archive/drop,", "storage archive and drop"},
		"parent base":    {"base: /storage/archive,", "base: /storage,", "storage archive and drop"},
		"queue in base":  {"path: /queue/drop", "path: /storage/drop/queue", "endpoint drop: path"},
		"base in queue":  {"path: /queue/drop", "path: /storage", "endpoint drop: path"},
		"queue is base":  {"path: /queue/backup", "path: /storage/archive/", "endpoint backup: path"},
		"relative match": {"base: /storage/drop,", "base: queue/x/..,", "overlaps storage drop"},
	} {
		src := strings.Replace(good, c.old, c.new, 1)
		if name == "relative match" {
			src = "root: /\n" + src
		}
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	src := strings.Replace(good, "base: /storage/drop,", "base: /storage/archive2,", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Errorf("sibling with common prefix: %v", err)
	}
}

func TestExposePathsOverlap(t *testing.T) {
	add := func(listen, p string) string {
		return strings.Replace(good, "    path: /d/\n", "    path: /d/\n  other:\n    listen: "+listen+"\n    path: "+p+"\n", 1)
	}
	if _, err := Parse([]byte(add("main", "/d/"))); err == nil || !strings.Contains(err.Error(), "expose drop and other: path /d/ used twice on listen main") {
		t.Errorf("same path: %v", err)
	}
	for _, p := range []string{"/e/", "/dx/", "/d/x/"} {
		if _, err := Parse([]byte(add("main", p))); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if _, err := Parse([]byte(add("plain", "/"))); err != nil {
		t.Errorf("other listener: %v", err)
	}
}

// TestExposePathsNested: an expose nested in another on a listener they
// share reserves its path in the storage of the outer one, as seen from
// that storage's expose and protect; on separate listeners nothing is
// reserved.
func TestExposePathsNested(t *testing.T) {
	src := strings.NewReplacer(
		"    path: /d/\n", "    path: /d/\n  inner:\n    listen: main\n    path: /d/v/w/\n  sib:\n    listen: main\n    path: /e/\n",
		"storage:\n", "storage:\n  inner: {type: local, base: /storage/inner, path: x, expose: inner}\n  sib: {type: local, base: /storage/sib, path: x, expose: sib}\n",
	).Replace(good)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if n := c.Storage["drop"].Nested(); !slices.Equal(n, []string{"v/w/"}) {
		t.Fatalf("drop nested %q", n)
	}
	for _, sn := range []string{"inner", "sib", "archive"} {
		if n := c.Storage[sn].Nested(); len(n) != 0 {
			t.Fatalf("%s nested %q", sn, n)
		}
	}
	c, err = Parse([]byte(strings.Replace(src, "  inner:\n    listen: main\n", "  inner:\n    listen: plain\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if n := c.Storage["drop"].Nested(); len(n) != 0 {
		t.Fatalf("other listener nested %q", n)
	}
	src = strings.Replace(privateGood, "storage:\n", "storage:\n  inner: {type: local, base: /storage/inner, path: x, expose: inner}\n", 1) +
		"  inner:\n    listen: main\n    path: /s/in/\n"
	if c, err = Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
	if n := c.Storage["drop"].Nested(); !slices.Equal(n, []string{"in/"}) {
		t.Fatalf("protect nested %q", n)
	}
}

func TestBasicAuthHash(t *testing.T) {
	const x = "    path: /d/\n"
	ok := []string{
		"dev:$2y$05$TpFzQdt1oY6UgSKCZGgt8eCbBXDAuiQxNl13XDuDnYKUSuIC9O79W",
		"dev:$2a$05$TpFzQdt1oY6UgSKCZGgt8eCbBXDAuiQxNl13XDuDnYKUSuIC9O79W",
	}
	for _, b := range ok {
		src := strings.Replace(good, x, x+"    auth: {basic: ['"+b+"']}\n", 1)
		if _, err := Parse([]byte(src)); err != nil {
			t.Errorf("%s: %v", b, err)
		}
	}
	for _, b := range []string{"dev:$2y$05$...", "dev:plain", "dev:$2y$99$TpFzQdt1oY6UgSKCZGgt8eCbBXDAuiQxNl13XDuDnYKUSuIC9O79W"} {
		src := strings.Replace(good, x, x+"    auth: {basic: ['"+b+"']}\n", 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "expose drop") {
			t.Errorf("%s: %v", b, err)
		}
	}
}

func TestCatalog(t *testing.T) {
	src := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", catalog: true}`, 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Storage["archive"].Catalog || c.Storage["drop"].Catalog {
		t.Fatalf("catalog %v %v", c.Storage["archive"].Catalog, c.Storage["drop"].Catalog)
	}
	src = strings.Replace(good, `  drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop}`,
		"  drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: \"{{ .Random }}\", expose: drop}\n  off: {type: s3, bucket: b, catalog: true}", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "catalog") {
		t.Fatalf("s3 catalog: %v", err)
	}
}

func TestRandom(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil || c.Storage["drop"].Random != (Random{}) {
		t.Fatalf("default: %v %+v", err, c.Storage["drop"].Random)
	}
	drop := `  drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop}`
	with := func(random string) string {
		return strings.Replace(good, drop, `  drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop, random: `+random+`}`, 1)
	}
	for random, want := range map[string]Random{
		`{alphabet: "abcdefghjkmnpqrstuvwxyz23456789"}`:             {"abcdefghjkmnpqrstuvwxyz23456789", 26},
		`{alphabet: "abcdefghjkmnpqrstuvwxyz23456789", length: 40}`: {"abcdefghjkmnpqrstuvwxyz23456789", 40},
		`{alphabet: "01"}`:                    {"01", 128},
		`{alphabet: "0123456789abcdef"}`:      {"0123456789abcdef", 32},
		`{length: 30}`:                        {RandomAlphabet, 30},
		`{alphabet: "AZaz09_~-", length: 41}`: {"AZaz09_~-", 41},
	} {
		c, err := Parse([]byte(with(random)))
		if err != nil || c.Storage["drop"].Random != want {
			t.Errorf("%s: %v %+v", random, err, c.Storage["drop"])
		}
	}
	for random, msg := range map[string]string{
		`{alphabet: "abca"}`:                         `character 'a' is repeated`,
		`{alphabet: "ab/cd"}`:                        `character '/' is not one of`,
		`{alphabet: "ab.cd"}`:                        `character '.' is not one of`,
		`{alphabet: "ab%cd"}`:                        `character '%' is not one of`,
		`{alphabet: "ab cd"}`:                        `character ' ' is not one of`,
		`{alphabet: "a"}`:                            "at least 2 characters",
		`{alphabet: "0123456789abcdef", length: 31}`: "length 31 gives 124.0 bits, under 128; the minimum length for this alphabet is 32",
		`{length: 22}`:                               "minimum length for this alphabet is 23",
		`{alphabet: "01", length: 129}`:              "length must be 1 to 128",
		`{length: -1}`:                               "length must be 1 to 128",
		`{alphabet: "ab", bits: 1}`:                  "bits not found",
	} {
		if _, err := Parse([]byte(with(random))); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v", random, err)
		}
	}
	src := drop + "\n  off: {type: s3, bucket: b, random: {length: 30}}"
	if _, err := Parse([]byte(strings.Replace(good, drop, src, 1))); err == nil || !strings.Contains(err.Error(), "random needs a local storage") {
		t.Errorf("s3: %v", err)
	}
}

func TestPretty(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil || c.Endpoint["drop"].Pretty != nil {
		t.Fatalf("default: %v %+v", err, c.Endpoint["drop"].Pretty)
	}
	const drop = "    storage: drop\n"
	with := func(pretty string) string {
		return strings.Replace(good, drop, drop+"    pretty: "+pretty+"\n", 1)
	}
	for pretty, want := range map[string]int{
		"{allow: ['*']}":            64,
		"{bits: 0, allow: ['*']}":   64,
		"{bits: 64, allow: ['*']}":  64,
		"{bits: 65, allow: ['*']}":  80,
		"{bits: 100, allow: ['*']}": 112,
		"{bits: 113, allow: ['*']}": 128,
		"{bits: 128, allow: ['*']}": 128,
	} {
		c, err := Parse([]byte(with(pretty)))
		if err != nil || c.Endpoint["drop"].Pretty == nil || c.Endpoint["drop"].Pretty.Bits != want {
			t.Errorf("%s: %v %+v", pretty, err, c.Endpoint["drop"])
		}
	}
	for pretty, msg := range map[string]string{
		"{bits: 63, allow: ['*']}":  "endpoint drop: pretty.bits must be 64 to 128",
		"{bits: 16, allow: ['*']}":  "endpoint drop: pretty.bits must be 64 to 128",
		"{bits: -1, allow: ['*']}":  "endpoint drop: pretty.bits must be 64 to 128",
		"{bits: 129, allow: ['*']}": "endpoint drop: pretty.bits must be 64 to 128",
		"{size: 64}":                "field size not found",
	} {
		if _, err := Parse([]byte(with(pretty))); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v", pretty, err)
		}
	}
	src := strings.Replace(good, "    limits: {body: {size: 50G}}\n", "    limits: {body: {size: 50G}}\n    pretty: {allow: ['*']}\n", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "endpoint backup: pretty needs respond url") {
		t.Errorf("accept: %v", err)
	}
	for _, path := range []string{`{{ .Id }}`, `{{ if false }}{{ .Random }}{{ end }}{{ .Id }}`} {
		src := strings.Replace(with("{allow: ['*']}"), `path: "{{ .Random }}", expose: drop`, `path: "`+path+`", expose: drop`, 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "endpoint drop: pretty needs a path of storage drop that uses .Random") {
			t.Errorf("%s: %v", path, err)
		}
	}
	src = strings.Replace(with("{allow: ['*']}"), `path: "{{ .Random }}", expose: drop`, `path: "{{ .Year }}{{ .Month }}{{ .Day }}/{{ .Random }}.bin", expose: drop`, 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Errorf("nested .Random: %v", err)
	}
}

func TestShard(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil || c.Storage["drop"].Shard != 0 {
		t.Fatalf("default: %v", err)
	}
	drop := `  drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop}`
	src := strings.Replace(good, drop, `  drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop, shard: 4}`, 1)
	if c, err := Parse([]byte(src)); err != nil || c.Storage["drop"].Shard != 4 {
		t.Fatalf("shard 4: %v", err)
	}
	for _, bad := range []string{
		`  drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop, shard: 5}`,
		`  drop: {type: local, base: /storage/drop, ttl: {user: true, max: 7d}, path: "{{ .Random }}", expose: drop, shard: -1}`,
		drop + "\n  off: {type: s3, bucket: b, shard: 1}",
	} {
		if _, err := Parse([]byte(strings.Replace(good, drop, bad, 1))); err == nil || !strings.Contains(err.Error(), "shard") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func hasWarning(w []string, parts ...string) bool {
	for _, s := range w {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(s, p)
		}
		if all {
			return true
		}
	}
	return false
}

func TestWarningRunBeforeURLStore(t *testing.T) {
	src := strings.Replace(good, "  drop:\n    endpoint: [drop]\n    steps:\n      - store: drop\n",
		"  drop:\n    endpoint: [drop]\n    steps:\n      - run: /opt/luk/zip\n      - store: drop\n", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); !hasWarning(w, "endpoint drop", "pipeline drop", "run step") {
		t.Fatalf("%v", w)
	}
}

// A tee step passes the set on unchanged: the stores after it get the
// names of the steps before it.
func TestWarningTeeKeepsNames(t *testing.T) {
	src := strings.Replace(good, "  drop:\n    endpoint: [drop]\n    steps:\n      - store: drop\n",
		"  drop:\n    endpoint: [drop]\n    steps:\n      - run: /opt/luk/s3copy\n        tee: true\n      - store: drop\n", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("%v", w)
	}
	src = strings.Replace(src, "        tee: true\n", "", 1)
	if c, err = Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); !hasWarning(w, "endpoint drop", "pipeline drop", "run step") {
		t.Fatalf("%v", w)
	}
}

// A relay step passes the set on like a tee step: the stores after it get
// the names of the steps before it.
func TestWarningRelayKeepsNames(t *testing.T) {
	src := strings.Replace(good, "  drop:\n    endpoint: [drop]\n    steps:\n      - store: drop\n",
		"  drop:\n    endpoint: [drop]\n    steps:\n      - relay: s3-upload\n      - store: drop\n", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("%v", w)
	}
	if s := c.Pipeline["drop"].Steps[0]; s.Relay != "s3-upload" || s.Run != "" {
		t.Fatalf("%+v", s)
	}
}

func TestRelayStep(t *testing.T) {
	for step, want := range map[string]string{
		"      - relay: S3\n":                                 `step 1: relay "S3": invalid job name`,
		"      - relay: .hidden\n":                            `step 1: relay ".hidden": invalid job name`,
		"      - relay: a/b\n":                                `step 1: relay "a/b": invalid job name`,
		"      - relay: " + strings.Repeat("a", 65) + "\n":    "invalid job name",
		"      - relay: s3-upload\n        tee: true\n":       "step 1: relay takes no tee or env",
		"      - relay: s3-upload\n        env: {A: b}\n":     "step 1: relay takes no tee or env",
		"      - relay: s3-upload\n        run: /opt/luk/x\n": "step 1 needs exactly one of run, store, encrypt or relay",
		"      - relay: s3-upload\n        store: drop\n":     "step 1 needs exactly one of run, store, encrypt or relay",
	} {
		src := strings.Replace(good, "    steps:\n      - store: drop\n", "    steps:\n"+step+"      - store: drop\n", 1)
		_, err := Parse([]byte(src))
		if err == nil || !strings.Contains(err.Error(), "pipeline drop: ") || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", step, want, err)
		}
		if err != nil && strings.Contains(err.Error(), "tee needs run") {
			t.Errorf("%q: %v", step, err)
		}
	}
	src := strings.Replace(good, "    steps:\n      - store: drop\n", "    steps:\n      - relay: s3-upload.v2_x\n      - store: drop\n", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
}

func TestTeeNeedsRun(t *testing.T) {
	for _, step := range []string{"      - store: drop\n        tee: true\n", "      - encrypt: {key: [robert@example.com]}\n        tee: true\n      - store: drop\n"} {
		src := strings.Replace(good, "    steps:\n      - store: drop\n", "    steps:\n"+step, 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "pipeline drop: step 1: tee needs run") {
			t.Fatalf("%q: %v", step, err)
		}
	}
	src := strings.Replace(good, "    steps:\n      - store: drop\n", "    steps:\n      - store: drop\n        tee: false\n", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
}

func TestWarningRunIntoPathWithoutName(t *testing.T) {
	src := strings.Replace(good, `archive: {type: local, base: /storage/archive, path: "{{ .Sender }}/{{ .File }}"}`,
		`archive: {type: local, base: /storage/archive, path: "{{ .Sender }}/{{ .Year }}{{ .Month }}{{ .Day }}"}`, 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); len(w) != 1 || !hasWarning(w, "pipeline devdb", "storage archive", ".File") {
		t.Fatalf("%v", w)
	}
	for _, p := range []string{"{{ .Random }}", "{{ .Sender }}/{{ .Id }}"} {
		s := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "`+p+`"}`, 1)
		c, err := Parse([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if w := c.Warnings(); !hasWarning(w, "pipeline devdb", "storage archive", ".File") {
			t.Errorf("%s: %v", p, w)
		}
	}
}

func TestWarningCatalogWithoutAuth(t *testing.T) {
	src := strings.Replace(good, `path: "{{ .Random }}", expose: drop}`, `path: "{{ .Random }}", expose: drop, catalog: true}`, 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); len(w) != 1 || !hasWarning(w, "storage drop", "catalog", "auth") {
		t.Fatalf("%v", w)
	}
	src = strings.Replace(src, "    path: /d/\n", "    path: /d/\n    auth: {basic: [\"u:$2y$10$abcdefghijklmnopqrstuuJ0x5N2mXv0g8y2t1R8vQ5b9nJ0mJ2e6\"]}\n", 1)
	c, err = Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("%v", w)
	}
	if _, err := Parse([]byte(strings.Replace(src, "    auth: {", "    plain: true\n    auth: {", 1))); err == nil || !strings.Contains(err.Error(), "plain excludes auth") {
		t.Fatalf("plain with auth: %v", err)
	}
	src = strings.Replace(src, "    auth: {basic: [\"u:$2y$10$abcdefghijklmnopqrstuuJ0x5N2mXv0g8y2t1R8vQ5b9nJ0mJ2e6\"]}\n", "    plain: true\n", 1)
	c, err = Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("plain: %v", w)
	}
}

func TestWarningIndexWithoutAuth(t *testing.T) {
	src := strings.Replace(good, "    path: /d/\n", "    path: /d/\n    index: true\n", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.Warnings(); len(w) != 1 || !hasWarning(w, "expose drop", "index", "auth") {
		t.Fatalf("%v", w)
	}
	for _, mod := range []string{"    plain: true\n", "    auth: {basic: [\"u:$2y$10$abcdefghijklmnopqrstuuJ0x5N2mXv0g8y2t1R8vQ5b9nJ0mJ2e6\"]}\n"} {
		c, err := Parse([]byte(strings.Replace(src, "    index: true\n", "    index: true\n"+mod, 1)))
		if err != nil {
			t.Fatal(err)
		}
		if w := c.Warnings(); len(w) != 0 {
			t.Errorf("%s: %v", mod, w)
		}
	}
	if _, err := Parse([]byte(strings.Replace(src, "    index: true\n", "    index: true\n    auth: {ssh: {allow: []}}\n", 1))); err == nil || !strings.Contains(err.Error(), "index excludes auth.ssh") {
		t.Fatalf("index with auth.ssh: %v", err)
	}
}

func TestTLSAlgorithm(t *testing.T) {
	for algo, want := range map[string]string{"": "ed25519", "ed25519": "ed25519", "ecdsa-p256": "ecdsa-p256"} {
		src := good
		if algo != "" {
			src = strings.Replace(good, "host: lukd.vm}", "host: lukd.vm, algorithm: "+algo+"}", 1)
		}
		c, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("%q: %v", algo, err)
		}
		if got := c.Listen["main"].TLS.Algorithm; got != want {
			t.Fatalf("%q: got %q", algo, got)
		}
	}
}

func TestListenValidation(t *testing.T) {
	const plain = "  plain:\n    addr: 127.0.0.1:8080\n"
	const second = "  second:\n    addr: 127.0.0.1:8443\n    host: [b.vm]\n    tls: {mode: self, cert: /tmp/b.crt, key: /tmp/b.key, host: b.vm}\n"
	withMain := func(extra string) string {
		return strings.Replace(good, "    tls: {mode: self, cert: /tmp/c.crt", "    host: [lukd.vm, A.vm]\n    tls: {mode: self, cert: /tmp/c.crt", 1) + "listen2:\n" + extra
	}
	// listen2 is spliced into listen below.
	splice := func(src string) string {
		i := strings.Index(src, "listen2:\n")
		extra := src[i+len("listen2:\n"):]
		src = src[:i]
		return strings.Replace(src, plain, plain+extra, 1)
	}
	bad := map[string]string{
		"no addr port":         strings.Replace(good, "addr: 127.0.0.1:8080", "addr: 127.0.0.1", 1),
		"unknown endpoint ref": strings.Replace(good, "    listen: main\n    endpoint: /backup", "    listen: nope\n    endpoint: /backup", 1),
		"unknown expose ref":   strings.Replace(good, "    listen: main\n    path: /d/", "    listen: [main, nope]\n    path: /d/", 1),
		"missing endpoint ref": strings.Replace(good, "    listen: main\n    endpoint: /backup", "    endpoint: /backup", 1),
		"missing expose ref":   strings.Replace(good, "    listen: main\n    path: /d/", "    path: /d/", 1),
		"shared no host":       splice(withMain(strings.Replace(second, "    host: [b.vm]\n", "", 1))),
		"shared host overlap":  splice(withMain(strings.Replace(second, "[b.vm]", "[a.VM]", 1))),
		"shared tls and plain": splice(withMain("  second:\n    addr: 127.0.0.1:8443\n    host: [b.vm]\n")),
		"shared cert":          splice(withMain(strings.Replace(second, "cert: /tmp/b.crt", "cert: /tmp/c.crt", 1))),
		"public with path":     strings.Replace(good, "addr: 127.0.0.1:8080", "addr: 127.0.0.1:8080\n    public: https://x.vm/d", 1),
		"public ftp":           strings.Replace(good, "addr: 127.0.0.1:8080", "addr: 127.0.0.1:8080\n    public: ftp://x.vm", 1),
		"endpoint path twice":  strings.Replace(good, "endpoint: /drop", "endpoint: /backup", 1),
		"no public for url":    strings.Replace(strings.Replace(good, "addr: 127.0.0.1:8080", "addr: 0.0.0.0:8080", 1), "    listen: main\n    path: /d/", "    listen: plain\n    path: /d/", 1),
		"host with port":       strings.Replace(good, "addr: 127.0.0.1:8080", "addr: 127.0.0.1:8080\n    host: [a.vm:80]", 1),
	}
	for name, src := range bad {
		if src == good {
			t.Fatalf("%s: fixture unchanged", name)
		}
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	i, j := strings.Index(good, "listen:\n"), strings.Index(good, "auth:\n")
	if _, err := Parse([]byte(good[:i] + "listen: {}\n" + good[j:])); err == nil || !strings.Contains(err.Error(), "at least one listener") {
		t.Errorf("empty listen: %v", err)
	}
	c, err := Parse([]byte(splice(withMain(second))))
	if err != nil {
		t.Fatalf("two tls listeners on one address: %v", err)
	}
	if got := c.Listen["main"].Host; len(got) != 2 || got[1] != "a.vm" {
		t.Fatalf("hosts not lowercased: %v", got)
	}
	g := c.Addrs()
	if len(g) != 2 || g[0].Addr != "127.0.0.1:8443" || len(g[0].Listen) != 2 || g[0].Listen[0].Name != "main" || g[1].Listen[0].Name != "plain" {
		t.Fatalf("addrs %+v", g)
	}
	twoListeners := strings.Replace(good, "    listen: [main]\n    endpoint: /drop", "    listen: plain\n    endpoint: /backup", 1)
	if _, err := Parse([]byte(twoListeners)); err != nil {
		t.Fatalf("same endpoint path on two listeners: %v", err)
	}
}

func TestListenPublic(t *testing.T) {
	for _, c := range []struct{ listen, want string }{
		{"{addr: 0.0.0.0:443, host: [a.vm], tls: {mode: self, cert: /c, key: /k, host: t.vm}}", "https://a.vm"},
		{"{addr: 0.0.0.0:8443, tls: {mode: self, cert: /c, key: /k, host: t.vm}}", "https://t.vm:8443"},
		{"{addr: 0.0.0.0:80, host: [a.vm]}", "http://a.vm"},
		{"{addr: 127.0.0.1:8080}", "http://127.0.0.1:8080"},
		{"{addr: '[::1]:80'}", "http://[::1]"},
		{"{addr: 0.0.0.0:8080}", ""},
		{"{addr: 127.0.0.1:8081, host: [x.vm], public: 'https://drop.example.com/'}", "https://drop.example.com"},
		{"{addr: 127.0.0.1:8081, public: 'http://drop.example.com:8000'}", "http://drop.example.com:8000"},
	} {
		src := strings.Replace(good, "  plain:\n    addr: 127.0.0.1:8080\n", "  plain: "+c.listen+"\n", 1)
		cfg, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("%s: %v", c.listen, err)
		}
		if got := cfg.Listen["plain"].Public; got != c.want {
			t.Errorf("%s: public %q, want %q", c.listen, got, c.want)
		}
	}
}

func TestDedup(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil || c.Storage["archive"].Dedup != nil {
		t.Fatalf("default: %v", err)
	}
	src := strings.Replace(good, `archive: {type: local, base: /storage/archive,`, `archive: {type: local, dedup: false, base: /storage/archive,`, 1)
	if c, err = Parse([]byte(src)); err != nil || c.Storage["archive"].Dedup == nil || *c.Storage["archive"].Dedup {
		t.Fatalf("dedup false: %v", err)
	}
}

func TestLinksMax(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil || c.Storage["archive"].MaxLinks() != DefaultLinksMax {
		t.Fatalf("default: %v", err)
	}
	src := strings.Replace(good, `archive: {type: local, base: /storage/archive,`, `archive: {type: local, links: {max: 3}, base: /storage/archive,`, 1)
	if c, err = Parse([]byte(src)); err != nil || c.Storage["archive"].MaxLinks() != 3 {
		t.Fatalf("max 3: %v", err)
	}
	src = strings.Replace(good, `archive: {type: local, base: /storage/archive,`, `archive: {type: local, links: {max: -1}, base: /storage/archive,`, 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "storage archive: links.max must be at least 1") {
		t.Fatalf("negative: %v", err)
	}
	src = strings.Replace(good, "storage:\n", "storage:\n  off: {type: s3, bucket: b, links: {max: 3}}\n", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "storage off: links.max needs a local storage") {
		t.Fatalf("s3: %v", err)
	}
}

func TestHardlink(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil || c.Storage["archive"].Hardlink != nil {
		t.Fatalf("default: %v", err)
	}
	src := strings.Replace(good, `archive: {type: local, base: /storage/archive,`, `archive: {type: local, hardlink: false, base: /storage/archive,`, 1)
	if c, err = Parse([]byte(src)); err != nil || c.Storage["archive"].Hardlink == nil || *c.Storage["archive"].Hardlink {
		t.Fatalf("hardlink false: %v", err)
	}
	src = strings.Replace(good, "storage:\n", "storage:\n  off: {type: s3, bucket: b, hardlink: true}\n", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "storage off: hardlink needs a local storage") {
		t.Fatalf("s3: %v", err)
	}
}

func TestFailedAge(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Limits.Failed.MaxAge(); got != 3*24*time.Hour {
		t.Fatalf("default %v", got)
	}
	c, err = Parse([]byte(good + "\nlimits: {failed: {age: 0}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Limits.Failed.MaxAge(); got != 0 {
		t.Fatalf("zero %v", got)
	}
	c, err = Parse([]byte(good + "\nlimits: {failed: {age: 12h}}\n"))
	if err != nil || c.Limits.Failed.MaxAge() != 12*time.Hour {
		t.Fatalf("set %v", err)
	}
	if _, err := Parse([]byte(good + "\nlimits: {failed: {age: -1h}}\n")); err == nil || !strings.Contains(err.Error(), "limits.failed.age") {
		t.Fatalf("negative: %v", err)
	}
	if got := (FailedLimits{}).MaxAge(); got != DefaultFailedAge {
		t.Fatalf("unset %v", got)
	}
}

func encryptConfig(gpg, step string) string {
	return strings.Replace(good, "  drop:\n    endpoint: [drop]\n    steps:\n      - store: drop\n",
		"  drop:\n    endpoint: [drop]\n    steps:\n"+step+"      - store: drop\n", 1) + gpg
}

func TestEncryptStep(t *testing.T) {
	src := encryptConfig("gpg:\n  keys: /etc/site/lukd/gpg\n  wkd:\n    cache: 2h\n",
		"      - encrypt:\n          wkd: [Robert@Example.net, marek@example.net]\n          key: matt@example.com\n          strict: true\n")
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Pipeline["drop"].Steps[0].Encrypt
	if e == nil || !e.Strict || strings.Join(e.WKD, ",") != "robert@example.net,marek@example.net" || strings.Join(e.Key, ",") != "matt@example.com" {
		t.Fatalf("encrypt %+v", e)
	}
	if c.GPG.Keys != "/etc/site/lukd/gpg" || time.Duration(c.GPG.WKD.Cache) != 2*time.Hour {
		t.Fatalf("gpg %+v", c.GPG)
	}
	if c.GPGCacheDir() != "/var/lib/luk/gpg-cache" {
		t.Fatalf("cache dir %s", c.GPGCacheDir())
	}
	if w := c.Warnings(); !hasWarning(w, "endpoint drop", "pipeline drop", "encrypt step") || hasWarning(w, ".File") {
		t.Fatalf("warnings %v", w)
	}

	c, err = Parse([]byte(encryptConfig("", "      - encrypt: {wkd: [a@b.example]}\n")))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(c.GPG.WKD.Cache) != DefaultWKDCache || c.Pipeline["drop"].Steps[0].Encrypt.Strict {
		t.Fatalf("defaults %+v %+v", c.GPG, c.Pipeline["drop"].Steps[0].Encrypt)
	}
}

func TestEncryptValidation(t *testing.T) {
	keys := "gpg:\n  keys: /etc/site/lukd/gpg\n"
	cases := map[string][2]string{
		"no recipient":         {keys, "      - encrypt: {strict: true}\n"},
		"empty lists":          {keys, "      - encrypt: {wkd: [], key: []}\n"},
		"key without gpg.keys": {"", "      - encrypt: {key: [a@b.example]}\n"},
		"relative gpg.keys":    {"gpg:\n  keys: gpg\n", "      - encrypt: {key: [a@b.example]}\n"},
		"negative cache":       {"gpg:\n  wkd:\n    cache: -1h\n", "      - encrypt: {wkd: [a@b.example]}\n"},
		"bad address":          {keys, "      - encrypt: {wkd: [not-an-address]}\n"},
		"display name":         {keys, "      - encrypt: {wkd: ['Robert <r@b.example>']}\n"},
		"slash":                {keys, "      - encrypt: {wkd: [a/b@b.example]}\n"},
		"duplicate":            {keys, "      - encrypt: {wkd: [a@b.example, A@B.example]}\n"},
		"in both lists":        {keys, "      - encrypt: {wkd: [a@b.example], key: [A@b.example]}\n"},
		"with run":             {keys, "      - encrypt: {wkd: [a@b.example]}\n        run: /bin/true\n"},
		"with store":           {keys, "      - encrypt: {wkd: [a@b.example]}\n        store: drop\n"},
		"unknown key":          {keys, "      - encrypt: {wkd: [a@b.example], bogus: 1}\n"},
	}
	for name, r := range cases {
		if _, err := Parse([]byte(encryptConfig(r[0], r[1]))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRestartChangesAll(t *testing.T) {
	cur, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	next, err := Parse([]byte(strings.NewReplacer(
		"addr: 127.0.0.1:8080", "addr: 127.0.0.1:8081",
		"host: lukd.vm}", "host: other.vm}",
		"auth:\n", "limits: {conn: {max: 7}}\nauth:\n",
	).Replace(good)))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"listen.main.public", "listen.main.tls", "listen.plain.addr", "listen.plain.public", "limits.conn.max"}
	if got := cur.Restart().Changes(next.Restart()); !slices.Equal(got, want) {
		t.Fatalf("changes %v, want %v", got, want)
	}
	if got := cur.Restart().Changes(cur.Restart()); len(got) != 0 {
		t.Fatalf("no change: %v", got)
	}
}

// acmeConfig is good with an acme listener download on :443 and a plain
// acme: true listener http on :80; extra is spliced into download.tls.
func acmeConfig(extra string) string {
	return strings.Replace("root: /srv/luk\n"+good, "  plain:\n    addr: 127.0.0.1:8080\n",
		"  plain:\n    addr: 127.0.0.1:8080\n"+
			"  download:\n    addr: 0.0.0.0:443\n    host: [drop.example.com, Get.Example.com]\n    tls:\n      mode: acme\n"+extra+
			"  http:\n    addr: 0.0.0.0:80\n    acme: true\n", 1)
}

func TestACMEListen(t *testing.T) {
	c, err := Parse([]byte(acmeConfig("      email: ops@example.com\n")))
	if err != nil {
		t.Fatal(err)
	}
	l := c.Listen["download"]
	if l.TLS.Directory != DefaultACMEDirectory || l.TLS.Email != "ops@example.com" || l.Public != "https://drop.example.com" || l.Host[1] != "get.example.com" {
		t.Fatalf("%+v %+v", l, l.TLS)
	}
	if !c.Listen["http"].ACME || len(c.Warnings()) != 0 {
		t.Fatalf("http %+v, warnings %v", c.Listen["http"], c.Warnings())
	}
	if got := c.ACMECacheDir(l.TLS.Directory); got != "/srv/luk/acme/acme-v02.api.letsencrypt.org_directory" {
		t.Fatalf("cache dir %s", got)
	}
	if got := c.ACMECacheDir("https://acme-staging-v02.api.letsencrypt.org/directory"); got != "/srv/luk/acme/acme-staging-v02.api.letsencrypt.org_directory" {
		t.Fatalf("staging cache dir %s", got)
	}
	if got := c.ACMECacheDir("https://ca.example.com:14000/dir"); got != "/srv/luk/acme/ca.example.com_14000_dir" {
		t.Fatalf("cache dir with port %s", got)
	}
	src := strings.Replace(acmeConfig(""), "addr: 0.0.0.0:80", "addr: 0.0.0.0:8080", 1)
	if c, err = Parse([]byte(src)); err != nil || len(c.Warnings()) != 1 || !strings.Contains(c.Warnings()[0], "port 8080") {
		t.Fatalf("port warning: %v %v", err, c.Warnings())
	}
	src = strings.Replace(acmeConfig(""), "addr: 0.0.0.0:443", "addr: 0.0.0.0:8443", 1)
	if c, err = Parse([]byte(src)); err != nil || c.Listen["download"].Public != "https://drop.example.com:8443" {
		t.Fatalf("public: %v", err)
	}
}

func TestACMEValidation(t *testing.T) {
	keyFile := t.TempDir() + "/eab.key"
	if err := os.WriteFile(keyFile, []byte("not base64 !\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noHTTP := strings.Replace(acmeConfig(""), "  http:\n    addr: 0.0.0.0:80\n    acme: true\n", "", 1)
	bad := map[string]string{
		"wildcard host":      strings.Replace(acmeConfig(""), "drop.example.com,", "'*.example.com',", 1),
		"ip host":            strings.Replace(acmeConfig(""), "drop.example.com,", "192.0.2.1,", 1),
		"single label host":  strings.Replace(acmeConfig(""), "drop.example.com,", "drop,", 1),
		"no host":            strings.Replace(acmeConfig(""), "    host: [drop.example.com, Get.Example.com]\n    tls:\n      mode: acme", "    tls:\n      mode: acme", 1),
		"cert":               acmeConfig("      cert: tls/c.crt\n"),
		"algorithm":          acmeConfig("      algorithm: ecdsa-p256\n"),
		"http directory":     acmeConfig("      directory: http://ca.example.com/dir\n"),
		"bad email":          acmeConfig("      email: 'Ops <ops@example.com>'\n"),
		"eab without kid":    acmeConfig("      eab: {key: AAAA}\n"),
		"eab without key":    acmeConfig("      eab: {kid: k}\n"),
		"eab key and file":   acmeConfig("      eab: {kid: k, key: AAAA, key_file: /etc/x}\n"),
		"eab bad key":        acmeConfig("      eab: {kid: k, key: 'not base64 !'}\n"),
		"eab bad key file":   acmeConfig("      eab: {kid: k, key_file: " + keyFile + "}\n"),
		"eab missing file":   acmeConfig("      eab: {kid: k, key_file: /nonexistent/eab.key}\n"),
		"no acme listener":   noHTTP,
		"acme true no acme":  strings.Replace(acmeConfig(""), "      mode: acme\n", "      mode: self\n      cert: tls/d.crt\n      key: tls/d.key\n      host: drop.example.com\n", 1),
		"acme true and tls":  strings.Replace(acmeConfig(""), "    acme: true\n", "    acme: true\n    tls: {mode: self, cert: /tmp/h.crt, key: /tmp/h.key, host: h.vm}\n", 1),
		"acme true endpoint": strings.Replace(acmeConfig(""), "    listen: main\n    endpoint: /backup", "    listen: [main, http]\n    endpoint: /backup", 1),
		"acme true expose":   strings.Replace(acmeConfig(""), "    listen: main\n    path: /d/", "    listen: [main, http]\n    path: /d/", 1),
		"email on self":      strings.Replace(good, "host: lukd.vm}", "host: lukd.vm, email: ops@example.com}", 1),
		"eab on files":       strings.Replace(good, "tls: {mode: self, cert: /tmp/c.crt, key: /tmp/c.key, host: lukd.vm}", "tls: {mode: files, cert: /tmp/c.crt, key: /tmp/c.key, eab: {kid: k, key: AAAA}}", 1),
		"same directory, other email": strings.Replace(acmeConfig("      email: a@example.com\n"), "  http:\n",
			"  other:\n    addr: 0.0.0.0:8443\n    host: [o.example.com]\n    tls: {mode: acme, email: b@example.com}\n  http:\n", 1),
	}
	for name, src := range bad {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(noHTTP)); err == nil || !strings.Contains(err.Error(), "listen download: tls mode acme needs a plain listener with acme: true") {
		t.Errorf("no acme: true listener: %v", err)
	}
	// Different directories may differ.
	src := strings.Replace(acmeConfig("      email: a@example.com\n"), "  http:\n",
		"  other:\n    addr: 0.0.0.0:8443\n    host: [o.example.com]\n    tls: {mode: acme, email: b@example.com, directory: 'https://acme-staging-v02.api.letsencrypt.org/directory'}\n  http:\n", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatalf("two directories: %v", err)
	}
}

func TestACMEEAB(t *testing.T) {
	keyFile := t.TempDir() + "/eab.key"
	if err := os.WriteFile(keyFile, []byte("c2VjcmV0LWtleQ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inline, err := Parse([]byte(acmeConfig("      eab: {kid: k1, key: c2VjcmV0LWtleQ}\n")))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse([]byte(acmeConfig("      eab: {kid: k1, key_file: " + keyFile + "}\n")))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Config{inline, file} {
		e := c.Listen["download"].TLS.EAB
		if mac, err := e.MAC(); err != nil || string(mac) != "secret-key" || e.KeySum == "" {
			t.Fatalf("%+v: %q %v", e, mac, err)
		}
	}
	if inline.Listen["download"].TLS.EAB.KeySum != file.Listen["download"].TLS.EAB.KeySum {
		t.Fatal("same key, different sums")
	}
	// Standard base64 with padding is accepted too.
	if c, err := Parse([]byte(acmeConfig("      eab: {kid: k1, key: 'c2VjcmV0LWtleQ=='}\n"))); err != nil {
		t.Fatal(err)
	} else if mac, _ := c.Listen["download"].TLS.EAB.MAC(); string(mac) != "secret-key" {
		t.Fatalf("padded: %q", mac)
	}

	// The running file keeps the sum, never the key, and compares equal.
	data, err := json.Marshal(inline.Restart())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "c2VjcmV0LWtleQ") || !strings.Contains(string(data), inline.Listen["download"].TLS.EAB.KeySum) {
		t.Fatalf("running file %s", data)
	}
	var back Restart
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if got := back.Changes(inline.Restart()); len(got) != 0 {
		t.Fatalf("round trip changes %v", got)
	}
	other, err := Parse([]byte(acmeConfig("      eab: {kid: k1, key: b3RoZXIta2V5}\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Changes(other.Restart()); !slices.Equal(got, []string{"listen.download.tls"}) {
		t.Fatalf("changed key: %v", got)
	}
	plain, err := Parse([]byte(acmeConfig("")))
	if err != nil {
		t.Fatal(err)
	}
	next, err := Parse([]byte(strings.Replace(acmeConfig(""), "  http:\n    addr: 0.0.0.0:80\n    acme: true\n", "  http:\n    addr: 0.0.0.0:80\n    acme: true\n  http6:\n    addr: '[::]:80'\n    acme: true\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := plain.Restart().Changes(next.Restart()); !slices.Equal(got, []string{"listen.http6"}) {
		t.Fatalf("new acme listener: %v", got)
	}
}

func TestEndpointLink(t *testing.T) {
	src := strings.Replace(good, "    respond: url\n    storage: drop", "    respond: url\n    storage: drop\n    link: {remove: ['*'], ttl: ['*']}", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	l := c.Endpoint["drop"].Link
	if len(l.Of(wire.LinkRemove)) != 1 || len(l.Of(wire.LinkTTL)) != 1 || l.Of(wire.LinkReplace) != nil || l.Of(wire.LinkList) != nil || l.Of("rename") != nil {
		t.Fatalf("%+v", l)
	}
	if c, err := Parse([]byte(strings.Replace(src, "ttl: ['*']}", "ttl: ['*'], list: [robert.socha, 'hosts:*.vm']}", 1))); err != nil || !slices.Equal(c.Endpoint["drop"].Link.Of(wire.LinkList), []string{"robert.socha", "hosts:*.vm"}) {
		t.Fatalf("list: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(good, "    limits: {body: {size: 50G}}\n", "    limits: {body: {size: 50G}}\n    link: {list: ['*']}\n", 1))); err == nil {
		t.Fatal("list on accept accepted")
	}
	src = strings.Replace(good, "    limits: {body: {size: 50G}}\n", "    limits: {body: {size: 50G}}\n    link: {replace: ['*']}\n", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "endpoint backup: link needs respond url") {
		t.Fatalf("accept: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(src, "link: {replace: ['*']}", "link: {}", 1))); err != nil {
		t.Fatalf("empty link: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(src, "link: {replace: ['*']}", "link: {rename: ['*']}", 1))); err == nil {
		t.Fatal("unknown link key accepted")
	}
	if c, err := Parse([]byte(strings.Replace(src, "link: {replace: ['*']}", "link: {replace: []}", 1))); err != nil || c.Endpoint["backup"].Link.Offered() {
		t.Fatalf("empty list: %v", err)
	}
}

// TestCapabilityLists checks the lists of identities of the endpoint
// capabilities: a boolean is refused naming the key, the entries are
// checked like allow entries, secret.allow and pretty.allow are required.
func TestCapabilityLists(t *testing.T) {
	at := "    respond: url\n    storage: drop\n"
	cases := map[string][2]string{
		"link bool":                   {"    link: {replace: true}\n", `link.replace: a list of identities, e.g. ["*"]`},
		"link scalar":                 {"    link: {list: robert.socha}\n", `link.list: a list of identities, e.g. ["*"]`},
		"private bool":                {"    private: {owner: true}\n", `private.owner: a list of identities, e.g. ["*"]`},
		"secret allow bool":           {"    secret: {path: /run/luk/volatile/queue, storage: volatile, allow: true}\n", `secret.allow: a list of identities, e.g. ["*"]`},
		"secret unknown key":          {"    secret: {path: /run/luk/volatile/queue, storage: volatile, allow: [], extra: 1}\n", "field extra not found in secret"},
		"pretty allow bool":           {"    pretty: {allow: true}\n", `pretty.allow: a list of identities, e.g. ["*"]`},
		"link unknown key":            {"    link: {list: [nobody]}\n", `endpoint drop: link.list: allow "nobody" is not a known key`},
		"link unknown ca":             {"    link: {remove: ['nope:*']}\n", `endpoint drop: link.remove: allow "nope:*" names an unknown CA`},
		"pretty bad pattern":          {"    pretty: {allow: ['hosts:[']}\n", `endpoint drop: pretty.allow: allow "hosts:[" has a bad pattern`},
		"pretty without allow":        {"    pretty: {bits: 64}\n", `endpoint drop: pretty.allow is required: a list of identities, e.g. ["*"]`},
		"secret without allow":        {"    secret: {path: /run/luk/volatile/queue, storage: volatile}\n", `endpoint drop: secret.allow is required`},
		"secret unknown key in allow": {"    secret: {path: /run/luk/volatile/queue, storage: volatile, allow: [nobody]}\n", `endpoint drop: secret.allow: allow "nobody" is not a known key`},
		"backup hostname any bool":    {"    backup: {hostname: {any: true}}\n", `backup.hostname.any: a list of identities, e.g. ["*"]`},
		"backup hostname scalar":      {"    backup: {hostname: robert.socha}\n", `backup.hostname: a mapping of any and principal`},
		"backup hostname null":        {"    backup: {hostname: }\n", `backup.hostname: a mapping of any and principal`},
		"backup unknown key":          {"    backup: {path: [robert.socha]}\n", "field path not found in backup"},
		"backup hostname unknown key": {"    backup: {hostname: {all: ['*']}}\n", "field all not found in backup.hostname"},
		"backup hostname unknown id":  {"    backup: {hostname: {principal: [nobody]}}\n", `endpoint drop: backup.hostname.principal: allow "nobody" is not a known key`},
		"backup hostname bad pattern": {"    backup: {hostname: {any: ['hosts:[']}}\n", `endpoint drop: backup.hostname.any: allow "hosts:[" has a bad pattern`},
	}
	for name, tc := range cases {
		src := strings.Replace(secretGood, "    secret: {allow: ['*'], path: /run/luk/volatile/queue, storage: volatile}\n", "", 1)
		src = strings.Replace(src, at, at+tc[0], 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), tc[1]) {
			t.Errorf("%s: %v", name, err)
		}
	}
	src := strings.Replace(secretGood, "secret: {allow: ['*'],", "secret: {allow: [],", 1)
	src = strings.Replace(src, at, at+"    pretty: {allow: [robert.socha]}\n    private: {}\n", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if e := c.Endpoint["drop"]; e.Secret.Allow == nil || len(e.Secret.Allow) != 0 || !slices.Equal(e.Pretty.Allow, []string{"robert.socha"}) || e.Private.Offered() {
		t.Fatalf("%+v %+v %+v", e.Secret, e.Pretty, e.Private)
	}
}

// TestBackupHostnameConfig: backup.hostname takes two lists of
// identities; without it there is no restriction (nil).
func TestBackupHostnameConfig(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil || c.Endpoint["backup"].Backup.Hostname != nil {
		t.Fatalf("default: %v %+v", err, c.Endpoint["backup"].Backup)
	}
	src := strings.Replace(good, `allow: [robert.socha, "hosts:*"]`+"\n", `allow: [robert.socha, "hosts:*"]`+"\n    backup:\n      hostname:\n        any: [robert.socha]\n        principal: [\"hosts:*\"]\n", 1)
	if c, err = Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
	if h := c.Endpoint["backup"].Backup.Hostname; h == nil || !slices.Equal(h.Any, []string{"robert.socha"}) || !slices.Equal(h.Principal, []string{"hosts:*"}) {
		t.Fatalf("lists: %+v", h)
	}
	if c, err = Parse([]byte(strings.Replace(src, "        any: [robert.socha]\n        principal: [\"hosts:*\"]\n", "        {}\n", 1))); err != nil {
		t.Fatal(err)
	}
	if h := c.Endpoint["backup"].Backup.Hostname; h == nil || h.Any != nil || h.Principal != nil {
		t.Fatalf("empty block: %+v", h)
	}
}

// privateGood is good with the protect expose secure of the drop storage
// and an endpoint drop accepting both private modes.
var privateGood = strings.NewReplacer(
	"    respond: url\n    storage: drop\n", "    respond: url\n    storage: drop\n    private: {owner: ['*'], any: ['*']}\n",
	"path: \"{{ .Random }}\", expose: drop}", "path: \"{{ .Random }}\", expose: drop, protect: secure}",
	"    path: /d/\n", "    path: /d/\n  secure:\n    listen: main\n    path: /s/\n    auth: {ssh: {allow: [\"*\", robert.socha, \"hosts:*.vm\"]}}\n",
).Replace(good)

func TestPrivateConfig(t *testing.T) {
	c, err := Parse([]byte(privateGood))
	if err != nil {
		t.Fatal(err)
	}
	if e := c.Endpoint["drop"]; !e.Private.Offered() {
		t.Fatalf("private %+v", e.Private)
	} else if w, ok := e.Private.Of(wire.AccessAny); !ok || len(w) != 1 {
		t.Fatalf("private any %v %v", w, ok)
	} else if w, ok := e.Private.Of(""); !ok || w != nil {
		t.Fatalf("public %v %v", w, ok)
	} else if _, ok := e.Private.Of("other"); ok {
		t.Fatal("unknown access mode")
	}
	if c.Endpoint["backup"].Private.Offered() {
		t.Fatal("backup accepts private uploads")
	}
	base, l, ok := c.ProtectURL("drop")
	if !ok || base != "luk://lukd.vm:8443/s/" || l.Name != "main" {
		t.Fatalf("protect url %q %v %v", base, l, ok)
	}
	if n, _, ok := c.StorageServedBy("secure"); !ok || n != "drop" {
		t.Fatalf("served by %q %v", n, ok)
	}
	if _, err := Parse([]byte(strings.Replace(good, `allow: [robert.socha, "hosts:*"]`, `allow: ["*"]`, 1))); err != nil {
		t.Fatalf("* in an endpoint allow: %v", err)
	}
	cases := map[string][3]string{
		"private without respond url": {"    allow: [robert.socha, \"hosts:*\"]\n", "    allow: [robert.socha, \"hosts:*\"]\n    private: {owner: ['*']}\n", "private needs respond url"},
		"private without protect":     {", protect: secure}", "}", "private needs storage drop to have protect"},
		"protect unknown":             {"protect: secure}", "protect: nope}", "unknown protect expose"},
		"protect without auth.ssh":    {"    auth: {ssh: {allow: [\"*\", robert.socha, \"hosts:*.vm\"]}}\n", "", "protect expose secure needs auth.ssh"},
		"protect is expose":           {"expose: drop, protect: secure}", "expose: secure, protect: secure}", "expose and protect must differ"},
		"protect on s3":               {"storage:\n", "storage:\n  off: {type: s3, bucket: b, protect: secure}\n", "protect needs a local storage"},
		"protect with basic":          {"auth: {ssh: {", "auth: {basic: ['dev:$2y$05$TpFzQdt1oY6UgSKCZGgt8eCbBXDAuiQxNl13XDuDnYKUSuIC9O79W'], ssh: {", "expose secure: auth.basic on a protect expose"},
		"ssh allow unknown key":       {`allow: ["*", robert.socha`, `allow: [nobody`, `allow "nobody" is not a known key`},
		"ssh allow unknown ca":        {`"hosts:*.vm"`, `"nope:*"`, "names an unknown CA"},
		"protect on plain listener":   {"    listen: main\n    path: /s/", "    listen: plain\n    path: /s/", "needs an https public URL"},
		"key named *":                 {"    - name: robert.socha\n", "    - name: \"*\"\n", `name "*"`},
		"protect used twice":          {"storage:\n", "storage:\n  two: {type: local, base: /storage/two, path: x, protect: secure}\n", "used by storages drop and two"},
	}
	for name, r := range cases {
		if !strings.Contains(privateGood, r[0]) {
			t.Fatalf("%s: fixture does not contain %q", name, r[0])
		}
		if _, err := Parse([]byte(strings.Replace(privateGood, r[0], r[1], 1))); err == nil || !strings.Contains(err.Error(), r[2]) {
			t.Errorf("%s: %v, want an error with %q", name, err, r[2])
		}
	}
}

// signedGood is good with the archive storage exposed by vault, an expose
// with auth.ssh: its public files go to signed requests of the identities
// vault allows.
var signedGood = strings.NewReplacer(
	`path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", expose: vault}`,
	"    path: /d/\n", "    path: /d/\n  vault:\n    listen: main\n    path: /v/\n    auth: {ssh: {allow: [robert.socha]}}\n",
).Replace(good)

func TestSignedExposeConfig(t *testing.T) {
	c, err := Parse([]byte(signedGood))
	if err != nil {
		t.Fatal(err)
	}
	if n, _, ok := c.StorageOfExpose("vault"); !ok || n != "archive" {
		t.Fatalf("storage of vault %q %v", n, ok)
	}
	base, l, ok := c.PublicURL("archive")
	if !ok || base != "luk://lukd.vm:8443/v/" || l == nil || l.Name != "main" {
		t.Fatalf("public url %q %v %v", base, l, ok)
	}
	if base, l, ok := c.PublicURL("drop"); !ok || base != "https://lukd.vm:8443/d/" || l != nil {
		t.Fatalf("public url of drop %q %v %v", base, l, ok)
	}
	if _, _, ok := c.ProtectURL("archive"); ok {
		t.Fatal("archive has a protect URL")
	}
	// The catalog of a storage behind auth.ssh publishes nothing.
	cat := strings.Replace(signedGood, `expose: vault}`, `expose: vault, catalog: true}`, 1)
	if c, err := Parse([]byte(cat)); err != nil {
		t.Fatal(err)
	} else if w := strings.Join(c.Warnings(), "\n"); strings.Contains(w, "catalog on expose vault") {
		t.Fatalf("warnings %s", w)
	}
	cases := map[string][3]string{
		"index":              {"    path: /v/\n", "    path: /v/\n    index: true\n", "index excludes auth.ssh"},
		"plain listener":     {"    listen: main\n    path: /v/", "    listen: plain\n    path: /v/", "expose vault: listen plain (first of the expose) needs an https public URL"},
		"expose and protect": {`expose: vault}`, `expose: vault, protect: vault}`, "expose and protect must differ"},
		"used twice":         {"storage:\n", "storage:\n  two: {type: local, base: /storage/two, path: x, expose: vault}\n", "used by storages"},
	}
	for name, r := range cases {
		if !strings.Contains(signedGood, r[0]) {
			t.Fatalf("%s: fixture does not contain %q", name, r[0])
		}
		if _, err := Parse([]byte(strings.Replace(signedGood, r[0], r[1], 1))); err == nil || !strings.Contains(err.Error(), r[2]) {
			t.Errorf("%s: %v, want an error with %q", name, err, r[2])
		}
	}
	// A storage with an auth.ssh expose and an auth.ssh protect.
	both := strings.NewReplacer(
		`expose: vault}`, `expose: vault, protect: secure}`,
		"    auth: {ssh: {allow: [robert.socha]}}\n", "    auth: {ssh: {allow: [robert.socha]}}\n  secure:\n    listen: main\n    path: /s/\n    auth: {ssh: {allow: [\"*\"]}}\n",
	).Replace(signedGood)
	if _, err := Parse([]byte(both)); err != nil {
		t.Fatalf("auth.ssh expose and protect: %v", err)
	}
}

// An expose with auth.basic and auth.ssh serves its public files to
// either; with index too.
func TestDualAuthExposeConfig(t *testing.T) {
	src := strings.Replace(signedGood, "auth: {ssh: {allow: [robert.socha]}}", "auth: {basic: ['dev:$2y$05$TpFzQdt1oY6UgSKCZGgt8eCbBXDAuiQxNl13XDuDnYKUSuIC9O79W'], ssh: {allow: [robert.socha]}}\n    index: true", 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if x := c.Expose["vault"]; x.Auth.SSH == nil || len(x.Auth.Basic) != 1 || !x.Index {
		t.Fatalf("vault %+v", x)
	}
	// Its URLs are https, still with the listener for the pin.
	if base, l, ok := c.PublicURL("archive"); !ok || base != "https://lukd.vm:8443/v/" || l == nil || l.Name != "main" {
		t.Fatalf("public url %q %v %v", base, l, ok)
	}
	if w := strings.Join(c.Warnings(), "\n"); strings.Contains(w, "vault") {
		t.Fatalf("warnings %s", w)
	}
}

// A queue directory never nests in another or holds what lukd keeps
// itself: the start of the receive role cleans every queue directory.
func TestQueuePathOverlaps(t *testing.T) {
	src := "root: /var/lib/luk\n" + good
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
	shared := strings.Replace(src, "path: /queue/drop", "path: /queue/backup", 1)
	if _, err := Parse([]byte(shared)); err != nil {
		t.Fatalf("one queue directory for two endpoints: %v", err)
	}
	for name, r := range map[string][3]string{
		"nested queue":    {"path: /queue/drop", "path: /queue/backup/drop", "endpoint backup and drop: paths /queue/backup and /queue/backup/drop nest"},
		"enclosing queue": {"path: /queue/drop", "path: /queue", "endpoint backup and drop: paths /queue/backup and /queue nest"},
		"relative nested": {"path: /queue/drop", "path: x", "paths"},
		"acme":            {"path: /queue/drop", "path: acme", "endpoint drop: path /var/lib/luk/acme overlaps the ACME cache /var/lib/luk/acme"},
		"in acme":         {"path: /queue/drop", "path: acme/q", "overlaps the ACME cache"},
		"gpg cache":       {"path: /queue/drop", "path: gpg-cache/x", "overlaps the WKD key cache /var/lib/luk/gpg-cache"},
		"nonces":          {"path: /queue/drop", "path: /run/luk", "endpoint drop: path /run/luk overlaps auth.nonces /run/luk/nonces"},
		"tls files":       {"path: /queue/drop", "path: /tmp", "endpoint drop: path /tmp holds the TLS file /tmp/c.crt of listener main"},
		"root":            {"path: /queue/drop", "path: /var/lib/luk", "overlaps"},
	} {
		y := strings.Replace(src, r[0], r[1], 1)
		if name == "relative nested" {
			y = strings.Replace(strings.Replace(src, "path: /queue/drop", "path: q/drop", 1), "path: /queue/backup", "path: q", 1)
		}
		if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), r[2]) {
			t.Errorf("%s: %v, want an error with %q", name, err, r[2])
		}
	}
	sec := strings.Replace("root: /var/lib/luk\n"+secretGood, "path: /run/luk/volatile/queue", "path: /run/luk/nonces/q", 1)
	if _, err := Parse([]byte(sec)); err == nil || !strings.Contains(err.Error(), "endpoint drop: secret.path /run/luk/nonces/q overlaps auth.nonces") {
		t.Errorf("secret in nonces: %v", err)
	}
}

// secretGood is good with the reveal uploads of endpoint drop going to the
// storage volatile, exposed nested in the expose of drop.
var secretGood = strings.NewReplacer(
	"    respond: url\n    storage: drop\n", "    respond: url\n    storage: drop\n    secret: {allow: ['*'], path: /run/luk/volatile/queue, storage: volatile}\n",
	"storage:\n", "storage:\n  volatile: {type: local, base: /run/luk/volatile/storage, path: \"{{ .Random }}\", expose: volatile, ttl: {user: true}}\n",
).Replace(good) + "  volatile:\n    listen: main\n    path: /d/volatile/\n"

func TestEndpointSecret(t *testing.T) {
	c, err := Parse([]byte(secretGood))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Endpoint["drop"]
	if e.Secret == nil || e.Secret.Path != "/run/luk/volatile/queue" || e.Secret.Storage != "volatile" {
		t.Fatalf("secret %+v", e.Secret)
	}
	if !e.Secrets(wire.PortalReveal) || e.Secrets(wire.PortalDirect) || e.Secrets(wire.PortalDownload) || c.Endpoint["backup"].Secrets(wire.PortalReveal) {
		t.Fatal("Secrets")
	}
	if n := c.Storage["drop"].Nested(); !slices.Equal(n, []string{"volatile/"}) {
		t.Fatalf("nested %q", n)
	}
	rel := strings.Replace(secretGood, "path: /run/luk/volatile/queue", "path: volatile/queue", 1)
	if c, err := Parse([]byte("root: /var/lib/luk\n" + rel)); err != nil || c.Endpoint["drop"].Secret.Path != "/var/lib/luk/volatile/queue" {
		t.Fatalf("relative secret.path: %v", err)
	}
	cases := map[string][3]string{
		"respond accept": {"    respond: url\n    storage: drop\n    secret:", "    storage: drop\n    secret:", "secret needs respond url"},
		"no path":        {"path: /run/luk/volatile/queue, ", "", "secret.path is required"},
		"path escapes":   {"path: /run/luk/volatile/queue", "path: ../q", "escapes root"},
		"unknown":        {"storage: volatile}", "storage: nope}", `secret.storage "nope" is not a known storage`},
		"s3":             {"storage: volatile}", "storage: off}\n  x:", "secret storage off is not a local storage"},
		"not exposed":    {"storage: volatile}", "storage: archive}", "secret storage archive is not exposed"},
		"same storage":   {"storage: volatile}", "storage: drop}", "secret.storage must differ from storage"},
		"in base":        {"path: /run/luk/volatile/queue", "path: /run/luk/volatile/storage/q", "secret.path /run/luk/volatile/storage/q overlaps storage volatile base"},
		"base in it":     {"path: /run/luk/volatile/queue", "path: /run/luk", "overlaps storage volatile base"},
		"in drop base":   {"path: /run/luk/volatile/queue", "path: /storage/drop/q", "overlaps storage drop base"},
		"is a queue":     {"path: /run/luk/volatile/queue", "path: /queue/backup", "secret.path /queue/backup overlaps the queue /queue/backup of endpoint backup"},
		"own queue":      {"path: /run/luk/volatile/queue", "path: /queue/drop/s", "overlaps the queue /queue/drop of endpoint drop"},
		"work dir":       {"path: /run/luk/volatile/queue", "path: /var/lib/luk/work/s", "overlaps the work directory"},
		"pretty":         {"    secret:", "    pretty: {allow: ['*']}\n    secret:", "pretty needs a path of secret storage volatile that uses .Random"},
	}
	for name, r := range cases {
		src := secretGood
		switch name {
		case "s3":
			src = strings.Replace(src, "storage:\n", "storage:\n  off: {type: s3, bucket: b}\n", 1)
			r[1] = "storage: off}"
		case "pretty":
			src = strings.Replace(src, `base: /run/luk/volatile/storage, path: "{{ .Random }}"`, "base: /run/luk/volatile/storage, path: x", 1)
		}
		if !strings.Contains(src, r[0]) {
			t.Fatalf("%s: fixture does not contain %q", name, r[0])
		}
		if _, err := Parse([]byte(strings.Replace(src, r[0], r[1], 1))); err == nil || !strings.Contains(err.Error(), r[2]) {
			t.Errorf("%s: %v, want an error with %q", name, err, r[2])
		}
	}
	two := strings.Replace(secretGood, "    limits: {body: {size: 50G}}\n", "    limits: {body: {size: 50G}}\n    respond: url\n    storage: archive2\n    secret: {allow: ['*'], path: /run/luk/volatile/queue/x, storage: volatile}\n", 1)
	two = strings.Replace(two, "storage:\n", "storage:\n  archive2: {type: local, base: /storage/archive2, path: x, expose: a2}\n", 1) + "  a2:\n    listen: plain\n    path: /a2/\n"
	two = strings.Replace(two, "    steps:\n      - store: drop\n", "    steps:\n      - store: drop\n  a2:\n    endpoint: [backup]\n    steps:\n      - store: archive2\n", 1)
	if _, err := Parse([]byte(two)); err == nil || !strings.Contains(err.Error(), "overlaps secret.path /run/luk/volatile/queue of endpoint drop") {
		t.Errorf("nested secret paths: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(two, "/run/luk/volatile/queue/x", "/run/luk/volatile/queue", 1))); err != nil {
		t.Errorf("shared secret path: %v", err)
	}
}

func TestSecretReserve(t *testing.T) {
	c, err := Parse([]byte(secretGood))
	if err != nil {
		t.Fatal(err)
	}
	if r := c.SecretReserves(); len(r) != 1 || r["/run/luk/volatile/queue"] != DefaultSecretReserve {
		t.Fatalf("default %v", r)
	}
	if c, err := Parse([]byte(strings.Replace(secretGood, "storage: volatile}", "storage: volatile, reserve: 4M}", 1))); err != nil || c.Endpoint["drop"].Secret.Reserve != 4<<20 {
		t.Fatalf("4M: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(secretGood, "storage: volatile}", "storage: volatile, reserve: -1M}", 1))); err == nil {
		t.Fatal("negative reserve accepted")
	}
}

// link.replace needs every pipeline of the endpoint to consist of store
// steps only; the error names the pipeline and the step.
func TestLinkReplaceStoreStepsOnly(t *testing.T) {
	src := strings.Replace(good, "    respond: url\n    storage: drop", "    respond: url\n    storage: drop\n    link: {replace: ['*']}", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatalf("store only: %v", err)
	}
	fanOut := strings.Replace(src, "    steps:\n      - store: drop\n", "    steps:\n      - store: drop\n      - store: archive\n", 1)
	if _, err := Parse([]byte(fanOut)); err != nil {
		t.Fatalf("store steps: %v", err)
	}
	for what, step := range map[string]string{"run": "      - run: /opt/luk/mark\n", "run tee": "      - run: /opt/luk/mark\n        tee: true\n", "encrypt": "      - encrypt: {key: [robert@example.com]}\n", "relay": "      - relay: s3-upload\n"} {
		bad := strings.Replace(src, "    steps:\n      - store: drop\n", "    steps:\n      - store: drop\n"+step, 1)
		_, err := Parse([]byte(bad))
		if want := "endpoint drop: link.replace needs pipelines of store steps only: pipeline drop step 2 is " + strings.TrimSuffix(what, " tee"); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: want %q, got %v", what, want, err)
		}
	}
	// Another pipeline of the endpoint counts too.
	other := strings.Replace(src, "storage:\n", "  mark:\n    endpoint: [drop]\n    steps:\n      - run: /opt/luk/mark\nstorage:\n", 1)
	if _, err := Parse([]byte(other)); err == nil || !strings.Contains(err.Error(), "pipeline mark step 1 is run") {
		t.Fatalf("other pipeline: %v", err)
	}
}

func TestQuota(t *testing.T) {
	parse := func(q string) (*Config, error) {
		return Parse([]byte(strings.Replace(good, "    limits: {body: {size: 50G}}\n", "    limits: {body: {size: 50G}}\n    quota: "+q+"\n", 1)))
	}
	c, err := parse(`{rate: 10G/1d, class: [{name: large, members: ["hosts#db*", "hosts:*.example.org", robert.socha], rate: 50G/12h, burst: 100G}]}`)
	if err != nil {
		t.Fatal(err)
	}
	q := c.Endpoint["backup"].Quota
	if q.Mode != QuotaEnforce || q.Burst != 10<<30 || q.Rate.String() != "10G/1d" || q.Class[0].Rate.String() != "50G/12h" {
		t.Fatalf("%+v", q)
	}
	cls := q.Classes()
	if len(cls) != 2 || cls[0].Name != "large" || cls[1].Name != "" || cls[1].Burst != 10<<30 {
		t.Fatalf("%+v", cls)
	}
	if c, err = parse(`{mode: passive, class: [{name: a, members: [robert.socha], rate: 1G/1h}, {name: rest, rate: 5G/1d, burst: 1T}]}`); err != nil {
		t.Fatal(err)
	}
	if cls := c.Endpoint["backup"].Quota.Classes(); cls[1].Name != "rest" || cls[1].Burst != 1<<40 || cls[0].Burst != 1<<30 {
		t.Fatalf("%+v", cls)
	}
	for q, want := range map[string]string{
		`{}`:                        "needs rate or class",
		`{mode: soft, rate: 1G/1d}`: `mode "soft" is not enforce or passive`,
		`{burst: 1G}`:               "burst needs rate",
		`{rate: 1G}`:                "invalid rate",
		`{rate: 0/1d}`:              "invalid rate",
		`{rate: 1G/0s}`:             "invalid rate",
		`{rate: 1G/1d, burst: -1}`:  "invalid size",
		`{class: [{name: a}]}`:      "class a: rate is required",
		`{class: [{rate: 1G/1d}]}`:  `name "" empty or duplicated`,
		`{rate: 1G/1d, unknown: 1}`: "field unknown not found",
		`{rate: 1G/1d, class: [{name: a, rate: 1G/1d}]}`:                                                     "class a has no members and rate is set at the top",
		`{class: [{name: a, rate: 1G/1d}, {name: b, rate: 1G/1d}]}`:                                          "classes a and b both have no members",
		`{class: [{name: a, members: [x], rate: 1G/1d}]}`:                                                    `allow "x" is not a known key`,
		`{class: [{name: a, members: ["nope#x"], rate: 1G/1d}]}`:                                             "names an unknown CA",
		`{class: [{name: a, members: ["hosts#["], rate: 1G/1d}]}`:                                            "bad pattern",
		`{class: [{name: a, members: ["*"], rate: 1G/1d}, {name: a, members: ["hosts:*"], rate: 1G/1d}]}`:    `name "a" empty or duplicated`,
		`{class: [{name: a, members: [robert.socha], rate: 1G/1d}, {name: b, members: ["*"], rate: 2G/1d}]}`: "key robert.socha matches classes a, b",
	} {
		if _, err := parse(q); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", q, err, want)
		}
	}
	// A certificate may match several classes; that is decided per request.
	if _, err := parse(`{class: [{name: a, members: ["hosts#db*"], rate: 1G/1d}, {name: b, members: ["hosts:*"], rate: 2G/1d}]}`); err != nil {
		t.Fatal(err)
	}
}

func TestKeyIDAllowAndNames(t *testing.T) {
	if _, err := Parse([]byte(strings.Replace(good, `allow: [robert.socha, "hosts:*"]`, `allow: [robert.socha, "hosts#db*.example.org"]`, 1))); err != nil {
		t.Fatal(err)
	}
	for _, r := range [][2]string{
		{"    - name: robert.socha\n", "    - name: robert#socha\n"},
		{"    - name: hosts\n", "    - name: ho#sts\n"},
	} {
		if _, err := Parse([]byte(strings.Replace(good, r[0], r[1], 1))); err == nil || !strings.Contains(err.Error(), "contains ':' or '#'") {
			t.Errorf("%q: %v", r[1], err)
		}
	}
}

func TestRetention(t *testing.T) {
	const rules = `retention: [{origin: [db1-prod, "*-prod"], keep: {last: 3, daily: 14, weekly: 8, monthly: 12, yearly: 2}}, {origin: "*-stage", keep: {daily: 7}}, {keep: {daily: 7, weekly: 4}}]`
	src := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", `+rules+`}`, 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	st := c.Storage["archive"]
	if k := st.Retention[0].Keep; k != (Keep{Last: 3, Daily: 14, Weekly: 8, Monthly: 12, Yearly: 2}) {
		t.Fatalf("keep %+v", k)
	}
	for origin, want := range map[string]int{"db1-prod": 0, "web1-prod": 0, "db1-stage": 1, "db1-dev": 2, "": 2} {
		if got := st.RetentionRule(origin); got != want {
			t.Errorf("%q: rule %d, want %d", origin, got, want)
		}
	}
	st.Retention = st.Retention[:2]
	if got := st.RetentionRule("db1-dev"); got != -1 {
		t.Errorf("without a catch-all: rule %d", got)
	}

	src = strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", retention: [{keep: {within: 2d}}]}`, 1)
	if c, err = Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
	k := c.Storage["archive"].Retention[0].Keep
	if k != (Keep{Within: Duration(48 * time.Hour)}) {
		t.Fatalf("within: %+v", k)
	}
	b, err := json.Marshal(k)
	if err != nil || string(b) != `{"within":"2d"}` {
		t.Fatalf("json: %s %v", b, err)
	}
	var back Keep
	if err := json.Unmarshal([]byte(`{"last":2,"within":"36h"}`), &back); err != nil || back != (Keep{Last: 2, Within: Duration(36 * time.Hour)}) {
		t.Fatalf("json back: %+v %v", back, err)
	}
}

func TestRetentionConflictReplace(t *testing.T) {
	src := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", conflict: replace, retention: [{keep: {daily: 1}}]}`, 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "storage archive: retention needs conflict version or reject, not replace") {
		t.Fatalf("replace: %v", err)
	}
	for _, conflict := range []string{"version", "reject"} {
		src := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", conflict: `+conflict+`, retention: [{keep: {daily: 1}}]}`, 1)
		if _, err := Parse([]byte(src)); err != nil {
			t.Fatalf("%s: %v", conflict, err)
		}
	}
}

func TestRetentionErrors(t *testing.T) {
	for rules, want := range map[string]string{
		`[{keep: {daily: 7}}, {origin: x, keep: {daily: 1}}]`: "storage archive: retention rule 1 matches every origin and must be the last: the rules after it are unreachable",
		`[{origin: "[x", keep: {daily: 7}}]`:                  `storage archive: retention rule 1: origin "[x": syntax error in pattern`,
		`[{origin: [""], keep: {daily: 7}}]`:                  "storage archive: retention rule 1: empty origin glob",
		`[{origin: x, keep: {daily: -1}}]`:                    "storage archive: retention rule 1: keep counts must not be negative",
		`[{origin: x, keep: {}}]`:                             "storage archive: retention rule 1: keep needs a count above 0",
		`[{origin: x, keep: {within: -1h}}]`:                  "storage archive: retention rule 1: keep.within must not be negative",
		`[{origin: x, keep: {within: 0s}}]`:                   "storage archive: retention rule 1: keep needs a count above 0 (last, daily, weekly, monthly, yearly) or within",
		`[{origin: x, keep: {within: 2x}}]`:                   `unknown unit "x"`,
		`[{origin: x}]`:                                       "storage archive: retention rule 1: keep needs a count above 0",
		`[{origin: x, keep: {hourly: 1}}]`:                    "field hourly not found",
	} {
		src := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", retention: `+rules+`}`, 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", rules, err)
		}
	}
	src := strings.Replace(good, "storage:\n", "storage:\n  off: {type: s3, bucket: b, retention: [{keep: {daily: 1}}]}\n", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "storage off: retention needs a local storage") {
		t.Errorf("s3: %v", err)
	}
}

func TestWatch(t *testing.T) {
	const rules = `watch: [{origin: [db1-prod], file: ["db.sql*"], every: 26h, size: {min: 2G, max: 20G, step: 500M}, same: 3}, {origin: "*-stage", every: 50h, size: {min: 100M}}, {file: "*.tar", same: 2}]`
	src := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", `+rules+`}`, 1)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	st := c.Storage["archive"]
	w := st.Watch[0]
	if *w.Every != Duration(26*time.Hour) || *w.Size.Min != 2<<30 || *w.Size.Max != 20<<30 || *w.Size.Step != 500<<20 || *w.Same != 3 {
		t.Fatalf("rule 1: %+v", w)
	}
	if w := st.Watch[1]; w.Size.Max != nil || w.Size.Step != nil || w.Same != nil || len(w.File) != 0 {
		t.Fatalf("rule 2: %+v", w)
	}
	for _, c := range []struct {
		origin, file string
		want         int
	}{
		{"db1-prod", "db.sql", 0}, {"db1-prod", "db.sql.gz", 0}, {"db1-prod", "site.tar", 2}, {"db1-prod", "other", -1},
		{"db1-stage", "anything", 1}, {"web1", "site.tar", 2}, {"web1", "site.zip", -1},
	} {
		if got := st.WatchRule(c.origin, c.file); got != c.want {
			t.Errorf("%s/%s: rule %d, want %d", c.origin, c.file, got, c.want)
		}
	}
}

func TestWatchErrors(t *testing.T) {
	for rules, want := range map[string]string{
		`[{origin: "[x", every: 1h}]`:               `storage archive: watch rule 1: origin "[x": syntax error in pattern`,
		`[{file: "[x", every: 1h}]`:                 `storage archive: watch rule 1: file "[x": syntax error in pattern`,
		`[{origin: [""], every: 1h}]`:               "storage archive: watch rule 1: empty origin glob",
		`[{file: [""], every: 1h}]`:                 "storage archive: watch rule 1: empty file glob",
		`[{origin: x, every: 0s}]`:                  "storage archive: watch rule 1: every must be above 0",
		`[{origin: x, every: -1h}]`:                 "storage archive: watch rule 1: every must be above 0",
		`[{origin: x, size: {min: 0}}]`:             "storage archive: watch rule 1: size.min must be above 0",
		`[{origin: x, size: {max: 0}}]`:             "storage archive: watch rule 1: size.max must be above 0",
		`[{origin: x, size: {step: 0}}]`:            "storage archive: watch rule 1: size.step must be above 0",
		`[{origin: x, size: {min: 2G, max: 1G}}]`:   "storage archive: watch rule 1: size.min must not exceed size.max",
		`[{origin: x, same: 1}]`:                    "storage archive: watch rule 1: same must be at least 2",
		`[{origin: x}]`:                             "storage archive: watch rule 1: needs a check (every, size.min, size.max, size.step, same)",
		`[{origin: x, size: {}}]`:                   "storage archive: watch rule 1: needs a check",
		`[{every: 1h}, {origin: x, every: 1h}]`:     "storage archive: watch rule 1 matches every series and must be the last: the rules after it are unreachable",
		`[{origin: x, every: 1h, hourly: 1}]`:       "field hourly not found",
		`[{origin: x, every: 1h, size: {avg: 1G}}]`: "field avg not found",
	} {
		src := strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", watch: `+rules+`}`, 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", rules, err)
		}
	}
	src := strings.Replace(good, "storage:\n", "storage:\n  off: {type: s3, bucket: b, watch: [{every: 1h}]}\n", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "storage off: watch needs a local storage") {
		t.Errorf("s3: %v", err)
	}
	src = strings.Replace(good, `path: "{{ .Sender }}/{{ .File }}"}`, `path: "{{ .Sender }}/{{ .File }}", watch: [{origin: x, every: 1h}, {every: 2h}]}`, 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Errorf("catch-all last: %v", err)
	}
}
