package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const baseMain = `
listen:
  main:
    addr: 127.0.0.1:8080
auth:
  keys:
    - name: robert.socha
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"
endpoint:
  backup:
    listen: main
    endpoint: /backup
    path: /queue/backup
    allow: [robert.socha]
pipeline:
  backup:
    endpoint: [backup]
    steps:
      - store: archive
storage:
  archive: {type: local, base: /storage/archive, path: "{{ .File }}"}
`

// writeTree creates files under a fresh directory and returns the path of
// its config.yaml; a nil value creates a directory.
func writeTree(t *testing.T, files map[string]*string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if body == nil {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(p, []byte(*body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, filepath.Join(dir, "config.yaml")
}

func s(v string) *string { return &v }

func pubLine(t *testing.T, comment string) (ssh.Signer, string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sg, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sg.PublicKey())))
	if comment != "" {
		line += " " + comment
	}
	return sg, line
}

func TestConfigDMergesNamedSections(t *testing.T) {
	_, ca := pubLine(t, "")
	_, key := pubLine(t, "ops")
	_, p := writeTree(t, map[string]*string{
		"config.yaml": s(baseMain),
		"config.d/10-drop.yaml": s(`
listen:
  other: {addr: 127.0.0.1:8081}
endpoint:
  drop:
    listen: other
    endpoint: /drop
    path: /queue/drop
    allow: [ops, "hosts:*"]
    respond: url
    storage: drop
pipeline:
  drop:
    endpoint: [drop]
    steps:
      - store: drop
storage:
  drop: {type: local, base: /storage/drop, path: "{{ .Random }}", expose: drop}
expose:
  drop: {listen: other, path: /d/}
`),
		"config.d/20-auth.yaml": s(`
auth:
  keys:
    - name: ops
      key: "` + key + `"
  ca:
    - name: hosts
      type: host
      key: "` + ca + `"
`),
	})
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen["main"] == nil || c.Listen["other"] == nil {
		t.Fatalf("listen %v", c.ListenNames())
	}
	if c.Endpoint["backup"] == nil || c.Endpoint["drop"] == nil || c.Pipeline["drop"] == nil ||
		c.Storage["archive"] == nil || c.Storage["drop"] == nil || c.Expose["drop"] == nil {
		t.Fatal("named sections not merged")
	}
	if len(c.Auth.Keys) != 2 || len(c.Auth.CA) != 1 || c.Auth.CA[0].Name != "hosts" {
		t.Fatalf("auth %+v", c.Auth)
	}
}

func TestConfigDDuplicateName(t *testing.T) {
	_, ca := pubLine(t, "")
	_, key := pubLine(t, "")
	cases := map[string]string{
		"listen":   "listen:\n  main: {addr: 127.0.0.1:9}\n",
		"endpoint": "endpoint:\n  backup: {listen: main, endpoint: /x, path: /q/x, allow: [robert.socha]}\n",
		"pipeline": "pipeline:\n  backup: {endpoint: [backup], steps: [{store: archive}]}\n",
		"storage":  "storage:\n  archive: {type: s3, bucket: other}\n",
		"keys":     "auth:\n  keys:\n    - name: robert.socha\n      key: \"" + key + "\"\n",
	}
	for name, snippet := range cases {
		_, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "config.d/a.yaml": s(snippet)})
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), filepath.Join(filepath.Dir(p), "config.d", "a.yaml")) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Between two snippets, for the sections the main file does not use.
	two := map[string]string{
		"expose": "expose:\n  drop: {listen: main, path: /d/}\n",
		"ca":     "auth:\n  ca:\n    - {name: hosts, type: host, key: \"" + ca + "\"}\n",
	}
	for name, snippet := range two {
		dir, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "config.d/a.yaml": s(snippet), "config.d/b.yaml": s(snippet)})
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, "config.d", "a.yaml")) || !strings.Contains(err.Error(), filepath.Join(dir, "config.d", "b.yaml")) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConfigDScalarTwice(t *testing.T) {
	cases := map[string][2]string{
		"root":            {"root: /srv/a\n", "root: /srv/b\n"},
		"limits.conn.max": {"limits: {conn: {max: 5}}\n", "limits:\n  conn:\n    max: 6\n"},
		"limits.failed":   {"limits: {failed: {age: 1d}}\n", "limits: {failed: {age: 2d}}\n"},
		"clock_skew":      {"auth: {clock_skew: 1m}\n", "auth: {clock_skew: 2m}\n"},
		"gpg.keys":        {"gpg: {keys: /etc/a}\n", "gpg: {keys: /etc/b}\n"},
		"gpg.wkd.cache":   {"gpg: {wkd: {cache: 1h}}\n", "gpg: {wkd: {cache: 2h}}\n"},
	}
	for name, v := range cases {
		dir, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "config.d/a.yaml": s(v[0]), "config.d/b.yaml": s(v[1])})
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, "config.d", "a.yaml")) || !strings.Contains(err.Error(), filepath.Join(dir, "config.d", "b.yaml")) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Different leaves of one section may come from different files.
	_, p := writeTree(t, map[string]*string{
		"config.yaml":     s(baseMain + "limits: {conn: {max: 5}}\n"),
		"config.d/a.yaml": s("limits: {conn: {idle: 5m}, header: {timeout: 3s}}\ngpg: {keys: /etc/k}\n"),
		"config.d/b.yaml": s("gpg: {wkd: {cache: 2h}}\nroot: /srv/luk\n"),
	})
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits.Conn.Max != 5 || c.Limits.Conn.Idle != Duration(5*60e9) || c.Limits.Header.Timeout != Duration(3e9) ||
		c.GPG.Keys != "/etc/k" || c.GPG.WKD.Cache != Duration(2*3600e9) || c.Root != "/srv/luk" {
		t.Fatalf("%+v %+v %s", c.Limits, c.GPG, c.Root)
	}
}

func TestConfigDOrderIndependent(t *testing.T) {
	_, key := pubLine(t, "")
	_, key2 := pubLine(t, "")
	a := "listen:\n  b: {addr: 127.0.0.1:9001}\nauth:\n  keys:\n    - {name: zed, key: \"" + key + "\"}\nstorage:\n  z: {type: s3, bucket: z}\n"
	b := "listen:\n  a: {addr: 127.0.0.1:9002}\nauth:\n  keys:\n    - {name: alf, key: \"" + key2 + "\"}\nlimits: {conn: {max: 9}}\n"
	_, p1 := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "config.d/1.yaml": s(a), "config.d/2.yaml": s(b)})
	_, p2 := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "config.d/x-first.yaml": s(b), "config.d/y-second.yaml": s(a)})
	var out [2]string
	for i, p := range []string{p1, p2} {
		c, err := Load(p)
		if err != nil {
			t.Fatal(err)
		}
		if c.GPG.Keys != filepath.Join(filepath.Dir(p), GPGDir) {
			t.Fatalf("gpg.keys %s", c.GPG.Keys)
		}
		c.GPG.Keys = ""
		m, err := yaml.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = string(m)
	}
	if out[0] != out[1] {
		t.Fatalf("order changes the result:\n%s\n---\n%s", out[0], out[1])
	}
}

func TestConfigDIgnoredAndMissing(t *testing.T) {
	_, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain)})
	if _, err := Load(p); err != nil {
		t.Fatalf("missing config.d and ssh.d: %v", err)
	}
	junk := "garbage: [\n"
	_, p = writeTree(t, map[string]*string{
		"config.yaml":            s(baseMain),
		"config.d/.hidden.yaml":  s(junk),
		"config.d/x.yml":         s(junk),
		"config.d/x.yaml~":       s(junk),
		"config.d/x.yaml.dpkg-o": s(junk),
		"config.d/README":        s(junk),
		"config.d/empty.yaml":    s("# nothing yet\n"),
		"ssh.d/.hidden.pub":      s(junk),
		"ssh.d/x.pub.bak":        s(junk),
		"ssh.d/README":           s(junk),
	})
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
}

func TestConfigDErrorsNameTheFile(t *testing.T) {
	dir, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "config.d/a.yaml": s("bogus: 1\n")})
	snip := filepath.Join(dir, "config.d", "a.yaml")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), snip) {
		t.Fatalf("unknown key: %v", err)
	}
	_, p = writeTree(t, map[string]*string{"config.yaml": s(baseMain), "config.d/a.yaml": s("limits: {conn: {idle: soon}}\n")})
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "config.d") {
		t.Fatalf("bad value: %v", err)
	}
	dir, p = writeTree(t, map[string]*string{
		"config.yaml":     s(baseMain),
		"config.d/a.yaml": s("endpoint:\n  drop: {listen: main, endpoint: drop, path: /q/d, allow: [robert.socha]}\nlimits: {conn: {max: -1}}\n"),
	})
	_, err := Load(p)
	if err == nil {
		t.Fatal("accepted")
	}
	snip = filepath.Join(dir, "config.d", "a.yaml")
	for _, want := range []string{snip + ": endpoint drop: endpoint", snip + ": limits.conn.max"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in %v", want, err)
		}
	}
	// A cross reference error of the main file stays attributed to it.
	_, p = writeTree(t, map[string]*string{"config.yaml": s(strings.Replace(baseMain, "allow: [robert.socha]", "allow: [nobody]", 1))})
	if _, err := Load(p); err == nil || !strings.HasPrefix(err.Error(), p+": endpoint backup") {
		t.Fatalf("main: %v", err)
	}
}

func TestKeyDTwoKeysOneIdentity(t *testing.T) {
	_, k1 := pubLine(t, "laptop")
	_, k2 := pubLine(t, "")
	main := strings.Replace(baseMain, "allow: [robert.socha]", "allow: [robert.socha, jan.kowalski]", 1)
	_, p := writeTree(t, map[string]*string{
		"config.yaml":            s(main),
		"ssh.d/jan.kowalski.pub": s("# Jan\n\n" + k1 + "\n  " + k2 + "  \n"),
	})
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	var got *Key
	for i := range c.Auth.Keys {
		if c.Auth.Keys[i].Name == "jan.kowalski" {
			got = &c.Auth.Keys[i]
		}
	}
	if got == nil || len(got.Parsed) != 2 || !strings.HasSuffix(got.File, "jan.kowalski.pub") {
		t.Fatalf("%+v", c.Auth.Keys)
	}
}

func TestKeyDErrors(t *testing.T) {
	_, k1 := pubLine(t, "")
	ca, caLine := pubLine(t, "")
	crt := &ssh.Certificate{Key: ca.PublicKey(), CertType: ssh.UserCert, KeyId: "x"}
	if err := crt.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	certLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(crt)))
	withCA := strings.Replace(baseMain, "endpoint:\n", "  ca:\n    - {name: people, type: user, key: \""+caLine+"\"}\nendpoint:\n", 1)
	cases := map[string]struct {
		main, file, body, want string
	}{
		"inline clash":     {baseMain, "robert.socha.pub", k1, "robert.socha"},
		"ca clash":         {withCA, "people.pub", k1, "people"},
		"options":          {baseMain, "jan.pub", `from="10.0.0.0/8" ` + k1, "options"},
		"cert-authority":   {baseMain, "jan.pub", "cert-authority " + k1, "options"},
		"certificate":      {baseMain, "jan.pub", certLine, "certificate"},
		"ca key":           {withCA, "jan.pub", caLine, "CA people"},
		"garbage":          {baseMain, "jan.pub", k1 + "\nnot a key\n", "jan.pub:2"},
		"empty":            {baseMain, "jan.pub", "# no keys\n", "no key"},
		"bad name":         {baseMain, "a:b.pub", k1, "name"},
		"same key twice":   {baseMain, "jan.pub", k1 + "\n" + k1 + "\n", "same key"},
		"key of an inline": {baseMain, "jan.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n x", "same key"},
	}
	for name, tc := range cases {
		_, p := writeTree(t, map[string]*string{"config.yaml": s(tc.main), "ssh.d/" + tc.file: s(tc.body)})
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "ssh.d") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestKeyDPermissions(t *testing.T) {
	_, k1 := pubLine(t, "")
	dir, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "ssh.d/jan.pub": s(k1)})
	f := filepath.Join(dir, "ssh.d", "jan.pub")
	for _, mode := range []os.FileMode{0o664, 0o646} {
		if err := os.Chmod(f, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "writable by group or others") || !strings.Contains(err.Error(), f) {
			t.Errorf("file %o: %v", mode, err)
		}
	}
	if err := os.Chmod(f, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(f), 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("dir: %v", err)
	}
	if err := os.Chmod(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
}

func TestKeyDCA(t *testing.T) {
	_, k1 := pubLine(t, "2025")
	_, k2 := pubLine(t, "2026")
	_, k3 := pubLine(t, "")
	main := strings.Replace(baseMain, "allow: [robert.socha]", "allow: [robert.socha, hosts:*, people:*]", 1)
	main = strings.Replace(main, "endpoint:\n", "  ca:\n    - {name: people, revoked: {key_ids: [gone], serials: [7]}}\nendpoint:\n", 1)
	dir, p := writeTree(t, map[string]*string{
		"config.yaml":              s(main),
		"ssh.d/ca/host/hosts.pub":  s("# rotation\n" + k1 + "\n" + k2 + "\n"),
		"ssh.d/ca/user/people.pub": s(k3 + "\n"),
		"ssh.d/ca/user/.x.pub":     s("junk"),
		"ssh.d/ca/user/README":     s("junk"),
	})
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]CA{}
	for _, ca := range c.Auth.CA {
		got[ca.Name] = ca
	}
	hosts, people := got["hosts"], got["people"]
	if len(got) != 2 || hosts.Type != "host" || len(hosts.Parsed) != 2 || hosts.File != filepath.Join(dir, "ssh.d/ca/host/hosts.pub") {
		t.Fatalf("hosts %+v", c.Auth.CA)
	}
	if people.Type != "user" || len(people.Parsed) != 1 || people.Revoked.KeyIDs[0] != "gone" || people.Revoked.Serials[0] != 7 {
		t.Fatalf("people %+v", people)
	}
	if !slices.Contains(c.Files, hosts.File) || !slices.Contains(c.Files, people.File) {
		t.Fatalf("files %v", c.Files)
	}
}

func TestKeyDCAErrors(t *testing.T) {
	ca, k1 := pubLine(t, "")
	_, k2 := pubLine(t, "")
	crt := &ssh.Certificate{Key: ca.PublicKey(), CertType: ssh.HostCert, KeyId: "x"}
	if err := crt.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	certLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(crt)))
	inline := func(entry string) string {
		return strings.Replace(baseMain, "endpoint:\n", "  ca:\n    - "+entry+"\nendpoint:\n", 1)
	}
	cases := map[string]struct {
		main  string
		files map[string]string
		want  []string
	}{
		"inline clash": {inline(`{name: hosts, type: host, key: "` + k2 + `"}`),
			map[string]string{"ssh.d/ca/host/hosts.pub": k1}, []string{"CA hosts is also defined in", "config.yaml"}},
		"host and user": {baseMain,
			map[string]string{"ssh.d/ca/host/hosts.pub": k1, "ssh.d/ca/user/hosts.pub": k2}, []string{"user/hosts.pub: CA hosts is also defined in", "host/hosts.pub"}},
		"inline identity": {baseMain,
			map[string]string{"ssh.d/ca/user/robert.socha.pub": k1}, []string{"CA robert.socha is the name of an identity in", "config.yaml"}},
		"ssh.d identity": {baseMain,
			map[string]string{"ssh.d/jan.pub": k2, "ssh.d/ca/user/jan.pub": k1}, []string{"CA jan is the name of an identity in", "ssh.d/jan.pub"}},
		"type mismatch": {inline("{name: hosts, type: user, revoked: {key_ids: [x]}}"),
			map[string]string{"ssh.d/ca/host/hosts.pub": k1}, []string{"CA hosts has type user in", "config.yaml"}},
		"keyless without file": {inline("{name: hosts, revoked: {key_ids: [x]}}"),
			nil, []string{"auth.ca hosts: no key and no ssh.d/ca file"}},
		"options":        {baseMain, map[string]string{"ssh.d/ca/host/hosts.pub": "cert-authority " + k1}, []string{"hosts.pub:1: authorized_keys options"}},
		"certificate":    {baseMain, map[string]string{"ssh.d/ca/host/hosts.pub": k1 + "\n" + certLine}, []string{"hosts.pub:2: a certificate"}},
		"unknown dir":    {baseMain, map[string]string{"ssh.d/ca/hosts/a.pub": k1}, []string{"ca/hosts: unexpected entry"}},
		"file under ca":  {baseMain, map[string]string{"ssh.d/ca/a.pub": k1}, []string{"ca/a.pub: unexpected entry"}},
		"host is a file": {baseMain, map[string]string{"ssh.d/ca/host": k1}, []string{"ca/host: not a directory"}},
		"bad name":       {baseMain, map[string]string{"ssh.d/ca/host/a:b.pub": k1}, []string{`CA name "a:b"`}},
		"empty":          {baseMain, map[string]string{"ssh.d/ca/host/hosts.pub": "# none\n"}, []string{"no key"}},
		"same key":       {baseMain, map[string]string{"ssh.d/ca/host/a.pub": k1, "ssh.d/ca/host/b.pub": k1}, []string{"auth.ca b: same host key as a"}},
		"identity key":   {baseMain, map[string]string{"ssh.d/jan.pub": k1, "ssh.d/ca/user/people.pub": k1}, []string{"auth.keys jan: the key of CA people"}},
	}
	for name, tc := range cases {
		files := map[string]*string{"config.yaml": s(tc.main)}
		for f, body := range tc.files {
			files[f] = s(body)
		}
		_, p := writeTree(t, files)
		_, err := Load(p)
		for _, want := range tc.want {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: want %q in %v", name, want, err)
			}
		}
	}
}

func TestKeyDCAPermissions(t *testing.T) {
	_, k1 := pubLine(t, "")
	dir, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "ssh.d/ca/host/hosts.pub": s(k1)})
	for _, rel := range []string{"ssh.d/ca/host/hosts.pub", "ssh.d/ca/host", "ssh.d/ca"} {
		f := filepath.Join(dir, rel)
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f, fi.Mode().Perm()|0o020); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), f+": writable by group or others") {
			t.Errorf("%s: %v", rel, err)
		}
		if err := os.Chmod(f, fi.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
}

// Every file holds one YAML document: a second one is an error naming the
// file, trailing comments and blank lines are not.
func TestOneDocumentPerFile(t *testing.T) {
	second := "\n---\nauth: {clock_skew: -1s}\nunknown_security_option: true\n"
	if _, err := Parse([]byte(good + second)); err == nil || !strings.Contains(err.Error(), "more than one YAML document") {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := Parse([]byte(good + "\n---\n")); err == nil {
		t.Fatal("Parse: empty second document accepted")
	}
	if _, err := Parse([]byte(good + "\n# trailing comment\n\n  \n")); err != nil {
		t.Fatalf("Parse trailing comment: %v", err)
	}
	_, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain + second)})
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), p+": more than one YAML document") {
		t.Fatalf("Load main: %v", err)
	}
	dir, p := writeTree(t, map[string]*string{"config.yaml": s(baseMain), "config.d/a.yaml": s("limits: {conn: {max: 10}}\n---\nlimits: {conn: {max: 20}}\n")})
	snip := filepath.Join(dir, "config.d", "a.yaml")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), snip+": more than one YAML document") {
		t.Fatalf("Load snippet: %v", err)
	}
	_, p = writeTree(t, map[string]*string{"config.yaml": s(baseMain + "# end\n\n"), "config.d/a.yaml": s("limits: {conn: {max: 10}}\n# end\n")})
	if _, err := Load(p); err != nil {
		t.Fatalf("Load trailing comments: %v", err)
	}
}
