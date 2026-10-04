package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/config"
	"luk/internal/quota"
	"luk/internal/wire"
)

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// quotaConfig has backup with classes large and small and the catch-all
// others, logs with a top-level rate and drop without quota. It returns
// the config path, its root and a host certificate file (Key ID
// db1.example.org, principal db1.example.org).
func quotaConfig(t *testing.T) (string, string, string) {
	t.Helper()
	root, dir := t.TempDir(), t.TempDir()
	ca, host := newTestSigner(t), newTestSigner(t)
	c := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, KeyId: "db1.example.org",
		ValidPrincipals: []string{"db1.example.org"}, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "host-cert.pub")
	if err := os.WriteFile(certFile, ssh.MarshalAuthorizedKey(c), 0o600); err != nil {
		t.Fatal(err)
	}
	text := `root: ` + root + `
listen: {main: {addr: "127.0.0.1:0"}}
auth:
  keys: [{name: robert.socha, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n"}]
  ca: [{name: hosts, type: host, key: "` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey()))) + `"}]
endpoint:
  backup:
    listen: main
    endpoint: /backup
    path: q/backup
    allow: ["*"]
    quota:
      class:
        - {name: large, members: ["hosts#db*"], rate: 50G/1d, burst: 100G}
        - {name: small, members: ["hosts:*.example.org"], rate: 20G/1d}
        - {name: others, rate: 5G/1d}
  logs: {listen: main, endpoint: /logs, path: q/logs, allow: ["*"], quota: {mode: passive, rate: 1G/1d}}
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: ["*"]}
pipeline:
  p: {endpoint: [backup, logs, drop], steps: [{store: s}]}
storage:
  s: {type: local, base: s, path: "{{ .Id }}"}
`
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	return p, root, certFile
}

func TestQuotaExplain(t *testing.T) {
	cfgPath, _, cert := quotaConfig(t)
	out, err := runLukd(t, "-c", cfgPath, "quota", "explain", cert)
	if err != nil {
		t.Fatal(err)
	}
	want := `ENDPOINT  CLASS    RATE    BURST  MODE     MATCH
backup      large  50G/1d  100G   enforce  hosts#db*
backup    * small  20G/1d  20G    enforce  hosts:*.example.org
logs      * -      1G/1d   1G     passive  (catch-all)
`
	if out != want {
		t.Fatalf("%s\nwant:\n%s", out, want)
	}
	out, err = runLukd(t, "-c", cfgPath, "quota", "explain", "--endpoint", "backup", "robert.socha")
	if err != nil {
		t.Fatal(err)
	}
	if want := "ENDPOINT  CLASS     RATE   BURST  MODE     MATCH\nbackup    * others  5G/1d  5G     enforce  (catch-all)\n"; out != want {
		t.Fatalf("%s\nwant:\n%s", out, want)
	}
	if _, err := runLukd(t, "-c", cfgPath, "quota", "explain", "nobody"); err == nil || !strings.Contains(err.Error(), "neither a file nor a known key name") {
		t.Fatal(err)
	}
	if _, err := runLukd(t, "-c", cfgPath, "quota", "explain", "--endpoint", "drop", "robert.socha"); err == nil || !strings.Contains(err.Error(), "endpoint drop has no quota") {
		t.Fatal(err)
	}
}

func TestQuotaLs(t *testing.T) {
	cfgPath, root, _ := quotaConfig(t)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	at := now.Add(-50 * time.Hour)
	b := quota.New(slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return at })
	if _, err := b.Open(quota.Path(root)); err != nil {
		t.Fatal(err)
	}
	host := &wire.Identity{Type: "certificate", CA: "hosts", KeyID: "db1.example.org", Principals: []string{"db1.example.org"}}
	send := func(endpoint, owner string, id *wire.Identity, n int64) {
		l, _ := quota.Resolve(cfg.Endpoint[endpoint].Quota, id)
		c := b.Begin(endpoint, owner, l)
		_ = c.Take(n)
		c.Done(n)
	}
	send("backup", "cert:hosts:db1.example.org", host, 8<<30)
	at = now.Add(-30 * time.Minute)
	send("backup", "cert:hosts:db1.example.org", host, 6<<30)
	send("backup", "cert:hosts:db1.example.org", host, 4<<30)
	send("logs", "key:robert.socha", &wire.Identity{Type: "key", Name: "robert.socha"}, 100<<20)

	out, err := runLukd(t, "-c", cfgPath, "quota", "ls")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 || strings.Join(strings.Fields(lines[0]), " ") != "ENDPOINT IDENTITY CLASS MODE RATE TOKENS 24H 7D LOW REFUSED SUGGEST" {
		t.Fatalf("%s", out)
	}
	// 10G in the last day, 18G in 7 days; the largest day 10G and upload
	// 8G with 50% are 15G/1d and 12G, raised to 15G.
	if got := strings.Join(strings.Fields(lines[1]), " "); !strings.HasPrefix(got, "backup hosts#db1.example.org small enforce 20G/1d ") ||
		!strings.HasSuffix(got, " 10G (2) 18G (3) 10G 0 15G/1d 15G") {
		t.Fatalf("%q", got)
	}
	// Less than a day of history: no suggestion.
	if got := strings.Join(strings.Fields(lines[2]), " "); !strings.HasPrefix(got, "logs robert.socha - passive 1G/1d ") ||
		!strings.HasSuffix(got, "/1G 100M (1) 100M (1) 924M 0 -") {
		t.Fatalf("%q", got)
	}
	out, err = runLukd(t, "-c", cfgPath, "quota", "ls", "--endpoint", "backup", "--margin", "0")
	if err != nil || !strings.Contains(out, " 10G/1d 10G\n") || strings.Contains(out, "logs") {
		t.Fatalf("%s %v", out, err)
	}
	if _, err := runLukd(t, "-c", cfgPath, "quota", "ls", "--margin", "x"); err == nil {
		t.Fatal("bad margin accepted")
	}
}
