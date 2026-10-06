package config

import (
	"strings"
	"testing"
)

func TestDataLayout(t *testing.T) {
	c, err := Parse([]byte("root: /srv/luk\n" + good))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct{ got, want string }{
		{c.DataDir(), "/srv/luk/data"},
		{c.RootDir(), "/srv/luk/root"},
		{c.WorkDir(), "/srv/luk/data/work"},
		{c.GPGCacheDir(), "/srv/luk/data/gpg-cache"},
		{c.ACMECacheDir("https://acme-v02.api.letsencrypt.org/directory"), "/srv/luk/data/acme/acme-v02.api.letsencrypt.org_directory"},
	} {
		if x.got != x.want {
			t.Errorf("got %q, want %q", x.got, x.want)
		}
	}
}

func TestRelativePathsResolveInData(t *testing.T) {
	src := strings.NewReplacer(
		"cert: /tmp/c.crt", "cert: tls/c.crt",
		"key: /tmp/c.key", "key: tls/c.key",
		"path: /queue/backup", "path: queue/backup",
		"base: /storage/archive", "base: storage/archive",
	).Replace("root: /srv/luk\n" + good)
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if tl := c.Listen["main"].TLS; tl.Cert != "/srv/luk/data/tls/c.crt" || tl.Key != "/srv/luk/data/tls/c.key" {
		t.Fatalf("tls %q %q", tl.Cert, tl.Key)
	}
	if got := c.Endpoint["backup"].Path; got != "/srv/luk/data/queue/backup" {
		t.Fatalf("endpoint path %q", got)
	}
	if got := c.Storage["archive"].Base; got != "/srv/luk/data/storage/archive" {
		t.Fatalf("base %q", got)
	}
}

func TestPathsOutsideData(t *testing.T) {
	for repl, want := range map[string]string{
		"path: /queue/backup|path: ../root/q":                `endpoint.backup.path: "../root/q" escapes /var/lib/luk/data`,
		"path: /queue/backup|path: /var/lib/luk/root/q":      "endpoint.backup.path: /var/lib/luk/root/q lies in /var/lib/luk/root",
		"base: /storage/archive|base: /var/lib/luk/root":     "storage.archive.base: /var/lib/luk/root lies in /var/lib/luk/root",
		"cert: /tmp/c.crt|cert: /var/lib/luk/root/job/c.crt": "listen.main.tls.cert: /var/lib/luk/root/job/c.crt lies in /var/lib/luk/root",
	} {
		old, nw, _ := strings.Cut(repl, "|")
		_, err := Parse([]byte(strings.Replace(good, old, nw, 1)))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", nw, want, err)
		}
	}
	nonces := "auth:\n  nonces: /var/lib/luk/root/n\n"
	_, err := Parse([]byte(strings.Replace(good, "auth:\n", nonces, 1)))
	if err == nil || !strings.Contains(err.Error(), "auth.nonces: /var/lib/luk/root/n lies in /var/lib/luk/root") {
		t.Errorf("nonces: %v", err)
	}
}
