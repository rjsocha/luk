package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// An expose with auth.basic and auth.ssh: luk gets with the key, a
// browser with the password.
func TestGetDualAuth(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	v := newVaultEnvAuth(t, "{basic: ['dev:"+string(hash)+"'], ssh: {allow: [robert.socha]}}")
	v.put(t, "db.sql.gz", "dump", "2026-10-03T10:00:00Z")
	if code, out, errs := runLuk(t, "get", strings.Replace(v.url, "/v/#", "/v/db.sql.gz#", 1), "-k", v.key, "-c"); code != 0 || out != "dump" {
		t.Fatalf("luk get: exit %d %q %q", code, out, errs)
	}
	// The https URL lukd hands out for such an expose, pin included.
	if code, out, errs := runLuk(t, "get", strings.Replace(strings.Replace(v.url, "/v/#", "/v/db.sql.gz#", 1), "luk://", "https://", 1), "-k", v.key, "-c"); code != 0 || out != "dump" {
		t.Fatalf("luk get https: exit %d %q %q", code, out, errs)
	}
	if out := mustRun(t, "get", v.url, "-k", v.key, "--json"); !strings.Contains(out, `"name": "db.sql.gz"`) {
		t.Fatalf("luk listing:\n%s", out)
	}
	if code, _, errs := runLuk(t, "get", v.url, "-k", v.other); code != 2 || !strings.Contains(errs, "404") {
		t.Fatalf("other: exit %d %q", code, errs)
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	get := func(p, user, pass string) (*http.Response, string) {
		t.Helper()
		r, err := http.NewRequest("GET", v.secure+p, nil)
		if err != nil {
			t.Fatal(err)
		}
		if user != "" {
			r.SetBasicAuth(user, pass)
		}
		res, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res, string(b)
	}
	if res, body := get("/v/db.sql.gz", "dev", "pw"); res.StatusCode != 200 || body != "dump" {
		t.Fatalf("basic: %d %q", res.StatusCode, body)
	}
	if res, body := get("/v/", "dev", "pw"); res.StatusCode != 200 || !strings.Contains(body, "db.sql.gz") || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("basic index: %d %v", res.StatusCode, res.Header)
	}
	if res, _ := get("/v/db.sql.gz", "", ""); res.StatusCode != 401 || res.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("no auth: %d %v", res.StatusCode, res.Header)
	}
}
