package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"luk/internal/client"
	"luk/internal/sshsig"
	"luk/internal/tlsself"
	"luk/internal/wire"
)

// scanEnv runs lukd with the tls mode self listener main: the endpoint
// drop (respond url, secret, pretty, private owner, link replace and list)
// for robert.socha and backup for other only.
type scanEnv struct {
	url  string // https://127.0.0.1:port
	pin  string
	key  string
	host string
}

func newScanEnv(t *testing.T) *scanEnv {
	t.Helper()
	tempConfig(t)
	addr, root := freeAddr(t), t.TempDir()
	e := &scanEnv{url: "https://" + addr, host: addr}
	var pub, otherPub string
	e.key, pub = newKeyFile(t)
	_, otherPub = newKeyFile(t)
	var err error
	if e.pin, err = tlsself.Generate(filepath.Join(root, "tls/s.crt"), filepath.Join(root, "tls/s.key"), "luk.test", tlsself.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf(`
root: %s
listen:
  main: {addr: "%s", tls: {mode: self, cert: tls/s.crt, key: tls/s.key, host: luk.test}}
auth:
  keys: [{name: robert.socha, key: "%s"}, {name: other, key: "%s"}]
endpoint:
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha], respond: url, storage: drop, pretty: {allow: ['*']}, link: {replace: ['*'], list: ['*']}, secret: {allow: ['*'], path: q/secret, storage: volatile}}
  backup: {listen: main, endpoint: /backup, path: q/backup, allow: [other]}
pipeline:
  drop: {endpoint: [drop], steps: [{store: drop}]}
  backup: {endpoint: [backup], steps: [{store: drop}]}
storage:
  drop: {type: local, base: s/drop, ttl: {user: true, min: 1h, max: 7d}, path: "{{ .Random }}", expose: drop}
  volatile: {type: local, base: s/volatile, ttl: {user: true, max: 1d}, path: "{{ .Random }}", expose: volatile}
expose:
  drop: {listen: main, path: /d/}
  volatile: {listen: main, path: /v/}
`, root, addr, pub, otherPub)
	startLukd(t, filepath.Join(t.TempDir(), "config.yaml"), text, addr)
	return e
}

func TestScan(t *testing.T) {
	e := newScanEnv(t)
	for _, target := range []string{e.url, e.url + "/", e.url + "/drop"} {
		code, out, errs := runLuk(t, "scan", "-k", e.key, target)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", target, code, errs)
		}
		want := e.pin + "\n" +
			"NAME  URL" + strings.Repeat(" ", len(e.url)+4) + "RESPOND  TTL          FLAGS\n" +
			"drop  " + e.url + "/drop  url      7d (1h..7d)  secret,pretty-url,mutable,link-ls\n"
		if out != want {
			t.Errorf("%s:\n%s\nwant:\n%s", target, out, want)
		}
		if !strings.Contains(errs, "subject:") || !strings.Contains(errs, "not after:") {
			t.Errorf("stderr %q", errs)
		}
	}
}

func TestScanJSON(t *testing.T) {
	e := newScanEnv(t)
	out := mustRun(t, "scan", "-k", e.key, "--json", e.url)
	var got struct {
		Pin       string              `json:"pin"`
		Endpoints []wire.EndpointInfo `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Pin != e.pin || len(got.Endpoints) != 1 {
		t.Fatalf("%s", out)
	}
	d := got.Endpoints[0]
	if d.Name != "drop" || d.URL != e.url+"/drop" || !d.Secret || d.TTL == nil || d.TTL.Default != "7d" || d.SecretTTL == nil || d.SecretTTL.Max != "1d" {
		t.Fatalf("%+v", d)
	}
	out = mustRun(t, "scan", "-k", e.key, "--json", "--pin", e.url)
	if strings.TrimSpace(out) != `{
  "pin": "`+e.pin+`"
}` {
		t.Fatalf("pin only: %s", out)
	}
	out = mustRun(t, "scan", "-k", e.key, "--json", "--endpoints", e.url)
	if strings.Contains(out, `"pin"`) || !strings.Contains(out, `"endpoints"`) {
		t.Fatalf("endpoints only: %s", out)
	}
}

func TestScanPin(t *testing.T) {
	e := newScanEnv(t)
	code, out, errs := runLuk(t, "scan", "--pin", e.url+"/drop")
	if code != 0 || out != e.pin+"\n" || !strings.Contains(errs, "subject:") {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
	if code, _, _ := runLuk(t, "scan", "--pin", "http://h/drop"); code != 1 {
		t.Errorf("http --pin: exit %d", code)
	}
}

func TestScanPrint(t *testing.T) {
	e := newScanEnv(t)
	out := mustRun(t, "scan", "-k", e.key, "--print", e.url)
	if want := "luk config endpoint add -e drop --url '" + e.url + "/drop#" + e.pin + "' --key " + e.key + "\n"; out != want {
		t.Fatalf("%q, want %q", out, want)
	}
	for target, name := range map[string]string{e.url + "/drop": "drop", e.url + "/a/up/": "up", e.url: "NAME"} {
		out = mustRun(t, "scan", "--pin", "--print", target)
		if want := "luk config endpoint add -e " + name + " --url '" + target + "#" + e.pin + "'\n"; out != want {
			t.Errorf("%q, want %q", out, want)
		}
	}
	// The printed command adds the endpoint; the listing then trusts its
	// pin and signs with its key.
	add := strings.Fields(strings.ReplaceAll(mustRun(t, "scan", "-k", e.key, "--print", e.url), "'", ""))
	mustRun(t, add[1:]...)
	if out := mustRun(t, "scan", "--endpoints", "drop"); !strings.Contains(out, "drop  "+e.url+"/drop") {
		t.Fatalf("by name: %s", out)
	}
	// The key of the config endpoint is printed with its commands.
	if out := mustRun(t, "scan", "--print", "drop"); !strings.HasSuffix(out, "' --key "+e.key+"\n") {
		t.Fatalf("config key: %q", out)
	}
	if code, out, _ := runLuk(t, "scan", "--json", "--print", e.url); code != 1 || out != "" {
		t.Errorf("--json --print: exit %d %q", code, out)
	}
}

func TestScanListingFails(t *testing.T) {
	e := newScanEnv(t)
	stranger, _ := newKeyFile(t)
	code, out, errs := runLuk(t, "scan", "-k", stranger, e.url)
	if code != 2 || out != e.pin+"\n" || !strings.Contains(errs, "luk: listing endpoints of "+e.host+": rejected (401 Unauthorized): unknown key") {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
	// A config pin that does not match fails the listing.
	mustRun(t, "config", "endpoint", "add", "-e", "drop", "--url", e.url+"/drop", "--pin", "sha256//"+strings.Repeat("A", 43)+"=", "-k", e.key)
	code, _, errs = runLuk(t, "scan", "--endpoints", e.url+"/drop")
	if code != 3 || !strings.Contains(errs, "pin mismatch") {
		t.Fatalf("pin mismatch: exit %d %q", code, errs)
	}
}

func TestScanNoListing(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	code, out, errs := runLuk(t, "scan", "-k", key, ts.URL)
	if code != 2 || out != tlsself.Pin(ts.Certificate())+"\n" || !strings.Contains(errs, "the server does not offer an endpoint listing") {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
}

// Without a key configured every agent key is tried until the server
// knows one; an http URL has no pin.
func TestScanAgentKeys(t *testing.T) {
	tempConfig(t)
	fps := agentWithKeys(t, 3)
	ks := newKeyServer(t, fps[2])
	code, out, errs := runLuk(t, "scan", ks.url)
	if code != 0 || out != "" || ks.signer() != fps[2] {
		t.Fatalf("exit %d %q %q, signer %s", code, out, errs, ks.signer())
	}
	ks = newKeyServer(t)
	code, _, errs = runLuk(t, "scan", ks.url)
	if code != 2 || !strings.Contains(errs, "none of the 3 agent keys is known") {
		t.Fatalf("exit %d %q", code, errs)
	}
}

// --print names the agent key the server knew, by its fingerprint.
func TestScanPrintAgentKey(t *testing.T) {
	tempConfig(t)
	fps := agentWithKeys(t, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blob, _ := base64.StdEncoding.DecodeString(r.Header.Get(wire.HeaderSignature))
		sig, err := sshsig.ParseBlob(blob)
		if err != nil || ssh.FingerprintSHA256(sig.Key) != fps[1] {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":"unknown key x"}`)
			return
		}
		fmt.Fprintf(w, `{"endpoints":[{"name":"backup","path":"/backup","url":"http://%s/backup","respond":"accept",
			"quota":{"mode":"enforce","rate":"10G/1d","burst":53687091200,"tokens":13421772800}}]}`, r.Host)
	}))
	defer srv.Close()
	out := mustRun(t, "scan", "--print", srv.URL)
	if want := "luk config endpoint add -e backup --url " + srv.URL + "/backup --key " + fps[1] + "\n"; out != want {
		t.Fatalf("%q, want %q", out, want)
	}
	out = mustRun(t, "scan", srv.URL)
	if !strings.Contains(out, "QUOTA") || !strings.Contains(out, "  10G/1d 50G (12.5G left)\n") {
		t.Fatalf("%s", out)
	}
}

// The endpoint table escapes the control characters a server sends.
func TestPrintEndpointsEscapes(t *testing.T) {
	var b strings.Builder
	err := printEndpoints(&b, []wire.EndpointInfo{{Name: "d\x1b[2J", URL: "https://h/d\nx", Respond: "url\t"}})
	want := "NAME      URL             RESPOND  TTL  FLAGS\n" + `d\x1b[2J  https://h/d\nx  url\t    -    -` + "\n"
	if err != nil || b.String() != want {
		t.Fatalf("%v\n%q\nwant %q", err, b.String(), want)
	}
}

// The backup hostname mode is a flag of its own, absent without one.
func TestPrintEndpointsBackupHost(t *testing.T) {
	var b strings.Builder
	err := printEndpoints(&b, []wire.EndpointInfo{
		{Name: "a", URL: "u", Respond: "accept", BackupHostname: wire.BackupHostPrincipal},
		{Name: "b", URL: "u", Respond: "url", Pretty: true, BackupHostname: "none\x1b"},
		{Name: "c", URL: "u", Respond: "url"},
	})
	want := "NAME  URL  RESPOND  TTL  FLAGS\n" +
		"a     u    accept   -    backup-host:principal\n" +
		"b     u    url      -    pretty-url,backup-host:none\\x1b\n" +
		"c     u    url      -    -\n"
	if err != nil || b.String() != want {
		t.Fatalf("%v\n%q\nwant %q", err, b.String(), want)
	}
}

// --print pins only a chain that does not verify (or with --pin): an acme
// certificate verifies against the system CAs and changes its key at
// every renewal.
func TestScanPrintPinFragment(t *testing.T) {
	pin := "sha256//" + strings.Repeat("A", 43) + "="
	for _, c := range []struct {
		cert    *client.Certificate
		pinOnly bool
		want    string
	}{
		{nil, false, ""},
		{&client.Certificate{Pin: pin}, false, "#" + pin},
		{&client.Certificate{Pin: pin, Verified: true}, false, ""},
		{&client.Certificate{Pin: pin, Verified: true}, true, "#" + pin},
	} {
		if got := pinFragment(c.cert, c.pinOnly); got != c.want {
			t.Errorf("%+v pin %v: %q, want %q", c.cert, c.pinOnly, got, c.want)
		}
	}
}
