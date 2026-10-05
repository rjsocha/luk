package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/channel/chantest"
	"luk/internal/client"
	"luk/internal/config"
	"luk/internal/sshsig"
	"luk/internal/tlsself"
	"luk/internal/wire"
)

// scanEnv runs lukd with the tls mode self listener main: the endpoint
// drop (respond url, secret, pretty, link replace and list) for
// robert.socha and backup for other only.
type scanEnv struct {
	url   string // https://127.0.0.1:port
	pin   string // the SPKI pin of the certificate, for downloads
	words string // the channel pin
	full  string // the lukd key, base64url
	key   string
	host  string
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
	p := filepath.Join(t.TempDir(), "config.yaml")
	startLukd(t, p, text, addr)
	k, err := channel.LoadKey(config.IdentityPath(p))
	if err != nil {
		t.Fatal(err)
	}
	e.words, e.full = channel.Words(k.Public), channel.KeyString(k.Public)
	return e
}

func TestScan(t *testing.T) {
	e := newScanEnv(t)
	for _, target := range []string{e.url, e.url + "/", e.url + "/drop"} {
		code, out, errs := runLuk(t, "scan", "-k", e.key, target)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", target, code, errs)
		}
		want := e.words + "\n" +
			"NAME  URL" + strings.Repeat(" ", len(e.url)+4) + "RESPOND  TTL          FLAGS\n" +
			"drop  " + e.url + "/drop  url      7d (1h..7d)  secret,pretty-url,mutable,link-ls\n"
		if out != want {
			t.Errorf("%s:\n%s\nwant:\n%s", target, out, want)
		}
		if errs != "download pin: "+e.pin+"\n" {
			t.Errorf("stderr %q", errs)
		}
	}
}

func TestScanJSON(t *testing.T) {
	e := newScanEnv(t)
	out := mustRun(t, "scan", "-k", e.key, "--json", e.url)
	var got struct {
		Pin         string              `json:"pin"`
		DownloadPin string              `json:"download_pin"`
		Endpoints   []wire.EndpointInfo `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Pin != e.words || got.DownloadPin != e.pin || len(got.Endpoints) != 1 {
		t.Fatalf("%s", out)
	}
	d := got.Endpoints[0]
	if d.Name != "drop" || d.URL != e.url+"/drop" || !d.Secret || d.TTL == nil || d.TTL.Default != "7d" || d.SecretTTL == nil || d.SecretTTL.Max != "1d" {
		t.Fatalf("%+v", d)
	}
	out = mustRun(t, "scan", "-k", e.key, "--json", "--pin", "--pin-format", "key", e.url)
	if strings.TrimSpace(out) != `{
  "pin": "`+e.full+`",
  "download_pin": "`+e.pin+`"
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
	if code != 0 || out != e.words+"\n" || errs != "download pin: "+e.pin+"\n" {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
	// Over http the channel has a pin too, and there is no download pin.
	l := newLukdEnv(t)
	code, out, errs = runLuk(t, "scan", "--pin", l.base+"/drop")
	if code != 0 || len(strings.Split(strings.TrimSpace(out), "-")) != 6 || errs != "" {
		t.Errorf("http --pin: exit %d %q %q", code, out, errs)
	}
}

// The channel pin is printed as words, or as the key with --pin-format
// key; the commands of --print carry it as the fragment.
func TestScanPrintsWords(t *testing.T) {
	e := newScanEnv(t)
	if out := mustRun(t, "scan", "-k", e.key, "--pin", e.url); out != e.words+"\n" {
		t.Fatalf("words: %q", out)
	}
	out := mustRun(t, "scan", "-k", e.key, "--pin", "--pin-format", "key", e.url)
	if k := strings.TrimSpace(out); len(k) != 43 || k != e.full {
		t.Fatalf("key: %q", out)
	}
	out = mustRun(t, "scan", "-k", e.key, "--print", e.url)
	if want := "luk config endpoint add -e drop --url '" + e.url + "/drop#" + e.words + "' --key " + e.key + "\n"; out != want {
		t.Fatalf("%q, want %q", out, want)
	}
	out = mustRun(t, "scan", "-k", e.key, "--print", "--pin-format", "key", e.url)
	if want := "luk config endpoint add -e drop --url '" + e.url + "/drop#" + e.full + "' --key " + e.key + "\n"; out != want {
		t.Fatalf("%q, want %q", out, want)
	}
	if code, _, errs := runLuk(t, "scan", "--pin-format", "hex", e.url); code != 1 || !strings.Contains(errs, "--pin-format") {
		t.Fatalf("bad format: exit %d %q", code, errs)
	}
}

// An https listener whose chain does not verify also has its download pin,
// the one lukd tls pin prints, on stderr.
func TestScanDownloadPin(t *testing.T) {
	e := newScanEnv(t)
	code, out, errs := runLuk(t, "scan", "-k", e.key, "--print", e.url)
	if code != 0 || strings.Contains(out, "sha256//") || errs != "download pin: "+e.pin+"\n" {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
	if code, _, errs := runLuk(t, "scan", "-k", e.key, "--endpoints", e.url); code != 0 || errs != "" {
		t.Fatalf("--endpoints: exit %d %q", code, errs)
	}
	for _, c := range []struct {
		cert *client.Certificate
		want string
	}{
		{nil, ""},
		{&client.Certificate{Pin: e.pin}, e.pin},
		{&client.Certificate{Pin: e.pin, Verified: true}, ""},
	} {
		if got := downloadPin(c.cert); got != c.want {
			t.Errorf("%+v: %q, want %q", c.cert, got, c.want)
		}
	}
}

// A lukd key that matches none of the pins configured or given for the
// URL is printed and said to differ; the signed listing never goes to it,
// so there are no endpoints and no commands from --print.
func TestScanPinMismatch(t *testing.T) {
	e := newScanEnv(t)
	other, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	wrong := channel.Words(other.Public)
	code, out, errs := runLuk(t, "scan", "-k", e.key, "--pin", e.url+"/drop#"+wrong)
	if code != 3 || out != e.words+"\n" || !strings.Contains(errs, "luk: the lukd key "+e.words+" matches no pin of this endpoint") {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
	mustRun(t, "config", "endpoint", "add", "-e", "drop", "--url", e.url+"/drop#"+wrong, "--key", e.key)
	code, out, errs = runLuk(t, "scan", "--print", "drop")
	if code != 3 || out != "" || !strings.Contains(errs, "matches no pin of this endpoint") {
		t.Fatalf("--print: exit %d %q %q", code, out, errs)
	}
	code, out, errs = runLuk(t, "scan", "drop")
	if code != 3 || out != e.words+"\n" || !strings.Contains(errs, "matches no pin of this endpoint") || strings.Contains(errs, "listing endpoints") {
		t.Fatalf("default: exit %d %q %q", code, out, errs)
	}
	code, out, _ = runLuk(t, "scan", "--json", "drop")
	var res map[string]any
	if code != 3 || json.Unmarshal([]byte(out), &res) != nil || res["pin"] != e.words || res["endpoints"] != nil {
		t.Fatalf("--json: exit %d %q", code, out)
	}
	if code, out, _ = runLuk(t, "scan", "--endpoints", "drop"); code != 3 || out != "" {
		t.Fatalf("--endpoints: exit %d %q", code, out)
	}
}

func TestScanPrint(t *testing.T) {
	e := newScanEnv(t)
	for target, name := range map[string]string{e.url + "/drop": "drop", e.url + "/a/up/": "up", e.url: "NAME"} {
		out := mustRun(t, "scan", "--pin", "--print", target)
		if want := "luk config endpoint add -e " + name + " --url '" + target + "#" + e.words + "'\n"; out != want {
			t.Errorf("%q, want %q", out, want)
		}
	}
	// A config endpoint is listed by its name and signs with its key.
	mustRun(t, "config", "endpoint", "add", "-e", "drop", "--url", e.url+"/drop#"+e.words, "--key", e.key)
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
	if code != 2 || out != e.words+"\n" || !strings.Contains(errs, "luk: listing endpoints of "+e.host+": rejected (401 Unauthorized): unknown key") {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
}

// A server that does not speak the channel is not lukd: nothing is
// listed and there is no channel pin.
func TestScanNotLukd(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	code, out, errs := runLuk(t, "scan", "-k", key, ts.URL)
	if code != 3 || out != "" || !strings.Contains(errs, "not answered by lukd: HTTP 404") {
		t.Fatalf("exit %d %q %q", code, out, errs)
	}
}

// Without a key configured every agent key is tried, each in a channel of
// its own, until the server knows one.
func TestScanAgentKeys(t *testing.T) {
	tempConfig(t)
	fps := agentWithKeys(t, 3)
	ks := newKeyServer(t, fps[2])
	code, out, errs := runLuk(t, "scan", ks.url)
	if code != 0 || out != ks.srv.Pin()+"\n" || ks.signer() != fps[2] {
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
	srv := chantest.New(t)
	srv.Op = func(req channel.Request, _ []byte) *chantest.Answer {
		blob, _ := base64.StdEncoding.DecodeString(req.Header.Get(wire.HeaderSignature))
		sig, err := sshsig.ParseBlob(blob)
		if req.Method != http.MethodGet || req.Target != wire.EndpointsPath {
			return &chantest.Answer{Status: http.StatusNotFound, Body: wire.ErrorResponse{Error: "not here"}}
		}
		if err != nil || ssh.FingerprintSHA256(sig.Key) != fps[1] {
			return &chantest.Answer{Status: http.StatusUnauthorized, Body: wire.ErrorResponse{Error: "unknown key x"}}
		}
		return &chantest.Answer{Status: http.StatusOK, Body: json.RawMessage(`{"endpoints":[{"name":"backup","path":"/backup","url":"` + srv.URL + `/backup","respond":"accept",
			"quota":{"mode":"enforce","rate":"10G/1d","burst":53687091200,"tokens":13421772800}}]}`)}
	}
	out := mustRun(t, "scan", "--print", srv.URL)
	if want := "luk config endpoint add -e backup --url '" + srv.URL + "/backup#" + srv.Pin() + "' --key " + fps[1] + "\n"; out != want {
		t.Fatalf("%q, want %q", out, want)
	}
	out = mustRun(t, "scan", srv.URL)
	if !strings.Contains(out, "QUOTA") || !strings.Contains(out, "  10G/1d 50G (12.5G left)\n") {
		t.Fatalf("%s", out)
	}
}

// One self-signed listener has an endpoint and an expose: uploads take
// the channel pin, downloads the SPKI pin, and neither takes the other.
func TestMixedListener(t *testing.T) {
	tempConfig(t)
	addr, root := freeAddr(t), t.TempDir()
	key, pub := newKeyFile(t)
	spki, err := tlsself.Generate(filepath.Join(root, "tls/s.crt"), filepath.Join(root, "tls/s.key"), "luk.test", tlsself.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf(`
root: %s
listen:
  main: {addr: "%s", public: "https://%s", tls: {mode: self, cert: tls/s.crt, key: tls/s.key, host: luk.test}}
auth:
  keys: [{name: robert.socha, key: "%s"}]
endpoint:
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha], respond: url, storage: drop, private: {owner: ['*']}}
pipeline:
  drop: {endpoint: [drop], steps: [{store: drop}]}
storage:
  drop: {type: local, base: s/drop, path: "{{ .Random }}", expose: drop, protect: secure}
expose:
  drop: {listen: main, path: /d/}
  secure: {listen: main, path: /p/, auth: {ssh: {allow: ["*"]}}}
`, root, addr, addr, pub)
	p := filepath.Join(t.TempDir(), "config.yaml")
	startLukd(t, p, text, addr)
	words := lukdPin(t, p)
	base := "https://" + addr

	link := strings.TrimSpace(mustRun(t, "send", "-e", base+"/drop#"+words, "-k", key, "--private", "--file", namedFile(t, "a.txt", "mixed")))
	if !strings.HasPrefix(link, "luk://"+addr+"/p/") || !strings.HasSuffix(link, "#"+spki) {
		t.Fatalf("link %q, want luk://%s/p/...#%s", link, addr, spki)
	}
	waitUntil(t, link+" downloads", func() bool {
		code, out, _ := runLuk(t, "get", link, "-k", key, "-c")
		return code == 0 && out == "mixed"
	})

	code, _, errs := runLuk(t, "send", "-e", base+"/drop#"+spki, "-k", key, "--file", namedFile(t, "b.txt", "b"))
	if code != 1 || !strings.Contains(errs, channel.ErrTLSPin.Error()) {
		t.Fatalf("send with the SPKI pin: exit %d %q", code, errs)
	}
	plain := strings.SplitN(link, "#", 2)[0]
	code, _, errs = runLuk(t, "get", plain+"#"+words, "-k", key, "-c")
	if code != 1 || !strings.Contains(errs, "URL fragment must be a pin, sha256//...") {
		t.Fatalf("get with the channel pin: exit %d %q", code, errs)
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

// An endpoint pinned with an old TLS pin must not stop the scan that tells
// the pin to replace it with, and that scan's own output must fix it.
func TestScanIgnoresStaleTLSPin(t *testing.T) {
	e := newScanEnv(t)
	stale := "sha256//" + e.pin
	cfgPath := client.DefaultConfigPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	text := "endpoint:\n  backup: {url: " + e.url + "/backup, pin: '" + stale + "', key: " + e.key + "}\n"
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	notice := "endpoint backup: pin " + stale + " is not a lukd key (old TLS pin?): replace it with the pin below\n"
	for _, target := range []string{e.url + "/backup", "backup", e.url + "/drop"} {
		code, out, errs := runLuk(t, "scan", "--pin", target)
		if code != 0 || out != e.words+"\n" || !strings.Contains(errs, notice) {
			t.Errorf("%s: exit %d out %q err %q", target, code, out, errs)
		}
	}
	code, out, errs := runLuk(t, "scan", "-k", e.key, e.url+"/backup")
	if code != 0 || !strings.HasPrefix(out, e.words+"\n") || !strings.Contains(errs, notice) {
		t.Errorf("listing: exit %d out %q err %q", code, out, errs)
	}
	// The pin given on the command line is the user's input and fails.
	if code, _, errs := runLuk(t, "scan", "--pin", e.url+"/backup#"+stale); code != 1 || !strings.Contains(errs, channel.ErrTLSPin.Error()) {
		t.Errorf("fragment: exit %d %q", code, errs)
	}
	// Commands that need a real pin keep failing on the stored one.
	if code, _, errs := runLuk(t, "send", "-e", "backup", "--file", cfgPath); code != 1 || !strings.Contains(errs, channel.ErrTLSPin.Error()) {
		t.Errorf("send: exit %d %q", code, errs)
	}
	// The printed command replaces the stale pin of the same name.
	out = mustRun(t, "scan", "--pin", "--print", e.url+"/backup")
	if want := "luk config endpoint add -e backup --url '" + e.url + "/backup#" + e.words + "'\n"; out != want {
		t.Fatalf("print %q, want %q", out, want)
	}
	mustRun(t, "config", "endpoint", "add", "-e", "backup", "--url", e.url+"/backup#"+e.words, "--key", e.key)
	cfg, _, err := client.LoadMerged()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Endpoint["backup"].Pins; len(got) != 1 || got[0] != e.words {
		t.Fatalf("pins %v", got)
	}
	if code, _, errs := runLuk(t, "scan", "--pin", "backup"); code != 0 || errs != "download pin: "+e.pin+"\n" {
		t.Errorf("after fix: exit %d %q", code, errs)
	}
}
