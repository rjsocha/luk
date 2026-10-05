package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/channel/chantest"
	"luk/internal/client"
	"luk/internal/tlsself"
	"luk/internal/wire"
)

func runLuk(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func tempConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "luk", "config.yaml")
	t.Setenv("LUK_CONFIG", p)
	t.Setenv("LUK_GLOBAL_CONFIG", filepath.Join(t.TempDir(), "site", "luk", "config.yaml"))
	t.Setenv("SSH_AUTH_SOCK", "")
	return p
}

func TestNoArgsPrintsHelp(t *testing.T) {
	tempConfig(t)
	code, out, _ := runLuk(t)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, w := range []string{"send", "config", "scan", "version", "completion"} {
		if !strings.Contains(out, w) {
			t.Errorf("help lacks %q:\n%s", w, out)
		}
	}
}

func TestSendUsageErrors(t *testing.T) {
	tempConfig(t)
	for _, args := range [][]string{
		{"send"},
		{"send", "--bogus"},
		{"send", "--secret", "--portal", "--stdin"},
		{"send", "--ask", "--stdin"},
		{"send", "--password", "--stdin"},
		{"send", "--stdin", "--bwlimit", "fast"},
		{"send", "--stdin", "--bwlimit", "-1"},
		{"send", "x"},
		{"send", "--file", "x", "y"},
		{"send", "--file", "x"},
	} {
		if code, _, _ := runLuk(t, args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
}

func TestSendAliases(t *testing.T) {
	tempConfig(t)
	root := newRoot(&bytes.Buffer{}, &bytes.Buffer{})
	for _, a := range []string{"send", "put", "push"} {
		c, _, err := root.Find([]string{a})
		if err != nil || c.Name() != "send" {
			t.Errorf("%s resolves to %v (%v)", a, c.Name(), err)
		}
	}
	if code, _, _ := runLuk(t, "put"); code != 1 {
		t.Errorf("put without file: exit %d", code)
	}
}

func TestVersion(t *testing.T) {
	tempConfig(t)
	for _, args := range [][]string{{"version"}, {"--version"}} {
		code, out, _ := runLuk(t, args...)
		if code != 0 || !strings.Contains(out, buildVersion) {
			t.Errorf("%v: exit %d out %q", args, code, out)
		}
	}
}

func TestConfigRoundTrip(t *testing.T) {
	path := tempConfig(t)
	ok := func(args ...string) string {
		t.Helper()
		code, out, errs := runLuk(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errs)
		}
		return out
	}
	ok("config", "endpoint", "add", "-e", "drop", "--url", "https://h:8443/drop", "--pin", goodPin)
	ok("config", "endpoint", "add", "-e", "bk", "--url", "http://h/bk")
	ok("config", "default", "-e", "drop")
	ok("config", "key", "-k", "~/.ssh/id.pub")
	c, err := client.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Default != "drop" || c.Key != "~/.ssh/id.pub" || !slices.Equal(c.Endpoint["drop"].Pins, []string{goodPin}) || c.Endpoint["bk"].URL != "http://h/bk" {
		t.Fatalf("saved %+v", c)
	}
	out := ok("config", "show")
	if !strings.Contains(out, path) || !strings.Contains(out, "https://h:8443/drop") {
		t.Errorf("show:\n%s", out)
	}
	ok("config", "endpoint", "rm", "-e", "drop")
	ok("config", "key", "--clear")
	c, _ = client.LoadConfig(path)
	if c.Default != "" || c.Key != "" || len(c.Endpoint) != 1 {
		t.Fatalf("after rm %+v", c)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
}

func TestConfigErrorsExitOne(t *testing.T) {
	path := tempConfig(t)
	for _, args := range [][]string{
		{"config", "endpoint", "add", "-e", "a", "--url", "ftp://h"},
		{"config", "endpoint", "add", "-e", "a", "--url", "http://h", "--pin", "sha256//x"},
		{"config", "endpoint", "add", "-e", "a", "--url", "https://h", "--pin", tlsPin},
		{"config", "endpoint", "add", "-e", "a", "--url", "https://h", "--pin", "nope"},
		{"config", "endpoint", "rm", "-e", "a"},
		{"config", "default", "--endpoint", "a"},
	} {
		if code, _, _ := runLuk(t, args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("failed commands created the config")
	}
}

func TestPositionalAndMissingFlagsExitOne(t *testing.T) {
	path := tempConfig(t)
	for _, args := range [][]string{
		{"config", "endpoint", "add", "a", "http://h"},
		{"config", "endpoint", "add", "-e", "a"},
		{"config", "endpoint", "add", "--url", "http://h"},
		{"config", "endpoint", "rm"},
		{"config", "endpoint", "rm", "a"},
		{"config", "default"},
		{"config", "default", "a"},
		{"config", "key"},
		{"config", "key", "x"},
		{"config", "show", "x"},
		{"scan"},
		{"scan", "https://h", "https://i"},
		{"scan", "--pin", "http://h"},
		{"scan", "--json", "--print", "https://h"},
		{"version", "x"},
	} {
		if code, _, _ := runLuk(t, args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("failed commands created the config")
	}
}

func TestRenamedFlags(t *testing.T) {
	path := tempConfig(t)
	mustRun(t, "config", "endpoint", "add", "--endpoint", "drop", "--url", "https://h/drop#"+goodPin)
	if out := mustRun(t, "config", "endpoint", "show", "--endpoint", "drop"); !strings.Contains(out, "pin:     "+goodPin) {
		t.Errorf("show:\n%s", out)
	}
	mustRun(t, "alias", "add", "--alias", "d", "--", "send", "-e", "drop")
	for _, tc := range []struct {
		args []string
		flag string
	}{
		{[]string{"config", "endpoint", "add", "--name", "x", "--url", "http://h/x"}, "--name"},
		{[]string{"config", "endpoint", "show", "--name", "drop"}, "--name"},
		{[]string{"config", "endpoint", "show", "-n", "drop"}, "-n"},
		{[]string{"config", "endpoint", "rm", "--name", "drop"}, "--name"},
		{[]string{"alias", "add", "--name", "x", "--", "send"}, "--name"},
		{[]string{"alias", "rm", "--name", "d"}, "--name"},
	} {
		code, _, errs := runLuk(t, tc.args...)
		if code != 1 || !strings.Contains(errs, "unknown shorthand flag: 'n'") && !strings.Contains(errs, "unknown flag: "+tc.flag) {
			t.Errorf("%v: exit %d, stderr %q", tc.args, code, errs)
		}
	}
	mustRun(t, "alias", "rm", "--alias", "d")
	mustRun(t, "config", "endpoint", "rm", "--endpoint", "drop")
	c, err := client.LoadConfig(path)
	if err != nil || len(c.Endpoint) != 0 || len(c.Alias) != 0 {
		t.Fatalf("after rm %+v %v", c, err)
	}
}

type sendEnv struct {
	key  string
	body []byte
	meta wire.Meta
	url  bool   // answer 201 with a URL instead of 202
	bad  bool   // answer a wrong sha256
	ttl  string // JSON fields added to a stored upload answer
}

func newSendEnv(t *testing.T) *sendEnv {
	t.Helper()
	tempConfig(t)
	e := &sendEnv{}
	srv := chantest.New(t)
	srv.Op = func(req channel.Request, _ []byte) *chantest.Answer {
		e.meta, _ = wire.DecodeMeta(req.Header.Get(wire.HeaderMeta))
		e.body = nil
		if e.meta.DryRun {
			return &chantest.Answer{Status: http.StatusOK, Body: json.RawMessage(`{"id":"abc","server":{"received":"2026-09-30T12:00:00Z"},"respond":{"mode":"accept"}}`)}
		}
		return nil
	}
	srv.Complete = func(_ channel.Request, _ channel.Nonce, content []byte) chantest.Answer {
		e.body = content
		sum := sha256.Sum256(e.body)
		if e.bad {
			sum[0] ^= 0xff
		}
		if e.url {
			return chantest.Answer{Status: http.StatusCreated, Body: json.RawMessage(fmt.Sprintf(`{"id":"abc","url":"https://lukd.test/d/xyz","expires":"2026-10-07T00:00:00Z"%s,"size":%d,"sha256":"%x"}`, e.ttl, len(e.body), sum))}
		}
		return chantest.Answer{Status: http.StatusAccepted, Body: json.RawMessage(fmt.Sprintf(`{"id":"abc"%s,"size":%d,"sha256":"%x"}`, e.ttl, len(e.body), sum))}
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	e.key = filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(e.key, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := runLuk(t, "config", "endpoint", "add", "-e", "t", "--url", srv.URL+"#"+srv.Pin()); code != 0 {
		t.Fatalf("%s", errs)
	}
	return e
}

func (e *sendEnv) send(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return runLuk(t, append([]string{"send", "-e", "t", "-k", e.key, "-q"}, args...)...)
}

func TestSendStdin(t *testing.T) {
	e := newSendEnv(t)
	r, w, _ := os.Pipe()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	go func() { w.WriteString("hello stdin"); w.Close() }()
	code, out, errs := e.send(t, "--stdin")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	// -q with respond accept: nothing on stdout.
	if string(e.body) != "hello stdin" || out != "" {
		t.Errorf("body %q out %q", e.body, out)
	}
	if e.meta.Size != nil || e.meta.SHA256 != "" || e.meta.File != "" || e.meta.Source != "stdin" {
		t.Errorf("stdin meta carries file data: %+v", e.meta)
	}
}

func stdinFrom(t *testing.T, data string) func() {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdin
	os.Stdin = r
	go func() { w.WriteString(data); w.Close() }()
	return func() { os.Stdin = old }
}

func TestSendStdinName(t *testing.T) {
	e := newSendEnv(t)
	defer stdinFrom(t, "tarball")()
	if code, _, errs := e.send(t, "--stdin", "--name", "dir.tar", "--type", "application/x-tar"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if e.meta.File != "dir.tar" || e.meta.Source != "stdin" || e.meta.Type != "application/x-tar" || e.meta.Size != nil {
		t.Errorf("meta %+v", e.meta)
	}
}

func TestSendNameOverridesFile(t *testing.T) {
	e := newSendEnv(t)
	p := filepath.Join(t.TempDir(), "abc.txt")
	if err := os.WriteFile(p, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := e.send(t, "--file", p, "--name", "note.txt"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if e.meta.File != "note.txt" || e.meta.Source != "file" || e.meta.Size == nil || e.meta.SHA256 == "" {
		t.Errorf("meta %+v", e.meta)
	}
	if code, _, errs := e.send(t, "--file", p); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if e.meta.File != "abc.txt" || e.meta.Source != "file" {
		t.Errorf("meta %+v", e.meta)
	}
	if code, _, _ := e.send(t, "--file", p, "--name", "a/b"); code != 1 {
		t.Errorf("slash in --name: exit %d, want 1", code)
	}
}

func TestSendType(t *testing.T) {
	e := newSendEnv(t)
	p := filepath.Join(t.TempDir(), "a.bin")
	if err := os.WriteFile(p, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := e.send(t, "--file", p, "--type", "text/plain; charset=utf-8"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if e.meta.Type != "text/plain; charset=utf-8" {
		t.Errorf("meta %+v", e.meta)
	}
	if code, _, _ := e.send(t, "--file", p, "--type", "not a type"); code != 1 {
		t.Errorf("bad --type: exit %d, want 1", code)
	}
}

func TestSendFileDashIsPath(t *testing.T) {
	e := newSendEnv(t)
	t.Chdir(t.TempDir())
	if code, _, _ := e.send(t, "--file", "-"); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if err := os.WriteFile("-", []byte("dash"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := e.send(t, "--file", "./-"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if string(e.body) != "dash" || e.meta.File != "-" || e.meta.Size == nil {
		t.Errorf("body %q meta %+v", e.body, e.meta)
	}
}

func TestSendInputSelection(t *testing.T) {
	e := newSendEnv(t)
	for _, args := range [][]string{
		{},
		{"--file", "x", "--stdin"},
		{"--file", "x", "--secret", "--stdin"},
	} {
		if code, _, _ := e.send(t, args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
}

func TestSendFileFIFO(t *testing.T) {
	e := newSendEnv(t)
	p := filepath.Join(t.TempDir(), "pipe.dat")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		f, err := os.OpenFile(p, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		f.WriteString("from fifo")
		f.Close()
	}()
	code, _, errs := e.send(t, "--file", p)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if string(e.body) != "from fifo" {
		t.Errorf("body %q", e.body)
	}
	if e.meta.Size != nil || e.meta.SHA256 != "" || e.meta.File != "" || e.meta.Source != "pipe" {
		t.Errorf("meta %+v", e.meta)
	}
}

func TestSendFileDirectory(t *testing.T) {
	e := newSendEnv(t)
	if code, _, _ := e.send(t, "--file", t.TempDir()); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
}

func TestSendBackupNeedsRegularFile(t *testing.T) {
	e := newSendEnv(t)
	if code, _, _ := e.send(t, "--stdin", "--backup"); code != 1 {
		t.Errorf("--stdin --backup: exit %d, want 1", code)
	}
	p := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := e.send(t, "--file", p, "--backup"); code != 1 {
		t.Errorf("fifo --backup: exit %d, want 1", code)
	}
}

func TestScanPinByConfigName(t *testing.T) {
	tempConfig(t)
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	if code, _, e := runLuk(t, "config", "endpoint", "add", "-e", "srv", "--url", ts.URL); code != 0 {
		t.Fatalf("%s", e)
	}
	code, out, errs := runLuk(t, "scan", "--pin", "srv")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if strings.TrimSpace(out) != tlsself.Pin(ts.Certificate()) {
		t.Errorf("pin %q", out)
	}
	if code, _, _ := runLuk(t, "scan", "--pin", "nope"); code != 1 {
		t.Errorf("unknown name: exit %d", code)
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{usageError{errors.New("x")}, 1},
		{&client.RejectedError{Status: 401}, 2},
		{&client.RejectedError{Status: 502}, 3},
		{&client.HashMismatchError{}, 4},
		{errors.New("boom"), 3},
		{fmt.Errorf("wrapped: %w", &client.HashMismatchError{}), 4},
		{&client.TransferError{Reason: client.Interrupted}, 130},
		{&client.TransferError{Reason: client.NoDecision}, 3},
		{&client.TransferError{Reason: client.Closed}, 3},
	}
	for _, c := range cases {
		if got := exitCode(c.err); got != c.want {
			t.Errorf("%v: got %d want %d", c.err, got, c.want)
		}
	}
}

func globalConfig(t *testing.T) string {
	t.Helper()
	return os.Getenv("LUK_GLOBAL_CONFIG")
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	code, out, errs := runLuk(t, args...)
	if code != 0 {
		t.Fatalf("%v: exit %d: %s", args, code, errs)
	}
	return out
}

func TestConfigWriteLayers(t *testing.T) {
	up := tempConfig(t)
	gp := globalConfig(t)
	mustRun(t, "config", "--global", "endpoint", "add", "-e", "g", "--url", "http://g/x")
	mustRun(t, "config", "endpoint", "add", "-e", "u", "--url", "http://u/x")
	mustRun(t, "config", "default", "-e", "g")
	mustRun(t, "config", "--global", "key", "-k", "gk.pub")

	g, err := client.LoadConfig(gp)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Endpoint) != 1 || g.Endpoint["g"].URL != "http://g/x" || g.Key != "gk.pub" || g.Default != "" {
		t.Errorf("global %+v", g)
	}
	u, _ := client.LoadConfig(up)
	if len(u.Endpoint) != 1 || u.Endpoint["u"].URL != "http://u/x" || u.Default != "g" || u.Key != "" {
		t.Errorf("user %+v", u)
	}
	st, _ := os.Stat(gp)
	if st.Mode().Perm() != 0o644 {
		t.Errorf("global file %v", st.Mode().Perm())
	}
	st, _ = os.Stat(filepath.Dir(gp))
	if st.Mode().Perm() != 0o755 {
		t.Errorf("global dir %v", st.Mode().Perm())
	}
	st, _ = os.Stat(up)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("user file %v", st.Mode().Perm())
	}
	st, _ = os.Stat(filepath.Dir(up))
	if st.Mode().Perm() != 0o700 {
		t.Errorf("user dir %v", st.Mode().Perm())
	}
}

func TestConfigRmGlobalOnly(t *testing.T) {
	up := tempConfig(t)
	gp := globalConfig(t)
	mustRun(t, "config", "--global", "endpoint", "add", "-e", "g", "--url", "http://g/x")
	code, _, errs := runLuk(t, "config", "endpoint", "rm", "-e", "g")
	if code != 1 || !strings.Contains(errs, "endpoint g is defined in the global config; use --global") {
		t.Errorf("exit %d: %s", code, errs)
	}
	if _, err := os.Stat(up); err == nil {
		t.Error("failed rm created the user layer")
	}
	mustRun(t, "config", "endpoint", "rm", "-e", "g", "--global")
	if g, _ := client.LoadConfig(gp); len(g.Endpoint) != 0 {
		t.Errorf("global %+v", g)
	}
}

func TestConfigGlobalPermissionError(t *testing.T) {
	tempConfig(t)
	dir := t.TempDir()
	os.Chmod(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	t.Setenv("LUK_GLOBAL_CONFIG", filepath.Join(dir, "sub", "config.yaml"))
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	code, _, errs := runLuk(t, "config", "--global", "key", "-k", "k")
	if code != 1 || !strings.Contains(errs, "--global needs root") {
		t.Errorf("exit %d: %s", code, errs)
	}
}

func TestConfigMalformedLayerNamesFile(t *testing.T) {
	up := tempConfig(t)
	gp := globalConfig(t)
	os.MkdirAll(filepath.Dir(gp), 0o755)
	os.WriteFile(gp, []byte("bogus: 1\n"), 0o644)
	code, _, errs := runLuk(t, "config", "show")
	if code != 1 || !strings.Contains(errs, gp) {
		t.Errorf("exit %d: %s", code, errs)
	}
	os.WriteFile(gp, nil, 0o644)
	os.MkdirAll(filepath.Dir(up), 0o700)
	os.WriteFile(up, []byte("bogus: 1\n"), 0o600)
	code, _, errs = runLuk(t, "config", "endpoint", "add", "-e", "a", "--url", "http://h")
	if code != 1 || !strings.Contains(errs, up) {
		t.Errorf("exit %d: %s", code, errs)
	}
}

func TestConfigShowSources(t *testing.T) {
	up := tempConfig(t)
	gp := globalConfig(t)
	mustRun(t, "config", "--global", "endpoint", "add", "-e", "g", "--url", "https://g/x", "--pin", goodPin, "--pin", keyPin)
	mustRun(t, "config", "--global", "key", "-k", "gk.pub")
	mustRun(t, "config", "endpoint", "add", "-e", "u", "--url", "http://u/x")
	mustRun(t, "config", "default", "-e", "u")
	out := mustRun(t, "config", "show")
	for _, want := range []string{
		"# global: " + gp + " (exists)", "# user:   " + up + " (exists)",
		"default: u  # user", "key: gk.pub  # global",
		"  g:  # global", "    pin: " + goodPin + "," + keyPin + "\n", "  u:  # user",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	out = mustRun(t, "config", "show", "--layer", "global")
	if !strings.Contains(out, gp) || !strings.Contains(out, "gk.pub") || strings.Contains(out, "http://u/x") {
		t.Errorf("layer global:\n%s", out)
	}
	out = mustRun(t, "config", "show", "--layer", "user")
	if !strings.Contains(out, "http://u/x") || strings.Contains(out, "gk.pub") {
		t.Errorf("layer user:\n%s", out)
	}
	if code, _, _ := runLuk(t, "config", "show", "--layer", "x"); code != 1 {
		t.Errorf("bad layer: exit %d", code)
	}
	os.Remove(gp)
	if out = mustRun(t, "config", "show"); !strings.Contains(out, "(missing)") {
		t.Errorf("missing not reported:\n%s", out)
	}
}

func TestScanResolvesThroughMergedConfig(t *testing.T) {
	tempConfig(t)
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	mustRun(t, "config", "--global", "endpoint", "add", "-e", "srv", "--url", ts.URL)
	mustRun(t, "config", "--global", "default", "-e", "srv")
	if out := mustRun(t, "scan", "--pin", "srv"); strings.TrimSpace(out) != tlsself.Pin(ts.Certificate()) {
		t.Errorf("pin %q", out)
	}
}

func TestSendResolvesThroughMergedConfig(t *testing.T) {
	tempConfig(t)
	var hit bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer ts.Close()
	mustRun(t, "config", "--global", "endpoint", "add", "-e", "srv", "--url", ts.URL+"#"+goodPin)
	mustRun(t, "config", "--global", "default", "-e", "srv")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "config", "--global", "key", "-k", keyPath)
	f := filepath.Join(t.TempDir(), "f")
	os.WriteFile(f, []byte("x"), 0o600)
	runLuk(t, "send", "-f", f, "-q")
	if !hit {
		t.Error("global default endpoint was not used")
	}
}

func writeCfg(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func twoLayers(t *testing.T) {
	t.Helper()
	up := tempConfig(t)
	writeCfg(t, client.GlobalConfigPath(), `default: zeta
endpoint:
  zeta:
    url: https://g.example/zeta
    pin: [`+goodPin+`]
    key: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  shared:
    url: http://g.example/shared
`)
	writeCfg(t, up, `endpoint:
  alpha:
    url: http://u.example/alpha
  shared:
    url: https://u.example/shared
    pin: [`+keyPin+`]
`)
}

// keyWords is keyPin in words form.
func keyWords(t *testing.T) string {
	t.Helper()
	k, err := base64.RawURLEncoding.DecodeString(keyPin)
	if err != nil {
		t.Fatal(err)
	}
	return channel.Words(k)
}

func TestEndpointLs(t *testing.T) {
	twoLayers(t)
	code, out, _ := runLuk(t, "config", "endpoint", "ls")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := [][]string{
		{"alpha", "http://u.example/alpha", "-", "-", "user"},
		{"shared", "https://u.example/shared", keyWords(t), "-", "user"},
		{"zeta", "https://g.example/zeta", goodPin, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "global", "*"},
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(want) {
		t.Fatalf("got %d lines:\n%s", len(lines), out)
	}
	for i, l := range lines {
		if f := strings.Fields(l); strings.Join(f, " ") != strings.Join(want[i], " ") {
			t.Errorf("line %d = %q, want %v", i, l, want[i])
		}
	}
	if !strings.HasPrefix(lines[0], "alpha   ") {
		t.Errorf("columns not aligned: %q", lines[0])
	}
}

func TestEndpointLsLayer(t *testing.T) {
	twoLayers(t)
	_, out, _ := runLuk(t, "config", "endpoint", "ls", "--layer", "global")
	if strings.Contains(out, "alpha") || !strings.Contains(out, "zeta") || strings.Contains(out, "user") {
		t.Errorf("global layer:\n%s", out)
	}
	if !strings.Contains(out, "*") {
		t.Errorf("default marker missing:\n%s", out)
	}
	_, out, _ = runLuk(t, "config", "endpoint", "ls", "--layer", "user")
	if strings.Contains(out, "zeta") || !strings.Contains(out, "alpha") || strings.Contains(out, "*") {
		t.Errorf("user layer:\n%s", out)
	}
	if code, _, _ := runLuk(t, "config", "endpoint", "ls", "--layer", "bogus"); code != 1 {
		t.Errorf("bad layer exit %d", code)
	}
	if code, _, _ := runLuk(t, "config", "endpoint", "ls", "x"); code != 1 {
		t.Errorf("positional exit %d", code)
	}
}

func TestEndpointLsEmpty(t *testing.T) {
	tempConfig(t)
	code, out, _ := runLuk(t, "config", "endpoint", "ls")
	if code != 0 || out != "" {
		t.Errorf("exit %d, out %q", code, out)
	}
}

func TestEndpointShow(t *testing.T) {
	twoLayers(t)
	code, out, _ := runLuk(t, "config", "endpoint", "show", "-e", "zeta")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, w := range []string{"name:    zeta", "url:     https://g.example/zeta\n         https://g.example/zeta#" + goodPin + "\npin:     " + goodPin, "key:     SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "source:  global", "default: true"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q:\n%s", w, out)
		}
	}
	_, out, _ = runLuk(t, "config", "endpoint", "show", "-e", "alpha")
	if strings.Contains(out, "#") || strings.Count(out, "\n") != 6 {
		t.Errorf("without a pin: no pinned URL line:\n%s", out)
	}
	for _, w := range []string{"pin:     -", "source:  user", "default: false"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q:\n%s", w, out)
		}
	}
	_, out, _ = runLuk(t, "config", "endpoint", "show", "-e", "shared")
	for _, w := range []string{"url:     https://u.example/shared", "pin:     " + keyPin, "source:  user"} {
		if !strings.Contains(out, w) {
			t.Errorf("override: missing %q:\n%s", w, out)
		}
	}
}

func TestEndpointShowErrors(t *testing.T) {
	twoLayers(t)
	code, _, errs := runLuk(t, "config", "endpoint", "show", "-e", "nope")
	if code != 1 || !strings.Contains(errs, `unknown endpoint "nope"`) {
		t.Errorf("unknown: exit %d, %q", code, errs)
	}
	if code, _, _ := runLuk(t, "config", "endpoint", "show"); code != 1 {
		t.Errorf("missing --name: exit %d", code)
	}
}

func TestSendDryRunMeta(t *testing.T) {
	e := newSendEnv(t)
	defer stdinFrom(t, "x")()
	if code, _, errs := e.send(t, "--stdin", "--dry-run"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !e.meta.DryRun {
		t.Errorf("meta %+v", e.meta)
	}
	defer stdinFrom(t, "x")()
	if code, _, errs := e.send(t, "--stdin"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if e.meta.DryRun {
		t.Errorf("dry_run set without the flag: %+v", e.meta)
	}
	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, bytes.Repeat([]byte("d"), 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := e.send(t, "--file", big, "--dry-run", "--progress"); code != 0 || e.body != nil {
		t.Fatalf("exit %d, body %d bytes: %s", code, len(e.body), errs)
	}
}

func TestSendProgressSilentWithoutTerminal(t *testing.T) {
	e := newSendEnv(t)
	defer stdinFrom(t, "x")()
	code, _, errs := e.send(t, "--stdin", "--progress", "--bwlimit", "10M")
	if code != 0 || errs != "" {
		t.Fatalf("exit %d: %q", code, errs)
	}
}

func TestTerminalSecretMeta(t *testing.T) {
	m := wire.Meta{Portal: wire.PortalDirect}
	c := secretBody([]byte("s3cret"), &m)
	if m.Source != wire.SourceTerminal || m.Size == nil || *m.Size != 6 || c.size != 6 || m.SHA256 == "" {
		t.Fatalf("%+v", m)
	}
	if err := m.Normalize(); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(io.NewSectionReader(c.source, 0, c.size))
	if sum := sha256.Sum256(b); m.SHA256 != fmt.Sprintf("%x", sum) {
		t.Errorf("sha256 %s", m.SHA256)
	}
}

func TestSendSecretPrompt(t *testing.T) {
	e := newSendEnv(t)
	old := askSecret
	askSecret = func(string) ([]byte, error) { return []byte("s3cret"), nil }
	defer func() { askSecret = old }()
	if code, _, errs := e.send(t, "--secret"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if string(e.body) != "s3cret" || e.meta.Source != wire.SourceTerminal || e.meta.Portal != wire.PortalReveal || e.meta.Size == nil {
		t.Errorf("body %q meta %+v", e.body, e.meta)
	}
}

func TestSendSecretStdin(t *testing.T) {
	e := newSendEnv(t)
	old := askSecret
	askSecret = func(string) ([]byte, error) { t.Error("prompted"); return nil, nil }
	defer func() { askSecret = old }()
	defer stdinFrom(t, "piped")()
	if code, _, errs := e.send(t, "--secret", "--stdin"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if string(e.body) != "piped" || e.meta.Source != wire.SourceStdin || e.meta.Portal != wire.PortalReveal {
		t.Errorf("body %q meta %+v", e.body, e.meta)
	}
}

func TestSendSecretType(t *testing.T) {
	e := newSendEnv(t)
	old := askSecret
	defer func() { askSecret = old }()
	askSecret = func(string) ([]byte, error) { return []byte("zażółć"), nil }
	if code, _, errs := e.send(t, "--secret"); code != 0 || e.meta.Type != "text/plain; charset=utf-8" {
		t.Fatalf("prompt: exit %d: %s %+v", code, errs, e.meta)
	}
	defer stdinFrom(t, "piped")()
	if code, _, errs := e.send(t, "--secret", "--stdin"); code != 0 || e.meta.Type != "text/plain; charset=utf-8" {
		t.Fatalf("stdin: exit %d: %s %+v", code, errs, e.meta)
	}
	f := filepath.Join(t.TempDir(), "pw.bin")
	if err := os.WriteFile(f, []byte{0xff, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := e.send(t, "--secret", "--file", f); code != 0 || e.meta.Type != "text/plain; charset=utf-8" || string(e.body) != "\xff\xfe" {
		t.Fatalf("file: exit %d: %s %+v", code, errs, e.meta)
	}
	if code, _, errs := e.send(t, "--secret", "--type", "application/json"); code != 0 || e.meta.Type != "application/json" {
		t.Fatalf("--type: exit %d: %s %+v", code, errs, e.meta)
	}
	if code, _, errs := e.send(t, "--portal", "--file", f); code != 0 || e.meta.Type != "" {
		t.Fatalf("portal: exit %d: %s %+v", code, errs, e.meta)
	}
	askSecret = func(string) ([]byte, error) { return []byte{'a', 0xff}, nil }
	e.meta = wire.Meta{}
	code, _, errs := e.send(t, "--secret")
	if code != 1 || !strings.Contains(errs, "the secret is not valid UTF-8") || e.meta.Portal != "" {
		t.Fatalf("invalid UTF-8: exit %d: %s %+v", code, errs, e.meta)
	}
}

func TestSendPortal(t *testing.T) {
	e := newSendEnv(t)
	defer stdinFrom(t, "data")()
	if code, _, errs := e.send(t, "--portal", "--stdin"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if e.meta.Portal != wire.PortalDownload {
		t.Errorf("meta %+v", e.meta)
	}
}

func TestSendAnswers(t *testing.T) {
	e := newSendEnv(t)
	defer stdinFrom(t, "data")()
	code, out, errs := e.send(t, "--stdin")
	if code != 0 || out != "" {
		t.Fatalf("exit %d: %q %s", code, out, errs)
	}
	e.url = true
	defer stdinFrom(t, "data")()
	code, out, errs = e.send(t, "--stdin")
	if code != 0 || out != "https://lukd.test/d/xyz\n" {
		t.Fatalf("exit %d: %q %s", code, out, errs)
	}
	defer stdinFrom(t, "data")()
	code, out, errs = runLuk(t, "send", "-e", "t", "-k", e.key, "--stdin")
	if code != 0 || out != "https://lukd.test/d/xyz\n" {
		t.Fatalf("exit %d: %q %s", code, out, errs)
	}
	defer stdinFrom(t, "data")()
	code, out, errs = runLuk(t, "send", "-e", "t", "-k", e.key, "--stdin", "--json")
	var r wire.Receipt
	if code != 0 || json.Unmarshal([]byte(out), &r) != nil || r != (wire.Receipt{ID: "abc", URL: "https://lukd.test/d/xyz", Expires: "2026-10-07T00:00:00Z", Size: 4, SHA256: sha256Hex("data")}) {
		t.Fatalf("exit %d: %q %s", code, out, errs)
	}
	e.url = false
	defer stdinFrom(t, "data")()
	code, out, errs = runLuk(t, "send", "-e", "t", "-k", e.key, "--stdin")
	if code != 0 || out != "" {
		t.Fatalf("exit %d: %q %s", code, out, errs)
	}
	defer stdinFrom(t, "data")()
	code, out, errs = runLuk(t, "send", "-e", "t", "-k", e.key, "--stdin", "--json")
	r = wire.Receipt{}
	if code != 0 || json.Unmarshal([]byte(out), &r) != nil || r != (wire.Receipt{ID: "abc", Size: 4, SHA256: sha256Hex("data")}) {
		t.Fatalf("exit %d: %q %s", code, out, errs)
	}
	for _, args := range [][]string{{"--dry-run"}, {"--dry-run", "--json"}} {
		defer stdinFrom(t, "data")()
		code, out, errs = runLuk(t, append([]string{"send", "-e", "t", "-k", e.key, "--stdin"}, args...)...)
		var d wire.Response
		if code != 0 || json.Unmarshal([]byte(out), &d) != nil || d.ID != "abc" || d.Respond.Mode != "accept" {
			t.Fatalf("%v: exit %d: %q %s", args, code, out, errs)
		}
	}
	code, _, errs = runLuk(t, "send", "-e", "t", "-k", e.key, "--stdin", "--json", "-q")
	if code != 1 || !strings.Contains(errs, "--json and --quiet are mutually exclusive") {
		t.Fatalf("exit %d: %s", code, errs)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestSendHashMismatchShowsReceipt(t *testing.T) {
	e := newSendEnv(t)
	e.bad = true
	defer stdinFrom(t, "data")()
	code, out, errs := e.send(t, "--stdin")
	if code != 4 || out != "" || !strings.Contains(errs, `"id": "abc"`) || !strings.Contains(errs, "sha256 mismatch") {
		t.Fatalf("exit %d: %q %q", code, out, errs)
	}
	e.url = true
	defer stdinFrom(t, "data")()
	code, _, errs = e.send(t, "--stdin")
	if code != 4 || !strings.Contains(errs, "https://lukd.test/d/xyz") {
		t.Fatalf("exit %d: %q", code, errs)
	}
}

func TestFlagParsingHoles(t *testing.T) {
	e := newSendEnv(t)
	t.Chdir(t.TempDir())
	for _, f := range []string{"backup.tar", "a", "b", "-x"} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-e", "backup", "-t", "prod", "--file", "--progress", "--bwlimit", "256K", "--file", "backup.tar"}, "--file needs a value"},
		{[]string{"--file", "a", "--file", "b"}, "--file given more than once"},
		{[]string{"--file", "a", "--json", "--json"}, "--json given more than once"},
		{[]string{"-e", "-q"}, "--endpoint needs a value"},
	} {
		code, _, errs := runLuk(t, append([]string{"send"}, tc.args...)...)
		if code != 1 || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: exit %d, stderr %q", tc.args, code, errs)
		}
	}
	if code, _, errs := e.send(t, "--file", "./-x", "--tag", "a", "--tag", "b"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
}

func TestSendNoCLIHint(t *testing.T) {
	e := newSendEnv(t)
	defer stdinFrom(t, "x")()
	code, _, errs := e.send(t, "--stdin", "--secret", "--cli-hint")
	if code != 1 || !strings.Contains(errs, "unknown flag: --cli-hint") {
		t.Fatalf("exit %d: %s", code, errs)
	}
}

func TestSendNoOwner(t *testing.T) {
	e := newSendEnv(t)
	defer stdinFrom(t, "x")()
	if code, _, errs := e.send(t, "--stdin", "--portal"); code != 0 || e.meta.NoOwner || e.meta.Portal != wire.PortalDownload {
		t.Fatalf("no_owner set without the flag: exit %d: %s %+v", code, errs, e.meta)
	}
	defer stdinFrom(t, "x")()
	if code, _, errs := e.send(t, "--stdin", "--portal", "--no-owner"); code != 0 || !e.meta.NoOwner {
		t.Fatalf("exit %d: %s %+v", code, errs, e.meta)
	}
	code, _, errs := e.send(t, "--stdin", "--portal", "--no-owner", "--no-owner")
	if code != 1 || !strings.Contains(errs, "--no-owner given more than once") {
		t.Fatalf("repeated flag: exit %d: %s", code, errs)
	}
}

func TestSendPrettyURL(t *testing.T) {
	e := newSendEnv(t)
	defer stdinFrom(t, "x")()
	if code, _, errs := e.send(t, "--stdin", "--pretty-url"); code != 0 || !e.meta.PrettyURL || e.meta.DryRun {
		t.Fatalf("exit %d: %s %+v", code, errs, e.meta)
	}
	defer stdinFrom(t, "x")()
	if code, _, errs := e.send(t, "--stdin", "--pretty-url", "--dry-run"); code != 0 || !e.meta.PrettyURL || !e.meta.DryRun {
		t.Fatalf("dry run: exit %d: %s %+v", code, errs, e.meta)
	}
	defer stdinFrom(t, "x")()
	if code, _, errs := e.send(t, "--stdin"); code != 0 || e.meta.PrettyURL {
		t.Fatalf("pretty_url set without the flag: exit %d: %s %+v", code, errs, e.meta)
	}
	code, _, errs := e.send(t, "--stdin", "--pretty-url", "--pretty-url")
	if code != 1 || !strings.Contains(errs, "--pretty-url given more than once") {
		t.Fatalf("repeated flag: exit %d: %s", code, errs)
	}
}

func TestSendTTLNote(t *testing.T) {
	e := newSendEnv(t)
	for _, tc := range []struct {
		fields, ttl, want string
	}{
		{`,"ttl":"21d","ttl_note":"capped"`, "60d", "luk: ttl 60d capped to 21d by the server\n"},
		{`,"ttl":"3d","ttl_note":"raised"`, "1d", "luk: ttl 1d raised to 3d by the server\n"},
		{`,"ttl":"21d","ttl_note":"ignored"`, "1d", "luk: ttl ignored by the server\n"},
		{`,"ttl_note":"ignored"`, "1d", "luk: ttl ignored by the server\n"},
		{`,"ttl":"7d","ttl_note":"capped","ttl_min":"1h","ttl_max":"7d"`, "30d", "luk: ttl 30d capped to 7d by the server (allowed 1h to 7d)\n"},
		{`,"ttl":"1h","ttl_note":"raised","ttl_min":"1h","ttl_max":"7d"`, "10m", "luk: ttl 10m raised to 1h by the server (allowed 1h to 7d)\n"},
		{`,"ttl":"7d","ttl_note":"capped","ttl_max":"7d"`, "30d", "luk: ttl 30d capped to 7d by the server (allowed up to 7d)\n"},
		{`,"ttl":"1h","ttl_note":"raised","ttl_min":"1h"`, "10m", "luk: ttl 10m raised to 1h by the server (allowed from 1h)\n"},
		{`,"ttl":"21d","ttl_note":"ignored","ttl_max":"21d"`, "1d", "luk: ttl ignored by the server\n"},
		{`,"ttl":"1d"`, "1d", ""},
		{`,"ttl":"7d","ttl_min":"1h","ttl_max":"7d"`, "max", ""},
		{"", "", ""},
	} {
		e.ttl = tc.fields
		for _, url := range []bool{true, false} {
			e.url = url
			for _, mode := range []string{"-q", "--json", "--progress"} {
				args := []string{"send", "-e", "t", "-k", e.key, "--stdin", mode}
				if tc.ttl != "" {
					args = append(args, "--ttl", tc.ttl)
				}
				restore := stdinFrom(t, "x")
				code, out, errs := runLuk(t, args...)
				restore()
				if code != 0 || errs != tc.want || e.meta.TTL != tc.ttl {
					t.Errorf("%s url=%v %s: exit %d stderr %q meta ttl %q, want %q", tc.fields, url, mode, code, errs, e.meta.TTL, tc.want)
				}
				if mode == "--json" && strings.Contains(tc.fields, "ttl_max") && !strings.Contains(out, `"ttl_max"`) {
					t.Errorf("%s: --json lost the range: %s", tc.fields, out)
				}
				if mode == "--json" && strings.Contains(tc.fields, "ttl_note") && !strings.Contains(out, `"ttl_note"`) {
					t.Errorf("%s: --json lost the note: %s", tc.fields, out)
				}
			}
		}
	}
}

func TestSendSecretPromptTwice(t *testing.T) {
	e := newSendEnv(t)
	old := askSecret
	defer func() { askSecret = old }()
	var prompts []string
	answers := []string{"s3cret", "s3cret"}
	askSecret = func(p string) ([]byte, error) {
		prompts = append(prompts, p)
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
	if code, _, errs := e.send(t, "--secret"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if len(prompts) != 2 || prompts[1] != "retype: " {
		t.Errorf("prompts %q", prompts)
	}
	answers = []string{"s3cret", "s3creT"}
	e.body = nil
	if code, _, errs := e.send(t, "--secret"); code != 1 || !strings.Contains(errs, "the secrets do not match") || e.body != nil {
		t.Errorf("mismatch: exit %d: %s body %q", code, errs, e.body)
	}
}

func TestSendParallelAndPins(t *testing.T) {
	e := newSendEnv(t)
	f := namedFile(t, "a", strings.Repeat("p", 300<<10))
	for _, n := range []string{"0", "65"} {
		if code, _, errs := e.send(t, "--file", f, "--parallel", n); code != 1 || !strings.Contains(errs, "--parallel must be 1 to 64") {
			t.Errorf("--parallel %s: exit %d: %s", n, code, errs)
		}
	}
	if code, _, errs := e.send(t, "--file", f, "--parallel", "3"); code != 0 || len(e.body) != 300<<10 {
		t.Fatalf("exit %d, %d bytes: %s", code, len(e.body), errs)
	}
	mustRun(t, "config", "endpoint", "add", "-e", "bare", "--url", "http://127.0.0.1:1/x")
	if code, _, errs := runLuk(t, "send", "-e", "bare", "-k", e.key, "--file", f); code != 1 || !strings.Contains(errs, client.ErrNoPin.Error()) {
		t.Fatalf("no pin: exit %d: %s", code, errs)
	}
}
