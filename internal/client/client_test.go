package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/channel/chantest"
	"luk/internal/config"
	"luk/internal/server"
	"luk/internal/wire"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testHandler(t *testing.T, user ssh.PublicKey) http.Handler {
	t.Helper()
	return newLukd(t, user).Handler("127.0.0.1:0")
}

// newLukd is the lukd of the client tests, without an identity key.
func newLukd(t *testing.T, user ssh.PublicKey) *server.Server {
	t.Helper()
	srv, _ := newLukdWith(t, user, nil)
	return srv
}

// newLukdWith is newLukd with its config text rewritten by mod; it also
// returns the root of lukd.
func newLukdWith(t *testing.T, user ssh.PublicKey, mod func(string) string) (*server.Server, string) {
	t.Helper()
	root := t.TempDir()
	text := `
root: ` + root + `
listen: {main: {addr: "127.0.0.1:0", public: "https://lukd.test"}}
auth:
  keys: [{name: robert.socha, key: "` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(user))) + `"}]
endpoint:
  backup: {listen: main, endpoint: /backup, path: q/backup, allow: [robert.socha]}
  drop: {listen: main, endpoint: /drop, path: q/drop, allow: [robert.socha], respond: url, storage: drop}
pipeline:
  all: {endpoint: [backup], steps: [{store: s}]}
  drop: {endpoint: [drop], steps: [{store: drop}]}
storage:
  s: {type: local, base: s/archive, path: "{{ .Id }}"}
  drop: {type: local, base: s/drop, path: "{{ .Random }}", expose: drop, ttl: {max: 1d}}
expose:
  drop: {listen: main, path: /d/}
`
	if mod != nil {
		text = mod(text)
	}
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"q/backup", "q/drop"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return server.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))), root
}

// lukdChannel is the lukd of the client tests with an identity key, over
// TLS or plain HTTP: its base URL and its pins.
func lukdChannel(t *testing.T, user ssh.PublicKey, tlsOn bool) (string, []channel.Pin) {
	t.Helper()
	ts, k, _ := chanTestServer(t, user, tlsOn)
	return ts.URL, mustPins(t, channel.Words(k.Public))
}

func fileOpts(t *testing.T, url string, pins []channel.Pin, s ssh.Signer, body []byte) Options {
	n := int64(len(body))
	sum := sha256.Sum256(body)
	return Options{URL: url, Pins: pins, Signer: s, Source: bytes.NewReader(body), Size: n,
		Meta: wire.Meta{Portal: wire.PortalDirect, File: "f", Source: wire.SourceFile, Size: &n, SHA256: hex.EncodeToString(sum[:])}}
}

func TestUploadFile(t *testing.T) {
	s := newSigner(t)
	base, pins := lukdChannel(t, s.PublicKey(), false)
	o := fileOpts(t, base+"/backup", pins, s, []byte("hello"))
	a, err := Upload(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != http.StatusAccepted || a.Debug != nil || a.Receipt == nil || a.Receipt.Size != 5 || a.Receipt.SHA256 != o.Meta.SHA256 || a.Receipt.ID == "" || a.Receipt.URL != "" {
		t.Fatalf("%+v %+v", a, a.Receipt)
	}
}

func TestUploadDrop(t *testing.T) {
	s := newSigner(t)
	base, pins := lukdChannel(t, s.PublicKey(), false)
	a, err := Upload(context.Background(), fileOpts(t, base+"/drop", pins, s, []byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != http.StatusCreated || a.Receipt == nil || !strings.HasPrefix(a.Receipt.URL, "https://lukd.test/d/") || a.Receipt.Expires == "" {
		t.Fatalf("%+v %+v", a, a.Receipt)
	}
}

func TestUploadEmptyFile(t *testing.T) {
	s := newSigner(t)
	base, pins := lukdChannel(t, s.PublicKey(), false)
	a, err := Upload(context.Background(), fileOpts(t, base+"/backup", pins, s, nil))
	if err != nil {
		t.Fatal(err)
	}
	if a.Receipt.Size != 0 {
		t.Fatalf("%+v", a.Receipt)
	}
}

func TestUploadStream(t *testing.T) {
	s := newSigner(t)
	base, pins := lukdChannel(t, s.PublicKey(), false)
	a, err := Upload(context.Background(), Options{URL: base + "/backup", Pins: pins, Signer: s, Body: strings.NewReader("streamed"), Size: -1, Meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourcePipe}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Receipt.Size != 8 {
		t.Fatalf("%+v", a.Receipt)
	}
}

func TestUploadRejected(t *testing.T) {
	base, pins := lukdChannel(t, newSigner(t).PublicKey(), false)
	_, err := Upload(context.Background(), fileOpts(t, base+"/backup", pins, newSigner(t), []byte("x")))
	var re *RejectedError
	if !errors.As(err, &re) || re.Status != 401 || re.Message == "" {
		t.Fatalf("%v", err)
	}
}

// An upload trusts lukd by its key over TLS as over HTTP, and nothing
// without a pin.
func TestUploadPins(t *testing.T) {
	s := newSigner(t)
	base, pins := lukdChannel(t, s.PublicKey(), true)
	if _, err := Upload(context.Background(), fileOpts(t, base+"/backup", pins, s, bytes.Repeat([]byte("y"), 1<<20))); err != nil {
		t.Fatal(err)
	}
	other, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var pe *PinMismatchError
	if _, err := Upload(context.Background(), fileOpts(t, base+"/backup", mustPins(t, channel.Words(other.Public)), s, []byte("x"))); !errors.As(err, &pe) {
		t.Fatalf("wrong pin: %v", err)
	}
	if _, err := Upload(context.Background(), fileOpts(t, base+"/backup", nil, s, []byte("x"))); !errors.Is(err, ErrNoPin) {
		t.Fatalf("no pin: %v", err)
	}
}

func TestResolve(t *testing.T) {
	c := &Config{Default: "drop", Endpoint: map[string]EndpointConfig{
		"drop": {URL: "https://h/drop", Pins: []string{testWords}},
		"bad":  {URL: "https://h/bad", Pins: []string{"sha256//p"}},
	}}
	u, p, err := c.Resolve("")
	if err != nil || u != "https://h/drop" || !slices.Equal(p, []string{testWords}) {
		t.Fatalf("%s %s %v", u, p, err)
	}
	u, p, err = c.Resolve("http://h:8080/backup#" + testKey + "," + testWords)
	if err != nil || u != "http://h:8080/backup" || !slices.Equal(p, []string{testKey, testWords}) {
		t.Fatalf("%s %s %v", u, p, err)
	}
	for _, arg := range []string{"https://h:8443/backup#sha256//ab+c/d=", "https://h:8443/backup#pin=sha256//ab+c/d=", "bad"} {
		if _, _, err := c.Resolve(arg); !errors.Is(err, channel.ErrTLSPin) && !strings.Contains(fmt.Sprint(err), "pin") {
			t.Fatalf("%s: %v", arg, err)
		}
	}
	if _, _, err := c.Resolve("https://h:8443/backup#sha256//x"); !errors.Is(err, channel.ErrTLSPin) {
		t.Fatalf("sha256 fragment: %v", err)
	}
	if _, _, err := c.Resolve("https://h:8443/backup#md5//x"); err == nil {
		t.Fatal("fragment that is not a pin accepted")
	}
	if _, _, err := c.Resolve("nope"); err == nil {
		t.Fatal("unknown endpoint")
	}
	if _, _, err := (&Config{}).Resolve(""); err == nil {
		t.Fatal("no default")
	}
}

func TestLoadConfigMissing(t *testing.T) {
	c, err := LoadConfig(filepath.Join(t.TempDir(), "none.yaml"))
	if err != nil || c == nil {
		t.Fatalf("%v", err)
	}
}

func TestLoadSignerFileWithCert(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "ssh_host_ed25519_key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.PublicKey().(*ssh.Certificate); ok {
		t.Fatal("certificate without a -cert.pub file")
	}
	ca := newSigner(t)
	sshPub, _ := ssh.NewPublicKey(pub)
	c := &ssh.Certificate{Key: sshPub, CertType: ssh.HostCert, KeyId: "luk.vm", ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+"-cert.pub", ssh.MarshalAuthorizedKey(c), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err = LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := s.PublicKey().(*ssh.Certificate); !ok || got.KeyId != "luk.vm" {
		t.Fatalf("%T", s.PublicKey())
	}
}

func TestLoadSignerNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := LoadSigner(""); err == nil || !strings.Contains(err.Error(), "agent") {
		t.Fatalf("%v", err)
	}
}

func TestReadMasked(t *testing.T) {
	var out bytes.Buffer
	got, err := readMasked(strings.NewReader("ab\x7fcż\r"), &out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "acż" {
		t.Fatalf("%q", got)
	}
	if out.String() != "**\b \b**\r\n" {
		t.Fatalf("echo %q", out.String())
	}
	if _, err := readMasked(strings.NewReader("a\x03"), io.Discard); err == nil {
		t.Fatal("ctrl-c not an error")
	}
}

func TestUploadHashMismatchWhenFileChanges(t *testing.T) {
	s := newSigner(t)
	base, pins := lukdChannel(t, s.PublicKey(), false)
	o := fileOpts(t, base+"/backup", pins, s, []byte("hello"))
	o.Source = strings.NewReader("HELLO")
	_, err := Upload(context.Background(), o)
	var he *HashMismatchError
	if !errors.As(err, &he) {
		t.Fatalf("%v", err)
	}
	if he.Local != hex.EncodeToString(sha256Sum("HELLO")) || he.Remote != o.Meta.SHA256 {
		t.Fatalf("%+v", he)
	}
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func TestUploadProgressAndLimit(t *testing.T) {
	s := newSigner(t)
	base, pins := lukdChannel(t, s.PublicKey(), false)
	o := fileOpts(t, base+"/backup", pins, s, make([]byte, 200<<10))
	var w bytes.Buffer
	o.Progress = &w
	o.BWLimit = 1 << 20
	start := time.Now()
	if _, err := Upload(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("upload took %s", d)
	}
	if out := w.String(); !strings.Contains(out, "200.0 KiB in ") || !strings.HasSuffix(out, "\n") {
		t.Fatalf("%q", out)
	}
}

func TestUploadDryRunEcho(t *testing.T) {
	s := newSigner(t)
	base, pins := lukdChannel(t, s.PublicKey(), false)
	o := fileOpts(t, base+"/backup", pins, s, []byte("hello"))
	o.Meta.DryRun = true
	a, err := Upload(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != 200 || a.Receipt != nil || a.Debug == nil || !a.Debug.Client.DryRun || a.Debug.Identity.Name != "robert.socha" || a.Debug.Server.Received == "" {
		t.Fatalf("%+v", a)
	}
}

// countingReaderAt counts the bytes read from it.
type countingReaderAt struct {
	n *atomic.Int64
	r io.ReaderAt
}

func (c countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.n.Add(int64(n))
	return n, err
}

func TestUploadDryRunSendsNoBody(t *testing.T) {
	s := newSigner(t)
	ts, k, counts := chanTestServer(t, s.PublicKey(), false)
	body := bytes.Repeat([]byte("d"), 1<<20)
	o := fileOpts(t, ts.URL+"/backup", mustPins(t, channel.Words(k.Public)), s, body)
	o.Meta.DryRun = true
	var read atomic.Int64
	o.Source = countingReaderAt{n: &read, r: bytes.NewReader(body)}
	var progress bytes.Buffer
	o.Progress = &progress
	a, err := Upload(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != 200 || a.Debug == nil || read.Load() != 0 || counts.transports.Load() != 1 || progress.Len() != 0 {
		t.Fatalf("status %d, read %d, %d messages, progress %q", a.Status, read.Load(), counts.transports.Load(), progress.String())
	}
}

type readFunc func([]byte) (int, error)

func (f readFunc) Read(p []byte) (int, error) { return f(p) }

func TestUploadStatusMustFitDryRun(t *testing.T) {
	sum := hex.EncodeToString(sha256Sum("hello"))
	cases := []struct {
		name   string
		dryRun bool
		status int
		body   string
		ok     bool
	}{
		{"200 without dry run", false, 200, `{"id":"a","server":{"sha256":"` + sum + `"}}`, false},
		{"201 with dry run", true, 201, `{"id":"a","url":"https://x/d/a","size":5,"sha256":"` + sum + `"}`, false},
		{"202 with dry run", true, 202, `{"id":"a","size":5,"sha256":"` + sum + `"}`, false},
		{"204", false, 204, ``, false},
		{"201 without url", false, 201, `{"id":"a","size":5,"sha256":"` + sum + `"}`, false},
		{"201", false, 201, `{"id":"a","url":"https://x/d/a","size":5,"sha256":"` + sum + `"}`, true},
		{"202", false, 202, `{"id":"a","size":5,"sha256":"` + sum + `"}`, true},
		{"200 dry run", true, 200, `{"id":"a","server":{"sha256":"` + sum + `"}}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := decodeAnswer(c.status, []byte(c.body), c.dryRun)
			if c.ok != (err == nil) {
				t.Fatalf("%+v %v", a, err)
			}
			if c.ok && a.Status != c.status {
				t.Fatalf("%+v", a)
			}
		})
	}
}

func TestUploadReceiptHashMismatch(t *testing.T) {
	srv := chantest.New(t)
	srv.Op = func(channel.Request, []byte) *chantest.Answer { return nil }
	srv.Complete = func(channel.Request, channel.Nonce, []byte) chantest.Answer {
		return chantest.Answer{Status: 202, Body: wire.Receipt{ID: "a", Size: 5, SHA256: strings.Repeat("0", 64)}}
	}
	_, err := Upload(context.Background(), fileOpts(t, srv.URL+"/backup", mustPins(t, srv.Pin()), newSigner(t), []byte("hello")))
	var he *HashMismatchError
	if !errors.As(err, &he) || he.Remote != strings.Repeat("0", 64) {
		t.Fatalf("%v", err)
	}
}

func TestLoadConfigOneDocument(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("default: a\n---\ndefault: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), p+": more than one YAML document") {
		t.Fatalf("second document: %v", err)
	}
	if err := os.WriteFile(p, []byte("default: a\n# end\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := LoadConfig(p); err != nil || c.Default != "a" {
		t.Fatalf("trailing comment: %+v %v", c, err)
	}
}
