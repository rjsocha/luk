package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"luk/internal/client"
	"luk/internal/sshsig"
	"luk/internal/wire"
)

// agentWithKeys serves a keyring of n new keys, commented key0, key1, ...,
// on SSH_AUTH_SOCK and returns their fingerprints in agent order.
func agentWithKeys(t *testing.T, n int) []string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	kr := agent.NewKeyring()
	var fps []string
	for i := range n {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: fmt.Sprintf("key%d", i)}); err != nil {
			t.Fatal(err)
		}
		pub, _ := ssh.NewPublicKey(priv.Public())
		fps = append(fps, ssh.FingerprintSHA256(pub))
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				agent.ServeAgent(kr, c)
			}()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
	return fps
}

// keyServer accepts only the allowed fingerprints and records the signer of
// the last request. reason replaces the unknown key answer when set; date,
// when set, is the Date header of the answers.
type keyServer struct {
	mu      sync.Mutex
	allowed map[string]bool
	reason  string
	date    string
	seen    string
	url     string
}

func newKeyServer(t *testing.T, allowed ...string) *keyServer {
	t.Helper()
	ks := &keyServer{allowed: map[string]bool{}}
	for _, fp := range allowed {
		ks.allowed[fp] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blob, _ := base64.StdEncoding.DecodeString(r.Header.Get(wire.HeaderSignature))
		sig, err := sshsig.ParseBlob(blob)
		if err != nil {
			http.Error(w, `{"error":"bad signature encoding"}`, http.StatusUnauthorized)
			return
		}
		fp := ssh.FingerprintSHA256(sig.Key)
		ks.mu.Lock()
		ks.seen = fp
		ok, reason := ks.allowed[fp], ks.reason
		if ks.date != "" {
			w.Header().Set("Date", ks.date)
		}
		ks.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case reason != "":
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"` + reason + `"}`))
		case !ok:
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unknown key ` + fp + `"}`))
		default:
			w.Write([]byte(`{"id":"abc","server":{"received":"2026-09-30T12:00:00Z"},"respond":{"mode":"accept"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	ks.url = srv.URL
	return ks
}

func (ks *keyServer) signer() string {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.seen
}

func dryRun(t *testing.T, args ...string) (int, string) {
	t.Helper()
	defer stdinFrom(t, "x")()
	code, _, errs := runLuk(t, append([]string{"send", "--stdin", "--dry-run", "-q"}, args...)...)
	return code, errs
}

func TestSendKeyPrecedence(t *testing.T) {
	tempConfig(t)
	fps := agentWithKeys(t, 3)
	ks := newKeyServer(t, fps...)
	mustRun(t, "config", "--global", "key", "-k", fps[1])
	mustRun(t, "config", "endpoint", "add", "-e", "withkey", "--url", ks.url, "--key", fps[2])
	mustRun(t, "config", "endpoint", "add", "-e", "nokey", "--url", ks.url)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-e", "withkey", "--key", fps[0]}, fps[0]},
		{[]string{"-e", "withkey"}, fps[2]},
		{[]string{"-e", "nokey"}, fps[1]},
		{[]string{"-e", ks.url}, fps[1]},
		{[]string{"-e", ks.url, "-k", fps[0]}, fps[0]},
	}
	for _, c := range cases {
		if code, errs := dryRun(t, c.args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", c.args, code, errs)
		}
		if got := ks.signer(); got != c.want {
			t.Errorf("%v: signed by %s, want %s", c.args, got, c.want)
		}
	}
	mustRun(t, "config", "--global", "key", "-k", "")
	if code, errs := dryRun(t, "-e", "nokey"); code != 0 || ks.signer() != fps[0] {
		t.Errorf("first agent key: exit %d %s, signed by %s", code, errs, ks.signer())
	}
}

func TestSendKeyFingerprintNotInAgent(t *testing.T) {
	tempConfig(t)
	agentWithKeys(t, 1)
	ks := newKeyServer(t)
	absent := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	code, errs := dryRun(t, "-e", ks.url, "-k", absent)
	if code != 1 || !strings.Contains(errs, absent) || !strings.Contains(errs, "not in the SSH agent") {
		t.Errorf("exit %d: %s", code, errs)
	}
}

func TestSendUnknownKeyHint(t *testing.T) {
	tempConfig(t)
	fps := agentWithKeys(t, 2)
	ks := newKeyServer(t, fps[1])
	const hint = "agent holds 2 keys; pick one with --key SHA256:... or set key on the endpoint (luk config endpoint add -e NAME --url URL --key SHA256:...)"
	code, errs := dryRun(t, "-e", ks.url)
	if code != 2 || !strings.Contains(errs, "rejected (401 Unauthorized): unknown key "+fps[0]) || !strings.Contains(errs, hint) {
		t.Errorf("implicit first key: exit %d: %s", code, errs)
	}
	if code, errs := dryRun(t, "-e", ks.url, "-k", fps[0]); code != 2 || strings.Contains(errs, "agent holds") {
		t.Errorf("explicit key: exit %d: %s", code, errs)
	}
	mustRun(t, "config", "endpoint", "add", "-e", "srv", "--url", ks.url, "--key", fps[0])
	if code, errs := dryRun(t, "-e", "srv"); code != 2 || strings.Contains(errs, "agent holds") {
		t.Errorf("endpoint key: exit %d: %s", code, errs)
	}
	ks.mu.Lock()
	ks.reason = wire.ErrTimestampWindow
	ks.mu.Unlock()
	if code, errs := dryRun(t, "-e", ks.url); code != 2 || strings.Contains(errs, "agent holds") {
		t.Errorf("other 401: exit %d: %s", code, errs)
	}
}

func TestSendUnknownKeyNoHintWithOneAgentKey(t *testing.T) {
	tempConfig(t)
	agentWithKeys(t, 1)
	ks := newKeyServer(t)
	if code, errs := dryRun(t, "-e", ks.url); code != 2 || !strings.Contains(errs, "unknown key") || strings.Contains(errs, "agent holds") {
		t.Errorf("exit %d: %s", code, errs)
	}
}

func TestEndpointKeyConfig(t *testing.T) {
	up := tempConfig(t)
	fp := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	mustRun(t, "config", "endpoint", "add", "-e", "a", "--url", "http://h/a", "-k", fp)
	mustRun(t, "config", "endpoint", "add", "-e", "b", "--url", "http://h/b")
	c, err := client.LoadConfig(up)
	if err != nil || c.Endpoint["a"].Key != fp || c.Endpoint["b"].Key != "" {
		t.Fatalf("saved %+v %v", c, err)
	}
	out := mustRun(t, "config", "endpoint", "show", "-e", "a")
	if !strings.Contains(out, "key:     "+fp) {
		t.Errorf("show a:\n%s", out)
	}
	out = mustRun(t, "config", "endpoint", "show", "-e", "b")
	if !strings.Contains(out, "key:     -") {
		t.Errorf("show b:\n%s", out)
	}
	out = mustRun(t, "config", "show")
	if !strings.Contains(out, "    key: "+fp) {
		t.Errorf("config show:\n%s", out)
	}
	for _, k := range []string{"SHA256:nope", "rel.pub"} {
		if code, _, errs := runLuk(t, "config", "endpoint", "add", "-e", "c", "--url", "http://h/c", "--key", k); code != 1 || !strings.Contains(errs, "key") {
			t.Errorf("%s: exit %d %s", k, code, errs)
		}
	}
	if code, _, errs := runLuk(t, "config", "key", "-k", "SHA256:nope"); code != 1 || !strings.Contains(errs, "fingerprint") {
		t.Errorf("config key: exit %d %s", code, errs)
	}
	mustRun(t, "config", "key", "-k", fp)
}

// A timestamp refused as out of the window prints the offset of the local
// clock from the Date of the answer.
func TestSendClockHint(t *testing.T) {
	tempConfig(t)
	agentWithKeys(t, 1)
	ks := newKeyServer(t)
	ks.mu.Lock()
	ks.reason = wire.ErrTimestampWindow
	ks.date = time.Now().Add(3 * time.Minute).UTC().Format(http.TimeFormat)
	ks.mu.Unlock()
	code, errs := dryRun(t, "-e", ks.url)
	if code != 2 || !regexp.MustCompile(`luk: your clock differs from the server by (2m59s|3m0s); check NTP\n`).MatchString(errs) {
		t.Fatalf("exit %d: %s", code, errs)
	}
	ks.mu.Lock()
	ks.reason = "timestamp before server start"
	ks.mu.Unlock()
	if code, errs := dryRun(t, "-e", ks.url); code != 2 || strings.Contains(errs, "your clock") {
		t.Fatalf("other 401: exit %d: %s", code, errs)
	}
}
