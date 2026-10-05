package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The client tells a quota refusal without the limits: try later (exit 2)
// or never (exit 2), before the body or cut while a stream is sent.
func TestSendQuota(t *testing.T) {
	tempConfig(t)
	addr, root := freeAddr(t), t.TempDir()
	key, pub := newKeyFile(t)
	text := fmt.Sprintf(`
root: %s
listen: {main: {addr: "%s"}}
auth: {keys: [{name: robert.socha, key: "%s"}]}
endpoint:
  backup: {listen: main, endpoint: /backup, path: q/backup, allow: [robert.socha], quota: {rate: 1K/1h, burst: 2K}}
pipeline:
  backup: {endpoint: [backup], steps: [{store: s}]}
storage:
  s: {type: local, base: s, path: "{{ .Id }}"}
`, root, addr, pub)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	startLukd(t, cfgPath, text, addr)
	mustRun(t, "config", "endpoint", "add", "-e", "backup", "--url", "http://"+addr+"/backup#"+lukdPin(t, cfgPath), "-k", key)
	file := func(n int) string {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if code, _, errs := runLuk(t, "send", "-e", "backup", "-q", "--file", file(1500)); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	// 548 bytes left: 952 more come in 56 minutes.
	code, _, errs := runLuk(t, "send", "-e", "backup", "-q", "--file", file(1500))
	if code != 2 || errs != "luk: quota exceeded, try again in 56m\n" {
		t.Fatalf("exit %d: %q", code, errs)
	}
	code, _, errs = runLuk(t, "send", "-e", "backup", "-q", "--file", file(3000))
	if code != 2 || errs != "luk: upload exceeds the quota of this endpoint\n" {
		t.Fatalf("exit %d: %q", code, errs)
	}
	data, _ := os.ReadFile(file(1500))
	defer stdinFrom(t, string(data))()
	code, _, errs = runLuk(t, "send", "-e", "backup", "-q", "--stdin")
	if code != 2 || !strings.HasPrefix(errs, "luk: quota exceeded, try again in ") {
		t.Fatalf("exit %d: %q", code, errs)
	}
	out := mustRun(t, "scan", "--endpoints", "backup")
	if !strings.Contains(out, "QUOTA") || !strings.Contains(out, " 1K/1h 2K (5") {
		t.Fatalf("%s", out)
	}
}
