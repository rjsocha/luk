package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"luk/internal/tlsself"
)

func TestGenerateTLSExistingAndMissing(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "lukd.yaml")
	src := fmt.Sprintf(`root: %s
listen:
  zeta:
    addr: 127.0.0.1:8443
    tls: {mode: self, cert: b.crt, key: b.key, host: b.vm, algorithm: ecdsa-p256}
  alpha:
    addr: 127.0.0.1:8444
    tls: {mode: self, cert: a.crt, key: a.key, host: a.vm}
auth:
  keys:
    - name: k
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n k"
endpoint:
  e: {listen: zeta, endpoint: /e, path: /queue/e, allow: [k]}
pipeline:
  p: {endpoint: [e], steps: [{run: /bin/true}]}
`, dir)
	if err := os.WriteFile(cfg, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var first bytes.Buffer
	if err := generateTLS(cfg, &first); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(first.String(), "(exists)") || strings.Count(first.String(), "sha256//") != 2 ||
		!strings.HasPrefix(first.String(), "alpha 127.0.0.1:8444 sha256//") || !strings.Contains(first.String(), "\nzeta 127.0.0.1:8443 sha256//") {
		t.Fatalf("first run:\n%s", first.String())
	}
	if err := os.Remove(filepath.Join(dir, "b.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "b.key")); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err := generateTLS(cfg, &second); err != nil {
		t.Fatal(err)
	}
	l1, l2 := strings.Split(strings.TrimSpace(first.String()), "\n"), strings.Split(strings.TrimSpace(second.String()), "\n")
	if len(l2) != 2 || l2[0] != l1[0]+" (exists)" || strings.Contains(l2[1], "(exists)") || l2[1] == l1[1] {
		t.Fatalf("second run:\n%s", second.String())
	}
	if err := os.Remove(filepath.Join(dir, "b.key")); err != nil {
		t.Fatal(err)
	}
	var third bytes.Buffer
	if err := generateTLS(cfg, &third); err == nil || !strings.Contains(third.String(), "(exists)") {
		t.Fatalf("half pair: %v\n%s", err, third.String())
	}
}

func TestGenerateTLSSkipsFiles(t *testing.T) {
	dir := t.TempDir()
	ext := t.TempDir()
	extPin, err := tlsself.Generate(filepath.Join(ext, "e.crt"), filepath.Join(ext, "e.key"), "e.vm", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "lukd.yaml")
	src := fmt.Sprintf(`root: %s
listen:
  ext:
    addr: 127.0.0.1:8445
    tls: {mode: files, cert: %s/e.crt, key: %s/e.key}
  own:
    addr: 127.0.0.1:8444
    tls: {mode: self, cert: a.crt, key: a.key, host: a.vm}
  missing:
    addr: 127.0.0.1:8446
    tls: {mode: files, cert: m/m.crt, key: m/m.key}
auth:
  keys:
    - name: k
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n k"
endpoint:
  e: {listen: own, endpoint: /e, path: /queue/e, allow: [k]}
pipeline:
  p: {endpoint: [e], steps: [{run: /bin/true}]}
`, dir, ext, ext)
	if err := os.WriteFile(cfg, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := generateTLS(cfg, &out); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 1 || !strings.HasPrefix(lines[0], "own 127.0.0.1:8444 sha256//") {
		t.Fatalf("generate:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "m")); !os.IsNotExist(err) {
		t.Fatalf("files listener touched: %v", err)
	}
	src = strings.Replace(src, "  missing:\n    addr: 127.0.0.1:8446\n    tls: {mode: files, cert: m/m.crt, key: m/m.key}\n", "", 1)
	if err := os.WriteFile(cfg, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	pins, err := runLukd(t, "tls", "pin", "-c", cfg)
	if err != nil || !strings.HasPrefix(pins, "ext 127.0.0.1:8445 "+extPin+"\nown 127.0.0.1:8444 sha256//") {
		t.Fatalf("pin: %v\n%s", err, pins)
	}
}
