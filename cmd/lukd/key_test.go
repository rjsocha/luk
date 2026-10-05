package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"luk/internal/channel"
	"luk/internal/config"
)

// writeIdentity creates the identity key next to the config file, so that
// lukd check passes on a generated configuration.
func writeIdentity(t *testing.T, cfgPath string) channel.Key {
	t.Helper()
	k, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.WriteKey(config.IdentityPath(cfgPath), k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyCommand(t *testing.T) {
	cfg, _ := statusConfig(t)
	keyPath := config.IdentityPath(cfg)

	if _, errOut, err := runLukdIn(t, "", "check", "--no-running", "-c", cfg); err == nil || !strings.Contains(errOut, "lukd key generate") || !strings.Contains(errOut, keyPath) {
		t.Fatalf("check without key: %q %v", errOut, err)
	}
	if _, err := runLukd(t, "key", "-c", cfg); err == nil {
		t.Fatal("key without a key file succeeded")
	}
	if out, err := runLukd(t, "key", "generate", "-c", cfg); err != nil || strings.Count(out, "-") != 5 || strings.Count(out, "\n") != 1 {
		t.Fatalf("generate: %q %v", out, err)
	}
	if _, errOut, err := runLukdIn(t, "", "check", "--no-running", "-c", cfg); err != nil {
		t.Fatalf("check with key: %q %v", errOut, err)
	}
	words, err := runLukd(t, "key", "-c", cfg)
	if err != nil || len(strings.Fields(words)) != 1 || strings.Count(words, "-") != 5 {
		t.Fatalf("key: %q %v", words, err)
	}
	full, err := runLukd(t, "key", "--pin-format", "key", "-c", cfg)
	full = strings.TrimSpace(full)
	if err != nil || len(full) != 43 {
		t.Fatalf("key --pin-format key: %q %v", full, err)
	}
	pin, err := channel.ParsePin(full)
	if err != nil {
		t.Fatal(err)
	}
	k, err := channel.LoadKey(keyPath)
	if err != nil || !pin.Matches(k.Public) {
		t.Fatalf("pin does not match the file: %v", err)
	}
	if _, err := runLukd(t, "key", "--pin-format", "bogus", "-c", cfg); err == nil {
		t.Fatal("bogus pin format accepted")
	}

	if _, err := runLukd(t, "key", "generate", "-c", cfg); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("second generate: %v", err)
	}
	if out, err := runLukd(t, "key", "generate", "--if-missing", "-c", cfg); err != nil || out != "" {
		t.Fatalf("--if-missing: %q %v", out, err)
	}
	if after, _ := runLukd(t, "key", "-c", cfg); after != words {
		t.Fatalf("--if-missing changed the key: %q != %q", after, words)
	}
	out, errOut, err := runLukdIn(t, "", "key", "generate", "--force", "-c", cfg)
	if err != nil || out == words || strings.Count(out, "-") != 5 {
		t.Fatalf("--force: %q %v", out, err)
	}
	if errOut != "reload lukd (systemctl reload lukd) for the new key to take effect\n" {
		t.Fatalf("--force: stderr %q", errOut)
	}
	if after, _ := runLukd(t, "key", "-c", cfg); after != out {
		t.Fatalf("pin after rotation %q != %q", after, out)
	}
	if fi, err := os.Stat(keyPath); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode: %v %v", fi, err)
	}
}

func TestConfigIdentityPath(t *testing.T) {
	cfg, _ := statusConfig(t)
	c, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(filepath.Dir(cfg), "identity.key"); c.IdentityPath != want || config.IdentityPath(cfg) != want {
		t.Fatalf("%q", c.IdentityPath)
	}
}

func TestCheckNoIdentity(t *testing.T) {
	cfg, _ := statusConfig(t)
	if out, errOut, err := runCheck(t, "--no-running", "--no-identity", "-c", cfg); err != nil || out != "ok\n" || errOut != "" {
		t.Fatalf("%q %q %v", out, errOut, err)
	}
}
