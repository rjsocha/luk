package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/server"
)

func runCheck(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := rootCmd()
	cmd.SetArgs(append([]string{"check"}, args...))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

func TestCheckAgainstRunningRole(t *testing.T) {
	cfgPath, root := statusConfig(t)
	writeIdentity(t, cfgPath)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Process(ctx, cfg, slog.New(slog.DiscardHandler)) }()
	stop := func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	defer func() {
		if ctx.Err() == nil {
			stop()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, ".lukd-process.running.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no running file")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if out, errOut, err := runCheck(t, "-c", cfgPath); err != nil || out != "ok\n" || errOut != "" {
		t.Fatalf("unchanged: %q %q %v", out, errOut, err)
	}

	text, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(text), `addr: "127.0.0.1:0"`, `addr: "127.0.0.1:1"`, 1)
	if err := os.WriteFile(cfgPath, []byte(changed), 0o640); err != nil {
		t.Fatal(err)
	}
	out, errOut, err := runCheck(t, "-c", cfgPath)
	var code exitCode
	if !errors.As(err, &code) || code != 1 || out != "" ||
		errOut != "listen.main.addr changed, restart required (reload would be refused)\n"+
			"listen.main.public changed, restart required (reload would be refused)\n" {
		t.Fatalf("changed addr: %q %q %v", out, errOut, err)
	}
	if out, errOut, err := runCheck(t, "--no-running", "-c", cfgPath); err != nil || out != "ok\n" || errOut != "" {
		t.Fatalf("--no-running: %q %q %v", out, errOut, err)
	}

	stop()
	out, errOut, err = runCheck(t, "-c", cfgPath)
	if err != nil || out != "ok\n" || !strings.Contains(errOut, "note: no lukd role runs on "+root) {
		t.Fatalf("stopped: %q %q %v", out, errOut, err)
	}
}

func TestCheckWarnsRelayWithoutJobFile(t *testing.T) {
	cfgPath, _ := statusConfig(t)
	text, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	relays := strings.Replace(string(text), "steps: [{store: archive}]", "steps: [{relay: s3-upload}, {relay: notify}, {store: archive}]", 1)
	if err := os.WriteFile(cfgPath, []byte(relays), 0o640); err != nil {
		t.Fatal(err)
	}
	writeIdentity(t, cfgPath)
	jobs := t.TempDir()
	for _, f := range []string{"s3-upload.yaml", "notify.yaml~", "notify.yaml.dpkg-old", ".notify.yaml"} {
		if err := os.WriteFile(filepath.Join(jobs, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := runJobs
	t.Cleanup(func() { runJobs = old })
	runJobs = jobs
	out, errOut, err := runCheck(t, "--no-running", "-c", cfgPath)
	if err != nil || out != "ok\n" || errOut != "warning: pipeline archive: step 2: relay job notify has no file in "+jobs+"\n" {
		t.Fatalf("%q %q %v", out, errOut, err)
	}
	runJobs = filepath.Join(jobs, "none")
	if out, errOut, err := runCheck(t, "--no-running", "-c", cfgPath); err != nil || out != "ok\n" || errOut != "" {
		t.Fatalf("unreadable run.d: %q %q %v", out, errOut, err)
	}
}

func TestCheckWarnsRelayPipelineNotListed(t *testing.T) {
	cfgPath, _ := statusConfig(t)
	text, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	relays := strings.Replace(string(text), "steps: [{store: archive}]", "steps: [{relay: s3-upload}, {relay: notify}, {store: archive}]", 1)
	if err := os.WriteFile(cfgPath, []byte(relays), 0o640); err != nil {
		t.Fatal(err)
	}
	writeIdentity(t, cfgPath)
	jobs := t.TempDir()
	os.Chmod(jobs, 0o755)
	for f, data := range map[string]string{
		"s3-upload.yaml": "command: /opt/luk/s3\npipelines: [offsite]\n",
		"notify.yaml":    "command: /opt/luk/notify\npipelines: [offsite, archive]\n",
	} {
		if err := os.WriteFile(filepath.Join(jobs, f), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := runJobs
	t.Cleanup(func() { runJobs = old })
	runJobs = jobs
	out, errOut, err := runCheck(t, "--no-running", "-c", cfgPath)
	want := "warning: pipeline archive: step 1: relay job s3-upload does not list the pipeline in its pipelines\n"
	if err != nil || out != "ok\n" || errOut != want {
		t.Fatalf("%q %q %v", out, errOut, err)
	}
}
