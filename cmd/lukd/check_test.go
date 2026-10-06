package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
		if err := os.WriteFile(filepath.Join(jobs, f), []byte("command: /opt/luk/s3\npipelines: [archive]\n"), 0o600); err != nil {
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

// A job file that exists but does not load (a run.d of before
// pipelines: was required) is named with the reason.
func TestCheckWarnsRelayJobInvalid(t *testing.T) {
	cfgPath, _ := statusConfig(t)
	text, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	relays := strings.Replace(string(text), "steps: [{store: archive}]", "steps: [{relay: s3-upload}, {store: archive}]", 1)
	if err := os.WriteFile(cfgPath, []byte(relays), 0o640); err != nil {
		t.Fatal(err)
	}
	writeIdentity(t, cfgPath)
	jobs := t.TempDir()
	os.Chmod(jobs, 0o755)
	if err := os.WriteFile(filepath.Join(jobs, "s3-upload.yaml"), []byte("command: /opt/luk/s3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := runJobs
	t.Cleanup(func() { runJobs = old })
	runJobs = jobs
	out, errOut, err := runCheck(t, "--no-running", "-c", cfgPath)
	want := "warning: pipeline archive: step 1: relay job s3-upload: "
	if err != nil || out != "ok\n" || !strings.HasPrefix(errOut, want) || !strings.Contains(errOut, "pipelines") || strings.Count(errOut, "\n") != 1 {
		t.Fatalf("%q %q %v", out, errOut, err)
	}
}

// As root, lukd check leaves the files of the service user (running
// state, storage bases) to a run as the owner of root: a FIFO the service
// user put there blocks nothing in root's run.
func TestCheckAsRootLeavesServiceFilesToOwner(t *testing.T) {
	cfgPath, root := statusConfig(t)
	writeIdentity(t, cfgPath)
	os.Chmod(cfgPath, 0o644)
	fakeUser(t, true)
	os.MkdirAll(filepath.Join(root, "s"), 0o750)
	for _, p := range []string{filepath.Join(root, "s", "archive"), filepath.Join(root, ".lukd-receive.lock"), filepath.Join(root, ".lukd-receive.running.json")} {
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var asUID uint32
	var calls int
	geteuid, reexecAs = func() int { return 0 }, func(uid, gid uint32, groups []uint32) error {
		calls++
		asUID = uid
		return exitCode(3)
	}
	t.Cleanup(func() { geteuid, reexecAs = os.Geteuid, reexec })
	type res struct {
		out, errOut string
		err         error
	}
	done := make(chan res, 1)
	go func() {
		out, errOut, err := runCheck(t, "-c", cfgPath)
		done <- res{out, errOut, err}
	}()
	select {
	case r := <-done:
		var code exitCode
		if !errors.As(r.err, &code) || code != 1 || r.out != "" || calls != 1 || asUID != uint32(os.Getuid()) {
			t.Fatalf("%q %q %v, %d calls as %d", r.out, r.errOut, r.err, calls, asUID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lukd check as root opened a FIFO of the service user")
	}
}

// Run again as the owner, lukd check does only the part root left to it.
func TestCheckOwnerPart(t *testing.T) {
	cfgPath, root := statusConfig(t)
	base := filepath.Join(root, "s", "archive")
	os.MkdirAll(base, 0o750)
	os.WriteFile(filepath.Join(base, "junk"), nil, 0o640)
	t.Setenv(reexecEnv, "1")
	out, errOut, err := runCheck(t, "-c", cfgPath, "--no-running")
	var code exitCode
	if !errors.As(err, &code) || code != 1 || out != "" || !strings.Contains(errOut, "storage archive:") || strings.Contains(errOut, "identity") {
		t.Fatalf("%q %q %v", out, errOut, err)
	}
	os.Remove(filepath.Join(base, "junk"))
	if out, errOut, err := runCheck(t, "-c", cfgPath, "--no-running"); err != nil || out != "" || errOut != "" {
		t.Fatalf("clean: %q %q %v", out, errOut, err)
	}
}

// lukd run compares the work path with the root of run.yaml as written:
// a run.yaml root that is not the lukd root as a string is reported.
func TestRunRootWarning(t *testing.T) {
	cfg := &config.Config{Root: "/srv/luk"}
	dir := t.TempDir()
	p := filepath.Join(dir, "run.yaml")
	if w := runRootWarning(cfg, p); w != nil {
		t.Fatalf("missing run.yaml: %q", w)
	}
	for root, want := range map[string]string{
		"/srv/luk":     "",
		"/srv/luk/":    "",
		"/var/lib/luk": p + ": root /var/lib/luk is not the lukd root /srv/luk as written: lukd run refuses every work directory",
	} {
		if err := os.WriteFile(p, []byte("root: "+root+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w := runRootWarning(cfg, p)
		if want == "" && w != nil || want != "" && (len(w) != 1 || w[0] != want) {
			t.Errorf("%s: %q", root, w)
		}
	}
}

func TestCheckAsRootWarnsRunRoot(t *testing.T) {
	cfgPath, root := statusConfig(t)
	writeIdentity(t, cfgPath)
	os.Chmod(cfgPath, 0o644)
	fakeUser(t, true)
	run := filepath.Join(t.TempDir(), "run.yaml")
	if err := os.WriteFile(run, []byte("root: "+root+"/other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := runGlobal
	runGlobal = run
	geteuid, reexecAs = func() int { return 0 }, func(uid, gid uint32, groups []uint32) error { return exitCode(0) }
	t.Cleanup(func() { geteuid, reexecAs, runGlobal = os.Geteuid, reexec, old })
	_, errOut, _ := runCheck(t, "--no-running", "-c", cfgPath)
	want := "warning: " + run + ": root " + root + "/other is not the lukd root " + root + " as written: lukd run refuses every work directory\n"
	if !strings.Contains(errOut, want) {
		t.Fatalf("%q", errOut)
	}
}
