package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestEarlySignals sends SIGHUP before the role has loaded its
// configuration: without a handler installed by then it ends the process
// (the test binary). SIGTERM then stops the role through its context.
func TestEarlySignals(t *testing.T) {
	cfgPath, root := statusConfig(t)
	beforeLoad = func() {
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Error(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Cleanup(func() { beforeLoad = nil })
	cmd := rootCmd()
	cmd.SetArgs([]string{"process", "-c", cfgPath})
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()
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
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("role did not stop")
	}
}
