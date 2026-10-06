package main

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"luk/internal/rund"
)

func TestPeerUID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	uid, err := peerUID(s.(*net.UnixConn))
	if err != nil || uid != uint32(os.Getuid()) {
		t.Fatalf("%d %v", uid, err)
	}
}

// checkWorkMain makes the test binary run lukd with its arguments (see
// TestMain), so check-work really executes the job.
const checkWorkMain = "LUKD_TEST_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(checkWorkMain) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// checkWorkTree is a work directory below a new root and its identity.
func checkWorkTree(t *testing.T) (root, w string, ino rund.Inode) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "root")
	w = filepath.Join(root, "work", "20261004T101500Z-0123abcd", "p", "1")
	os.MkdirAll(w, 0o750)
	_, ino, err := rund.CheckWork(root, w, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	return root, w, ino
}

func TestCheckWorkCmd(t *testing.T) {
	root, w, ino := checkWorkTree(t)
	var ran []string
	execJob = func(argv0 string, argv, env []string) error {
		ran = append([]string{argv0}, argv...)
		return nil
	}
	defer func() { execJob = syscall.Exec }()
	check := func(args ...string) error {
		ran = nil
		cmd := rootCmd()
		cmd.SetArgs(append([]string{"run", rund.CheckWorkCmd}, args...))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		return cmd.Execute()
	}
	dev, in := strconv.FormatUint(ino.Dev, 10), strconv.FormatUint(ino.Ino, 10)
	if err := check(root, w, dev, in, "--", "/opt/job", w); err != nil || !slices.Equal(ran, []string{"/opt/job", "/opt/job", w}) {
		t.Fatalf("%q %v", ran, err)
	}
	if err := check(root, w, dev, strconv.FormatUint(ino.Ino+1, 10), "--", "/opt/job", w); err == nil || !strings.Contains(err.Error(), "not the checked") || ran != nil {
		t.Fatalf("other inode: %q %v", ran, err)
	}
	for _, args := range [][]string{
		{root, w, "x", in, "--", "/opt/job", w},
		{root, w, dev, in},
		{root, w, dev, in, "--"},
		{root, w, dev, "--", in, "/opt/job"},
		{root, w, dev, in, "/opt/job", w},
	} {
		if err := check(args...); err == nil || ran != nil {
			t.Errorf("%q: %q %v", args, ran, err)
		}
	}
}

// TestCheckWorkExec runs check-work as the unit does: the job replaces it
// with its own argv and environment, and a swapped directory never starts
// it.
func TestCheckWorkExec(t *testing.T) {
	root, w, ino := checkWorkTree(t)
	job := filepath.Join(t.TempDir(), "job")
	os.WriteFile(job, []byte("#!/bin/sh\nprintf '%s|' \"$0\" \"$@\" \"$LUK_JOB\" \"$$\"\n"), 0o755)
	run := func() (string, string, int, error) {
		cmd := exec.Command(os.Args[0], "run", rund.CheckWorkCmd, root, w,
			strconv.FormatUint(ino.Dev, 10), strconv.FormatUint(ino.Ino, 10), "--", job, w)
		cmd.Env = append(os.Environ(), checkWorkMain+"=1", "LUK_JOB=j")
		var out, errOut strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Start()
		if err != nil {
			return "", "", 0, err
		}
		pid := cmd.Process.Pid
		err = cmd.Wait()
		return out.String(), errOut.String(), pid, err
	}
	out, errOut, pid, err := run()
	if want := job + "|" + w + "|j|" + strconv.Itoa(pid) + "|"; err != nil || out != want {
		t.Fatalf("%q %q %v, want %q", out, errOut, err, want)
	}
	id := filepath.Dir(filepath.Dir(w))
	os.Rename(id, id+".real")
	os.Symlink(id+".real", id)
	out, errOut, _, err = run()
	if err == nil || out != "" || !strings.Contains(errOut, "job not started") {
		t.Fatalf("symlinked: %q %q %v", out, errOut, err)
	}
	os.Remove(id)
	os.MkdirAll(filepath.Join(id, "p", "1"), 0o750)
	out, errOut, _, err = run()
	if err == nil || out != "" || !strings.Contains(errOut, "not the checked") {
		t.Fatalf("swapped: %q %q %v", out, errOut, err)
	}
}
