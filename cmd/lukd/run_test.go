package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func TestCheckWorkCmd(t *testing.T) {
	root := t.TempDir()
	w := filepath.Join(root, "work", "20261004T101500Z-0123abcd", "p", "1")
	os.MkdirAll(w, 0o750)
	_, ino, err := rund.CheckWork(root, w, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	check := func(args ...string) error {
		cmd := rootCmd()
		cmd.SetArgs(append([]string{"run", rund.CheckWorkCmd}, args...))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		return cmd.Execute()
	}
	dev, in := strconv.FormatUint(ino.Dev, 10), strconv.FormatUint(ino.Ino, 10)
	if err := check(root, w, dev, in); err != nil {
		t.Fatal(err)
	}
	if err := check(root, w, dev, strconv.FormatUint(ino.Ino+1, 10)); err == nil || !strings.Contains(err.Error(), "not the checked") {
		t.Fatalf("other inode: %v", err)
	}
	if err := check(root, w, "x", in); err == nil {
		t.Fatal("bad device accepted")
	}
	if err := check(root, w, dev); err == nil {
		t.Fatal("missing inode accepted")
	}
}
