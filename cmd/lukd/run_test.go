package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
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
