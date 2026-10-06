package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"luk/internal/server"
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

// testMainEnv makes the test binary run lukd with its arguments (see
// TestMain).
const testMainEnv = "LUKD_TEST_MAIN"

func TestMain(m *testing.M) {
	// The roles refuse a root outside btrfs; the test roots are temporary
	// directories wherever TMPDIR lies.
	if os.Getenv("LUK_TEST_BTRFS") == "" {
		server.CheckRootFS = func(string) error { return nil }
	}
	if os.Getenv(testMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}
