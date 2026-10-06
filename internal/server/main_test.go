package server

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// The roles refuse a root outside btrfs; the test roots are temporary
	// directories wherever TMPDIR lies.
	if os.Getenv("LUK_TEST_BTRFS") == "" {
		CheckRootFS = func(string) error { return nil }
	}
	os.Exit(m.Run())
}
