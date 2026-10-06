package server

import (
	"strings"
	"testing"
)

func TestCheckRootFSDefault(t *testing.T) {
	err := checkRootFS(t.TempDir(), func(string) (bool, error) { return false, nil })
	if err == nil || !strings.HasSuffix(err.Error(), ": not a btrfs filesystem") || !strings.HasPrefix(err.Error(), "root /") {
		t.Fatalf("got %v", err)
	}
	if err := checkRootFS("/x", func(string) (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
}
