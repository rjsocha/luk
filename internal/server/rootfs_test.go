package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"luk/internal/config"
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

func TestCheckRootFSProbeError(t *testing.T) {
	err := checkRootFS("/x", func(string) (bool, error) { return false, errors.New("statfs failed") })
	if err == nil || err.Error() != "root /x: statfs failed" {
		t.Fatalf("got %v", err)
	}
}

// Both roles refuse a root outside btrfs before they touch it.
func TestRolesRefuseNonBtrfsRoot(t *testing.T) {
	old := CheckRootFS
	CheckRootFS = func(root string) error { return fmt.Errorf("root %s: not a btrfs filesystem", root) }
	t.Cleanup(func() { CheckRootFS = old })
	for role, run := range map[string]func(context.Context, *config.Config, *slog.Logger) error{"receive": Receive, "process": Process} {
		e := newRoleEnv(t)
		err := run(context.Background(), e.cfg, slog.New(slog.DiscardHandler))
		if err == nil || err.Error() != "root "+e.cfg.Root+": not a btrfs filesystem" {
			t.Errorf("%s: %v", role, err)
		}
		if exists(filepath.Join(e.root, "data", role)) || exists(filepath.Join(e.root, "data", role+".lock")) {
			t.Errorf("%s: prepared directories", role)
		}
	}
}
