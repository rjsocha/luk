package server

import (
	"fmt"

	"luk/internal/btrfs"
)

// CheckRootFS refuses a root that does not lie on btrfs: the job
// workspaces are subvolumes of it. A variable, so tests on other
// filesystems replace it (see TestMain).
var CheckRootFS = func(root string) error { return checkRootFS(root, btrfs.IsBtrfs) }

func checkRootFS(root string, isBtrfs func(string) (bool, error)) error {
	ok, err := isBtrfs(root)
	if err != nil {
		return fmt.Errorf("root %s: %w", root, err)
	}
	if !ok {
		return fmt.Errorf("root %s: not a btrfs filesystem", root)
	}
	return nil
}
