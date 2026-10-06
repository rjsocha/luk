package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"luk/internal/config"
)

// roles names every role; each has its lock and running file in
// <root>/data.
var roles = []string{"receive", "process"}

// runningFile keeps the restart-only settings a role runs with, so lukd
// check can tell a change that its reload would refuse. It is only read
// while the role holds its lock: a file left by a stopped role is ignored.
func runningFile(data, name string) string {
	return filepath.Join(data, name+".running.json")
}

// writeRunning replaces the running file of the role with the restart-only
// settings of cfg.
func writeRunning(cfg *config.Config, role string) error {
	data, err := json.MarshalIndent(cfg.Restart(), "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(runningFile(cfg.DataDir(), role), append(data, '\n'))
}

func writeAtomic(p string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	err = f.Chmod(0o640)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// saveRunning writes the running file of the role; a failure only costs
// lukd check its comparison.
func saveRunning(cfg *config.Config, role string, log *slog.Logger) {
	if err := writeRunning(cfg, role); err != nil {
		log.Warn("running file not written, lukd check cannot compare restart-only settings", "error", err)
	}
}

// RunningChanges compares the restart-only settings of cfg with the running
// file of every role running on cfg.Root (its lock is held) and returns
// the settings its reload would refuse, each once (see
// config.Restart.Changes). Notes say what could not be compared: no role
// running on cfg.Root, which is also the case when cfg changes root, or a
// running role without a running file.
func RunningChanges(cfg *config.Config) (changes, notes []string, err error) {
	next := cfg.Restart()
	running := false
	for _, name := range roles {
		held, err := roleHeld(cfg.DataDir(), name)
		if err != nil {
			return nil, nil, err
		}
		if !held {
			continue
		}
		running = true
		p := runningFile(cfg.DataDir(), name)
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			notes = append(notes, fmt.Sprintf("the %s role runs on %s without %s: its restart-only settings are not compared", name, cfg.Root, p))
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		var cur config.Restart
		if err := json.Unmarshal(data, &cur); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, c := range cur.Changes(next) {
			if !slices.Contains(changes, c) {
				changes = append(changes, c)
			}
		}
	}
	if !running {
		notes = append(notes, fmt.Sprintf("no lukd role runs on %s: restart-only settings are not compared (a changed root is refused by the running lukd only, see its journal)", cfg.Root))
	}
	return changes, notes, nil
}

// RoleRunning reports whether a lukd runs the role (receive or process)
// with the data directory data (<root>/data), that is holds its lock.
func RoleRunning(data, role string) (bool, error) {
	return roleLocked(data, role, "")
}

// roleHeld is RoleRunning for lukd check.
func roleHeld(data, name string) (bool, error) {
	return roleLocked(data, name, " (lukd check --no-running skips the comparison with the running lukd)")
}

// roleLocked reports whether a lukd holds the lock of the role in data;
// hint follows an error opening the lock. The probe takes a shared lock
// for an instant; a role starting at that very moment retries its lock
// (see lockRole).
func roleLocked(data, name, hint string) (bool, error) {
	p := filepath.Join(data, name+".lock")
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w%s", err, hint)
	}
	defer f.Close()
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		if err != syscall.EINTR {
			break
		}
	}
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", p, err)
	}
	return false, nil
}
