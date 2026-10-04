package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"luk/internal/config"
)

func readRunning(t *testing.T, root, name string) config.Restart {
	t.Helper()
	data, err := os.ReadFile(runningFile(root, name))
	if err != nil {
		t.Fatal(err)
	}
	var r config.Restart
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// changedAddr loads the configuration of e with another listen address.
func (e *roleEnv) changedAddr(t *testing.T) *config.Config {
	t.Helper()
	p := filepath.Join(e.dir, "config.yaml")
	text, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	next := strings.Replace(string(text), `addr: "`+e.addr+`"`, `addr: "`+freePort(t)+`"`, 1)
	if err := os.WriteFile(p, []byte(next), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestRunningFileAtStartAndReload(t *testing.T) {
	e := newRoleEnv(t)
	var logs syncBuf
	e.start(t, Receive, &logs)
	p := runningFile(e.root, "receive")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if c := readRunning(t, e.root, "receive").Changes(e.cfg.Restart()); len(c) != 0 {
		t.Fatalf("running file differs: %v", c)
	}
	if exists(runningFile(e.root, "process")) {
		t.Fatal("receive wrote the running file of process")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reload", func() bool { return strings.Contains(logs.String(), `msg="config reloaded"`) })
	waitFor(t, "running file", func() bool { return exists(p) })
	if c := readRunning(t, e.root, "receive").Changes(e.cfg.Restart()); len(c) != 0 {
		t.Fatalf("running file after reload differs: %v", c)
	}
}

func TestProcessWritesItsRunningFile(t *testing.T) {
	e := newRoleEnv(t)
	var logs syncBuf
	e.start(t, Process, &logs)
	if c := readRunning(t, e.root, "process").Changes(e.cfg.Restart()); len(c) != 0 {
		t.Fatalf("running file differs: %v", c)
	}
	if exists(runningFile(e.root, "receive")) {
		t.Fatal("process wrote the running file of receive")
	}
}

func TestRunningChangesWhileRoleRuns(t *testing.T) {
	e := newRoleEnv(t)
	var logs syncBuf
	e.start(t, Process, &logs)
	changes, notes, err := RunningChanges(e.cfg)
	if err != nil || len(changes) != 0 || len(notes) != 0 {
		t.Fatalf("same config: %v %v %v", changes, notes, err)
	}
	changes, notes, err = RunningChanges(e.changedAddr(t))
	if err != nil || !slices.Equal(changes, []string{"listen.main.addr"}) || len(notes) != 0 {
		t.Fatalf("changed addr: %v %v %v", changes, notes, err)
	}
}

func TestRunningChangesLockNotHeld(t *testing.T) {
	e := newRoleEnv(t)
	for _, role := range roles {
		if err := writeRunning(e.cfg, role); err != nil {
			t.Fatal(err)
		}
	}
	f, err := lockRole(e.root, "receive")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	changes, notes, err := RunningChanges(e.changedAddr(t))
	if err != nil || len(changes) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "no lukd role runs on "+e.root) {
		t.Fatalf("%v %v %v", changes, notes, err)
	}
}

func TestRunningChangesWithoutRunningFile(t *testing.T) {
	e := newRoleEnv(t)
	f, err := lockRole(e.root, "process")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	changes, notes, err := RunningChanges(e.changedAddr(t))
	if err != nil || len(changes) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "the process role runs on "+e.root+" without") {
		t.Fatalf("%v %v %v", changes, notes, err)
	}
}
