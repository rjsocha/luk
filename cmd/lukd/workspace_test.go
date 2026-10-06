package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"luk/internal/jobchan"
)

func TestWorkspaceRefusesNames(t *testing.T) {
	for _, action := range []string{"create", "remove", "own"} {
		for _, u := range []string{"../x", "lukd-run-a", "/var/lib/luk"} {
			_, err := runLukd(t, "run", "workspace", action, u)
			if err == nil || err.Error() != "workspace: invalid unit name" {
				t.Errorf("%s %q: %v", action, u, err)
			}
		}
		if _, err := runLukd(t, "run", "workspace", action); err == nil {
			t.Errorf("%s without a unit", action)
		}
	}
}

func TestWorkspaceRunArgs(t *testing.T) {
	for _, args := range [][]string{
		{"run", "workspace", "run", "/ws"},
		{"run", "workspace", "run", "/ws", "--"},
		{"run", "workspace", "run", "--", "/bin/true"},
	} {
		if _, err := runLukd(t, args...); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
}

// writeTemp writes s to a temporary file and returns it open.
func writeTemp(t *testing.T, s string) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// The wrapper end to end: the test binary runs as lukd with a channel on
// stdin, as systemd-run starts it.
func TestWorkspaceRunWrapper(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	ws := filepath.Join(t.TempDir(), "ws")
	os.Mkdir(ws, 0o700)
	proc, remote, err := jobchan.Pair()
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	cmd := exec.Command(os.Args[0], "run", "workspace", "run", ws, "--", "/bin/sh", "-c", "cp in/a out/b", ws)
	cmd.Env = append(os.Environ(), testMainEnv+"=1")
	cmd.Dir = ws
	cmd.Stdin = remote
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	remote.Close()
	proc.Send(jobchan.Frame{T: jobchan.TMeta}, writeTemp(t, "{}"))
	proc.Send(jobchan.Frame{T: jobchan.TIn, Name: "a"}, writeTemp(t, "A"))
	proc.Send(jobchan.Frame{T: jobchan.TGo}, nil)
	var got []string
	for {
		f, fd, err := proc.Recv()
		if err != nil || f.T == jobchan.TEnd {
			break
		}
		if fd != nil {
			fd.Close()
		}
		got = append(got, f.T+":"+f.Name)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"status:", "out:b"}) {
		t.Fatalf("%q", got)
	}
	if b, err := os.ReadFile(filepath.Join(ws, "out", "b")); err != nil || string(b) != "A" {
		t.Fatalf("out/b %q %v", b, err)
	}
}
