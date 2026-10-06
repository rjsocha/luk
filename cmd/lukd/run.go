package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"luk/internal/config"
	"luk/internal/rund"
)

// runJobs is the run.d of lukd run that lukd check compares relay steps
// with.
var runJobs = rund.DefaultJobs

// runGlobal is the run.yaml of lukd run whose root lukd check compares
// with the lukd root.
var runGlobal = rund.DefaultConfig

func runCmd() *cobra.Command {
	var jobs string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run one allowlisted job as its user (lukd-run@.service)",
		Long: "Serve one connection of lukd-run.socket on stdin: check that the peer is\n" +
			"the luk user, read the request, run the job of " + rund.DefaultJobs + "/<job>.yaml\n" +
			"on the peer's work directory with systemd-run and stream its output back.\n" +
			"Runs as root. --config defaults to " + rund.DefaultConfig + " here.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := rund.DefaultConfig
			if f := cmd.Flags().Lookup("config"); f != nil && f.Changed {
				cfg = f.Value.String()
			}
			return serveRun(cfg, jobs)
		},
	}
	cmd.Flags().StringVar(&jobs, "jobs", rund.DefaultJobs, "directory of the job files")
	return cmd
}

func serveRun(cfg, jobs string) error {
	if os.Geteuid() != 0 {
		return errors.New("lukd run must run as root")
	}
	c, err := net.FileConn(os.Stdin)
	if err != nil {
		return fmt.Errorf("stdin is not a socket: %w", err)
	}
	defer c.Close()
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("stdin is not a unix socket")
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv := &rund.Server{
		Config:  cfg,
		Jobs:    jobs,
		Locks:   rund.DefaultLocks,
		Owner:   0,
		PeerUID: func() (uint32, error) { return peerUID(uc) },
		Runner:  rund.Systemd{},
		Log:     log,
	}
	if err := srv.Serve(uc); err != nil {
		log.Error("lukd run", "err", err)
		return err
	}
	return nil
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var cerr error
	err = raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}

// relayWarnings names the relay steps of cfg whose job has no file in dir,
// the run.d of lukd run, whose readable file does not load (with the
// reason) or whose valid file does not list the pipeline. dir is root's
// and changes without a reload, so it is never required: an unreadable
// dir or file gives no warning.
func relayWarnings(cfg *config.Config, dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	have := map[string]bool{}
	for _, e := range ents {
		if !rund.Ignored(e.Name()) {
			have[strings.TrimSuffix(e.Name(), rund.JobExt)] = true
		}
	}
	jobs := &rund.Jobs{}
	if fi, err := os.Lstat(dir); err == nil {
		if js, err := rund.LoadJobs(dir, fi.Sys().(*syscall.Stat_t).Uid); err == nil {
			jobs = js
		}
	}
	var w []string
	for _, pn := range slices.Sorted(maps.Keys(cfg.Pipeline)) {
		for i, s := range cfg.Pipeline[pn].Steps {
			switch j, bad := jobs.OK[s.Relay], jobs.Bad[s.Relay]; {
			case s.Relay == "":
			case !have[s.Relay]:
				w = append(w, fmt.Sprintf("pipeline %s: step %d: relay job %s has no file in %s", pn, i+1, s.Relay, dir))
			case bad != nil && !errors.Is(bad, fs.ErrPermission):
				w = append(w, fmt.Sprintf("pipeline %s: step %d: relay job %s: %v", pn, i+1, s.Relay, bad))
			case j != nil && !slices.Contains(j.Pipelines, pn):
				w = append(w, fmt.Sprintf("pipeline %s: step %d: relay job %s does not list the pipeline in its pipelines", pn, i+1, s.Relay))
			}
		}
	}
	return w
}

// runRootWarning reports a root of run.yaml p that differs from the root
// of cfg: lukd run compares the work path with it as written, so it
// refuses every work directory of this lukd. A missing or unreadable p
// gives no warning.
func runRootWarning(cfg *config.Config, p string) []string {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil
	}
	g, err := rund.LoadGlobal(p, fi.Sys().(*syscall.Stat_t).Uid)
	if err != nil || g.Root == cfg.Root {
		return nil
	}
	return []string{fmt.Sprintf("%s: root %s is not the lukd root %s as written: lukd run refuses every work directory", p, g.Root, cfg.Root)}
}
