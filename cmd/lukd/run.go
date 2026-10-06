package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
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

// runOwner and runTop are the Owner and Top of lukd run, with which lukd
// check reads the configuration as lukd run does.
var (
	runOwner uint32
	runTop   string
)

func runCmd() *cobra.Command {
	var jobs string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the unit of one step as its user (lukd-run@.service)",
		Long: "Serve one connection of lukd-run.socket on stdin: check that the peer is\n" +
			"the service user, read the request, which names a step of a pipeline (or a\n" +
			"nested job of that step) and carries the channel of the unit, and run what\n" +
			"the lukd configuration (config of run.yaml) says the step runs: its run\n" +
			"program, or a job of " + rund.DefaultJobs + "/<job>.yaml. The unit runs with\n" +
			"systemd-run in a workspace of its own; its output streams back.\n" +
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
	cmd.AddCommand(workspaceCmd())
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
	self, err := os.Executable()
	if err != nil {
		return err
	}
	srv := &rund.Server{
		Config:  cfg,
		Jobs:    jobs,
		Locks:   rund.DefaultLocks,
		Owner:   0,
		Lukd:    self,
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

// relayWarnings names the relay steps, the run: {job} steps and the jobs
// of the run steps of cfg whose job has no file in dir, the run.d of lukd run, or whose
// readable file does not load (with the reason), then the valid jobs of
// dir that no step names (unused) and the other readable
// job files that do not load. dir is root's and
// changes without a reload, so it is never required: an unreadable dir or
// file gives no warning.
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
	used := map[string]bool{}
	for _, pn := range slices.Sorted(maps.Keys(cfg.Pipeline)) {
		for i, s := range cfg.Pipeline[pn].Steps {
			what, names := "job", s.Jobs
			switch {
			case s.Relay != "":
				what, names = "relay job", []string{s.Relay}
			case s.Run.Job != "":
				what, names = "run job", []string{s.Run.Job}
			}
			for _, j := range names {
				used[j] = true
				switch bad := jobs.Bad[j]; {
				case !have[j]:
					w = append(w, fmt.Sprintf("pipeline %s: step %d: %s %s has no file in %s", pn, i+1, what, j, dir))
				case bad != nil && !errors.Is(bad, fs.ErrPermission):
					w = append(w, fmt.Sprintf("pipeline %s: step %d: %s %s: %v", pn, i+1, what, j, bad))
				}
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(jobs.OK)) {
		if !used[name] {
			w = append(w, fmt.Sprintf("%s: unused: no step names the job", filepath.Join(dir, name+rund.JobExt)))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(jobs.Bad)) {
		if bad := jobs.Bad[name]; !used[name] && !errors.Is(bad, fs.ErrPermission) {
			w = append(w, fmt.Sprintf("run.d job %s: %v", name, bad))
		}
	}
	return w
}

// unitsWarning reports pipelines whose run and relay steps may all run at
// once (the sum of their queue.concurrency) past limits.units.max: the
// steps then wait in lukd run.
func unitsWarning(cfg *config.Config, g *rund.Global) []string {
	sum := 0
	for _, p := range cfg.Pipeline {
		if !slices.ContainsFunc(p.Steps, func(s config.Step) bool { return s.Run.Set() || s.Relay != "" }) {
			continue
		}
		sum += max(p.Queue.Concurrency, 1)
	}
	if sum <= g.Limits.Units.Max {
		return nil
	}
	return []string{fmt.Sprintf("queue.concurrency of run steps %d exceeds limits.units.max %d: steps wait in lukd run", sum, g.Limits.Units.Max)}
}

// runRootWarning reports a root of run.yaml p that differs from the root
// of cfg: the units of lukd run get the root as written, so a different
// one is an empty tmpfs for every unit. It also reports a config of p that
// is not the file of cfg: lukd run takes what each step runs from that
// file. When it is that file, a configuration lukd run refuses (LoadLukd)
// is reported: no step may run. It then adds unitsWarning. A missing or
// unreadable p gives no warning.
func runRootWarning(cfg *config.Config, p string) []string {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil
	}
	g, err := rund.LoadGlobal(p, fi.Sys().(*syscall.Stat_t).Uid)
	if err != nil {
		return nil
	}
	var w []string
	if g.Root != cfg.Root {
		w = append(w, fmt.Sprintf("%s: root %s is not the lukd root %s as written: every unit gets it as an empty tmpfs", p, g.Root, cfg.Root))
	}
	abs, err := filepath.Abs(cfg.Path)
	switch {
	case err != nil:
	case g.Config != abs:
		w = append(w, fmt.Sprintf("%s: config %s is not the checked configuration %s: lukd run takes what each step runs from it", p, g.Config, abs))
	default:
		if _, err := rund.LoadLukd(g.Config, runTop, runOwner); err != nil {
			w = append(w, fmt.Sprintf("%s: lukd run refuses the configuration %s, no step may run: %v", p, g.Config, err))
		}
	}
	return append(w, unitsWarning(cfg, g)...)
}
