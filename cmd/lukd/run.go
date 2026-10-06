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
	"strconv"
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
		Short: "Run one allowlisted job as its user (lukd-run@.service)",
		Long: "Serve one connection of lukd-run.socket on stdin: check that the peer is\n" +
			"the luk user, read the request, run the job of " + rund.DefaultJobs + "/<job>.yaml\n" +
			"on the peer's work directory with systemd-run and stream its output back.\n" +
			"The pipeline of the work directory must relay to the job or list it in jobs\n" +
			"of a run step in the lukd configuration (config of run.yaml).\n" +
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
	cmd.AddCommand(checkWorkCmd())
	return cmd
}

// execJob replaces lukd by the command of a job; tests record it.
var execJob = syscall.Exec

// checkWorkCmd starts every job (rund.VerifyWork): as the job user inside
// the namespace of the job it checks the work directory, then executes
// the command of the job in its own place, the same process, with the
// environment of the unit.
func checkWorkCmd() *cobra.Command {
	return &cobra.Command{
		Use:    rund.CheckWorkCmd + " ROOT WORK DEV INO -- COMMAND [ARG...]",
		Short:  "Check the work directory of a job inside its unit, then run the job",
		Hidden: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 4 || len(args) < 5 {
				return errors.New("want ROOT WORK DEV INO -- COMMAND [ARG...]")
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			var want rund.Inode
			var err error
			if want.Dev, err = strconv.ParseUint(args[2], 10, 64); err != nil {
				return fmt.Errorf("device %q: %w", args[2], err)
			}
			if want.Ino, err = strconv.ParseUint(args[3], 10, 64); err != nil {
				return fmt.Errorf("inode %q: %w", args[3], err)
			}
			if err := rund.VerifyWork(args[0], args[1], want); err != nil {
				return fmt.Errorf("job not started: %w", err)
			}
			job := args[4:]
			if err := execJob(job[0], job, os.Environ()); err != nil {
				return fmt.Errorf("job not started: %s: %w", job[0], err)
			}
			return nil
		},
	}
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
		Checker: self,
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

// relayWarnings names the relay steps and the jobs of the run steps of
// cfg whose job has no file in dir, the run.d of lukd run, or whose
// readable file does not load (with the reason), then the valid jobs of
// dir that no relay step and no jobs name (unused) and the other readable
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
			if s.Relay != "" {
				what, names = "relay job", []string{s.Relay}
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
			w = append(w, fmt.Sprintf("%s: unused: no relay step and no jobs of a run step name the job", filepath.Join(dir, name+rund.JobExt)))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(jobs.Bad)) {
		if bad := jobs.Bad[name]; !used[name] && !errors.Is(bad, fs.ErrPermission) {
			w = append(w, fmt.Sprintf("run.d job %s: %v", name, bad))
		}
	}
	return w
}

// runRootWarning reports a root of run.yaml p that differs from the root
// of cfg: lukd run compares the work path with it as written, so it
// refuses every work directory of this lukd. It also reports a config of
// p that is not the file of cfg: lukd run takes the jobs of the pipelines
// from that file. When it is that file, a configuration lukd run refuses
// (LoadJobPipelines) is reported: no pipeline may run a job. A missing or
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
		w = append(w, fmt.Sprintf("%s: root %s is not the lukd root %s as written: lukd run refuses every work directory", p, g.Root, cfg.Root))
	}
	abs, err := filepath.Abs(cfg.Path)
	switch {
	case err != nil:
	case g.Config != abs:
		w = append(w, fmt.Sprintf("%s: config %s is not the checked configuration %s: lukd run takes the jobs of the pipelines from it", p, g.Config, abs))
	default:
		if _, err := rund.LoadJobPipelines(g.Config, runTop, runOwner); err != nil {
			w = append(w, fmt.Sprintf("%s: lukd run refuses the configuration %s, no pipeline may run a job: %v", p, g.Config, err))
		}
	}
	return w
}
