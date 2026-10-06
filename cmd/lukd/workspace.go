package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"luk/internal/jobchan"
	"luk/internal/rund"
	"luk/internal/workspace"
	"luk/internal/wrap"
)

// workspaceCmd holds the one-purpose helpers of lukd run: create, remove
// and own run as root in helper units or ExecStartPre=+ of a job unit and
// take a unit name only; prune runs in lukd-run-prune.service; run is the
// wrapper, the main process of every unit, as the user of the unit.
func workspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "workspace",
		Short:  "Helpers of lukd run: the workspaces of the units and the wrapper",
		Hidden: true,
	}
	unitCmd := func(action, short string, fn func(unit string, log *slog.Logger) error) *cobra.Command {
		return &cobra.Command{
			Use:   action + " UNIT",
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				if !workspace.ValidUnit(args[0]) {
					return errors.New("workspace: invalid unit name")
				}
				if geteuid() != 0 {
					return errors.New("lukd run workspace " + action + " must run as root")
				}
				return fn(args[0], slog.New(slog.NewTextHandler(os.Stderr, nil)))
			},
		}
	}
	cmd.AddCommand(unitCmd("create", "Create the empty workspace of a unit (helper unit)", func(unit string, _ *slog.Logger) error {
		root, err := runRoot()
		if err != nil {
			return err
		}
		return workspace.Create("/", root, unit, 0)
	}))
	cmd.AddCommand(unitCmd("remove", "Remove the workspace of an inactive unit (helper unit)", func(unit string, log *slog.Logger) error {
		root, err := runRoot()
		if err == nil {
			err = workspace.Remove("/", root, unit, 0, workspace.Systemctl)
		}
		if err == nil {
			return nil
		}
		log.Warn("workspace not removed", "unit", unit, "error", err)
		if err := workspace.AddLeftover(workspace.CountDir, time.Now(), log); err != nil {
			log.Error("workspace count not raised", "error", err)
		}
		return exitCode(1)
	}))
	cmd.AddCommand(unitCmd("own", "Give the fresh workspace of a unit to its user (ExecStartPre=+)", func(unit string, _ *slog.Logger) error {
		return workspace.Own("/", unit, 0, workspace.Systemctl)
	}))
	cmd.AddCommand(&cobra.Command{
		Use:   "prune",
		Short: "Remove the workspaces of inactive units (lukd-run-prune.service)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if geteuid() != 0 {
				return errors.New("lukd run workspace prune must run as root")
			}
			root, err := runRoot()
			if err != nil {
				return err
			}
			log := slog.New(slog.NewTextHandler(os.Stderr, nil))
			left, err := workspace.Prune("/", root, rund.DefaultLocks, 0, workspace.Systemctl, log)
			if err != nil {
				return err
			}
			return workspace.SetLeftover(workspace.CountDir, left, time.Now(), log)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "run WORKSPACE -- COMMAND [ARG...]",
		Short: "Run the command of a unit in its workspace with the channel on stdin",
		Args: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 1 || len(args) < 2 {
				return errors.New("usage: lukd run workspace run WORKSPACE -- COMMAND [ARG...]")
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			ch, err := jobchan.FromFile(os.Stdin)
			if err != nil {
				return err
			}
			defer ch.Close()
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
			defer stop()
			w := &wrap.Wrapper{Ch: ch, Workspace: args[0], Argv: args[1:], Stdout: os.Stdout, Stderr: os.Stderr}
			if code := w.Run(ctx); code != 0 {
				return exitCode(code)
			}
			return nil
		},
	})
	return cmd
}

// runRoot is the root of run.yaml, read as lukd run reads it.
func runRoot() (string, error) {
	if err := rund.CheckParents(filepath.Dir(rund.DefaultConfig), "/", 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	g, err := rund.LoadGlobal(rund.DefaultConfig, 0)
	if err != nil {
		return "", err
	}
	return g.Root, nil
}
