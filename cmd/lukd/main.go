package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/spf13/cobra"

	"luk/internal/cliflags"
	"luk/internal/config"
	"luk/internal/rund"
	"luk/internal/server"
	"luk/internal/status"
	"luk/internal/tlsself"
)

var buildVersion = "dev"

// beforeLoad runs before a role loads its configuration; tests send
// signals there.
var beforeLoad func()

func main() {
	if err := rootCmd().Execute(); err != nil {
		var code exitCode
		if errors.As(err, &code) {
			os.Exit(int(code))
		}
		fmt.Fprintln(os.Stderr, "lukd:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var cfgPath string
	root := &cobra.Command{
		Use:           "lukd",
		Short:         "lukd: SSH-Authenticated Storage Server",
		Version:       buildVersion,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "/etc/site/lukd/config.yaml", "configuration file")

	run := func(fn func(context.Context, *config.Config, *slog.Logger) error) func(*cobra.Command, []string) error {
		return func(*cobra.Command, []string) error {
			// The signals first: a SIGHUP or SIGTERM during the load and
			// the start of the role must not end lukd by default action.
			server.Version = buildVersion
			server.CatchHangup()
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if beforeLoad != nil {
				beforeLoad()
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			return fn(ctx, cfg, server.NewLogger(os.Stderr, cfg))
		}
	}
	root.AddCommand(&cobra.Command{
		Use:   "receive",
		Short: "Run the receive role: listeners, queue writes, downloads, expiry",
		Long: "Run the receive role: listeners, verification, queue writes, downloads,\n" +
			"portals and expiry of exposed files. Uploads stay committed in the queue\n" +
			"for lukd process; SIGHUP reloads the configuration and re-reads the TLS\n" +
			"certificates of the self and files listeners (acme certificates are renewed\n" +
			"and swapped in by lukd itself, see lukd tls acme).",
		Args: cobra.NoArgs,
		RunE: run(server.Receive),
	})
	root.AddCommand(&cobra.Command{
		Use:   "process",
		Short: "Run the process role: pipelines of the committed queue entries",
		Long: "Run the process role: no listener; it runs the pipelines of the committed\n" +
			"queue entries (picked up every 5s), keeps the failure records and status.json and\n" +
			"maintains the storages. SIGHUP reloads the configuration.",
		Args: cobra.NoArgs,
		RunE: run(server.Process),
	})
	var noRunning, noIdentity, noPasswords bool
	var serviceUser string
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Validate the configuration",
		Long: "Validate the configuration. When a lukd role runs on its root, compare the\n" +
			"restart-only settings (root, listen, limits.conn, limits.header.timeout,\n" +
			"auth.nonces) with the ones it runs with and fail on a change its reload\n" +
			"would refuse. A local storage base holding anything but .db/ and file/ (an\n" +
			"older layout) fails the check; an orphaned permanent name in a readable\n" +
			"base (see lukd storage permanent) is a warning.\n" +
			"The identity key (see lukd key) must exist and be loadable; --no-identity\n" +
			"skips that, as the process role never reads the key.\n" +
			"Every password the encrypt steps name (password.d) must exist and not be\n" +
			"empty; --no-passwords skips that, as the receive role never reads them.\n" +
			"--no-running skips that comparison, before a restart. Run as root, it also\n" +
			"checks that the service user (--user) can read every configuration input:\n" +
			"config.yaml, config.d, ssh.d, the tls files, the eab key file, gpg.keys and\n" +
			"the passwords. The part that reads the files of the service user (running\n" +
			"state, storage bases) then runs again as the owner of the root.\n" +
			"A relay step or a jobs entry of a run step whose job has no file in\n" +
			rund.DefaultJobs + " is a warning when that directory is readable, and so is\n" +
			"one whose readable job file does not load (with the reason), a job no relay\n" +
			"step and no jobs name (unused) and any other readable job file that does not\n" +
			"load. Run as root, a root in " + rund.DefaultConfig + " that is not the root\n" +
			"of the configuration as written is a warning (lukd run would refuse every work\n" +
			"directory), and so is a config there that is not the checked file (lukd run\n" +
			"takes the jobs of the pipelines from it) or that lukd run refuses.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			errw := cmd.ErrOrStderr()
			// Run again by root as the owner of root: only the part that
			// reads the files of the service user.
			if os.Getenv(reexecEnv) == "1" && geteuid() != 0 {
				failed, err := checkOwned(cfg, errw, noRunning)
				if err != nil {
					return err
				}
				if failed {
					return exitCode(1)
				}
				return nil
			}
			warnings := slices.Concat(cfg.Warnings(), relayWarnings(cfg, runJobs))
			// run.yaml is root's (mode 0600): only root reads it here.
			if geteuid() == 0 {
				warnings = append(warnings, runRootWarning(cfg, runGlobal)...)
			}
			for _, w := range warnings {
				fmt.Fprintln(errw, "warning: "+w)
			}
			failed := false
			if noIdentity {
				// The process role never reads the key: it is neither
				// loaded nor required to be readable here.
				cfg.IdentityPath = ""
			} else if err := checkIdentity(cfg); err != nil {
				fmt.Fprintln(errw, err)
				failed = true
			}
			if noPasswords {
				// The receive role never reads the passwords: password.d
				// is hidden from it, and it need not be readable here.
				cfg.PasswordDir = ""
			} else {
				ossl := cfg.OpenSSLPasswordNames()
				for _, n := range cfg.PasswordNames() {
					read := config.ReadPassword
					if ossl[n] {
						read = config.ReadOpenSSLPassword
					}
					if _, err := read(cfg.PasswordDir, n); err != nil {
						fmt.Fprintf(errw, "password %s: %v\n", n, err)
						failed = true
					}
				}
			}
			// As the service user the inputs are opened by the load
			// itself (ExecReload); root reads everything, so it checks.
			if geteuid() == 0 {
				for _, err := range checkReadable(cfg, serviceUser) {
					fmt.Fprintln(errw, err)
					failed = true
				}
			}
			// Root leaves the files of the service user (running state,
			// storage bases), which it may replace with a FIFO or a
			// symlink, to a run as the owner of root (see asOwner). A
			// missing root holds none of them.
			var code exitCode
			err = nil
			if _, lerr := os.Lstat(cfg.Root); geteuid() == 0 && !errors.Is(lerr, os.ErrNotExist) {
				err = asOwner("lukd check", cfg.Root)
			}
			switch {
			case errors.As(err, &code):
				failed = failed || code != 0
			case err != nil:
				fmt.Fprintln(errw, err)
				failed = true
			default:
				f, err := checkOwned(cfg, errw, noRunning)
				if err != nil {
					return err
				}
				failed = failed || f
			}
			if failed {
				return exitCode(1)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	checkCmd.Flags().BoolVar(&noRunning, "no-running", false, "do not compare with the settings of the running lukd")
	checkCmd.Flags().BoolVar(&noIdentity, "no-identity", false, "do not check the identity key (the process role never reads it)")
	checkCmd.Flags().BoolVar(&noPasswords, "no-passwords", false, "do not check the passwords of the encrypt steps (the receive role never reads them)")
	checkCmd.Flags().StringVar(&serviceUser, "user", "luk", "service user that must read the configuration (checked when run as root)")
	completeFlags(checkCmd, map[string]cobra.CompletionFunc{"user": completeNone})
	root.AddCommand(checkCmd)

	tlsCmd := &cobra.Command{Use: "tls", Short: "TLS certificates and their pins"}
	tlsCmd.AddCommand(&cobra.Command{
		Use:   "generate",
		Short: "Create the certificate of every self-signed listener and print its pin",
		Long: "Create the certificate of every self-signed listener and print its pin.\n" +
			"Listeners with tls mode files or acme are skipped: an external tool or the CA provides them.\n" +
			"Run it as the service user so the server can read the files:\n" +
			"  runuser -u luk -- lukd tls generate",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return generateTLS(cfgPath, os.Stdout)
		},
	})
	tlsCmd.AddCommand(&cobra.Command{
		Use:   "pin",
		Short: "Print the pin of every tls listener (self and files)",
		Long: "Print the pin of every tls listener (self and files).\n" +
			"Acme listeners are skipped: their clients verify the CA, not a pin.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return eachTLS(cfgPath, func(l *config.Listen) error {
				if l.TLS.Mode == "acme" {
					return nil
				}
				pin, err := tlsself.PinFile(l.TLS.Cert)
				if err == nil {
					fmt.Fprintf(cmd.OutOrStdout(), "%s %s %s\n", l.Name, l.Addr, pin)
				}
				return err
			})
		},
	})
	tlsCmd.AddCommand(acmeCmd(&cfgPath))
	root.AddCommand(tlsCmd)

	var asJSON bool
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Print the last pipeline result per pipeline and sender, and the watch evaluations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			return status.Print(cmd.OutOrStdout(), status.Path(cfg.Root), asJSON)
		},
	}
	statusCmd.Flags().BoolVar(&asJSON, "json", false, "print the raw status.json")
	root.AddCommand(statusCmd)
	root.AddCommand(queueCmd(&cfgPath))
	root.AddCommand(storageCmd(&cfgPath))
	root.AddCommand(quotaCmd(&cfgPath))
	root.AddCommand(runCmd())
	root.AddCommand(keyCmd(&cfgPath))
	cliflags.Guard(root, func(err error) error { return err })
	return root
}

// eachTLS calls fn for every tls listener, in name order.
func eachTLS(cfgPath string, fn func(l *config.Listen) error) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	found := false
	for _, name := range cfg.ListenNames() {
		l := cfg.Listen[name]
		if l.TLS == nil {
			continue
		}
		found = true
		if err := fn(l); err != nil {
			return err
		}
	}
	if !found {
		return fmt.Errorf("%s: no tls listener", cfgPath)
	}
	return nil
}

func generateTLS(cfgPath string, w io.Writer) error {
	var errs []error
	err := eachTLS(cfgPath, func(l *config.Listen) error {
		t, id := l.TLS, l.Name+" "+l.Addr
		if t.Mode != "self" {
			return nil
		}
		_, certErr := os.Stat(t.Cert)
		_, keyErr := os.Stat(t.Key)
		if certErr == nil && keyErr == nil {
			pin, err := tlsself.PinFile(t.Cert)
			if err == nil {
				fmt.Fprintf(w, "%s %s (exists)\n", id, pin)
			} else {
				errs = append(errs, err)
			}
			return nil
		}
		pin, err := tlsself.Generate(t.Cert, t.Key, t.Host, t.Algorithm)
		if err == nil {
			fmt.Fprintf(w, "%s %s\n", id, pin)
		} else {
			errs = append(errs, err)
		}
		return nil
	})
	return errors.Join(append([]error{err}, errs...)...)
}

// checkOwned is the part of lukd check that reads the files of the
// service user: the orphaned permanent names (warnings), the layouts of
// the storage bases and, unless noRunning, the restart-only settings of
// the running roles. It reports whether the check failed.
func checkOwned(cfg *config.Config, errw io.Writer, noRunning bool) (bool, error) {
	for _, w := range permanentOrphans(cfg) {
		fmt.Fprintln(errw, "warning: "+w)
	}
	failed := false
	for _, err := range storageLayouts(cfg) {
		fmt.Fprintln(errw, err)
		failed = true
	}
	if noRunning {
		return failed, nil
	}
	changes, notes, err := server.RunningChanges(cfg)
	if err != nil {
		return false, err
	}
	for _, n := range notes {
		fmt.Fprintln(errw, "note: "+n)
	}
	for _, c := range changes {
		fmt.Fprintln(errw, c+" changed, restart required (reload would be refused)")
	}
	return failed || len(changes) > 0, nil
}
