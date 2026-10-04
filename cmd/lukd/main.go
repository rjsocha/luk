package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
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
			"queue entries (picked up every 5s), keeps failed/ and status.json and\n" +
			"maintains the storages. SIGHUP reloads the configuration.",
		Args: cobra.NoArgs,
		RunE: run(server.Process),
	})
	var noRunning bool
	var serviceUser string
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Validate the configuration",
		Long: "Validate the configuration. When a lukd role runs on its root, compare the\n" +
			"restart-only settings (root, listen, limits.conn, limits.header.timeout,\n" +
			"auth.nonces) with the ones it runs with and fail on a change its reload\n" +
			"would refuse. A local storage base holding anything but .db/ and file/ (an\n" +
			"older layout) fails the check.\n" +
			"--no-running skips that comparison, before a restart. Run as root, it also\n" +
			"checks that the service user (--user) can read every configuration input:\n" +
			"config.yaml, config.d, ssh.d, the tls files, the eab key file and gpg.keys.\n" +
			"A relay step whose job has no file in " + rund.DefaultJobs + " is a warning when\n" +
			"that directory is readable.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			errw := cmd.ErrOrStderr()
			for _, w := range append(cfg.Warnings(), relayWarnings(cfg, runJobs)...) {
				fmt.Fprintln(errw, "warning: "+w)
			}
			failed := false
			for _, err := range storageLayouts(cfg) {
				fmt.Fprintln(errw, err)
				failed = true
			}
			// As the service user the inputs are opened by the load
			// itself (ExecReload); root reads everything, so it checks.
			if geteuid() == 0 {
				for _, err := range checkReadable(cfg, serviceUser) {
					fmt.Fprintln(errw, err)
					failed = true
				}
			}
			if !noRunning {
				changes, notes, err := server.RunningChanges(cfg)
				if err != nil {
					return err
				}
				for _, n := range notes {
					fmt.Fprintln(errw, "note: "+n)
				}
				for _, c := range changes {
					fmt.Fprintln(errw, c+" changed, restart required (reload would be refused)")
				}
				failed = failed || len(changes) > 0
			}
			if failed {
				return exitCode(1)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	checkCmd.Flags().BoolVar(&noRunning, "no-running", false, "do not compare with the settings of the running lukd")
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
		Short: "Print the last pipeline result per pipeline and sender",
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
