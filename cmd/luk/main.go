package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/spf13/cobra"

	"luk/internal/client"
	"luk/internal/cliflags"
)

var buildVersion = "dev"

type usageError struct{ error }

func newRoot(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "luk",
		Short: "Upload files to a lukd endpoint, signed by an SSH key",
		Long: `luk uploads one file to a lukd endpoint. Every request is signed with an
SSH key, so the server decides by who signed it, not by a shared token.`,
		Version:           buildVersion,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Args:              cobra.ArbitraryArgs,
		ValidArgsFunction: completeAlias,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usageError{fmt.Errorf("unknown command %q", args[0])}
			}
			return cmd.Help()
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(newSendCmd(stdout), newGetCmd(stdout), newLinkCmd(stdout), newConfigCmd(stdout, stderr), newScanCmd(stdout, stderr), newAliasCmd(stdout), newVersionCmd(stdout))
	withAliasHelp(root)
	return root
}

// noArgs rejects positional arguments as a usage error.
func noArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usageError{fmt.Errorf("unexpected argument %q: pass values with flags", args[0])}
	}
	return nil
}

// oneURL accepts exactly one positional argument: the link URL that luk get
// and luk link act on.
func oneURL(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return usageError{fmt.Errorf("%s needs one link URL", cmd.CommandPath())}
	}
	return nil
}

func run(args []string, stdout, stderr io.Writer) int {
	root := newRoot(stdout, stderr)
	args, err := expandAlias(root, args)
	// Completion parses the flags twice, which the guard would count as
	// repeated flags.
	if len(args) == 0 || (args[0] != cobra.ShellCompRequestCmd && args[0] != cobra.ShellCompNoDescRequestCmd) {
		cliflags.Guard(root, func(err error) error { return usageError{err} })
	}
	if err == nil {
		root.SetArgs(args)
		err = root.Execute()
	}
	if err != nil {
		if strings.HasPrefix(err.Error(), "required flag") {
			err = usageError{err}
		}
		fmt.Fprintln(stderr, "luk:", err)
		var re *client.RejectedError
		if errors.As(err, &re) && re.ClockOffset != nil {
			fmt.Fprintf(stderr, "luk: your clock differs from the server by %s; check NTP\n", re.ClockOffset.Abs())
		}
		return exitCode(err)
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func newVersionCmd(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the luk version",
		Args:  noArgs,
		Run:   func(*cobra.Command, []string) { fmt.Fprintln(out, buildVersion) },
	}
}

// interruptContext is the context of a request, cancelled by Ctrl-C.
var interruptContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

func exitCode(err error) int {
	var ue usageError
	var re *client.RejectedError
	var he *client.HashMismatchError
	var te *client.TransferError
	switch {
	case errors.As(err, &ue):
		return 1
	case errors.As(err, &te) && te.Reason == client.Interrupted:
		return 130
	case errors.As(err, &re) && re.Status < 500:
		return 2
	case errors.As(err, &he):
		return 4
	default:
		return 3
	}
}
