// Command luk-job is the helper of run step programs: it lists the inputs,
// reads the upload meta, places outputs with their meta and fails the step
// with a message.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"luk/internal/cliflags"
)

var buildVersion = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	root := newRoot(stdout, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		var code exitCode
		if errors.As(err, &code) {
			return int(code)
		}
		fmt.Fprintln(stderr, "luk-job:", err)
		return 1
	}
	return 0
}

// noArgs rejects positional arguments.
func noArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unexpected argument %q: pass values with flags", args[0])
	}
	return nil
}

func newRoot(stdout, stderr io.Writer) *cobra.Command {
	var work string
	root := &cobra.Command{
		Use:   "luk-job",
		Short: "Helper for lukd run step programs",
		Long: "luk-job runs inside a lukd run step. It works on the step work directory\n" +
			"from LUK_WORK, or --work when given.",
		Version:       buildVersion,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          noArgs,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("{{.Version}}\n")
	root.PersistentFlags().StringVar(&work, "work", "", "step work directory (default $LUK_WORK)")
	dir := func() (string, error) { return workDir(work) }

	var inputsJSON bool
	inputs := &cobra.Command{
		Use:   "inputs",
		Short: "Print the absolute paths of the input files, one per line",
		Args:  noArgs,
		RunE: func(*cobra.Command, []string) error {
			w, err := dir()
			if err != nil {
				return err
			}
			return printInputs(stdout, w, inputsJSON)
		},
	}
	inputs.Flags().BoolVar(&inputsJSON, "json", false, "print an array of {path, name, size, meta}")

	input := &cobra.Command{
		Use:   "input",
		Short: "Print the path of the single input file",
		Args:  noArgs,
		RunE: func(*cobra.Command, []string) error {
			w, err := dir()
			if err != nil {
				return err
			}
			return printInput(stdout, w)
		},
	}

	var metaJSON bool
	var field string
	meta := &cobra.Command{
		Use:   "meta",
		Short: "Print the upload meta (server and client)",
		Long: "Print the upload meta.json as path=value lines, the JSON object with --json,\n" +
			"or one value with --field (a dotted path such as client.backup.hostname):\n" +
			"strings raw, other values as JSON (always JSON with --json).",
		Args: noArgs,
		RunE: func(*cobra.Command, []string) error {
			w, err := dir()
			if err != nil {
				return err
			}
			return printMeta(stdout, w, field, metaJSON)
		},
	}
	meta.Flags().BoolVar(&metaJSON, "json", false, "print JSON")
	meta.Flags().StringVar(&field, "field", "", "dotted path of one value")

	var o outputOpts
	output := &cobra.Command{
		Use:   "output",
		Short: "Put a file into out/ with its meta and print its path",
		Long: "Put --file into out/ under --name (default its base name): a hardlink on the\n" +
			"same filesystem, else a synced copy; with --move a rename, else a copy and\n" +
			"remove. --meta key=value (repeatable, dotted keys nest, values are JSON when\n" +
			"valid JSON, else strings) is merged over --meta-file (a JSON object) into\n" +
			"out/<name>.meta.json.",
		Args: noArgs,
		RunE: func(*cobra.Command, []string) error {
			w, err := dir()
			if err != nil {
				return err
			}
			p, err := placeOutput(w, o)
			if err == nil {
				fmt.Fprintln(stdout, p)
			}
			return err
		},
	}
	output.Flags().StringVar(&o.file, "file", "", "file to put into out/")
	output.Flags().StringVar(&o.name, "name", "", "name in out/ (default the base name of --file)")
	output.Flags().StringArrayVar(&o.meta, "meta", nil, "meta key=value (repeatable)")
	output.Flags().StringVar(&o.metaFile, "meta-file", "", "JSON object file with meta")
	output.Flags().BoolVar(&o.move, "move", false, "move the file instead of linking or copying it")
	output.MarkFlagRequired("file")

	var message string
	fail := &cobra.Command{
		Use:   "fail",
		Short: "Fail the step with a message and exit 1",
		Long: "Write the message to <work>/fail and exit 1. When the step exits non-zero,\n" +
			"lukd reports the message as the step error instead of the output tail.",
		Args: noArgs,
		RunE: func(*cobra.Command, []string) error {
			w, err := dir()
			if err != nil {
				return err
			}
			return writeFail(w, message)
		},
	}
	fail.Flags().StringVar(&message, "message", "", "the step error")
	fail.MarkFlagRequired("message")

	var job, outDir string
	var files []string
	runC := &cobra.Command{
		Use:   "run",
		Short: "Run a nested job, an allowlisted job of lukd run, as its own user",
		Long: "Run --job, a job the admin put in /etc/site/lukd/run.d/ and the run step\n" +
			"lists in jobs, as its own user in its own workspace, through the socket of\n" +
			"the step, <work>/.luk/run.sock. Its inputs are the files of --file\n" +
			"(repeatable; regular files, not symlinks, with distinct base names; a\n" +
			"<name>.meta.json among them is the meta of <name>), else the input set of\n" +
			"the step. Its results are cloned into the existing directory --out, under\n" +
			"a temporary name renamed once complete (an existing name is refused);\n" +
			"without --out the job must write none. The job's stdout and stderr are\n" +
			"relayed and luk-job exits with its exit status; a refused request, a\n" +
			"connection or protocol error exits 1 with a message. One nested job runs\n" +
			"at a time per step. SIGTERM or SIGINT closes the connection, which stops\n" +
			"the job, and exits 1.",
		Args: noArgs,
		RunE: func(*cobra.Command, []string) error {
			w, err := dir()
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			err = askRun(ctx, w, job, files, outDir, stdout, stderr)
			var code exitCode
			if err != nil && !errors.As(err, &code) {
				fmt.Fprintln(stderr, "luk-job run:", err)
				return exitCode(1)
			}
			return err
		},
	}
	runC.Flags().StringVar(&job, "job", "", "job name")
	runC.Flags().StringArrayVar(&files, "file", nil, "input file of the job (repeatable; default the input set of the step)")
	runC.Flags().StringVar(&outDir, "out", "", "existing directory for the results of the job")
	runC.MarkFlagRequired("job")

	version := &cobra.Command{
		Use:   "version",
		Short: "Print the luk-job version",
		Args:  noArgs,
		Run:   func(*cobra.Command, []string) { fmt.Fprintln(stdout, buildVersion) },
	}
	root.AddCommand(inputs, input, meta, output, fail, runC, version)
	cliflags.Guard(root, func(err error) error { return err })
	return root
}
