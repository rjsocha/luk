package main

import (
	"bufio"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"luk/internal/config"
	"luk/internal/status"
	"luk/internal/store"
)

// storagePermanentCmd is lukd storage permanent: the permanent names of a
// storage, and the removal of the orphaned and the empty ones.
func storagePermanentCmd(cfgPath *string) *cobra.Command {
	var storage string
	var asJSON, prune, yes bool
	cmd := &cobra.Command{
		Use:   "permanent",
		Short: "List the permanent names of a storage, remove orphaned and empty ones",
		Long: "List the permanent names of a local storage (the directories under\n" +
			".db/permanent): PATH and NAME (as published), CURRENT (the stored name of\n" +
			"the current version, the version published last), RECEIVED and EXPIRES (of\n" +
			"that version; never without an expiry) and ORPHAN when the configuration no\n" +
			"longer allocates the name: no endpoint of the storage has its\n" +
			"permanent.path, or no entry of that endpoint covers it. A name whose\n" +
			"version is gone (removed, expired) is empty: CURRENT, RECEIVED and EXPIRES\n" +
			"are -, it answers 404 until a later version is published.\n" +
			"An orphan is not served and never removed by lukd itself. --prune\n" +
			"removes, under the base lock, the directories of the orphans and of the\n" +
			"empty names (with the record of the version published last); the versions\n" +
			"stay, they are ordinary stored files (lukd storage rm, ttl, retention).\n" +
			"It asks for confirmation on a terminal; elsewhere --yes is required.",
		Example: "  lukd storage permanent --storage drop\n" +
			"  lukd storage permanent --storage drop --prune\n" +
			"  lukd storage permanent --storage drop --prune --yes",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _, l, err := openStorage(*cfgPath, storage)
			if err != nil {
				return err
			}
			list, lerr := l.PermanentList()
			if prune {
				p := &pruning{
					what: "orphaned or empty",
					pick: func(p store.PermanentInfo) bool { return p.Orphan || p.Current == "" },
					prune: func(p store.PermanentInfo) error {
						if p.Orphan {
							return l.PruneOrphan(p.Key)
						}
						return l.PruneEmpty(p.Key)
					},
				}
				if err := p.run(storage, list, yes, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
					return errors.Join(err, lerr)
				}
				return lerr
			}
			if err := printPermanent(cmd.OutOrStdout(), list, asJSON); err != nil {
				return err
			}
			return lerr
		},
	}
	f := cmd.Flags()
	f.StringVar(&storage, "storage", "", "storage name")
	f.BoolVar(&asJSON, "json", false, "print JSON")
	f.BoolVar(&prune, "prune", false, "remove the directories of the orphaned permanent names and of those without a current version")
	f.BoolVar(&yes, "yes", false, "with --prune: do not ask for confirmation")
	cmd.MarkFlagRequired("storage")
	cmd.MarkFlagsMutuallyExclusive("json", "prune")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"storage": completeStorage})
	return cmd
}

// printPermanent prints the permanent names as aligned columns, or JSON.
func printPermanent(w io.Writer, list []store.PermanentInfo, asJSON bool) error {
	if asJSON {
		if list == nil {
			list = []store.PermanentInfo{}
		}
		b, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	}
	if len(list) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PATH\tNAME\tCURRENT\tRECEIVED\tEXPIRES\tORPHAN")
	for _, p := range list {
		path, name := p.Path, p.Name
		if name == "" {
			// Nothing of the name can be read: the directory tells.
			name = p.Key
		}
		orphan := "-"
		if p.Orphan {
			orphan = "ORPHAN"
		}
		exp := "-"
		if p.Current != "" {
			exp = cmp.Or(p.Expires, "never")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", dash(status.Clean(path)), status.Clean(name), dash(status.Clean(p.Current)),
			dash(status.Clean(p.Received)), status.Clean(exp), orphan)
	}
	return tw.Flush()
}

// pruning removes the permanent names pick selects with prune: what
// names them in the messages.
type pruning struct {
	what  string
	pick  func(store.PermanentInfo) bool
	prune func(store.PermanentInfo) error
}

// run removes the names of list p selects, after a confirmation on a
// terminal unless yes.
func (p *pruning) run(storage string, list []store.PermanentInfo, yes bool, in io.Reader, w, errw io.Writer) error {
	var names []store.PermanentInfo
	for _, pi := range list {
		if p.pick(pi) {
			names = append(names, pi)
		}
	}
	if len(names) == 0 {
		fmt.Fprintf(errw, "storage %s: no %s permanent names\n", storage, p.what)
		return nil
	}
	if !yes {
		if !stdinIsTerminal() {
			return errors.New("refusing to remove without --yes: stdin is not a terminal")
		}
		fmt.Fprintf(errw, "Remove the %s permanent names of storage %s (stored versions stay):\n", p.what, storage)
		for _, pi := range names {
			fmt.Fprintf(errw, "  %s (current %s)\n", status.Clean(pi.Key), dash(status.Clean(pi.Current)))
		}
		fmt.Fprint(errw, "[y/N] ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return errors.New("nothing removed")
		}
	}
	var errs []error
	for _, pi := range names {
		if err := p.prune(pi); err != nil {
			errs = append(errs, err)
			continue
		}
		fmt.Fprintf(w, "%s: removed\n", status.Clean(pi.Key))
	}
	return errors.Join(errs...)
}

// permanentOrphans names, for lukd check, the orphaned permanent names
// of every local storage whose base can be read (see
// store.Local.PermanentList); a base that cannot be read is skipped.
func permanentOrphans(cfg *config.Config) []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(cfg.Storage)) {
		st := cfg.Storage[name]
		if st.Type != "local" {
			continue
		}
		list, err := store.FromConfig(st).PermanentList()
		if err != nil {
			continue
		}
		for _, p := range list {
			if p.Orphan {
				out = append(out, fmt.Sprintf("storage %s: permanent name %s is an orphan: no endpoint allocates it (lukd storage permanent --storage %s --prune)", name, status.Clean(p.Key), name))
			}
		}
	}
	return out
}
