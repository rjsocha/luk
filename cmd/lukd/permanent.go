package main

import (
	"bufio"
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
// storage, and the removal of the orphaned ones.
func storagePermanentCmd(cfgPath *string) *cobra.Command {
	var storage string
	var asJSON, prune, yes bool
	cmd := &cobra.Command{
		Use:   "permanent",
		Short: "List the permanent names of a storage, remove orphaned ones",
		Long: "List the permanent names of a local storage (the directories under\n" +
			".db/permanent): PATH and NAME (as the current version records them), NEWEST\n" +
			"(the received time of the current version), VERSIONS (live versions of the\n" +
			"name in the storage), CURRENT (the stored name of the current version) and\n" +
			"ORPHAN when the configuration no longer allocates the name: no endpoint of\n" +
			"the storage has its permanent.path, or no entry of that endpoint covers it.\n" +
			"An orphan is not served and never removed by lukd itself. --prune-orphans\n" +
			"removes the directories of the orphans under the base lock; the versions\n" +
			"stay, they are ordinary stored files (lukd storage rm, ttl, retention).\n" +
			"It asks for confirmation on a terminal; elsewhere --yes is required.",
		Example: "  lukd storage permanent --storage drop\n" +
			"  lukd storage permanent --storage drop --prune-orphans",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _, l, err := openStorage(*cfgPath, storage)
			if err != nil {
				return err
			}
			list, lerr := l.PermanentList()
			if prune {
				if err := pruneOrphans(l, storage, list, yes, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
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
	f.BoolVar(&prune, "prune-orphans", false, "remove the directories of the orphaned permanent names")
	f.BoolVar(&yes, "yes", false, "with --prune-orphans: do not ask for confirmation")
	cmd.MarkFlagRequired("storage")
	cmd.MarkFlagsMutuallyExclusive("json", "prune-orphans")
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
	fmt.Fprintln(tw, "PATH\tNAME\tNEWEST\tVERSIONS\tCURRENT\tORPHAN")
	for _, p := range list {
		path, name := p.Path, p.Name
		if name == "" {
			// The current version cannot be read: the directory tells.
			name = p.Key
		}
		orphan := "-"
		if p.Orphan {
			orphan = "ORPHAN"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", dash(status.Clean(path)), status.Clean(name), dash(status.Clean(p.Received)),
			p.Versions, dash(status.Clean(p.Current)), orphan)
	}
	return tw.Flush()
}

// pruneOrphans removes the directories of the orphans of list, after a
// confirmation on a terminal unless yes.
func pruneOrphans(l store.Local, storage string, list []store.PermanentInfo, yes bool, in io.Reader, w, errw io.Writer) error {
	var orphans []store.PermanentInfo
	for _, p := range list {
		if p.Orphan {
			orphans = append(orphans, p)
		}
	}
	if len(orphans) == 0 {
		fmt.Fprintf(errw, "storage %s: no orphaned permanent names\n", storage)
		return nil
	}
	if !yes {
		if !stdinIsTerminal() {
			return errors.New("refusing to remove without --yes: stdin is not a terminal")
		}
		fmt.Fprintf(errw, "Remove the orphaned permanent names of storage %s (the versions stay):\n", storage)
		for _, p := range orphans {
			fmt.Fprintf(errw, "  %s (%d versions)\n", status.Clean(p.Key), p.Versions)
		}
		fmt.Fprint(errw, "[y/N] ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return errors.New("nothing removed")
		}
	}
	var errs []error
	for _, p := range orphans {
		if err := l.PruneOrphan(p.Key); err != nil {
			errs = append(errs, err)
			continue
		}
		fmt.Fprintf(w, "%s: removed\n", status.Clean(p.Key))
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
				out = append(out, fmt.Sprintf("storage %s: permanent name %s is an orphan: no endpoint allocates it (lukd storage permanent --storage %s --prune-orphans)", name, status.Clean(p.Key), name))
			}
		}
	}
	return out
}
