package main

import (
	"bufio"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"luk/internal/config"
	"luk/internal/expose"
	"luk/internal/status"
	"luk/internal/store"
	"luk/internal/tlsself"
	"luk/internal/watch"
	"luk/internal/wire"
)

// storageFile is one stored file as lukd storage ls shows it: its name,
// its URL when the storage is exposed, the number of names holding its
// content (see store.Local.Links), and its sidecar.
type storageFile struct {
	Name  string `json:"name"`
	URL   string `json:"url,omitempty"`
	Links int    `json:"links"`
	store.Sidecar
}

func storageCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "storage",
		Short: "Files of a local storage",
		Long: "Files of a local storage, read from their sidecars. The commands work on files\n" +
			"and may run while lukd runs (rm, ttl, hold and release take the base lock). Run\n" +
			"as root they run again as the owner of the storage base (the service user).",
	}

	var lsStorage, owner, older string
	var asJSON, human bool
	ls := &cobra.Command{
		Use:   "ls",
		Short: "List the stored files",
		Long: "List the stored files of a local storage, newest first: name, size, received,\n" +
			"expiry, owner (the name the portal shows, and the owner key), endpoint, flags\n" +
			"(once, mutable, reveal or download, private or any, shared when other names\n" +
			"hold the same content as hardlinks, hold for a file on hold) and the URL when the\n" +
			"storage is exposed (the luk:// URL of its protect expose for a private file).\n" +
			"--owner keeps the files of an identity: a key name, or the full owner key\n" +
			"(key:<name>, cert:<ca>:<keyid>); --older those received longer ago than the\n" +
			"duration (7d, 12h). Aliases and claimed files are not listed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var age time.Duration
			if older != "" {
				d, err := wire.ParseDuration(older)
				if err != nil || d <= 0 {
					return fmt.Errorf("--older %q: want a positive duration such as 7d or 12h", older)
				}
				age = d
			}
			cfg, st, l, err := openStorage(*cfgPath, lsStorage)
			if err != nil {
				return err
			}
			// Unreadable entries are reported after the readable ones.
			files, werr := storageFiles(cfg, lsStorage, l, owner, age, time.Now())
			if err := printStorage(cmd.OutOrStdout(), files, st.Expose != "" || st.Protect != "", asJSON, human); err != nil {
				return err
			}
			return werr
		},
	}
	ls.Flags().StringVar(&lsStorage, "storage", "", "storage name")
	ls.Flags().StringVar(&owner, "owner", "", "only the files of this identity: a key name or an owner key")
	ls.Flags().StringVar(&older, "older", "", "only the files received longer ago than this (e.g. 7d)")
	ls.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	ls.Flags().BoolVarP(&human, "human-readable", "H", false, "sizes with a unit (1.5K, 4M, 12.5G) instead of bytes")
	ls.MarkFlagRequired("storage")
	completeFlags(ls, map[string]cobra.CompletionFunc{"storage": completeStorage, "owner": completeOwner, "older": completeNone})

	var rmStorage string
	var names []string
	var yes bool
	rm := &cobra.Command{
		Use:   "rm",
		Short: "Remove stored files and their sidecars",
		Long: "Remove stored files and their sidecars under the base lock; emptied\n" +
			"directories are pruned, an alias moves to the next newest file and the\n" +
			"catalog is rebuilt. Every name is checked before anything is removed.\n" +
			"A file on hold is refused: release it first.\n" +
			"Asks for confirmation on a terminal; elsewhere --yes is required.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _, l, err := openStorage(*cfgPath, rmStorage)
			if err != nil {
				return err
			}
			return removeStored(l, rmStorage, names, yes, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	rm.Flags().StringVar(&rmStorage, "storage", "", "storage name")
	rm.Flags().StringArrayVar(&names, "name", nil, "stored name, as ls shows it (repeatable)")
	rm.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	rm.MarkFlagRequired("storage")
	rm.MarkFlagRequired("name")
	completeFlags(rm, map[string]cobra.CompletionFunc{"storage": completeStorage, "name": completeStored})

	var retStorage string
	var retJSON bool
	ret := &cobra.Command{
		Use:   "retention",
		Short: "Show what the retention rules keep and prune",
		Long: "Show the retention plan of a local storage without changing anything: per\n" +
			"series (pipeline, origin, file name) the rule that applies and every file,\n" +
			"newest first, with KEEP and the reasons (last, within, daily 2026-10-04,\n" +
			"weekly 2026-W40, monthly 2026-10, yearly 2026) or PRUNE. Files of a series no rule\n" +
			"matches are kept (no rule). A file on hold is HELD: kept, and not counted by\n" +
			"the rule. The maintenance of the process role removes the pruned files.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, st, l, err := openStorage(*cfgPath, retStorage)
			if err != nil {
				return err
			}
			plans, werr := l.RetentionPlan(st, time.Now())
			if err := printRetention(cmd.OutOrStdout(), st, plans, retJSON); err != nil {
				return err
			}
			return werr
		},
	}
	ret.Flags().StringVar(&retStorage, "storage", "", "storage name")
	ret.Flags().BoolVar(&retJSON, "json", false, "print JSON")
	ret.MarkFlagRequired("storage")
	completeFlags(ret, map[string]cobra.CompletionFunc{"storage": completeStorage})

	var watchStorage string
	var watchJSON, suggest bool
	wat := &cobra.Command{
		Use:   "watch",
		Short: "Evaluate the watch rules of a storage",
		Long: "Evaluate the watch rules of a local storage now, read only: its rules, then per\n" +
			"series (pipeline, origin, file name) the rule that applies, the state (OK,\n" +
			"WARN, CRIT), the newest copy, its size, the number of copies and the message\n" +
			"naming every failed check. A series no rule matches is listed as not watched;\n" +
			"a rule no series matches is WARN. --suggest adds, per series, values observed\n" +
			"on its newest copies (sizes, largest step, intervals, identical newest copies)\n" +
			"as hints for setting the thresholds; they are never used as thresholds.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, st, l, err := openStorage(*cfgPath, watchStorage)
			if err != nil {
				return err
			}
			series, werr := l.SeriesCopies()
			rows := storageWatch(watchStorage, st, series, time.Now(), suggest)
			if err := printWatch(cmd.OutOrStdout(), st, rows, watchJSON, suggest); err != nil {
				return err
			}
			return werr
		},
	}
	wat.Flags().StringVar(&watchStorage, "storage", "", "storage name")
	wat.Flags().BoolVar(&watchJSON, "json", false, "print JSON")
	wat.Flags().BoolVar(&suggest, "suggest", false, "add observed values per series as hints for thresholds")
	wat.MarkFlagRequired("storage")
	completeFlags(wat, map[string]cobra.CompletionFunc{"storage": completeStorage})

	var ttlStorage, expires string
	var ttlNames []string
	ttl := &cobra.Command{
		Use:   "ttl",
		Short: "Set the expiry of stored files",
		Long: "Set the expiry of stored files under the base lock, whatever the ttl policy of\n" +
			"the storage says (ttl.user, ttl.min, ttl.max and the tag ttls do not apply). --expires takes\n" +
			"never (no expiry), a duration from now (30d, 12h) or an RFC 3339 time, which\n" +
			"must not be past. Every name is checked before anything changes. The name of\n" +
			"an alias or a permanent name is refused: name the file it points to, and the\n" +
			"alias or permanent name follows.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			exp, err := parseExpires(expires, time.Now())
			if err != nil {
				return err
			}
			_, _, l, err := openStorage(*cfgPath, ttlStorage)
			if err != nil {
				return err
			}
			return amendStored(l, ttlStorage, ttlNames, nil, func(sc *store.Sidecar) { sc.Expires = exp },
				"expires "+cmp.Or(exp, "never"), cmd.OutOrStdout())
		},
	}
	ttl.Flags().StringVar(&ttlStorage, "storage", "", "storage name")
	ttl.Flags().StringArrayVar(&ttlNames, "name", nil, "stored name, as ls shows it (repeatable)")
	ttl.Flags().StringVar(&expires, "expires", "", "never, a duration from now (e.g. 30d) or an RFC 3339 time")
	ttl.MarkFlagRequired("storage")
	ttl.MarkFlagRequired("name")
	ttl.MarkFlagRequired("expires")
	completeFlags(ttl, map[string]cobra.CompletionFunc{"storage": completeStorage, "name": completeStored, "expires": completeNone})

	cmd.AddCommand(ls, rm, ttl, holdCmd(cfgPath, true), holdCmd(cfgPath, false), ret, wat, storagePermanentCmd(cfgPath))
	return cmd
}

// holdCmd is lukd storage hold (on) or release.
func holdCmd(cfgPath *string, on bool) *cobra.Command {
	var storage string
	var names []string
	cmd := &cobra.Command{
		Use:   "release",
		Short: "Release stored files from hold",
		Long: "Clear the hold of stored files under the base lock: the expiry, the retention\n" +
			"rules and cleanup.age apply to them again, and they may be removed and\n" +
			"replaced. Every name is checked before anything changes.",
		Args: cobra.NoArgs,
	}
	if on {
		cmd.Use, cmd.Short = "hold", "Put stored files on hold"
		cmd.Long = "Put stored files on hold under the base lock. Nothing removes a file on hold:\n" +
			"not its expiry, the retention rules (which keep their number of copies beside\n" +
			"it) or cleanup.age, and lukd storage rm and the link actions remove and\n" +
			"replace refuse it, until lukd storage release. An expired file on hold is kept\n" +
			"but not served. A once upload cannot be held. Every name is checked before\n" +
			"anything changes. The name of an alias or a permanent name is refused: name\n" +
			"the file it points to."
	}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		_, _, l, err := openStorage(*cfgPath, storage)
		if err != nil {
			return err
		}
		check, done := func(store.Sidecar) error { return nil }, "released"
		if on {
			done = "on hold"
			check = func(sc store.Sidecar) error {
				if sc.Client.Once {
					return errors.New("a once upload cannot be held")
				}
				return nil
			}
		}
		return amendStored(l, storage, names, check, func(sc *store.Sidecar) { sc.Hold = on }, done, cmd.OutOrStdout())
	}
	cmd.Flags().StringVar(&storage, "storage", "", "storage name")
	cmd.Flags().StringArrayVar(&names, "name", nil, "stored name, as ls shows it (repeatable)")
	cmd.MarkFlagRequired("storage")
	cmd.MarkFlagRequired("name")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"storage": completeStorage, "name": completeStored})
	return cmd
}

// parseExpires is the expiry --expires asks for at now: empty for never,
// now plus a duration, or an RFC 3339 time after now; in UTC.
func parseExpires(s string, now time.Time) (string, error) {
	if s == "never" {
		return "", nil
	}
	if d, err := wire.ParseDuration(s); err == nil {
		if d <= 0 {
			return "", fmt.Errorf("--expires %q: want a positive duration", s)
		}
		return now.Add(d).UTC().Format(time.RFC3339), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", fmt.Errorf("--expires %q: want never, a duration such as 30d or 12h, or an RFC 3339 time", s)
	}
	if !t.After(now) {
		return "", fmt.Errorf("--expires %q: in the past", s)
	}
	return t.UTC().Format(time.RFC3339), nil
}

// checkStored reads the sidecars of the stored files names of l, refusing
// an invalid or unknown name and an alias or permanent name, which is told
// to do (remove, name) the file it points to instead.
func checkStored(l store.Local, storage string, names []string, do string) ([]store.Sidecar, error) {
	var scs []store.Sidecar
	for _, name := range names {
		f, sc, err := l.Open(name)
		switch {
		case errors.Is(err, store.ErrInvalid):
			return nil, fmt.Errorf("--name %q: refused: %w", name, err)
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("storage %s: no stored file %q", storage, name)
		case err != nil:
			return nil, err
		}
		f.Close()
		if sc.AliasOf != "" {
			return nil, fmt.Errorf("storage %s: %q is an alias of %q; %s that file", storage, name, sc.AliasOf, do)
		}
		scs = append(scs, sc)
	}
	return scs, nil
}

// amendStored rewrites the sidecars of the stored files names of l with
// set, after checking them all (check, when set, may refuse one), and
// prints done for each. A file replaced since the check is left alone.
func amendStored(l store.Local, storage string, names []string, check func(store.Sidecar) error, set func(*store.Sidecar), done string, w io.Writer) error {
	scs, err := checkStored(l, storage, names, "name")
	if err != nil {
		return err
	}
	if check != nil {
		for i, name := range names {
			if err := check(scs[i]); err != nil {
				return fmt.Errorf("storage %s: %q: %w", storage, name, err)
			}
		}
	}
	var errs []error
	for i, name := range names {
		_, err := l.Amend(name, scs[i].ID, func(sc *store.Sidecar) error {
			if check != nil {
				if err := check(*sc); err != nil {
					return err
				}
			}
			set(sc)
			return nil
		})
		if errors.Is(err, fs.ErrNotExist) {
			err = errors.New("removed or replaced meanwhile")
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		fmt.Fprintf(w, "%s: %s\n", status.Clean(name), done)
	}
	return errors.Join(errs...)
}

// watchRow is one line of lukd storage watch: the evaluation of a series
// (State empty and Rule 0 when no rule matches it) or of a rule no series
// matches, and with --suggest the hints of the series.
type watchRow struct {
	status.Watch
	Hints *watch.Hints `json:"hints,omitempty"`
}

// storageWatch evaluates the watch rules of the storage name on its series
// at now: every series in series order, then the rules no series matches.
func storageWatch(name string, st *config.Storage, series []store.SeriesCopies, now time.Time, suggest bool) []watchRow {
	rows := []watchRow{}
	for _, s := range series {
		var w status.Watch
		if i := st.WatchRule(s.Origin, s.File); i >= 0 {
			w = watch.Record(name, i+1, st.Watch[i], s, now)
		} else {
			w = status.Watch{Storage: name, Pipeline: s.Pipeline, Origin: s.Origin, File: s.File, Copies: len(s.Copies), Message: "not watched"}
			if len(s.Copies) > 0 {
				w.NewestReceived, w.Size = s.Copies[0].Received.UTC().Format(time.RFC3339), s.Copies[0].Size
			}
		}
		r := watchRow{Watch: w}
		if suggest {
			h := watch.Suggest(s.Copies)
			r.Hints = &h
		}
		rows = append(rows, r)
	}
	for _, w := range watch.Unmatched(name, st, series, now) {
		rows = append(rows, watchRow{Watch: w})
	}
	return rows
}

// printWatch prints the rules of st and the rows: a table of the
// evaluations and, with suggest, one of the hints.
func printWatch(w io.Writer, st *config.Storage, rows []watchRow, asJSON, suggest bool) error {
	if asJSON {
		b, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	}
	if len(st.Watch) == 0 {
		fmt.Fprintln(w, "no watch rules")
	}
	for i, r := range st.Watch {
		fmt.Fprintf(w, "rule %d: %s: %s\n", i+1, status.Clean(watch.RuleText(r)), watch.ChecksText(r))
	}
	fmt.Fprintln(w)
	ws := make([]status.Watch, len(rows))
	for i, r := range rows {
		ws[i] = r.Watch
	}
	if err := status.PrintWatch(w, ws); err != nil || !suggest {
		return err
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "HINTS: observed on the newest %d copies of each series; not thresholds\n", watch.SuggestCopies)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SERIES\tPIPELINE\tCOPIES\tNEWEST SIZE\tMIN SIZE\tMAX SIZE\tMAX STEP\tINTERVAL\tMIN INTERVAL\tMAX INTERVAL\tSAME")
	for _, r := range rows {
		if r.Hints == nil {
			continue
		}
		h := r.Hints
		fmt.Fprintf(tw, "%s/%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", status.Clean(r.Origin), status.Clean(r.File), dash(status.Clean(r.Pipeline)),
			h.Copies, wire.HumanSize(h.NewestSize), wire.HumanSize(h.MinSize), wire.HumanSize(h.MaxSize), wire.HumanSize(h.MaxStep),
			dash(h.Interval), dash(h.MinInterval), dash(h.MaxInterval), h.Same)
	}
	return tw.Flush()
}

// printRetention prints the retention plans of the storage st: per series
// a line naming it and its rule, then its files as aligned columns.
func printRetention(w io.Writer, st *config.Storage, plans []store.SeriesPlan, asJSON bool) error {
	if asJSON {
		b, err := json.MarshalIndent(plans, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	}
	for i, p := range plans {
		if i > 0 {
			fmt.Fprintln(w)
		}
		rule := "no rule"
		if p.Rule > 0 {
			r := st.Retention[p.Rule-1]
			origin := "any origin"
			if len(r.Origin) > 0 {
				origin = "origin " + strings.Join(r.Origin, ",")
			}
			rule = fmt.Sprintf("rule %d (%s; keep %s)", p.Rule, status.Clean(origin), keepText(*p.Keep))
		}
		fmt.Fprintf(w, "series pipeline=%s origin=%s file=%s: %s\n", dash(status.Clean(p.Pipeline)),
			dash(status.Clean(p.Origin)), dash(status.Clean(p.File)), rule)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  NAME\tRECEIVED\tACTION\tREASONS")
		for _, f := range p.Files {
			action := "PRUNE"
			switch {
			case f.Hold:
				action = "HELD"
			case f.Keep:
				action = "KEEP"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", status.Clean(f.Name), dash(status.Clean(f.Received)), action,
				dash(strings.Join(f.Reasons, ", ")))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// keepText is the counts of k above 0 and its window: "last 3, daily 14,
// within 2d".
func keepText(k config.Keep) string {
	var out []string
	for _, c := range []struct {
		name string
		n    int
	}{{"last", k.Last}, {"daily", k.Daily}, {"weekly", k.Weekly}, {"monthly", k.Monthly}, {"yearly", k.Yearly}} {
		if c.n > 0 {
			out = append(out, c.name+" "+strconv.Itoa(c.n))
		}
	}
	if k.Within > 0 {
		out = append(out, "within "+wire.FormatDuration(time.Duration(k.Within)))
	}
	return strings.Join(out, ", ")
}

// openStorage loads the configuration and the local storage name, and runs
// as the owner of its base (see asOwner).
func openStorage(cfgPath, name string) (*config.Config, *config.Storage, store.Local, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, store.Local{}, err
	}
	st := cfg.Storage[name]
	switch {
	case st == nil:
		return nil, nil, store.Local{}, fmt.Errorf("unknown storage %q", name)
	case st.Type != "local":
		return nil, nil, store.Local{}, fmt.Errorf("storage %s is not a local storage (%s)", name, st.Type)
	}
	if err := asOwner("lukd storage", st.Base); err != nil {
		return nil, nil, store.Local{}, err
	}
	if err := store.CheckLayout(st.Base); err != nil {
		return nil, nil, store.Local{}, fmt.Errorf("storage %s: %w", name, err)
	}
	return cfg, st, store.FromConfig(st), nil
}

// storageLayouts checks the base of every local storage (see
// store.CheckLayout), in name order.
func storageLayouts(cfg *config.Config) []error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(cfg.Storage)) {
		if st := cfg.Storage[name]; st.Type == "local" {
			if err := store.CheckLayout(st.Base); err != nil {
				errs = append(errs, fmt.Errorf("storage %s: %w", name, err))
			}
		}
	}
	return errs
}

// pinOf is the URL fragment pinning the certificate of the listener l
// when it has tls mode self or files and its certificate file is
// readable; empty otherwise.
func pinOf(l *config.Listen) string {
	if l == nil || l.TLS == nil || (l.TLS.Mode != "self" && l.TLS.Mode != "files") {
		return ""
	}
	p, err := tlsself.PinFile(l.TLS.Cert)
	if err != nil {
		return ""
	}
	return "#" + p
}

// storageFiles reads the stored files of l, newest first, keeping those of
// owner (when set) received more than age (when set) before now.
func storageFiles(cfg *config.Config, name string, l store.Local, owner string, age time.Duration, now time.Time) ([]storageFile, error) {
	// Private files have the luk:// URL of the protect expose, public
	// files of an expose with auth.ssh one too (https with auth.basic
	// too), pinned as lukd answers it when the certificate file is
	// readable.
	base, bl, exposed := cfg.PublicURL(name)
	pbase, pl, protected := cfg.ProtectURL(name)
	ppin, bpin := "", ""
	if protected {
		ppin = pinOf(pl)
	}
	if exposed {
		bpin = pinOf(bl)
	}
	files := []storageFile{}
	err := l.Walk(func(rel string, sc store.Sidecar) error {
		if sc.AliasOf != "" {
			return nil
		}
		if owner != "" && (sc.OwnerKey == "" || (sc.OwnerKey != owner && sc.OwnerKey != "key:"+owner)) {
			return nil
		}
		if age > 0 {
			at, err := time.Parse(time.RFC3339, sc.Received)
			if err != nil || now.Sub(at) <= age {
				return nil
			}
		}
		f := storageFile{Name: rel, Links: l.Links(rel, sc), Sidecar: sc}
		switch {
		case sc.Client.Access != "" && protected:
			f.URL = expose.NameURL(pbase, rel) + ppin
		case sc.Client.Access == "" && exposed:
			f.URL = expose.NameURL(base, rel) + bpin
		}
		files = append(files, f)
		return nil
	})
	slices.SortFunc(files, func(a, b storageFile) int {
		return cmp.Or(b.Order().Compare(a.Order()), strings.Compare(b.ID, a.ID), strings.Compare(a.Name, b.Name))
	})
	return files, err
}

func printStorage(w io.Writer, files []storageFile, exposed, asJSON, human bool) error {
	if asJSON {
		b, err := json.MarshalIndent(files, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	head := "NAME\tSIZE\tRECEIVED\tEXPIRES\tOWNER\tOWNER KEY\tENDPOINT\tFLAGS"
	if exposed {
		head += "\tURL"
	}
	fmt.Fprintln(tw, head)
	for _, f := range files {
		var flags []string
		if f.Client.Once {
			flags = append(flags, "once")
		}
		if f.Client.Mutable {
			flags = append(flags, "mutable")
		}
		if f.Client.Portal == wire.PortalReveal || f.Client.Portal == wire.PortalDownload {
			flags = append(flags, f.Client.Portal)
		}
		if f.Client.Access != "" {
			flags = append(flags, f.Client.Access)
		}
		if f.Links > 1 {
			flags = append(flags, "shared")
		}
		if f.Hold {
			flags = append(flags, "hold")
		}
		size := strconv.FormatInt(f.Size, 10)
		if human {
			size = wire.HumanSize(f.Size)
		}
		line := strings.Join([]string{status.Clean(f.Name), size, dash(status.Clean(f.Received)),
			dash(status.Clean(f.Expires)), dash(status.Clean(f.Owner)), dash(status.Clean(f.OwnerKey)),
			dash(status.Clean(f.Endpoint)), dash(strings.Join(flags, ","))}, "\t")
		if exposed {
			line += "\t" + dash(f.URL)
		}
		fmt.Fprintln(tw, line)
	}
	return tw.Flush()
}

// removeStored removes the stored files names of l after checking them all
// and, without yes, a confirmation on a terminal. A file on hold is
// refused. A file replaced or put on hold since the check is kept.
func removeStored(l store.Local, storage string, names []string, yes bool, in io.Reader, w, errw io.Writer) error {
	scs, err := checkStored(l, storage, names, "remove")
	if err != nil {
		return err
	}
	for i, name := range names {
		if scs[i].Hold {
			return fmt.Errorf("storage %s: %q is on hold; release it first (lukd storage release)", storage, name)
		}
	}
	if !yes {
		if !stdinIsTerminal() {
			return errors.New("refusing to remove without --yes: stdin is not a terminal")
		}
		fmt.Fprintf(errw, "Remove from storage %s:\n", storage)
		for i, name := range names {
			fmt.Fprintf(errw, "  %s (%d bytes, received %s, owner %s)\n", status.Clean(name), scs[i].Size,
				dash(status.Clean(scs[i].Received)), dash(status.Clean(scs[i].OwnerKey)))
		}
		fmt.Fprint(errw, "[y/N] ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return errors.New("nothing removed")
		}
	}
	var errs []error
	for i, name := range names {
		err := l.RemoveIf(name, scs[i].ID)
		if errors.Is(err, fs.ErrNotExist) {
			err = fmt.Errorf("%s: removed or replaced meanwhile, kept", name)
		}
		if errors.Is(err, store.ErrOnHold) {
			err = fmt.Errorf("%s: put on hold meanwhile, kept", name)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		fmt.Fprintf(w, "%s: removed\n", status.Clean(name))
	}
	return errors.Join(errs...)
}
