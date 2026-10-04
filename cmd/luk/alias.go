package main

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"luk/internal/client"
)

func newAliasCmd(out io.Writer) *cobra.Command {
	var global bool
	cmd := &cobra.Command{
		Use:   "alias",
		Short: "List, add or remove command aliases",
		Long: `Aliases are top-level commands defined in the config: "luk NAME ARGS..."
runs "luk EXPANSION... ARGS...". The expansion starts with a built-in command;
an alias may not shadow a built-in command or expand to another alias. Edits
write the user layer, or the global one with --global (needs root); a user
alias replaces a global alias of the same name.`,
	}
	cmd.PersistentFlags().BoolVar(&global, "global", false, "write the global layer instead of the user layer")

	var name string
	var expansion []string
	add := edit(&global, "add", "Add or replace an alias; the expansion follows --",
		"  luk alias add --alias drop -- send --endpoint drop --ttl 2d\n  luk drop --file report.pdf\n  luk drop --file report.pdf --ttl 1h",
		func(layer, _ *client.Config) error {
			return layer.AddAlias(name, expansion, builtinOf(cmd.Root()), aliasFlagCheck(cmd.Root()))
		})
	add.Long = `Add or replace an alias; the expansion follows --. Flags of the expansion
are defaults: a flag given when the alias is run replaces the same flag of
the expansion (-e and --endpoint are the same flag). Turn a bool flag of the
expansion off with --flag=false; values of a repeatable flag such as --tag
given on the call replace all of its values in the expansion.`
	add.Use = "add --alias NAME -- ARGS..."
	add.Args = func(c *cobra.Command, args []string) error {
		if c.ArgsLenAtDash() != 0 && len(args) > 0 {
			return usageError{fmt.Errorf("unexpected argument %q: the expansion goes after --", args[0])}
		}
		expansion = args
		return nil
	}
	add.Flags().StringVar(&name, "alias", "", "alias name")
	add.MarkFlagRequired("alias")
	completeFlags(add, map[string]cobra.CompletionFunc{"alias": completeNone})

	var rmName string
	rm := edit(&global, "rm", "Remove an alias", "  luk alias rm --alias drop",
		func(layer, merged *client.Config) error {
			if _, ok := layer.Alias[rmName]; !ok {
				if _, inMerged := merged.Alias[rmName]; inMerged {
					return fmt.Errorf("alias %s is defined in the global config; use --global", rmName)
				}
			}
			return layer.RemoveAlias(rmName)
		})
	rm.Flags().StringVar(&rmName, "alias", "", "alias name")
	rm.MarkFlagRequired("alias")
	completeFlags(rm, map[string]cobra.CompletionFunc{"alias": completeAliasName})

	ls := &cobra.Command{
		Use:     "ls",
		Short:   "List aliases: name, expansion, source",
		Example: "  luk alias ls",
		Args:    noArgs,
		RunE: func(*cobra.Command, []string) error {
			cfg, src, err := client.LoadMerged()
			if err != nil {
				return usageError{err}
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			for _, n := range sortedAliases(cfg) {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", n, shellJoin(cfg.Alias[n]), src.Alias[n])
			}
			return tw.Flush()
		},
	}
	cmd.AddCommand(ls, add, rm)
	return cmd
}

// builtinOf reports whether a word names a command or command alias of
// root, including the help, completion and completion request commands
// cobra adds on its own.
func builtinOf(root *cobra.Command) func(string) bool {
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	names := map[string]bool{cobra.ShellCompRequestCmd: true, cobra.ShellCompNoDescRequestCmd: true}
	for _, c := range root.Commands() {
		names[c.Name()] = true
		for _, a := range c.Aliases {
			names[a] = true
		}
	}
	return func(w string) bool { return names[w] }
}

// expandAlias rewrites args when the first word is a config alias, also
// behind a completion request once the alias word is complete. A config
// that cannot be read only matters when the word is not a built-in command.
func expandAlias(root *cobra.Command, args []string) ([]string, error) {
	builtin := builtinOf(root)
	var prefix []string
	if len(args) > 0 && (args[0] == cobra.ShellCompRequestCmd || args[0] == cobra.ShellCompNoDescRequestCmd) {
		if len(args) < 3 {
			return args, nil
		}
		prefix, args = args[:1], args[1:]
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || builtin(args[0]) {
		return slices.Concat(prefix, args), nil
	}
	cfg, _, err := client.LoadMerged()
	if err != nil {
		if prefix != nil {
			return slices.Concat(prefix, args), nil
		}
		return nil, usageError{fmt.Errorf("%q is not a command and the aliases cannot be read: %w", args[0], err)}
	}
	exp, ok := cfg.Alias[args[0]]
	if !ok {
		return slices.Concat(prefix, args), nil
	}
	if err := client.ValidateAlias(args[0], exp, builtin, aliasFlagCheck(root)); err != nil {
		return nil, usageError{err}
	}
	return slices.Concat(prefix, overrideAlias(root, exp, args[1:], prefix != nil)), nil
}

// overrideAlias joins an expansion and the user arguments, leaving out of
// the expansion every flag the user arguments give. A completion request
// leaves out every flag of the expansion, so the defaults can be completed
// and replaced.
func overrideAlias(root *cobra.Command, exp, user []string, completing bool) []string {
	c, _, err := root.Find(slices.Concat(exp, user))
	if err != nil {
		return slices.Concat(exp, user)
	}
	lookup := flagLookup(c)
	set := map[*pflag.Flag]bool{}
	for _, w := range splitFlags(user, lookup) {
		if w.flag != nil {
			set[w.flag] = true
		}
	}
	kept := slices.DeleteFunc(splitFlags(exp, lookup), func(w argWord) bool {
		return w.flag != nil && (completing || set[w.flag])
	})
	return append(joinWords(kept), user...)
}

// aliasFlagCheck reports a single-valued flag given more than once in an
// expansion, which no flag of a call could replace one copy of.
func aliasFlagCheck(root *cobra.Command) func([]string) error {
	return func(exp []string) error {
		c, _, err := root.Find(exp)
		if err != nil {
			return nil
		}
		seen := map[*pflag.Flag]bool{}
		for _, w := range splitFlags(exp, flagLookup(c)) {
			if w.flag == nil || repeatable(w.flag) {
				continue
			}
			if seen[w.flag] {
				return fmt.Errorf("--%s given more than once", w.flag.Name)
			}
			seen[w.flag] = true
		}
		return nil
	}
}

func repeatable(f *pflag.Flag) bool {
	t := f.Value.Type()
	return strings.Contains(t, "Array") || strings.Contains(t, "Slice")
}

// flagLookup finds a flag of c, own or inherited, by long name or by
// shorthand.
func flagLookup(c *cobra.Command) func(name string, short bool) *pflag.Flag {
	c.InheritedFlags() // merges the persistent flags into c.Flags()
	fs := c.Flags()
	return func(name string, short bool) *pflag.Flag {
		if short {
			return fs.ShorthandLookup(name)
		}
		return fs.Lookup(name)
	}
}

// argWord is one flag or other word of an argv. A shorthand of a group like
// -qe holds its letter and inline value in word and the index of the group
// in group; any other word has group -1.
type argWord struct {
	flag  *pflag.Flag // nil for a positional or unknown word
	word  string
	group int
	value []string // the separate value word of the flag, if any
}

// splitFlags splits argv into words the way pflag reads them, up to --.
func splitFlags(argv []string, lookup func(string, bool) *pflag.Flag) []argWord {
	var ws []argWord
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			for _, r := range argv[i:] {
				ws = append(ws, argWord{word: r, group: -1})
			}
			return ws
		case strings.HasPrefix(a, "--"):
			name, _, inline := strings.Cut(a[2:], "=")
			w := argWord{flag: lookup(name, false), word: a, group: -1}
			if w.flag != nil && !inline && w.flag.NoOptDefVal == "" && i+1 < len(argv) {
				i++
				w.value = argv[i : i+1]
			}
			ws = append(ws, w)
		case len(a) > 1 && a[0] == '-':
			for s, g := a[1:], i; s != ""; {
				w := argWord{flag: lookup(s[:1], true), group: g}
				n := 1
				switch {
				case w.flag == nil, len(s) > 2 && s[1] == '=':
					n = len(s)
				case w.flag.NoOptDefVal != "":
				case len(s) > 1:
					n = len(s)
				case i+1 < len(argv):
					i++
					w.value = argv[i : i+1]
				}
				w.word, s = s[:n], s[n:]
				ws = append(ws, w)
			}
		default:
			ws = append(ws, argWord{word: a, group: -1})
		}
	}
	return ws
}

// joinWords is the inverse of splitFlags; shorthands left of a group are
// joined back into one word.
func joinWords(ws []argWord) []string {
	var out []string
	last := -1
	for _, w := range ws {
		switch {
		case w.group >= 0 && w.group == last:
			out[len(out)-1] += w.word
		case w.group >= 0:
			out = append(out, "-"+w.word)
		default:
			out = append(out, w.word)
		}
		last = w.group
		out = append(out, w.value...)
	}
	return out
}

// completeAlias offers the alias names of the config as first words.
func completeAlias(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeAliasName(cmd, args, toComplete)
}

// aliasHelp is the "Aliases" section of the root help, padded like the
// command list; empty without aliases or when the config cannot be read.
func aliasHelp(root *cobra.Command) string {
	cfg, _, err := client.LoadMerged()
	if err != nil || len(cfg.Alias) == 0 {
		return ""
	}
	names := sortedAliases(cfg)
	width := 0
	if cmds := root.Commands(); len(cmds) > 0 {
		width = cmds[0].NamePadding()
	}
	for _, n := range names {
		width = max(width, len(n))
	}
	var b strings.Builder
	b.WriteString("\n\nAliases:")
	for _, n := range names {
		fmt.Fprintf(&b, "\n  %-*s %s", width, n, shellJoin(cfg.Alias[n]))
	}
	return b.String()
}

// withAliasHelp adds the alias section to the usage template of root, after
// the commands.
func withAliasHelp(root *cobra.Command) {
	cobra.AddTemplateFunc("lukAliases", aliasHelp)
	const mark = "{{if .HasAvailableLocalFlags}}"
	root.SetUsageTemplate(strings.Replace(root.UsageTemplate(), mark, "{{if not .HasParent}}{{lukAliases .}}{{end}}"+mark, 1))
}

func sortedAliases(cfg *client.Config) []string {
	names := make([]string, 0, len(cfg.Alias))
	for n := range cfg.Alias {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9@%_+=:,./-]+$`)

// shellJoin quotes words for display the way a POSIX shell would read them.
func shellJoin(argv []string) string {
	q := make([]string, len(argv))
	for i, w := range argv {
		if shellSafe.MatchString(w) {
			q[i] = w
		} else {
			q[i] = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
		}
	}
	return strings.Join(q, " ")
}
