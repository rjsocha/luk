// Package cliflags hardens cobra/pflag parsing: a single-valued flag may be
// given once, and a string value may not look like a flag.
package cliflags

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Guard wraps every non-repeatable flag of root and its subcommands, and sets
// the flag error func of root so the guard messages are reported verbatim.
func Guard(root *cobra.Command, wrap func(error) error) {
	g := &state{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		g.wrap(c.Flags())
		g.wrap(c.PersistentFlags())
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		if g.err != nil {
			err = g.err
		}
		return wrap(err)
	})
}

// AllowDash is the flag annotation that lets a string flag take the value
// "-" (stdout or stdin) despite the guard.
const AllowDash = "cliflags_allow_dash"

type state struct{ err error }

func (s *state) wrap(fs *pflag.FlagSet) {
	fs.VisitAll(func(f *pflag.Flag) {
		if _, done := f.Value.(*guarded); done {
			return
		}
		if t := f.Value.Type(); strings.Contains(t, "Array") || strings.Contains(t, "Slice") {
			return
		}
		f.Value = &guarded{Value: f.Value, flag: f, st: s}
	})
}

type guarded struct {
	pflag.Value
	flag *pflag.Flag
	st   *state
	n    int
}

func (g *guarded) Set(v string) error {
	g.n++
	var err error
	switch {
	case g.n > 1:
		err = fmt.Errorf("--%s given more than once", g.flag.Name)
	case g.Value.Type() == "string" && strings.HasPrefix(v, "-") && (v != "-" || g.flag.Annotations[AllowDash] == nil):
		err = fmt.Errorf("--%s needs a value, got %q (use ./%s for a value with that name)", g.flag.Name, v, v)
	default:
		return g.Value.Set(v)
	}
	if g.st.err == nil {
		g.st.err = err
	}
	return err
}
