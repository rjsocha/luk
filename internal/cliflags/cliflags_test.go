package cliflags

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func cmdFor() (*cobra.Command, *[]string) {
	var f, tag []string
	var file string
	root := &cobra.Command{Use: "x", SilenceUsage: true, SilenceErrors: true}
	sub := &cobra.Command{Use: "s", RunE: func(*cobra.Command, []string) error { f = nil; return nil }}
	sub.Flags().StringVar(&file, "file", "", "")
	sub.Flags().StringArrayVar(&tag, "tag", nil, "")
	root.AddCommand(sub)
	Guard(root, func(e error) error { return e })
	return root, &f
}

func TestGuard(t *testing.T) {
	for _, tc := range []struct{ args, want string }{
		{"s --file a --file b", "--file given more than once"},
		{"s --file --progress", `--file needs a value, got "--progress"`},
		{"s --tag a --tag b", ""},
		{"s --file ./-x", ""},
	} {
		root, _ := cmdFor()
		root.SetArgs(strings.Fields(tc.args))
		err := root.Execute()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.args, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestAllowDash(t *testing.T) {
	for _, c := range []struct {
		args []string
		ok   bool
	}{
		{[]string{"--output", "-"}, true}, {[]string{"--output", "-x"}, false}, {[]string{"--input", "-"}, false},
	} {
		var out, in string
		cmd := &cobra.Command{Use: "x", SilenceUsage: true, SilenceErrors: true, RunE: func(*cobra.Command, []string) error { return nil }}
		cmd.Flags().StringVar(&out, "output", "", "")
		cmd.Flags().StringVar(&in, "input", "", "")
		_ = cmd.Flags().SetAnnotation("output", AllowDash, []string{"true"})
		Guard(cmd, func(err error) error { return err })
		cmd.SetArgs(c.args)
		if err := cmd.Execute(); (err == nil) != c.ok {
			t.Errorf("%v: %v", c.args, err)
		}
	}
}

// A completion request is not guarded: cobra parses its flags twice.
func TestGuardOffForCompletion(t *testing.T) {
	saved := os.Args
	os.Args = []string{"x", "__complete"}
	defer func() { os.Args = saved }()
	root, _ := cmdFor()
	root.SetArgs(strings.Fields("s --file a --file a"))
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
}
