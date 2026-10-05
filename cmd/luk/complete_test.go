package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// complete runs a completion request and returns its candidates and the
// directive line.
func complete(t *testing.T, args ...string) ([]string, string) {
	t.Helper()
	code, out, errs := runLuk(t, append([]string{cobra.ShellCompRequestCmd}, args...)...)
	if code != 0 || strings.Contains(errs, "luk:") {
		t.Fatalf("%v: exit %d: %s", args, code, errs)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	return lines[:len(lines)-1], lines[len(lines)-1]
}

func wantCompletion(t *testing.T, args []string, want []string, directive string) {
	t.Helper()
	got, dir := complete(t, args...)
	if !slices.Equal(got, want) || dir != directive {
		t.Errorf("%v: got %q %s, want %q %s", args, got, dir, want, directive)
	}
}

func TestCompleteEndpoint(t *testing.T) {
	twoLayers(t)
	all := []string{"alpha\thttp://u.example/alpha", "shared\thttps://u.example/shared", "zeta\thttps://g.example/zeta"}
	for _, args := range [][]string{
		{"send", "--endpoint", ""},
		{"put", "-e", ""},
		{"scan", ""},
		{"config", "default", "--endpoint", ""},
		{"config", "endpoint", "rm", "-e", ""},
		{"config", "endpoint", "key", "-e", ""},
		{"config", "endpoint", "rm", "--endpoint", ""},
		{"config", "endpoint", "show", "-e", ""},
		{"config", "endpoint", "add", "-e", ""},
	} {
		wantCompletion(t, args, all, ":4")
	}
	wantCompletion(t, []string{"send", "-e", "s"}, all[1:2], ":4")
	for _, args := range [][]string{
		{"config", "endpoint", "add", "--url", ""},
		{"config", "endpoint", "add", "--pin", ""},
	} {
		wantCompletion(t, args, nil, ":4")
	}
}

func TestCompleteEndpointBrokenConfig(t *testing.T) {
	up := tempConfig(t)
	writeCfg(t, up, "endpoint: [\n")
	wantCompletion(t, []string{"send", "-e", ""}, nil, ":4")
	wantCompletion(t, []string{"config", "endpoint", "rm", "-e", ""}, nil, ":4")
	wantCompletion(t, []string{"alias", "rm", "--alias", ""}, nil, ":4")
}

func TestCompleteKey(t *testing.T) {
	tempConfig(t)
	for _, args := range [][]string{
		{"send", "--key", ""},
		{"config", "key", "-k", ""},
	} {
		wantCompletion(t, args, nil, ":0")
	}
	fps := agentWithKeys(t, 2)
	want := []string{fps[0] + "\tkey0 ssh-ed25519", fps[1] + "\tkey1 ssh-ed25519"}
	for _, args := range [][]string{
		{"send", "--key", ""},
		{"send", "-k", "SHA"},
		{"config", "key", "--key", ""},
		{"config", "endpoint", "add", "-k", ""},
		{"config", "endpoint", "key", "-e", "x", "-k", ""},
	} {
		wantCompletion(t, args, want, ":0")
	}
	wantCompletion(t, []string{"send", "-k", fps[1][:12]}, want[1:], ":0")
	wantCompletion(t, []string{"send", "-k", "~/.ssh/"}, nil, ":0")
}

func TestCompleteAliasName(t *testing.T) {
	tempConfig(t)
	mustRun(t, "alias", "add", "--alias", "drop", "--", "send", "--endpoint", "drop")
	mustRun(t, "alias", "add", "--global", "--alias", "pd", "--", "scan", "-k", "x y")
	wantCompletion(t, []string{"alias", "rm", "--alias", ""}, []string{"drop\tsend --endpoint drop", "pd\tscan -k 'x y'"}, ":4")
	wantCompletion(t, []string{"alias", "rm", "--alias", "p"}, []string{"pd\tscan -k 'x y'"}, ":4")
	wantCompletion(t, []string{"alias", "add", "--alias", ""}, nil, ":4")
}

func TestCompleteFixedAndFree(t *testing.T) {
	tempConfig(t)
	ttl := []string{"max", "1h", "1d", "7d"}
	layer := []string{"global", "user"}
	pinFormat := []string{"words", "key"}
	for _, c := range []struct {
		args      []string
		want      []string
		directive string
	}{
		{[]string{"send", "--ttl", ""}, ttl, ":4"},
		{[]string{"send", "--type", ""}, nil, ":4"},
		{[]string{"send", "-t", ""}, nil, ":4"},
		{[]string{"send", "--tag", ""}, nil, ":4"},
		{[]string{"send", "--name", ""}, nil, ":4"},
		{[]string{"send", "--bwlimit", ""}, nil, ":4"},
		{[]string{"send", "--file", ""}, nil, ":0"},
		{[]string{"send", "-f", ""}, nil, ":0"},
		{[]string{"config", "check", "--file", ""}, nil, ":0"},
		{[]string{"config", "show", "--layer", ""}, layer, ":4"},
		{[]string{"config", "endpoint", "ls", "--layer", ""}, layer, ":4"},
		{[]string{"config", "endpoint", "ls", "--pin-format", ""}, pinFormat, ":4"},
		{[]string{"scan", "--pin-format", ""}, pinFormat, ":4"},
		{[]string{"send", "--parallel", ""}, nil, ":4"},
		{[]string{"get", "--parallel", ""}, nil, ":4"},
		{[]string{"config", "endpoint", "add", "--pin", ""}, nil, ":4"},
	} {
		wantCompletion(t, c.args, c.want, c.directive)
	}
}

func TestCompleteGetFlags(t *testing.T) {
	tempConfig(t)
	got, dir := complete(t, "get", "--")
	for _, f := range []string{"--remote-name", "--remote-header-name", "--parallel"} {
		if !slices.ContainsFunc(got, func(c string) bool { return strings.HasPrefix(c, f+"\t") }) {
			t.Errorf("get --: no %s in %q %s", f, got, dir)
		}
	}
	got, _ = complete(t, "get", "-")
	for _, f := range []string{"-O", "-J"} {
		if !slices.ContainsFunc(got, func(c string) bool { return strings.HasPrefix(c, f+"\t") }) {
			t.Errorf("get -: no %s in %q", f, got)
		}
	}
}

func TestCompleteThroughAlias(t *testing.T) {
	up := tempConfig(t)
	writeCfg(t, up, `endpoint:
  drop:
    url: https://u.example/drop
alias:
  drop: [send, --endpoint, drop]
  pd: [scan]
`)
	wantCompletion(t, []string{"drop", "--ttl", ""}, []string{"max", "1h", "1d", "7d"}, ":4")
	wantCompletion(t, []string{"drop", "--type", ""}, nil, ":4")
	wantCompletion(t, []string{"pd", ""}, []string{"drop\thttps://u.example/drop"}, ":4")
	wantCompletion(t, []string{"drop", "--key", ""}, nil, ":0")
	fps := agentWithKeys(t, 1)
	wantCompletion(t, []string{"drop", "--key", ""}, []string{fps[0] + "\tkey0 ssh-ed25519"}, ":0")
}

// TestEveryValueFlagCompletes keeps new flags that take a value from
// silently falling back to file completion.
func TestEveryValueFlagCompletes(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.NoOptDefVal != "" {
				return
			}
			if _, ok := c.GetFlagCompletionFunc(f.Name); !ok {
				t.Errorf("%s --%s: no completion", c.CommandPath(), f.Name)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRoot(nil, nil))
}
