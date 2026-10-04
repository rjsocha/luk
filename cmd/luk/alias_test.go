package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"luk/internal/client"
)

func TestAliasAddRmLsLayers(t *testing.T) {
	up := tempConfig(t)
	gp := globalConfig(t)
	mustRun(t, "alias", "add", "--global", "--alias", "drop", "--", "send", "--endpoint", "g")
	mustRun(t, "alias", "add", "--alias", "bk", "--", "put", "-e", "backup", "--name", "a b")
	g, _ := client.LoadConfig(gp)
	if !slices.Equal(g.Alias["drop"], []string{"send", "--endpoint", "g"}) || len(g.Alias) != 1 {
		t.Errorf("global %+v", g.Alias)
	}
	u, _ := client.LoadConfig(up)
	if !slices.Equal(u.Alias["bk"], []string{"put", "-e", "backup", "--name", "a b"}) || len(u.Alias) != 1 {
		t.Errorf("user %+v", u.Alias)
	}
	want := "bk    put -e backup --name 'a b'  user\ndrop  send --endpoint g           global\n"
	if out := mustRun(t, "alias", "ls"); out != want {
		t.Errorf("ls:\n%s", out)
	}
	mustRun(t, "alias", "add", "--alias", "drop", "--", "send", "--endpoint", "u")
	if out := mustRun(t, "alias", "ls"); !strings.Contains(out, "drop  send --endpoint u           user\n") {
		t.Errorf("user does not replace global:\n%s", out)
	}
	mustRun(t, "alias", "rm", "--alias", "drop")
	code, _, errs := runLuk(t, "alias", "rm", "--alias", "drop")
	if code != 1 || !strings.Contains(errs, "alias drop is defined in the global config; use --global") {
		t.Errorf("exit %d: %s", code, errs)
	}
	mustRun(t, "alias", "rm", "--alias", "drop", "--global")
	if code, _, errs := runLuk(t, "alias", "rm", "--alias", "nope"); code != 1 || !strings.Contains(errs, `unknown alias "nope"`) {
		t.Errorf("exit %d: %s", code, errs)
	}
	if out := mustRun(t, "alias", "ls"); out != "bk  put -e backup --name 'a b'  user\n" {
		t.Errorf("ls:\n%s", out)
	}
}

func TestAliasAddRejects(t *testing.T) {
	tempConfig(t)
	mustRun(t, "alias", "add", "--alias", "drop", "--", "send", "-e", "drop")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--alias", "put", "--", "send"}, "shadows the built-in command put"},
		{[]string{"--alias", "config", "--", "send"}, "shadows the built-in command config"},
		{[]string{"--alias", "completion", "--", "send"}, "shadows the built-in command completion"},
		{[]string{"--alias", "help", "--", "send"}, "shadows the built-in command help"},
		{[]string{"--alias", "x", "--", "drop", "-f", "a"}, `expansion must start with a built-in command, got "drop"`},
		{[]string{"--alias", "x", "--", "x"}, `expansion must start with a built-in command, got "x"`},
		{[]string{"--alias", "x", "--"}, "expansion is empty"},
		{[]string{"--alias", "x"}, "expansion is empty"},
		{[]string{"--alias", "x", "send"}, "the expansion goes after --"},
		{[]string{"--alias", "a b", "--", "send"}, "must not start with - or contain spaces"},
		{[]string{"--alias", "", "--", "send"}, "alias name is empty"},
	} {
		code, _, errs := runLuk(t, append([]string{"alias", "add"}, tc.args...)...)
		if code != 1 || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: exit %d, stderr %q", tc.args, code, errs)
		}
	}
}

func TestAliasExpansion(t *testing.T) {
	e := newSendEnv(t)
	mustRun(t, "alias", "add", "--alias", "drop", "--", "push", "-e", "t", "-k", e.key, "-q")
	defer stdinFrom(t, "payload")()
	code, out, errs := runLuk(t, "drop", "--stdin", "--name", "x.txt")
	if code != 0 || string(e.body) != "payload" || e.meta.File != "x.txt" || out != "abc\n" {
		t.Fatalf("exit %d out %q err %q body %q meta %+v", code, out, errs, e.body, e.meta)
	}
	code, _, errs = runLuk(t, "drop", "--stdin", "-q", "-q")
	if code != 1 || !strings.Contains(errs, "--quiet given more than once") {
		t.Errorf("repeated flag: exit %d: %s", code, errs)
	}
	code, _, errs = runLuk(t, "drop", "--stdin", "--endpoint", "t", "-e", "t")
	if code != 1 || !strings.Contains(errs, "--endpoint given more than once") {
		t.Errorf("repeated flag: exit %d: %s", code, errs)
	}
	if code, _, errs := runLuk(t, "drop", "--stdin", "--endpoint", "t", "--quiet"); code != 0 {
		t.Errorf("override: exit %d: %s", code, errs)
	}
	if code, _, errs := runLuk(t, "nope"); code != 1 || !strings.Contains(errs, `unknown command "nope"`) {
		t.Errorf("unknown: exit %d: %s", code, errs)
	}
}

func TestAliasOverride(t *testing.T) {
	root := newRoot(nil, nil)
	exp := []string{"send", "--endpoint", "drop", "--secret", "--ttl", "2d"}
	tags := []string{"send", "-t", "a", "--tag", "b", "-qe", "drop"}
	for _, tc := range []struct {
		exp, user, want []string
		completing      bool
	}{
		{exp, []string{"--ttl", "60m"}, []string{"send", "--endpoint", "drop", "--secret", "--ttl", "60m"}, false},
		{exp, []string{"-e", "other"}, []string{"send", "--secret", "--ttl", "2d", "-e", "other"}, false},
		{exp, []string{"--ttl=60m"}, []string{"send", "--endpoint", "drop", "--secret", "--ttl=60m"}, false},
		{exp, []string{"--secret=false"}, []string{"send", "--endpoint", "drop", "--ttl", "2d", "--secret=false"}, false},
		{exp, []string{"--nope", "--", "--ttl"}, slices.Concat(exp, []string{"--nope", "--", "--ttl"}), false},
		{tags, []string{"-t", "c"}, []string{"send", "-qe", "drop", "-t", "c"}, false},
		{tags, []string{"--endpoint=x"}, []string{"send", "-t", "a", "--tag", "b", "-q", "--endpoint=x"}, false},
		{tags, []string{"-q"}, []string{"send", "-t", "a", "--tag", "b", "-e", "drop", "-q"}, false},
		{exp, []string{"--tt"}, []string{"send", "--tt"}, true},
		{exp, []string{"--ttl", ""}, []string{"send", "--ttl", ""}, true},
		{[]string{"config", "--global", "show"}, nil, []string{"config", "show"}, true},
		{[]string{"send", "-q", "--", "-x"}, nil, []string{"send", "--", "-x"}, true},
	} {
		if got := overrideAlias(root, tc.exp, tc.user, tc.completing); !slices.Equal(got, tc.want) {
			t.Errorf("%v %v: got %q, want %q", tc.exp, tc.user, got, tc.want)
		}
	}
}

func TestAliasOverrideRun(t *testing.T) {
	e := newSendEnv(t)
	mustRun(t, "alias", "add", "--alias", "drop", "--", "send", "--endpoint", "t", "-k", e.key, "--secret", "--ttl", "2d", "-t", "a", "-t", "b")
	defer stdinFrom(t, "payload")()
	code, _, errs := runLuk(t, "drop", "--stdin", "--ttl", "60m", "--secret=false", "--tag", "c")
	if code != 0 || e.meta.TTL != "60m" || e.meta.Portal != "direct" || !slices.Equal(e.meta.Tags, []string{"c"}) {
		t.Fatalf("exit %d err %q meta %+v", code, errs, e.meta)
	}
	code, _, errs = runLuk(t, "drop", "--stdin", "--portal")
	if code != 1 || !strings.Contains(errs, "--portal and --secret are mutually exclusive") {
		t.Errorf("exclusive: exit %d: %s", code, errs)
	}
	code, _, errs = runLuk(t, "drop", "--stdin", "--ttl", "1h", "--ttl", "2h")
	if code != 1 || !strings.Contains(errs, "--ttl given more than once") {
		t.Errorf("repeated: exit %d: %s", code, errs)
	}
}

func TestAliasRepeatedFlag(t *testing.T) {
	up := tempConfig(t)
	code, _, errs := runLuk(t, "alias", "add", "--alias", "x", "--", "send", "--ttl", "1h", "--ttl", "2h")
	if code != 1 || !strings.Contains(errs, `alias "x": --ttl given more than once`) {
		t.Errorf("add: exit %d: %s", code, errs)
	}
	mustRun(t, "alias", "add", "--alias", "tags", "--", "send", "-t", "a", "--tag", "b")
	writeCfg(t, up, "alias:\n  x: [send, --ttl, 1h, --ttl, 2h]\n  y: [send, -e, a, --endpoint, b]\n  tags: [send, -t, a, --tag, b]\n")
	code, _, errs = runLuk(t, "config", "check")
	for _, w := range []string{`alias "x": --ttl given more than once`, `alias "y": --endpoint given more than once`} {
		if code != 1 || !strings.Contains(errs, w) {
			t.Errorf("check lacks %q: exit %d: %s", w, code, errs)
		}
	}
	if strings.Contains(errs, `alias "tags"`) {
		t.Errorf("repeatable flag reported: %s", errs)
	}
	code, _, errs = runLuk(t, "x", "--stdin", "--ttl", "3h")
	if code != 1 || !strings.Contains(errs, `alias "x": --ttl given more than once`) {
		t.Errorf("run: exit %d: %s", code, errs)
	}
}

func TestAliasInvalidAtLoad(t *testing.T) {
	up := tempConfig(t)
	writeCfg(t, up, "alias:\n  a: [b]\n  b: [send]\n  put: [send]\n  e: []\n")
	for _, tc := range []struct{ word, want string }{
		{"a", `expansion must start with a built-in command, got "b"`},
		{"e", "expansion is empty"},
	} {
		if code, _, errs := runLuk(t, tc.word); code != 1 || !strings.Contains(errs, tc.want) {
			t.Errorf("%s: exit %d: %s", tc.word, code, errs)
		}
	}
	code, _, errs := runLuk(t, "config", "check")
	for _, w := range []string{`alias "a": expansion must start`, `alias "e": expansion is empty`, `alias "put": shadows the built-in command put`} {
		if code != 1 || !strings.Contains(errs, up+": "+w) {
			t.Errorf("check lacks %q: exit %d: %s", w, code, errs)
		}
	}
	if strings.Contains(errs, `alias "b"`) {
		t.Errorf("valid alias reported: %s", errs)
	}
	code, _, errs = runLuk(t, "config", "check", "--file", up)
	if code != 1 || !strings.Contains(errs, `alias "put": shadows`) {
		t.Errorf("check --file: exit %d: %s", code, errs)
	}
}

func TestBrokenConfigKeepsBuiltins(t *testing.T) {
	up := tempConfig(t)
	writeCfg(t, up, "alias: [\n")
	code, out, errs := runLuk(t, "config", "check")
	if code != 1 || !strings.Contains(errs, up) || out != "" {
		t.Errorf("check: exit %d out %q err %q", code, out, errs)
	}
	for _, args := range [][]string{{"version"}, {"--help"}, {}, {"alias", "--help"}} {
		if code, _, errs := runLuk(t, args...); code != 0 {
			t.Errorf("%v: exit %d: %s", args, code, errs)
		}
	}
	if code, _, errs := runLuk(t, "drop"); code != 1 || !strings.Contains(errs, `"drop" is not a command and the aliases cannot be read`) {
		t.Errorf("drop: exit %d: %s", code, errs)
	}
	if code, out, _ := runLuk(t, "__complete", "d"); code != 0 || !strings.Contains(out, ":4") {
		t.Errorf("complete: exit %d: %s", code, out)
	}
}

func TestHelpListsAliases(t *testing.T) {
	tempConfig(t)
	mustRun(t, "alias", "add", "--alias", "drop", "--", "send", "--endpoint", "drop")
	mustRun(t, "alias", "add", "--global", "--alias", "longer", "--", "scan", "-k", "x y")
	out := mustRun(t, "--help")
	want := "\n\nAliases:\n  drop        send --endpoint drop\n  longer      scan -k 'x y'\n\nFlags:"
	if !strings.Contains(out, want) {
		t.Errorf("help:\n%s", out)
	}
	if strings.Index(out, "Available Commands:") > strings.Index(out, "Aliases:") {
		t.Errorf("aliases before commands:\n%s", out)
	}
	if out := mustRun(t, "send", "--help"); strings.Contains(out, "longer") {
		t.Errorf("subcommand help lists aliases:\n%s", out)
	}
}

func TestAliasCompletion(t *testing.T) {
	tempConfig(t)
	mustRun(t, "alias", "add", "--alias", "drop", "--", "send", "--endpoint", "drop")
	out := mustRun(t, "__complete", "dr")
	if !strings.Contains(out, "drop\tsend --endpoint drop\n") {
		t.Errorf("alias name:\n%s", out)
	}
	out = mustRun(t, "__complete", "")
	for _, w := range []string{"drop\t", "send\t", "config\t"} {
		if !strings.Contains(out, w) {
			t.Errorf("first word lacks %q:\n%s", w, out)
		}
	}
	mustRun(t, "alias", "add", "--alias", "secret", "--", "send", "--secret", "--ttl", "2d")
	out = mustRun(t, "__complete", "drop", "--")
	if !strings.Contains(out, "--file\t") || !strings.Contains(out, "--stdin\t") || !strings.Contains(out, "--endpoint\t") {
		t.Errorf("flags through alias:\n%s", out)
	}
	out = mustRun(t, "__complete", "secret", "--tt")
	if !strings.Contains(out, "--ttl\t") {
		t.Errorf("alias flag not offered:\n%s", out)
	}
	out = mustRun(t, "__complete", "secret", "--ttl", "1h", "--")
	if strings.Contains(out, "--ttl\t") || !strings.Contains(out, "--secret\t") {
		t.Errorf("user flag offered:\n%s", out)
	}
	want := mustRun(t, "__complete", "send", "--ttl", "")
	if out := mustRun(t, "__complete", "secret", "--ttl", ""); out != want || !strings.Contains(out, "7d\n") {
		t.Errorf("ttl values:\n%s\nwant:\n%s", out, want)
	}
	out = mustRun(t, "__completeNoDesc", "drop", "--st")
	if !strings.Contains(out, "--stdin\n") {
		t.Errorf("no desc:\n%s", out)
	}
}

func TestAliasExampleConfig(t *testing.T) {
	tempConfig(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "luk.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.ParseConfig("luk.example.yaml", data)
	if err != nil || len(c.Alias) == 0 {
		t.Fatalf("%v %+v", err, c)
	}
	root := newRoot(nil, nil)
	if err := client.ValidateAliases(c, builtinOf(root), aliasFlagCheck(root)); err != nil {
		t.Error(err)
	}
}
