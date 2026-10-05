package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func complete(t *testing.T, args ...string) []string {
	t.Helper()
	// As the shell calls it: the flag guard is off for a completion.
	saved := os.Args
	os.Args = []string{"lukd", "__complete"}
	defer func() { os.Args = saved }()
	var out bytes.Buffer
	cmd := rootCmd()
	cmd.SetArgs(append([]string{"__complete"}, args...))
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !strings.HasPrefix(l, ":") {
			got = append(got, l)
		}
	}
	return got
}

func TestCompleteFlags(t *testing.T) {
	cfgPath, _ := storageConfig(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"storage", "ls", "-c", cfgPath, "--storage", ""}, "drop,plain"},
		{[]string{"storage", "rm", "-c", cfgPath, "--storage", "p"}, "plain"},
		{[]string{"storage", "retention", "-c", cfgPath, "--storage", ""}, "drop,plain"},
		{[]string{"storage", "ls", "-c", cfgPath, "--owner", ""}, "robert.socha"},
		{[]string{"quota", "ls", "-c", cfgPath, "--endpoint", ""}, "drop"},
		{[]string{"tls", "acme", "revoke", "-c", cfgPath, "--reason", "key"}, "keyCompromise"},
		{[]string{"storage", "ls", "-c", "/nonexistent.yaml", "--storage", ""}, ""},
		{[]string{"key", "-c", cfgPath, "--pin-format", ""}, "words,key"},
		{[]string{"key", "-c", cfgPath, ""}, "generate\tCreate the identity key and print its pin"},
	} {
		if got := strings.Join(complete(t, c.args...), ","); got != c.want {
			t.Errorf("%v: %q, want %q", c.args, got, c.want)
		}
	}
}
