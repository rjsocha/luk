package main

import (
	"encoding/json"
	"strings"
	"testing"

	"luk/internal/wire"
)

// lines splits the output into its non-empty lines.
func lines(out string) []string {
	var l []string
	for _, s := range strings.Split(out, "\n") {
		if s != "" {
			l = append(l, s)
		}
	}
	return l
}

func distinct(urls []string) bool {
	seen := map[string]bool{}
	for _, u := range urls {
		if seen[u] {
			return false
		}
		seen[u] = true
	}
	return true
}

func TestSendLinksOnce(t *testing.T) {
	e := newLukdEnv(t)
	out := mustRun(t, "send", "-e", "drop", "-k", e.key, "--links", "3", "--once", "--file", namedFile(t, "a.txt", "one body"))
	urls := lines(out)
	if len(urls) != 3 || !distinct(urls) {
		t.Fatalf("urls %q", out)
	}
	for _, u := range urls {
		waitContent(t, u, "one body")
		if code, _ := httpGet(t, u); code != 404 {
			t.Fatalf("%s: second download %d", u, code)
		}
	}
	if a, d := e.logs.count("upload accepted"), e.logs.count("upload deduplicated"); a != 1 || d != 2 {
		t.Fatalf("%d bodies received, %d deduplicated", a, d)
	}
}

func TestSendLinksStdin(t *testing.T) {
	e := newLukdEnv(t)
	defer stdinFrom(t, "streamed once")()
	code, out, errs := runLuk(t, "send", "-e", "drop", "-k", e.key, "--links", "3", "--stdin", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var answers []wire.Receipt
	if err := json.Unmarshal([]byte(out), &answers); err != nil || len(answers) != 3 {
		t.Fatalf("json %q: %v", out, err)
	}
	var urls []string
	for i, a := range answers {
		if a.Deduplicated != (i > 0) || a.Size != 13 {
			t.Fatalf("answer %d %+v", i, a)
		}
		urls = append(urls, a.URL)
	}
	if !distinct(urls) {
		t.Fatalf("urls %v", urls)
	}
	for _, u := range urls {
		waitContent(t, u, "streamed once")
	}
	if a, d := e.logs.count("upload accepted"), e.logs.count("upload deduplicated"); a != 1 || d != 2 {
		t.Fatalf("%d bodies received, %d deduplicated", a, d)
	}
}

func TestSendLinksFileResent(t *testing.T) {
	e := newSendEnv(t)
	e.url = true
	file := namedFile(t, "r.txt", "resend me")
	code, out, errs := runLuk(t, "send", "-e", "t", "-k", e.key, "--links", "2", "--file", file)
	if code != 0 || len(lines(out)) != 2 {
		t.Fatalf("exit %d: %q %s", code, out, errs)
	}
	if string(e.body) != "resend me" || e.meta.Size == nil || *e.meta.Size != 9 || e.meta.Source != wire.SourceFile {
		t.Fatalf("second request: body %q meta %+v", e.body, e.meta)
	}
}

func TestSendLinksStreamWanted(t *testing.T) {
	e := newSendEnv(t)
	e.url = true
	defer stdinFrom(t, "only once")()
	code, out, errs := runLuk(t, "send", "-e", "t", "-k", e.key, "--links", "3", "--stdin")
	if code != 3 || len(lines(out)) != 1 || !strings.Contains(errs, "1 of 3 links made") {
		t.Fatalf("exit %d: %q %q", code, out, errs)
	}
	// The repeat carried what the first answer said.
	if e.meta.Source != wire.SourceStdin || e.meta.Size == nil || *e.meta.Size != 9 || e.meta.SHA256 == "" {
		t.Fatalf("repeat meta %+v", e.meta)
	}
}

func TestSendLinksJSONOnError(t *testing.T) {
	e := newSendEnv(t)
	e.url = true
	defer stdinFrom(t, "only once")()
	code, out, _ := runLuk(t, "send", "-e", "t", "-k", e.key, "--links", "2", "--stdin", "--json")
	var answers []wire.Receipt
	if code != 3 || json.Unmarshal([]byte(out), &answers) != nil || len(answers) != 1 {
		t.Fatalf("exit %d: %q", code, out)
	}
}

func TestSendLinksUsage(t *testing.T) {
	e := newSendEnv(t)
	file := namedFile(t, "u.txt", "x")
	for _, args := range [][]string{
		{"--links", "0"},
		{"--links", "-1"},
		{"--links", "2", "--dry-run"},
		{"--links", "1", "--dry-run"},
	} {
		code, _, errs := runLuk(t, append([]string{"send", "-e", "t", "-k", e.key, "--file", file}, args...)...)
		if code != 1 || !strings.Contains(errs, "--links") {
			t.Errorf("%v: exit %d %q", args, code, errs)
		}
	}
	// The default is one upload, printed as an object with --json.
	code, out, errs := runLuk(t, "send", "-e", "t", "-k", e.key, "--file", file, "--json")
	if code != 0 || !strings.HasPrefix(out, "{") {
		t.Fatalf("exit %d: %q %s", code, out, errs)
	}
}

func TestSendLinksAlias(t *testing.T) {
	e := newSendEnv(t)
	e.url = true
	mustRun(t, "alias", "add", "--alias", "three", "--", "send", "-e", "t", "--links", "3")
	file := namedFile(t, "a.txt", "aliased")
	if code, out, errs := runLuk(t, "three", "-k", e.key, "--file", file); code != 0 || len(lines(out)) != 3 {
		t.Fatalf("alias: exit %d %q %s", code, out, errs)
	}
	if code, out, errs := runLuk(t, "three", "-k", e.key, "--file", file, "--links", "2"); code != 0 || len(lines(out)) != 2 {
		t.Fatalf("override: exit %d %q %s", code, out, errs)
	}
}

func TestSendLinksMax(t *testing.T) {
	file := namedFile(t, "a.txt", "x")
	code, _, errs := runLuk(t, "send", "-e", "t", "-k", newSendEnv(t).key, "--file", file, "--links", "26")
	if code != 1 || !strings.Contains(errs, "--links is at most 25") {
		t.Fatalf("exit %d %q", code, errs)
	}
}

func TestSendLinksLimitReached(t *testing.T) {
	e := newLukdEnvTTL(t, "{user: true, max: 7d}, links: {max: 2}")
	code, out, errs := runLuk(t, "send", "-e", "drop", "-k", e.key, "--links", "3", "--file", namedFile(t, "a.txt", "limited"))
	if code != 2 || len(lines(out)) != 2 || !strings.Contains(errs, "rejected (429 Too Many Requests): limit of 2 links to the same content reached; 2 of 3 links made") {
		t.Fatalf("exit %d: %q %q", code, out, errs)
	}
	for _, u := range lines(out) {
		waitContent(t, u, "limited")
	}
}
