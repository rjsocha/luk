package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodPin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tmp.abc123")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckFile(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(bad, []byte("bogus: 1\n"), 0o600)
	t.Setenv("LUK_CONFIG", bad)
	t.Setenv("LUK_GLOBAL_CONFIG", bad)
	t.Setenv("SSH_AUTH_SOCK", "")
	existing := writeFile(t, "")
	ep := func(url, pin string) string {
		s := "endpoint:\n  a:\n    url: " + url + "\n"
		if pin != "" {
			s += "    pin: " + pin + "\n"
		}
		return s
	}
	cases := []struct {
		name, body, want string
	}{
		{"valid", "default: a\nkey: " + existing + "\n" + ep("https://h:1/x", goodPin), ""},
		{"empty", "", ""},
		{"unknown key", "bogus: 1\n", "bogus"},
		{"bad url", ep("ftp://h/x", ""), "invalid URL"},
		{"no host", ep("https:///x", ""), "invalid URL"},
		{"fragment", ep("https://h/x#"+goodPin, ""), "fragment"},
		{"pin http", ep("http://h/x", goodPin), "https"},
		{"pin prefix", ep("https://h/x", "sha1//AAAA"), "sha256//"},
		{"pin base64", ep("https://h/x", "sha256//!!!"), "32 bytes"},
		{"pin length", ep("https://h/x", "sha256//AAAA"), "32 bytes"},
		{"default missing", "default: nope\n" + ep("http://h/x", ""), `default "nope"`},
		{"relative key", "key: k.pub\n", "absolute path"},
		{"fingerprint key", "key: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" + ep("http://h/x", "") + "    key: SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s\n", ""},
		{"bad fingerprint", "key: SHA256:AAAA\n", "not a fingerprint"},
		{"bad endpoint fingerprint", ep("http://h/x", "") + "    key: SHA256:AAAA\n", `endpoint "a": key`},
		{"relative endpoint key", ep("http://h/x", "") + "    key: k.pub\n", "absolute path"},
	}
	for _, c := range cases {
		code, out, errs := runLuk(t, "config", "check", "--file", writeFile(t, c.body))
		if c.want == "" {
			if code != 0 || out != "ok\n" || errs != "" {
				t.Errorf("%s: exit %d out %q err %q", c.name, code, out, errs)
			}
		} else if code != 1 || !strings.Contains(errs, c.want) {
			t.Errorf("%s: exit %d err %q", c.name, code, errs)
		}
	}
}

func TestCheckFileListsEveryProblem(t *testing.T) {
	body := "default: x\nkey: rel\nendpoint:\n  a:\n    url: ftp://h\n"
	code, _, errs := runLuk(t, "config", "check", "--file", writeFile(t, body))
	if code != 1 || len(strings.Split(strings.TrimSpace(errs), "\n")) != 3 {
		t.Errorf("exit %d err %q", code, errs)
	}
}

func TestCheckFileMissingKeyWarns(t *testing.T) {
	code, out, errs := runLuk(t, "config", "check", "--file", writeFile(t, "key: /nonexistent/k.pub\n"))
	if code != 0 || out != "ok\n" || !strings.Contains(errs, "warning") || !strings.Contains(errs, "/nonexistent/k.pub") {
		t.Errorf("exit %d out %q err %q", code, out, errs)
	}
}

func TestCheckFileMissingEndpointKeyWarns(t *testing.T) {
	body := "endpoint:\n  a:\n    url: http://h/x\n    key: /nonexistent/a.pub\n"
	code, out, errs := runLuk(t, "config", "check", "--file", writeFile(t, body))
	if code != 0 || out != "ok\n" || !strings.Contains(errs, "warning") || !strings.Contains(errs, "/nonexistent/a.pub") {
		t.Errorf("exit %d out %q err %q", code, out, errs)
	}
}

func TestCheckFileMissingFile(t *testing.T) {
	code, _, _ := runLuk(t, "config", "check", "--file", filepath.Join(t.TempDir(), "none"))
	if code != 1 {
		t.Errorf("exit %d", code)
	}
}

func TestCheckLayers(t *testing.T) {
	up := tempConfig(t)
	gp := os.Getenv("LUK_GLOBAL_CONFIG")
	os.MkdirAll(filepath.Dir(gp), 0o755)
	os.MkdirAll(filepath.Dir(up), 0o755)
	os.WriteFile(gp, []byte("endpoint:\n  g:\n    url: http://g/x\n"), 0o644)
	os.WriteFile(up, []byte("default: g\n"), 0o600)
	code, out, errs := runLuk(t, "config", "check")
	if code != 0 || !strings.Contains(out, "checked "+gp) || !strings.Contains(out, "checked "+up) || !strings.HasSuffix(out, "ok\n") {
		t.Errorf("exit %d out %q err %q", code, out, errs)
	}
	os.WriteFile(up, []byte("default: nope\nkey: rel\n"), 0o600)
	code, _, errs = runLuk(t, "config", "check")
	if code != 1 || !strings.Contains(errs, up+": key") || !strings.Contains(errs, `default "nope"`) {
		t.Errorf("exit %d err %q", code, errs)
	}
}

func TestEndpointAddSplitsPinFragment(t *testing.T) {
	up := tempConfig(t)
	other := "sha256//BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	for i, frag := range []string{"#" + goodPin, "#pin=" + goodPin} {
		name := string(rune('a' + i))
		mustRun(t, "config", "endpoint", "add", "-e", name, "--url", "https://h:8443/x"+frag)
	}
	mustRun(t, "config", "endpoint", "add", "-e", "c", "--url", "https://h/x#"+goodPin, "--pin", goodPin)
	data, _ := os.ReadFile(up)
	if strings.Contains(string(data), "#") || strings.Count(string(data), "pin: "+goodPin) != 3 {
		t.Fatalf("fragment stored:\n%s", data)
	}
	if code, _, errs := runLuk(t, "config", "check", "--file", up); code != 0 {
		t.Errorf("check: %d %q", code, errs)
	}
	for _, args := range [][]string{
		{"--url", "https://h/x#" + goodPin, "--pin", other},
		{"--endpoint", "https://h/x#frag"},
	} {
		code, _, errs := runLuk(t, append([]string{"config", "endpoint", "add", "-e", "z"}, args...)...)
		if code != 1 || errs == "" {
			t.Errorf("%v: exit %d %q", args, code, errs)
		}
	}
}
