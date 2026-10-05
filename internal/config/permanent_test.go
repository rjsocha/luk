package config

import (
	"strings"
	"testing"
)

// withPermanent adds the permanent block p (YAML flow or block lines
// indented under the key) to the endpoint drop of good.
func withPermanent(p string) string {
	const drop = "    storage: drop\n"
	return strings.Replace(good, drop, drop+"    permanent:\n"+p, 1)
}

const permanentNames = `      names:
        revocation/hosts.krl: {allow: [robert.socha]}
        builds/*: {allow: ["hosts:*"], max: 50}
        "builds/release-*": {allow: [robert.socha]}
`

func TestPermanentConfig(t *testing.T) {
	c, err := Parse([]byte(withPermanent(permanentNames)))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Endpoint["drop"].Permanent
	if p.Path != DefaultPermanentPath {
		t.Fatalf("path %q", p.Path)
	}
	if got := c.Storage["drop"].Permanents(); len(got) != 1 || got["drop"] != p {
		t.Fatalf("storage permanents %v", got)
	}
	for name, want := range map[string]string{
		"revocation/hosts.krl": "revocation/hosts.krl",
		"builds/x":             "builds/*",
		"builds/release-1":     "builds/release-*",
		"builds/release-":      "builds/release-*",
	} {
		key, _, ok := p.Entry(name)
		if !ok || key != want {
			t.Errorf("%s: %q %v, want %q", name, key, ok, want)
		}
	}
	for _, name := range []string{"builds/a/b", "builds", "revocation/other", "x"} {
		if key, _, ok := p.Entry(name); ok {
			t.Errorf("%s covered by %q", name, key)
		}
	}
	if e := p.Names["builds/*"]; e.MaxOf() != 50 {
		t.Fatalf("max %d", e.MaxOf())
	}
	if e := p.Names["builds/release-*"]; e.MaxOf() != DefaultPermanentMax {
		t.Fatalf("default max %d", e.MaxOf())
	}
	if c.Storage["archive"].Permanents() != nil {
		t.Fatal("archive has permanent names")
	}
	c, err = Parse([]byte(withPermanent("      path: pub/latest\n" + permanentNames)))
	if err != nil || c.Endpoint["drop"].Permanent.Path != "pub/latest" {
		t.Fatalf("path: %v", err)
	}
}

func TestPermanentPrecedenceTie(t *testing.T) {
	p := &Permanent{Names: map[string]*PermanentName{
		"a/*x": {}, "a/x*": {}, "a/*": {}, "a/xx": {}, `a/\*`: {}, "a/[xy]x": {},
	}}
	for name, want := range map[string]string{
		"a/xx": "a/xx", // exact first
		"a/xy": "a/x*", // one literal more than a/*
		"a/yx": "a/*x", // a/*x and a/[xy]x both have 3 literals: the first by sort
		"a/*":  `a/\*`, // an escaped * is a literal
		"a/zz": "a/*",  // only a/*
		"a/x":  "a/*x", // a/*x, a/x* (3 literals): a/*x sorts first
	} {
		if key, _, ok := p.Entry(name); !ok || key != want {
			t.Errorf("%s: %q, want %q", name, key, want)
		}
	}
}

func TestPermanentConfigErrors(t *testing.T) {
	for p, msg := range map[string]string{
		"      names: {}\n":                                     "permanent.names is empty",
		"      names: {x: {max: 1}}\n":                          `permanent.names "x": allow is required`,
		"      names: {x: {allow: [nobody]}}\n":                 `permanent.names "x": allow: allow "nobody" is not a known key`,
		"      names: {x: {allow: true}}\n":                     "a list of identities",
		"      names: {x: {allow: ['*'], keep: 1}}\n":           "field keep not found",
		"      names: {x: {allow: ['*'], max: 2}}\n":            "max applies to patterns only",
		"      names: {'x/*': {allow: ['*'], max: 0}}\n":        "max must be at least 1",
		"      names: {'x/../y': {allow: ['*']}}\n":             `element ".." is not a name`,
		"      names: {'/x': {allow: ['*']}}\n":                 "is absolute",
		"      names: {'x//y': {allow: ['*']}}\n":               "empty element",
		"      names: {'x/current': {allow: ['*']}}\n":          `element "current" is reserved`,
		"      names: {'x/[': {allow: ['*']}}\n":                "bad pattern",
		"      names: {'x/*/..': {allow: ['*']}}\n":             "is not a name",
		"      names: {x: {allow: ['*'], other: 1}}\n":          "field other not found",
		"      path: ../x\n      names: {x: {allow: ['*']}}\n":  "permanent.path",
		"      path: 'a/*'\n      names: {x: {allow: ['*']}}\n": "without wildcards",
		"      size: 1\n      names: {x: {allow: ['*']}}\n":     "field size not found",
	} {
		if _, err := Parse([]byte(withPermanent(p))); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%q: %v, want %q", p, err, msg)
		}
	}
	// respond accept
	src := strings.Replace(good, "    limits: {body: {size: 50G}}\n", "    limits: {body: {size: 50G}}\n    permanent: {names: {x: {allow: ['*']}}}\n", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "endpoint backup: permanent needs respond url") {
		t.Errorf("accept: %v", err)
	}
	// an expose with auth.ssh
	src = strings.Replace(withPermanent(permanentNames), "    path: /d/\n", "    path: /d/\n    auth: {ssh: {allow: ['*']}}\n", 1)
	src = strings.Replace(src, "    addr: 127.0.0.1:8443\n", "    addr: 127.0.0.1:8443\n    public: https://lukd.vm:8443\n", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "permanent needs an expose without auth.ssh") {
		t.Errorf("auth.ssh: %v", err)
	}
	// a nested expose under the path
	src = withPermanent(permanentNames) + "  nested:\n    listen: main\n    path: /d/permanent/x/\n"
	src = strings.Replace(src, "storage:\n", "storage:\n  nested: {type: local, base: /storage/nested, path: \"{{ .Random }}\", expose: nested}\n", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "permanent.path permanent overlaps the nested expose under permanent/x/") {
		t.Errorf("nested: %v", err)
	}
}

// TestPermanentPathPerStorage: two endpoints storing into one storage
// need permanent.paths apart.
func TestPermanentPathPerStorage(t *testing.T) {
	second := `  drop2:
    listen: [main]
    endpoint: /drop2
    path: /queue/drop
    allow: [robert.socha]
    respond: url
    storage: drop
    permanent:
      path: %s
      names: {x: {allow: ['*']}}
pipeline:
  drop2:
    endpoint: [drop2]
    steps:
      - store: drop
`
	base := withPermanent(permanentNames)
	for path, msg := range map[string]string{
		"permanent":   "endpoint drop and drop2: the same permanent.path permanent on storage drop",
		"permanent/x": "endpoint drop and drop2: permanent.path permanent and permanent/x nest on storage drop",
		"other":       "",
	} {
		src := strings.Replace(base, "pipeline:\n", strings.Replace(second, "%s", path, 1), 1)
		_, err := Parse([]byte(src))
		switch {
		case msg == "" && err != nil:
			t.Errorf("%s: %v", path, err)
		case msg != "" && (err == nil || !strings.Contains(err.Error(), msg)):
			t.Errorf("%s: %v, want %q", path, err, msg)
		}
	}
}

func TestPermanentWarnings(t *testing.T) {
	c, err := Parse([]byte(withPermanent("      names:\n        'a/*x': {allow: ['*']}\n        'a/x*': {allow: ['*']}\n        'b/*': {allow: ['*']}\n        'c/*': {allow: ['*']}\n")))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, w := range c.Warnings() {
		if strings.Contains(w, "permanent") {
			got = append(got, w)
		}
	}
	if len(got) != 1 || !strings.Contains(got[0], `"a/*x" and "a/x*" may cover the same names`) {
		t.Fatalf("warnings %q", got)
	}
}

func TestPermanentOverlap(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"x", "x", true}, {"x", "y", false}, {"b/*", "b/x", true}, {"b/x", "b/*", true},
		{"b/*", "c/*", false}, {"a/*", "*/b", true}, {"a/x*", "a/xy*", true}, {"a/x*", "a/y*", false}, {"a/*x", "a/x*", true}, {"a/*", "a/*/b", false},
		{"a/x?", "a/xy", true},
	} {
		if got := PermanentOverlap(c.a, c.b); got != c.want {
			t.Errorf("%s %s: %v", c.a, c.b, got)
		}
	}
}
