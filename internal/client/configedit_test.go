package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveConfigCreatesAndRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "luk", "config.yaml")
	want := &Config{Default: "a", Key: "k.pub", Endpoint: map[string]EndpointConfig{
		"a": {URL: "https://h:1/x", Pin: "sha256//abc", Key: "SHA256:x"},
		"b": {URL: "http://h/y"},
	}}
	if err := SaveConfig(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Default != "a" || got.Key != "k.pub" || got.Endpoint["a"] != want.Endpoint["a"] || got.Endpoint["b"] != want.Endpoint["b"] {
		t.Fatalf("got %+v", got)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v", st.Mode().Perm())
	}
	st, _ = os.Stat(filepath.Dir(path))
	if st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("leftover files: %v", entries)
	}
}

func TestSaveConfigKeepsExistingMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("default: \"\"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfig(path, &Config{}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
}

func TestAddEndpoint(t *testing.T) {
	c := &Config{}
	bad := []struct{ name, url, pin string }{
		{"", "https://h/x", ""},
		{"a", "ftp://h/x", ""},
		{"a", "https:///x", ""},
		{"a", "h/x", ""},
		{"a", "http://h/x", "sha256//abc"},
		{"a", "https://h/x", "abc"},
	}
	for _, b := range bad {
		if err := c.AddEndpoint(b.name, b.url, b.pin, ""); err == nil {
			t.Errorf("%+v accepted", b)
		}
	}
	if len(c.Endpoint) != 0 {
		t.Fatalf("invalid input stored: %v", c.Endpoint)
	}
	if err := c.AddEndpoint("a", "https://h/x", "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.AddEndpoint("a", "http://h/y", "", ""); err != nil {
		t.Fatal(err)
	}
	if c.Endpoint["a"] != (EndpointConfig{URL: "http://h/y"}) {
		t.Errorf("not replaced: %+v", c.Endpoint["a"])
	}
}

func TestRemoveEndpointAndDefault(t *testing.T) {
	c := &Config{}
	_ = c.AddEndpoint("a", "http://h/a", "", "")
	_ = c.AddEndpoint("b", "http://h/b", "", "")
	if err := c.SetDefault("nope"); err == nil {
		t.Error("unknown default accepted")
	}
	if err := c.SetDefault("a"); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveEndpoint("nope"); err == nil {
		t.Error("unknown rm accepted")
	}
	if err := c.RemoveEndpoint("b"); err != nil || c.Default != "a" {
		t.Fatalf("rm b: %v default=%q", err, c.Default)
	}
	if err := c.RemoveEndpoint("a"); err != nil || c.Default != "" {
		t.Fatalf("rm a: %v default=%q", err, c.Default)
	}
}

func TestMerge(t *testing.T) {
	g := &Config{Default: "a", Key: "gk", Endpoint: map[string]EndpointConfig{
		"a":      {URL: "https://g/a", Pin: "sha256//g", Key: "/g/a.pub"},
		"only-g": {URL: "http://g/x"},
	}}
	u := &Config{Default: "b", Endpoint: map[string]EndpointConfig{
		"a": {URL: "http://u/a"},
		"b": {URL: "http://u/b"},
	}}
	m, src := Merge(g, u)
	if m.Default != "b" || src.Default != "user" {
		t.Errorf("default %q from %q", m.Default, src.Default)
	}
	if m.Key != "gk" || src.Key != "global" {
		t.Errorf("key %q from %q", m.Key, src.Key)
	}
	if m.Endpoint["a"] != (EndpointConfig{URL: "http://u/a"}) || src.Endpoint["a"] != "user" {
		t.Errorf("a: %+v from %q (pin and key must not leak from global)", m.Endpoint["a"], src.Endpoint["a"])
	}
	if src.Endpoint["only-g"] != "global" || src.Endpoint["b"] != "user" || len(m.Endpoint) != 3 {
		t.Errorf("endpoints %+v %+v", m.Endpoint, src.Endpoint)
	}
	m, src = Merge(&Config{}, &Config{Key: "uk"})
	if m.Key != "uk" || m.Default != "" || src.Default != "" {
		t.Errorf("empty global: %+v", m)
	}
}

func TestLoadMerged(t *testing.T) {
	dir := t.TempDir()
	gp, up := filepath.Join(dir, "g.yaml"), filepath.Join(dir, "u.yaml")
	t.Setenv("LUK_GLOBAL_CONFIG", gp)
	t.Setenv("LUK_CONFIG", up)
	m, _, err := LoadMerged()
	if err != nil || m.Default != "" || len(m.Endpoint) != 0 {
		t.Fatalf("both missing: %+v %v", m, err)
	}
	os.WriteFile(gp, []byte("default: a\nendpoint:\n  a:\n    url: http://g/a\n"), 0o644)
	if m, _, err = LoadMerged(); err != nil || m.Default != "a" {
		t.Fatalf("user missing: %+v %v", m, err)
	}
	os.WriteFile(up, []byte("bogus: 1\n"), 0o600)
	if _, _, err = LoadMerged(); err == nil || !strings.Contains(err.Error(), up) {
		t.Fatalf("malformed user: %v", err)
	}
	os.WriteFile(up, nil, 0o600)
	os.WriteFile(gp, []byte("bogus: 1\n"), 0o644)
	if _, _, err = LoadMerged(); err == nil || !strings.Contains(err.Error(), gp) {
		t.Fatalf("malformed global: %v", err)
	}
}

func TestSaveConfigModeNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "site", "luk", "config.yaml")
	if err := SaveConfigMode(path, &Config{}, 0o755, 0o644); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o644 {
		t.Errorf("file %v", st.Mode().Perm())
	}
	st, _ = os.Stat(filepath.Dir(path))
	if st.Mode().Perm() != 0o755 {
		t.Errorf("dir %v", st.Mode().Perm())
	}
}

const testFP = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestAddEndpointKey(t *testing.T) {
	c := &Config{}
	for _, k := range []string{"SHA256:short", "SHA256:" + strings.Repeat("!", 43), "rel.pub"} {
		if err := c.AddEndpoint("a", "http://h/x", "", k); err == nil {
			t.Errorf("key %q accepted", k)
		}
	}
	for _, k := range []string{testFP, "~/.ssh/id.pub", "/k/id"} {
		if err := c.AddEndpoint("a", "http://h/x", "", k); err != nil {
			t.Fatalf("key %q: %v", k, err)
		}
		if c.Endpoint["a"].Key != k {
			t.Errorf("stored %+v", c.Endpoint["a"])
		}
	}
}

func TestKeyFor(t *testing.T) {
	c := &Config{Default: "withkey", Key: "/global.pub", Endpoint: map[string]EndpointConfig{
		"withkey": {URL: "http://h/a", Key: testFP},
		"nokey":   {URL: "http://h/b"},
	}}
	cases := []struct{ endpoint, flag, want string }{
		{"withkey", "/flag", "/flag"},
		{"withkey", "", testFP},
		{"", "", testFP},
		{"nokey", "", "/global.pub"},
		{"http://h/a", "", "/global.pub"},
		{"http://h/a", "/flag", "/flag"},
		{"unknown", "", "/global.pub"},
	}
	for _, k := range cases {
		if got := c.KeyFor(k.endpoint, k.flag); got != k.want {
			t.Errorf("KeyFor(%q, %q) = %q, want %q", k.endpoint, k.flag, got, k.want)
		}
	}
	c.Key = ""
	if got := c.KeyFor("nokey", ""); got != "" {
		t.Errorf("no key anywhere: %q", got)
	}
}

func TestValidateConfigKeys(t *testing.T) {
	c := &Config{Key: "SHA256:bad", Endpoint: map[string]EndpointConfig{
		"a": {URL: "http://h/a", Key: "SHA256:alsobad"},
		"b": {URL: "http://h/b", Key: testFP},
	}}
	err := ValidateConfig(c, UserLayer)
	if err == nil || !strings.Contains(err.Error(), `endpoint "a": key`) || !strings.Contains(err.Error(), "SHA256:bad") {
		t.Fatalf("%v", err)
	}
	c.Key = testFP
	delete(c.Endpoint, "a")
	if err := ValidateConfig(c, UserLayer); err != nil {
		t.Fatal(err)
	}
}

func TestMergeOverlay(t *testing.T) {
	g := &Config{Endpoint: map[string]EndpointConfig{
		"a": {URL: "https://g/a", Pin: "sha256//g", Key: "/g/a.pub"},
		"b": {URL: "http://g/b"},
	}}
	u := &Config{Endpoint: map[string]EndpointConfig{
		"a":    {Key: testFP},
		"b":    {URL: "http://u/b"},
		"gone": {Key: testFP},
	}}
	m, src := Merge(g, u)
	if m.Endpoint["a"] != (EndpointConfig{URL: "https://g/a", Pin: "sha256//g", Key: testFP}) {
		t.Errorf("overlay a: %+v", m.Endpoint["a"])
	}
	if src.Endpoint["a"] != "global" || src.EndpointKey["a"] != "user" {
		t.Errorf("sources of a: %q key %q", src.Endpoint["a"], src.EndpointKey["a"])
	}
	if m.Endpoint["b"] != (EndpointConfig{URL: "http://u/b"}) || src.Endpoint["b"] != "user" || src.EndpointKey["b"] != "" {
		t.Errorf("whole b: %+v %q %q", m.Endpoint["b"], src.Endpoint["b"], src.EndpointKey["b"])
	}
	if _, ok := m.Endpoint["gone"]; ok || len(src.Unmatched) != 1 || src.Unmatched[0] != "gone" {
		t.Errorf("unmatched: %+v %v", m.Endpoint, src.Unmatched)
	}
	if g.Endpoint["a"].Key != "/g/a.pub" {
		t.Errorf("global layer changed: %+v", g.Endpoint["a"])
	}
	err := UnmatchedError("/u.yaml", src)
	if err == nil || !strings.Contains(err.Error(), `/u.yaml: endpoint "gone" has no url`) || !strings.Contains(err.Error(), "luk config endpoint key -e gone --clear") {
		t.Errorf("%v", err)
	}
}

func TestLoadMergedUnmatched(t *testing.T) {
	dir := t.TempDir()
	up := filepath.Join(dir, "u.yaml")
	t.Setenv("LUK_GLOBAL_CONFIG", filepath.Join(dir, "g.yaml"))
	t.Setenv("LUK_CONFIG", up)
	os.WriteFile(up, []byte("endpoint:\n  x:\n    key: "+testFP+"\n"), 0o600)
	if _, _, err := LoadMerged(); err == nil || !strings.Contains(err.Error(), up) || !strings.Contains(err.Error(), `endpoint "x"`) {
		t.Fatalf("%v", err)
	}
}

func TestValidateOverlay(t *testing.T) {
	c := &Config{Endpoint: map[string]EndpointConfig{"a": {Key: testFP}}}
	if err := ValidateConfig(c, UserLayer); err != nil {
		t.Errorf("user overlay: %v", err)
	}
	for _, l := range []Layer{GlobalLayer, Standalone} {
		if err := ValidateConfig(c, l); err == nil || !strings.Contains(err.Error(), "url is missing") {
			t.Errorf("layer %d: %v", l, err)
		}
	}
	for e, want := range map[EndpointConfig]string{
		{}:                       "neither url nor key",
		{Key: "rel.pub"}:         "absolute path",
		{Key: testFP, Pin: "x"}:  "pin without url",
		{Key: "SHA256:tooshort"}: "SHA256:tooshort",
	} {
		c := &Config{Endpoint: map[string]EndpointConfig{"a": e}}
		if err := ValidateConfig(c, UserLayer); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", e, err, want)
		}
	}
}

func TestSetClearEndpointKey(t *testing.T) {
	c := &Config{Endpoint: map[string]EndpointConfig{"own": {URL: "http://h/own"}}}
	if err := c.SetEndpointKey("g", testFP); err != nil {
		t.Fatal(err)
	}
	if err := c.SetEndpointKey("own", "~/.ssh/id.pub"); err != nil {
		t.Fatal(err)
	}
	if c.Endpoint["g"] != (EndpointConfig{Key: testFP}) || c.Endpoint["own"] != (EndpointConfig{URL: "http://h/own", Key: "~/.ssh/id.pub"}) {
		t.Fatalf("%+v", c.Endpoint)
	}
	for _, k := range []string{"", "rel.pub", "SHA256:x"} {
		if err := c.SetEndpointKey("n", k); err == nil {
			t.Errorf("key %q accepted", k)
		}
	}
	if _, ok := c.Endpoint["n"]; ok {
		t.Error("invalid key stored")
	}
	if !c.ClearEndpointKey("g") || !c.ClearEndpointKey("own") || c.ClearEndpointKey("own") || c.ClearEndpointKey("none") {
		t.Error("clear results")
	}
	if _, ok := c.Endpoint["g"]; ok || c.Endpoint["own"] != (EndpointConfig{URL: "http://h/own"}) {
		t.Errorf("after clear %+v", c.Endpoint)
	}
}

func TestOverlayRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := SaveConfig(path, &Config{Endpoint: map[string]EndpointConfig{"g": {Key: testFP}}}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "url") {
		t.Errorf("overlay written with url:\n%s", data)
	}
	c, err := LoadConfig(path)
	if err != nil || c.Endpoint["g"] != (EndpointConfig{Key: testFP}) {
		t.Fatalf("%+v %v", c, err)
	}
}
