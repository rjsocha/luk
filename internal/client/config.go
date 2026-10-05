// Package client is luk's side: its config, the signing key, and the upload.
package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"luk/internal/channel"
)

type Config struct {
	Default  string                    `yaml:"default,omitempty"`
	Key      string                    `yaml:"key,omitempty"`
	Endpoint map[string]EndpointConfig `yaml:"endpoint"`
	Alias    map[string][]string       `yaml:"alias,omitempty"`
	// Link maps the host of a link URL to the endpoint luk link uses.
	Link map[string]string `yaml:"link,omitempty"`
}

// EndpointConfig is one endpoint entry. In the user layer an entry without
// URL is an overlay: it sets only Key on the global endpoint of its name.
// Pins are the lukd keys the channel accepts, in key or words form.
type EndpointConfig struct {
	URL  string  `yaml:"url,omitempty"`
	Pins PinList `yaml:"pin,omitempty"`
	Key  string  `yaml:"key,omitempty"`
}

// PinList is the pins of an endpoint: a YAML list, or one pin as a scalar.
type PinList []string

func (p *PinList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.ShortTag() != "!!null" {
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		*p = PinList{s}
		return nil
	}
	var l []string
	if err := n.Decode(&l); err != nil {
		return err
	}
	*p = l
	return nil
}

// GlobalConfigPath is the system-wide layer; $LUK_GLOBAL_CONFIG overrides it.
func GlobalConfigPath() string {
	if p := os.Getenv("LUK_GLOBAL_CONFIG"); p != "" {
		return p
	}
	return "/etc/site/luk/config.yaml"
}

// DefaultConfigPath is the user layer; $LUK_CONFIG overrides it.
func DefaultConfigPath() string {
	if p := os.Getenv("LUK_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "luk", "config.yaml")
}

func LoadConfig(path string) (*Config, error) {
	c := &Config{}
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseConfig(path, data)
}

// ParseConfig decodes one config file strictly: unknown keys and a second
// YAML document are errors and empty data is an empty config. path is only
// used in error messages.
func ParseConfig(path string, data []byte) (*Config, error) {
	c := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(c)
	if err == nil {
		var extra yaml.Node
		if err = dec.Decode(&extra); err == nil {
			err = errors.New("more than one YAML document")
		}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Sources records which layer each merged value came from.
type Sources struct {
	Default string
	Key     string
	// Endpoint is the layer of the url and pin of an endpoint.
	Endpoint map[string]string
	// EndpointKey is the layer of the key of an endpoint when it is not the
	// layer of its url: "user" for an overlay with a global endpoint.
	EndpointKey map[string]string
	// Unmatched lists, sorted, the user overlays without a global endpoint
	// of their name; they are not in the merged config.
	Unmatched []string
	Alias     map[string]string
	Link      map[string]string
}

// IsOverlay reports whether e is an overlay entry: no url, only a key.
func (e EndpointConfig) IsOverlay() bool { return e.URL == "" }

// Merge overlays user on global: default and key replace when set, aliases
// merge by name and a user entry replaces the global one whole; link
// mappings merge by host. Endpoints merge by name: a user entry with a url
// replaces the global one whole (nothing is inherited), a user entry without
// a url is an overlay that sets the key of the global endpoint of that name
// (url and pin stay global); an overlay without one is left out and listed in
// Sources.Unmatched.
func Merge(global, user *Config) (*Config, Sources) {
	m := &Config{Endpoint: map[string]EndpointConfig{}, Alias: map[string][]string{}, Link: map[string]string{}}
	src := Sources{Endpoint: map[string]string{}, EndpointKey: map[string]string{}, Alias: map[string]string{}, Link: map[string]string{}}
	for _, l := range []struct {
		name string
		c    *Config
	}{{"global", global}, {"user", user}} {
		if l.c.Default != "" {
			m.Default, src.Default = l.c.Default, l.name
		}
		if l.c.Key != "" {
			m.Key, src.Key = l.c.Key, l.name
		}
		for n, e := range l.c.Endpoint {
			if l.c == user && e.IsOverlay() {
				continue
			}
			m.Endpoint[n], src.Endpoint[n] = e, l.name
		}
		for n, a := range l.c.Alias {
			m.Alias[n], src.Alias[n] = a, l.name
		}
		for h, e := range l.c.Link {
			m.Link[h], src.Link[h] = e, l.name
		}
	}
	for n, e := range user.Endpoint {
		if !e.IsOverlay() {
			continue
		}
		g, ok := global.Endpoint[n]
		if !ok || g.IsOverlay() {
			src.Unmatched = append(src.Unmatched, n)
			continue
		}
		g.Key = e.Key
		m.Endpoint[n], src.Endpoint[n], src.EndpointKey[n] = g, "global", "user"
	}
	sort.Strings(src.Unmatched)
	return m, src
}

// LoadLayers loads the global and the user layer.
func LoadLayers() (*Config, *Config, error) {
	g, err := LoadConfig(GlobalConfigPath())
	if err != nil {
		return nil, nil, err
	}
	u, err := LoadConfig(DefaultConfigPath())
	if err != nil {
		return nil, nil, err
	}
	return g, u, nil
}

// LoadMerged loads the global and user layers and merges them. A user
// overlay without a global endpoint of its name is an error.
func LoadMerged() (*Config, Sources, error) {
	g, u, err := LoadLayers()
	if err != nil {
		return nil, Sources{}, err
	}
	m, src := Merge(g, u)
	if err := UnmatchedError(DefaultConfigPath(), src); err != nil {
		return nil, Sources{}, err
	}
	return m, src, nil
}

// UnmatchedError reports each user overlay without a global endpoint, with
// the command that removes it; nil when there is none.
func UnmatchedError(userPath string, src Sources) error {
	var errs []error
	for _, n := range src.Unmatched {
		errs = append(errs, fmt.Errorf("%s: endpoint %q has no url and sets only key, but the global config has no endpoint %q; add a url or remove it (luk config endpoint key -e %s --clear)", userPath, n, n, n))
	}
	return errors.Join(errs...)
}

// Resolve turns an endpoint argument (a config name, a URL, or empty for
// the default) into a URL and its channel pins. A URL may carry the pins
// as its fragment, comma-separated: "#lusab-babad-...,<key>".
func (c *Config) Resolve(arg string) (string, []string, error) {
	u, pins, _, err := c.resolve(arg, false)
	return u, pins, err
}

// ResolveLenient is Resolve for luk scan, the command that replaces a
// stale pin: the stored pins of a named endpoint that are not lukd keys
// (an old TLS pin) are left out instead of failing, and each is returned
// as a notice for the user. Pins given in a URL fragment still fail.
func (c *Config) ResolveLenient(arg string) (string, []string, []string, error) {
	return c.resolve(arg, true)
}

func (c *Config) resolve(arg string, lenient bool) (string, []string, []string, error) {
	if arg == "" {
		arg = c.Default
		if arg == "" {
			return "", nil, nil, errors.New("no endpoint: pass --endpoint or set default in the config")
		}
	}
	if !strings.Contains(arg, "://") {
		e, ok := c.Endpoint[arg]
		if !ok {
			return "", nil, nil, fmt.Errorf("unknown endpoint %q", arg)
		}
		u, pins, err := splitPins(e.URL)
		if err != nil {
			return "", nil, nil, err
		}
		var notices []string
		if len(e.Pins) > 0 {
			if lenient {
				e.Pins, notices = usablePins(arg, e.Pins)
			} else if err := checkPins(e.Pins); err != nil {
				return "", nil, nil, fmt.Errorf("endpoint %q: %w", arg, err)
			}
			pins = e.Pins
		}
		return u, pins, notices, nil
	}
	u, pins, err := splitPins(arg)
	return u, pins, nil, err
}

// usablePins splits the stored pins of endpoint name into those that are
// lukd keys and a notice for each that is not.
func usablePins(name string, pins []string) ([]string, []string) {
	var ok, notices []string
	for _, p := range pins {
		if _, err := channel.ParsePin(p); err != nil {
			notices = append(notices, fmt.Sprintf("endpoint %s: pin %s is not a lukd key (old TLS pin?): replace it with the pin below", name, p))
			continue
		}
		ok = append(ok, p)
	}
	return ok, notices
}

// KeyFor picks the signing key for an endpoint argument (as Resolve takes
// it): flag, else the key of the named endpoint, else the global key. A URL
// names no endpoint. "" means the first key of the SSH agent.
func (c *Config) KeyFor(arg, flag string) string {
	if flag != "" {
		return flag
	}
	if arg == "" {
		arg = c.Default
	}
	if e, ok := c.Endpoint[arg]; ok && !strings.Contains(arg, "://") && e.Key != "" {
		return e.Key
	}
	return c.Key
}

// splitPins splits an endpoint URL from the channel pins of its fragment.
func splitPins(raw string) (string, []string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", nil, fmt.Errorf("invalid endpoint URL %q", raw)
	}
	var pins []string
	if u.Fragment != "" {
		if _, err := channel.ParsePins(u.Fragment); err != nil {
			return "", nil, err
		}
		pins = strings.Split(u.Fragment, ",")
	}
	u.Fragment, u.RawFragment = "", ""
	return u.String(), pins, nil
}

// checkPins checks that each of pins is a channel pin.
func checkPins(pins []string) error {
	for _, p := range pins {
		if _, err := channel.ParsePin(p); err != nil {
			return err
		}
	}
	return nil
}

// PinsFor is the channel pins for the endpoint URL u: those of fragment,
// else those of the first config endpoint (by name) with the scheme, host
// and port of u, else none. Endpoints of one origin are one lukd, so they
// share its key.
func PinsFor(cfg *Config, u *url.URL, fragment string) ([]channel.Pin, error) {
	if fragment != "" {
		return channel.ParsePins(fragment)
	}
	if cfg == nil {
		return nil, nil
	}
	names := make([]string, 0, len(cfg.Endpoint))
	for n := range cfg.Endpoint {
		names = append(names, n)
	}
	sort.Strings(names)
	want := origin(u)
	for _, n := range names {
		e := cfg.Endpoint[n]
		eu, err := url.Parse(e.URL)
		if err != nil || len(e.Pins) == 0 || origin(eu) != want {
			continue
		}
		return channel.ParsePins(strings.Join(e.Pins, ","))
	}
	return nil, nil
}

// PinsForLenient is PinsFor for luk scan: a stored pin that is not a lukd
// key (an old TLS pin) is ignored, as if the endpoint had none, and
// returned as a notice. A fragment is the user's own input and still fails.
func PinsForLenient(cfg *Config, u *url.URL, fragment string) ([]channel.Pin, []string, error) {
	if fragment != "" || cfg == nil {
		pins, err := PinsFor(cfg, u, fragment)
		return pins, nil, err
	}
	names := make([]string, 0, len(cfg.Endpoint))
	for n := range cfg.Endpoint {
		names = append(names, n)
	}
	sort.Strings(names)
	want := origin(u)
	var notices []string
	for _, n := range names {
		e := cfg.Endpoint[n]
		eu, err := url.Parse(e.URL)
		if err != nil || len(e.Pins) == 0 || origin(eu) != want {
			continue
		}
		ok, bad := usablePins(n, e.Pins)
		notices = append(notices, bad...)
		if len(ok) == 0 {
			continue
		}
		pins, err := channel.ParsePins(strings.Join(ok, ","))
		return pins, notices, err
	}
	return nil, notices, nil
}

// origin is the scheme, lowercase host and port of u, the default port
// made explicit.
func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// SaveConfig writes c to path atomically, creating the directory (0700)
// and the file (0600) when missing. An existing file keeps its mode.
func SaveConfig(path string, c *Config) error {
	return SaveConfigMode(path, c, 0o700, 0o600)
}

// SaveConfigMode is SaveConfig with explicit modes for a new directory and file.
func SaveConfigMode(path string, c *Config, dirMode, fileMode os.FileMode) error {
	if path == "" {
		return errors.New("no config path")
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	mode := fileMode
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// AddEndpoint adds or replaces an endpoint after validating it. The pins
// may come as the fragment of rawURL or as pins, not as two different
// lists.
func (c *Config) AddEndpoint(name, rawURL string, pins []string, key string) error {
	if strings.Contains(rawURL, "#") {
		u, fragPins, err := splitPins(rawURL)
		if err != nil {
			return err
		}
		if len(fragPins) > 0 && len(pins) > 0 && !slices.Equal(pins, fragPins) {
			return errors.New("pin given twice with different values")
		}
		if len(fragPins) > 0 {
			pins = fragPins
		}
		rawURL = u
	}
	e := EndpointConfig{URL: rawURL, Pins: pins, Key: key}
	if err := validateEndpoint(name, e); err != nil {
		return err
	}
	if c.Endpoint == nil {
		c.Endpoint = map[string]EndpointConfig{}
	}
	c.Endpoint[name] = e
	return nil
}

func validateEndpoint(name string, e EndpointConfig) error {
	if name == "" {
		return errors.New("endpoint name is empty")
	}
	u, err := url.Parse(e.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("endpoint %q: invalid URL %q, want http(s)://host/...", name, e.URL)
	}
	if u.Fragment != "" || strings.HasSuffix(e.URL, "#") {
		return fmt.Errorf("endpoint %q: URL must not have a fragment, use pin", name)
	}
	if err := ValidateKey(e.Key); err != nil {
		return fmt.Errorf("endpoint %q: %w", name, err)
	}
	if err := checkPins(e.Pins); err != nil {
		return fmt.Errorf("endpoint %q: %w", name, err)
	}
	return nil
}

// ValidateKey checks a configured key: a fingerprint (SHA256:...), an
// absolute path, or a path starting with ~/.
func ValidateKey(key string) error {
	if strings.HasPrefix(key, fingerprintPrefix) {
		return ValidateFingerprint(key)
	}
	if key != "" && !filepath.IsAbs(key) && !strings.HasPrefix(key, "~/") {
		return fmt.Errorf("key %q must be an absolute path or start with ~/", key)
	}
	return nil
}

// Layer says what a validated config file is.
type Layer int

const (
	// Standalone is one file on its own, merged with nothing (check --file).
	Standalone Layer = iota
	// GlobalLayer is the global layer of a merge.
	GlobalLayer
	// UserLayer is the user layer of a merge, the only one with overlays.
	UserLayer
)

// ValidateConfig checks one layer and returns every problem, joined. A
// standalone config must also resolve its own default; a layer that is merged
// later may name an endpoint from another layer (see ValidateDefault). Only
// the user layer may have overlays (entries without url, see Merge).
func ValidateConfig(c *Config, layer Layer) error {
	names := make([]string, 0, len(c.Endpoint))
	for n := range c.Endpoint {
		names = append(names, n)
	}
	sort.Strings(names)
	var errs []error
	for _, n := range names {
		e := c.Endpoint[n]
		var err error
		switch {
		case e.IsOverlay() && layer == UserLayer:
			err = validateOverlay(n, e)
		case e.IsOverlay():
			err = fmt.Errorf("endpoint %q: url is missing (only the user layer may set key alone on a global endpoint)", n)
		default:
			err = validateEndpoint(n, e)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if err := ValidateKey(c.Key); err != nil {
		errs = append(errs, err)
	}
	var endpoints map[string]EndpointConfig
	if layer == Standalone {
		if err := ValidateDefault(c); err != nil {
			errs = append(errs, err)
		}
		endpoints = c.Endpoint
		if endpoints == nil {
			endpoints = map[string]EndpointConfig{}
		}
	}
	if err := ValidateLinks(c, endpoints); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func validateOverlay(name string, e EndpointConfig) error {
	if len(e.Pins) > 0 {
		return fmt.Errorf("endpoint %q: pin without url; an entry without url sets only key (url and pin come from the global config)", name)
	}
	if e.Key == "" {
		return fmt.Errorf("endpoint %q: neither url nor key", name)
	}
	if err := ValidateKey(e.Key); err != nil {
		return fmt.Errorf("endpoint %q: %w", name, err)
	}
	return nil
}

// SetEndpointKey sets the key of the endpoint name in this layer. An entry
// with a url gets the key; otherwise the entry becomes an overlay of only
// the key (user layer). key must not be empty, see ClearEndpointKey.
func (c *Config) SetEndpointKey(name, key string) error {
	if key == "" {
		return errors.New("empty key")
	}
	e := c.Endpoint[name]
	e.Key = key
	var err error
	if e.IsOverlay() {
		err = validateOverlay(name, e)
	} else {
		err = validateEndpoint(name, e)
	}
	if err != nil {
		return err
	}
	if c.Endpoint == nil {
		c.Endpoint = map[string]EndpointConfig{}
	}
	c.Endpoint[name] = e
	return nil
}

// ClearEndpointKey removes the key of the endpoint name from this layer: an
// overlay goes away, an entry with a url keeps the rest. It reports whether
// the layer had a key for name.
func (c *Config) ClearEndpointKey(name string) bool {
	e, ok := c.Endpoint[name]
	if !ok || e.Key == "" && !e.IsOverlay() {
		return false
	}
	if e.IsOverlay() {
		delete(c.Endpoint, name)
		return true
	}
	e.Key = ""
	c.Endpoint[name] = e
	return true
}

// ValidateDefault checks that the default, when set, names an endpoint.
func ValidateDefault(c *Config) error {
	if _, ok := c.Endpoint[c.Default]; c.Default != "" && !ok {
		return fmt.Errorf("default %q is not a defined endpoint", c.Default)
	}
	return nil
}

// RemoveEndpoint deletes an endpoint; removing the default clears it.
func (c *Config) RemoveEndpoint(name string) error {
	if _, ok := c.Endpoint[name]; !ok {
		return fmt.Errorf("unknown endpoint %q", name)
	}
	delete(c.Endpoint, name)
	if c.Default == name {
		c.Default = ""
	}
	return nil
}

func (c *Config) SetDefault(name string) error {
	if _, ok := c.Endpoint[name]; !ok {
		return fmt.Errorf("unknown endpoint %q", name)
	}
	c.Default = name
	return nil
}
