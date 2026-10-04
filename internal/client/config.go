// Package client is luk's side: its config, the signing key, and the upload.
package client

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Default  string                    `yaml:"default,omitempty"`
	Key      string                    `yaml:"key,omitempty"`
	Endpoint map[string]EndpointConfig `yaml:"endpoint"`
	Alias    map[string][]string       `yaml:"alias,omitempty"`
	// Link maps the host of a link URL to the endpoint luk link uses.
	Link map[string]string `yaml:"link,omitempty"`
}

type EndpointConfig struct {
	URL string `yaml:"url"`
	Pin string `yaml:"pin,omitempty"`
	Key string `yaml:"key,omitempty"`
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
	Default  string
	Key      string
	Endpoint map[string]string
	Alias    map[string]string
	Link     map[string]string
}

// Merge overlays user on global: default and key replace when set, endpoints
// and aliases merge by name and a user entry replaces the global one whole;
// link mappings merge by host.
func Merge(global, user *Config) (*Config, Sources) {
	m := &Config{Endpoint: map[string]EndpointConfig{}, Alias: map[string][]string{}, Link: map[string]string{}}
	src := Sources{Endpoint: map[string]string{}, Alias: map[string]string{}, Link: map[string]string{}}
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
			m.Endpoint[n], src.Endpoint[n] = e, l.name
		}
		for n, a := range l.c.Alias {
			m.Alias[n], src.Alias[n] = a, l.name
		}
		for h, e := range l.c.Link {
			m.Link[h], src.Link[h] = e, l.name
		}
	}
	return m, src
}

// LoadMerged loads the global and user layers and merges them.
func LoadMerged() (*Config, Sources, error) {
	g, err := LoadConfig(GlobalConfigPath())
	if err != nil {
		return nil, Sources{}, err
	}
	u, err := LoadConfig(DefaultConfigPath())
	if err != nil {
		return nil, Sources{}, err
	}
	m, src := Merge(g, u)
	return m, src, nil
}

// Resolve turns an endpoint argument (a config name, a URL, or empty for
// the default) into a URL and a pin. A URL may carry the pin as a fragment:
// "#sha256//..." or "#pin=sha256//...".
func (c *Config) Resolve(arg string) (string, string, error) {
	if arg == "" {
		arg = c.Default
		if arg == "" {
			return "", "", errors.New("no endpoint: pass --endpoint or set default in the config")
		}
	}
	if !strings.Contains(arg, "://") {
		e, ok := c.Endpoint[arg]
		if !ok {
			return "", "", fmt.Errorf("unknown endpoint %q", arg)
		}
		arg, pin, err := splitPin(e.URL)
		if err != nil {
			return "", "", err
		}
		if e.Pin != "" {
			pin = e.Pin
		}
		return arg, pin, nil
	}
	return splitPin(arg)
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

func splitPin(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "", fmt.Errorf("invalid endpoint URL %q", raw)
	}
	var pin string
	if u.Fragment != "" {
		pin = strings.TrimPrefix(u.Fragment, "pin=")
		if !strings.HasPrefix(pin, "sha256//") {
			return "", "", fmt.Errorf("endpoint URL fragment must be a pin, sha256//...: %q", raw)
		}
	}
	u.Fragment, u.RawFragment = "", ""
	return u.String(), pin, nil
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

// AddEndpoint adds or replaces an endpoint after validating it.
func (c *Config) AddEndpoint(name, rawURL, pin, key string) error {
	if strings.Contains(rawURL, "#") {
		u, fragPin, err := splitPin(rawURL)
		if err != nil {
			return err
		}
		if fragPin != "" && pin != "" && pin != fragPin {
			return errors.New("pin given twice with different values")
		}
		if fragPin != "" {
			pin = fragPin
		}
		rawURL = u
	}
	e := EndpointConfig{URL: rawURL, Pin: pin, Key: key}
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
	if e.Pin == "" {
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("endpoint %q: a pin needs an https endpoint", name)
	}
	b64, ok := strings.CutPrefix(e.Pin, "sha256//")
	if !ok {
		return fmt.Errorf("endpoint %q: pin must start with sha256//", name)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("endpoint %q: pin must be sha256// and base64 of 32 bytes", name)
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

// ValidateConfig checks one layer and returns every problem, joined. A
// standalone config must also resolve its own default; a layer that is merged
// later may name an endpoint from another layer (see ValidateDefault).
func ValidateConfig(c *Config, standalone bool) error {
	names := make([]string, 0, len(c.Endpoint))
	for n := range c.Endpoint {
		names = append(names, n)
	}
	sort.Strings(names)
	var errs []error
	for _, n := range names {
		if err := validateEndpoint(n, c.Endpoint[n]); err != nil {
			errs = append(errs, err)
		}
	}
	if err := ValidateKey(c.Key); err != nil {
		errs = append(errs, err)
	}
	var endpoints map[string]EndpointConfig
	if standalone {
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
