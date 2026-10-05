package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const (
	// SnippetDir, next to the main file, holds *.yaml parts of the
	// configuration.
	SnippetDir = "config.d"
	// SSHDir, next to the main file, holds one <name>.pub per identity and
	// ca/<type>/<name>.pub per CA.
	SSHDir = "ssh.d"
	// GPGDir, next to the main file, is the default gpg.keys.
	GPGDir = "gpg.d"
	// PasswordDir, next to the main file, holds one file per password of
	// the insecure encryption (see ReadPassword).
	PasswordDir = "password.d"
	// IdentityFile, next to the main file, is the identity key of lukd (see
	// lukd key).
	IdentityFile = "identity.key"
	caDir        = "ca"
	maxKeyFile   = 1 << 20
)

// Sections whose entries are keyed by name: mappings by their key, lists
// by the `name` of each item. Every other leaf is set in one file only.
var (
	namedMaps  = map[string]bool{"listen": true, "endpoint": true, "pipeline": true, "storage": true, "expose": true}
	namedLists = map[string]bool{"auth.keys": true, "auth.ca": true}
)

// IdentityPath is the identity key file belonging to the main file cfgPath.
func IdentityPath(cfgPath string) string {
	return filepath.Join(filepath.Dir(cfgPath), IdentityFile)
}

// Load reads the main file p, the snippets of config.d and the identities
// and CAs of ssh.d next to it, and validates the merged result. Errors name the
// file that defines the faulty part when it is known, else p.
func Load(p string) (*Config, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(p)
	m := &merger{root: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, origin: map[string]string{}}
	m.add(p, data)
	snippets, err := listDir(filepath.Join(dir, SnippetDir), ".yaml")
	if err != nil {
		return nil, err
	}
	for _, f := range snippets {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		m.add(f, b)
	}
	if len(m.errs) > 0 {
		return nil, errors.Join(m.errs...)
	}
	m.sortLists()
	var c Config
	if err := m.root.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if c.GPG.Keys == "" {
		if abs, err := filepath.Abs(filepath.Join(dir, GPGDir)); err == nil {
			c.GPG.Keys = abs
		}
	}
	if err := c.loadKeys(filepath.Join(dir, SSHDir), m.origin); err != nil {
		return nil, err
	}
	errs := c.validate()
	for i, e := range errs {
		errs[i] = fmt.Errorf("%s: %w", m.fileOf(e.Error(), p), e)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	c.Path = p
	c.IdentityPath = IdentityPath(p)
	if abs, err := filepath.Abs(filepath.Join(dir, PasswordDir)); err == nil {
		c.PasswordDir = abs
	}
	c.Files = append([]string{p}, snippets...)
	for _, k := range c.Auth.Keys {
		if k.File != "" {
			c.Files = append(c.Files, k.File)
		}
	}
	for _, ca := range c.Auth.CA {
		if ca.File != "" {
			c.Files = append(c.Files, ca.File)
		}
	}
	return &c, nil
}

// listDir returns the files of dir ending in ext, dotfiles left out, in
// lexical order; a missing dir has none.
func listDir(dir, ext string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if n := e.Name(); !strings.HasPrefix(n, ".") && strings.HasSuffix(n, ext) {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out, nil
}

// merger builds one document out of the files. origin maps what each file
// defined ("endpoint backup", "auth.keys robert.socha", "limits.conn.max")
// to the file.
type merger struct {
	root   *yaml.Node
	origin map[string]string
	errs   []error
}

func (m *merger) add(file string, data []byte) {
	// Strict decoding per file keeps unknown keys and bad values an error
	// of the file they are in.
	var probe Config
	if err := DecodeStrict(data, &probe); err != nil {
		m.errs = append(m.errs, fmt.Errorf("%s: %w", file, err))
		return
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		m.errs = append(m.errs, fmt.Errorf("%s: %w", file, err))
		return
	}
	if len(doc.Content) == 0 {
		return
	}
	if top := deref(doc.Content[0]); top.Kind == yaml.MappingNode {
		m.merge(m.root, top, "", file)
	}
}

func (m *merger) merge(dst, src *yaml.Node, at, file string) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		k, v := src.Content[i], deref(src.Content[i+1])
		p := k.Value
		if at != "" {
			p = at + "." + k.Value
		}
		if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
			continue
		}
		switch {
		case namedMaps[p]:
			d := child(dst, k, yaml.MappingNode)
			for j := 0; j+1 < len(v.Content); j += 2 {
				if m.claim(p+" "+v.Content[j].Value, file, "defined") {
					d.Content = append(d.Content, v.Content[j], v.Content[j+1])
				}
			}
		case namedLists[p]:
			d := child(dst, k, yaml.SequenceNode)
			for _, it := range v.Content {
				it = deref(it)
				if name := itemName(it); name == "" || m.claim(p+" "+name, file, "defined") {
					d.Content = append(d.Content, it)
				}
			}
		case v.Kind == yaml.MappingNode:
			m.merge(child(dst, k, yaml.MappingNode), v, p, file)
		default:
			if m.claim(p, file, "set") {
				dst.Content = append(dst.Content, k, v)
			}
		}
	}
}

// claim records that file defines id; false when another file (or the
// same one) already did.
func (m *merger) claim(id, file, verb string) bool {
	prev, ok := m.origin[id]
	switch {
	case !ok:
		m.origin[id] = file
		return true
	case prev == file:
		m.errs = append(m.errs, fmt.Errorf("%s: %s: %s twice", file, id, verb))
	default:
		m.errs = append(m.errs, fmt.Errorf("%s: %s in %s and %s", id, verb, prev, file))
	}
	return false
}

// sortLists orders the named lists by name, so the result does not depend
// on the order of the files.
func (m *merger) sortLists() {
	for i := 0; i+1 < len(m.root.Content); i += 2 {
		if m.root.Content[i].Value != "auth" {
			continue
		}
		a := m.root.Content[i+1]
		for j := 0; j+1 < len(a.Content); j += 2 {
			if l := a.Content[j+1]; namedLists["auth."+a.Content[j].Value] {
				sort.SliceStable(l.Content, func(x, y int) bool { return itemName(l.Content[x]) < itemName(l.Content[y]) })
			}
		}
	}
}

// fileOf returns the file defining the longest origin that starts msg,
// else def.
func (m *merger) fileOf(msg, def string) string {
	best := ""
	for id := range m.origin {
		if len(id) > len(best) && strings.HasPrefix(msg, id) && (len(msg) == len(id) || msg[len(id)] == ':' || msg[len(id)] == ' ') {
			best = id
		}
	}
	if best == "" {
		return def
	}
	return m.origin[best]
}

// child returns the value of key k in dst, adding an empty one of kind.
func child(dst, k *yaml.Node, kind yaml.Kind) *yaml.Node {
	for i := 0; i+1 < len(dst.Content); i += 2 {
		if dst.Content[i].Value == k.Value {
			return dst.Content[i+1]
		}
	}
	tag := "!!map"
	if kind == yaml.SequenceNode {
		tag = "!!seq"
	}
	v := &yaml.Node{Kind: kind, Tag: tag}
	dst.Content = append(dst.Content, k, v)
	return v
}

func deref(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	return n
}

func itemName(n *yaml.Node) string {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "name" {
			return n.Content[i+1].Value
		}
	}
	return ""
}

// checkDir reports whether dir exists; it must be a directory not
// writable by group or others.
func checkDir(dir string) (bool, error) {
	fi, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("%s: not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return false, fmt.Errorf("%s: writable by group or others", dir)
	}
	return true, nil
}

// loadKeys adds the identities of dir after the inline ones, then the CAs
// of dir/ca. The directories and their files must not be writable by group
// or others.
func (c *Config) loadKeys(dir string, origin map[string]string) error {
	if ok, err := checkDir(dir); !ok {
		return err
	}
	files, err := listDir(dir, ".pub")
	if err != nil {
		return err
	}
	var errs []error
	for _, f := range files {
		name, keys, err := readPubFile(f, false)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		k := &Key{Name: name, File: f, Parsed: keys}
		if prev, ok := origin["auth.keys "+k.Name]; ok {
			errs = append(errs, fmt.Errorf("%s: identity %s is also defined in %s", f, k.Name, prev))
			continue
		}
		if prev, ok := origin["auth.ca "+k.Name]; ok {
			errs = append(errs, fmt.Errorf("%s: identity %s is the name of a CA in %s", f, k.Name, prev))
			continue
		}
		origin["auth.keys "+k.Name] = f
		c.Auth.Keys = append(c.Auth.Keys, *k)
	}
	return errors.Join(append(errs, c.loadCAs(filepath.Join(dir, caDir), origin))...)
}

// loadCAs adds the CAs of dir: host/<name>.pub and user/<name>.pub. An
// auth.ca entry of the same name without key takes the keys of the file;
// any other reuse of the name is an error.
func (c *Config) loadCAs(dir string, origin map[string]string) error {
	if ok, err := checkDir(dir); !ok {
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	defined := map[string]string{}
	for _, e := range ents {
		typ, sub := e.Name(), filepath.Join(dir, e.Name())
		if typ != "host" && typ != "user" {
			errs = append(errs, fmt.Errorf("%s: unexpected entry, %s holds only host/ and user/", sub, dir))
			continue
		}
		ok, err := checkDir(sub)
		if !ok {
			errs = append(errs, err)
			continue
		}
		files, err := listDir(sub, ".pub")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, f := range files {
			name, keys, err := readPubFile(f, true)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if prev, ok := defined[name]; ok {
				errs = append(errs, fmt.Errorf("%s: CA %s is also defined in %s", f, name, prev))
				continue
			}
			defined[name] = f
			if prev, ok := origin["auth.keys "+name]; ok {
				errs = append(errs, fmt.Errorf("%s: CA %s is the name of an identity in %s", f, name, prev))
				continue
			}
			i := slices.IndexFunc(c.Auth.CA, func(ca CA) bool { return ca.Name == name })
			if i < 0 {
				origin["auth.ca "+name] = f
				c.Auth.CA = append(c.Auth.CA, CA{Name: name, Type: typ, File: f, Parsed: keys})
				continue
			}
			ca := &c.Auth.CA[i]
			switch {
			case ca.Key != "":
				errs = append(errs, fmt.Errorf("%s: CA %s is also defined in %s", f, name, origin["auth.ca "+name]))
			case ca.Type != "" && ca.Type != typ:
				errs = append(errs, fmt.Errorf("%s: CA %s has type %s in %s", f, name, ca.Type, origin["auth.ca "+name]))
			default:
				ca.Type, ca.File, ca.Parsed = typ, f, keys
			}
		}
	}
	return errors.Join(errs...)
}

// readPubFile reads ssh.d/<name>.pub, or ssh.d/ca/<type>/<name>.pub when
// ca: one public key per line in authorized_keys form without options,
// comments after the key allowed.
func readPubFile(p string, ca bool) (string, []ssh.PublicKey, error) {
	what, holds := "identity", "ssh.d holds plain keys"
	if ca {
		what, holds = "CA", "ssh.d/ca holds CA keys"
	}
	name := strings.TrimSuffix(filepath.Base(p), ".pub")
	if strings.ContainsAny(name, ":#") {
		return "", nil, fmt.Errorf("%s: %s name %q contains ':' or '#'", p, what, name)
	}
	f, err := os.Open(p)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	if !fi.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%s: not a regular file", p)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return "", nil, fmt.Errorf("%s: writable by group or others", p)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return "", nil, err
	}
	if len(b) > maxKeyFile {
		return "", nil, fmt.Errorf("%s: larger than %d bytes", p, maxKeyFile)
	}
	var keys []ssh.PublicKey
	seen := map[string]int{}
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
		switch {
		case err != nil:
			return "", nil, fmt.Errorf("%s:%d: %v", p, i+1, err)
		case len(opts) > 0:
			return "", nil, fmt.Errorf("%s:%d: authorized_keys options are not supported (CA keys belong in ssh.d/ca or auth.ca)", p, i+1)
		}
		if _, ok := pub.(*ssh.Certificate); ok {
			return "", nil, fmt.Errorf("%s:%d: a certificate; %s", p, i+1, holds)
		}
		if l, ok := seen[string(pub.Marshal())]; ok {
			return "", nil, fmt.Errorf("%s:%d: same key as line %d", p, i+1, l)
		}
		seen[string(pub.Marshal())] = i + 1
		keys = append(keys, pub)
	}
	if len(keys) == 0 {
		return "", nil, fmt.Errorf("%s: no key", p)
	}
	return name, keys, nil
}
