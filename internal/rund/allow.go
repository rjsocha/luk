package rund

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"luk/internal/config"
)

const (
	// DefaultLukdConfig is the main file of the lukd configuration whose
	// steps allow the pipelines of a job (see LoadJobPipelines).
	DefaultLukdConfig = "/etc/site/lukd/config.yaml"
	// maxConfigFile bounds one file of the lukd configuration,
	// maxSnippets the files of its config.d.
	maxConfigFile = 1 << 20
	maxSnippets   = 256
)

// jobsFile is the part of a file of the lukd configuration lukd run
// reads: the relay steps and the jobs of the run steps of the pipelines,
// and the paths that hold data or secrets of lukd (see Lukd.Paths).
// Every other key is left to lukd.
type jobsFile struct {
	Pipeline map[string]*struct {
		Steps []struct {
			Run   yaml.Node `yaml:"run"`
			Relay string    `yaml:"relay"`
			Jobs  []string  `yaml:"jobs"`
		} `yaml:"steps"`
	} `yaml:"pipeline"`
	Root   string `yaml:"root"`
	Listen map[string]*struct {
		TLS *struct {
			Cert string `yaml:"cert"`
			Key  string `yaml:"key"`
			EAB  struct {
				KeyFile string `yaml:"key_file"`
			} `yaml:"eab"`
		} `yaml:"tls"`
	} `yaml:"listen"`
	Auth struct {
		Nonces string `yaml:"nonces"`
	} `yaml:"auth"`
	GPG struct {
		Keys string `yaml:"keys"`
	} `yaml:"gpg"`
	Endpoint map[string]*struct {
		Path   string `yaml:"path"`
		Secret *struct {
			Path string `yaml:"path"`
		} `yaml:"secret"`
	} `yaml:"endpoint"`
	Storage map[string]*struct {
		Base string `yaml:"base"`
	} `yaml:"storage"`
}

// paths are the absolute paths of f that hold data or secrets of lukd
// besides root: the TLS files and the EAB key file of the listeners,
// auth.nonces, gpg.keys, the queues and secret queues of the endpoints
// and the bases of the storages. A relative path lies under root (lukd
// anchors it there).
func (f *jobsFile) paths() []string {
	ps := []string{f.Auth.Nonces, f.GPG.Keys}
	for _, l := range f.Listen {
		if l != nil && l.TLS != nil {
			ps = append(ps, l.TLS.Cert, l.TLS.Key, l.TLS.EAB.KeyFile)
		}
	}
	for _, e := range f.Endpoint {
		if e == nil {
			continue
		}
		ps = append(ps, e.Path)
		if e.Secret != nil {
			ps = append(ps, e.Secret.Path)
		}
	}
	for _, st := range f.Storage {
		if st != nil {
			ps = append(ps, st.Base)
		}
	}
	var out []string
	for _, p := range ps {
		if filepath.IsAbs(p) {
			out = append(out, filepath.Clean(p))
		}
	}
	return out
}

// Lukd is what lukd run takes from the lukd configuration: per job the
// pipelines that may run it, sorted, and the paths that hold data or
// secrets of lukd, which a job must not see (sorted, without duplicates).
type Lukd struct {
	Pipelines map[string][]string
	Paths     []string
}

// LoadJobPipelines is the Pipelines of LoadLukd.
func LoadJobPipelines(p, top string, owner uint32) (map[string][]string, error) {
	lk, err := LoadLukd(p, top, owner)
	if err != nil {
		return nil, err
	}
	return lk.Pipelines, nil
}

// LoadLukd reads the steps and the paths of the lukd configuration: the
// main file p and the *.yaml of config.d next to it (dotfiles left out, in
// lexical order), as lukd loads them. The pipelines of a job are those
// with a step relay: <job> and those with a run step whose jobs lists it;
// the paths are the root of the merged configuration (config.DefaultRoot
// when no file sets it) and those of every file (see jobsFile.paths). A missing p (or
// a missing directory above it) allows nothing. Every directory from top down to config.d, p
// and the snippets must pass the checks of run.d (CheckParents,
// readSafe) for owner; a refused or malformed file, too many snippets or
// a pipeline defined in two files or a step with both run and relay (an
// error of lukd as well) refuse the whole configuration.
func LoadLukd(p, top string, owner uint32) (*Lukd, error) {
	dir := filepath.Dir(p)
	if err := CheckParents(dir, top, owner); errors.Is(err, os.ErrNotExist) {
		return &Lukd{Pipelines: map[string][]string{}}, nil
	} else if err != nil {
		return nil, err
	}
	b, err := readSafe(p, owner, maxConfigFile)
	if errors.Is(err, os.ErrNotExist) {
		return &Lukd{Pipelines: map[string][]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	snippets, err := snippetFiles(filepath.Join(dir, config.SnippetDir), owner)
	if err != nil {
		return nil, err
	}
	// origin maps each pipeline to the file that defines it.
	origin := map[string]string{}
	rs := map[string][]string{}
	var paths []string
	// root of the merged configuration: lukd takes it from the one file
	// that sets it.
	var root string
	for i, f := range append([]string{p}, snippets...) {
		if i > 0 {
			if b, err = readSafe(f, owner, maxConfigFile); err != nil {
				return nil, err
			}
		}
		var jf jobsFile
		if err := decodeOne(b, &jf); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		paths = append(paths, jf.paths()...)
		root = cmp.Or(root, jf.Root)
		for name, pl := range jf.Pipeline {
			if prev, ok := origin[name]; ok {
				return nil, fmt.Errorf("pipeline %s: defined in %s and %s", name, prev, f)
			}
			origin[name] = f
			if pl == nil {
				continue
			}
			for i, s := range pl.Steps {
				if s.Run.Kind != 0 && s.Relay != "" {
					return nil, fmt.Errorf("%s: pipeline %s: step %d: more than one of run and relay", f, name, i+1)
				}
				var jobs []string
				if s.Relay != "" {
					jobs = append(jobs, s.Relay)
				}
				// lukd refuses jobs on any other step.
				if s.Run.Kind != 0 {
					jobs = append(jobs, s.Jobs...)
				}
				// The steps of one pipeline come one after the other: a
				// job it already allows ends in name.
				for _, j := range jobs {
					if ps := rs[j]; len(ps) == 0 || ps[len(ps)-1] != name {
						rs[j] = append(ps, name)
					}
				}
			}
		}
	}
	for _, ps := range rs {
		slices.Sort(ps)
	}
	if root = cmp.Or(root, config.DefaultRoot); filepath.IsAbs(root) {
		paths = append(paths, filepath.Clean(root))
	}
	slices.Sort(paths)
	return &Lukd{Pipelines: rs, Paths: slices.Compact(paths)}, nil
}

// snippetFiles lists the *.yaml of dir that are not dotfiles, in lexical
// order, as lukd does; a missing dir has none. dir must be a directory
// (not a symlink) that passes checkSafe.
func snippetFiles(dir string, owner uint32) ([]string, error) {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", dir)
	}
	if err := checkSafe(fi, owner); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if n := e.Name(); !strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".yaml") {
			if len(out) == maxSnippets {
				return nil, fmt.Errorf("%s: more than %d files", dir, maxSnippets)
			}
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out, nil
}

// decodeOne decodes the one YAML document of data into v, unknown keys
// ignored; a second document is an error, as in lukd. Empty data, or only
// comments, leaves v as it is.
func decodeOne(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return errors.New("more than one YAML document")
	case errors.Is(err, io.EOF):
		return nil
	default:
		return err
	}
}

// allowed reports whether pipeline may run job by the lukd configuration
// of g (LoadLukd) and returns that configuration. A refused configuration
// allows nothing (logged).
func (s *Server) allowed(g *Global, job, pipeline string) (*Lukd, bool) {
	lk, err := LoadLukd(g.Config, s.Top, s.Owner)
	if err != nil {
		s.Log.Error("lukd configuration refused, no pipeline may run a job", "config", g.Config, "err", err)
		return nil, false
	}
	return lk, slices.Contains(lk.Pipelines[job], pipeline)
}
