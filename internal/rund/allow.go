package rund

import (
	"bytes"
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
// reads: the relay steps and the jobs of the run steps of the pipelines.
// Every other key is left to lukd.
type jobsFile struct {
	Pipeline map[string]*struct {
		Steps []struct {
			Run   string   `yaml:"run"`
			Relay string   `yaml:"relay"`
			Jobs  []string `yaml:"jobs"`
		} `yaml:"steps"`
	} `yaml:"pipeline"`
}

// LoadJobPipelines reads the steps of the lukd configuration: the main
// file p and the *.yaml of config.d next to it (dotfiles left out, in
// lexical order), as lukd loads them. It returns, per job, the pipelines
// that may run it, sorted: those with a step relay: <job> and those with
// a run step whose jobs lists it. A missing p (or a missing directory
// above it) allows nothing. Every directory from top down to config.d, p
// and the snippets must pass the checks of run.d (CheckParents,
// readSafe) for owner; a refused or malformed file, too many snippets or
// a pipeline defined in two files (an error of lukd as well) refuse the
// whole configuration.
func LoadJobPipelines(p, top string, owner uint32) (map[string][]string, error) {
	dir := filepath.Dir(p)
	if err := CheckParents(dir, top, owner); errors.Is(err, os.ErrNotExist) {
		return map[string][]string{}, nil
	} else if err != nil {
		return nil, err
	}
	b, err := readSafe(p, owner, maxConfigFile)
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]string{}, nil
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
		for name, pl := range jf.Pipeline {
			if prev, ok := origin[name]; ok {
				return nil, fmt.Errorf("pipeline %s: defined in %s and %s", name, prev, f)
			}
			origin[name] = f
			if pl == nil {
				continue
			}
			for _, s := range pl.Steps {
				var jobs []string
				if s.Relay != "" {
					jobs = append(jobs, s.Relay)
				}
				// lukd refuses jobs on any other step.
				if s.Run != "" {
					jobs = append(jobs, s.Jobs...)
				}
				for _, j := range jobs {
					if !slices.Contains(rs[j], name) {
						rs[j] = append(rs[j], name)
					}
				}
			}
		}
	}
	for _, ps := range rs {
		slices.Sort(ps)
	}
	return rs, nil
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
// of g (LoadJobPipelines). A refused configuration allows nothing
// (logged).
func (s *Server) allowed(g *Global, job, pipeline string) bool {
	ps, err := LoadJobPipelines(g.Config, s.Top, s.Owner)
	if err != nil {
		s.Log.Error("lukd configuration refused, no pipeline may run a job", "config", g.Config, "err", err)
		return false
	}
	return slices.Contains(ps[job], pipeline)
}
