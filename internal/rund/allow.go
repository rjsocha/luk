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
	"time"

	"gopkg.in/yaml.v3"

	"luk/internal/config"
)

const (
	// DefaultLukdConfig is the main file of the lukd configuration whose
	// steps decide what a step runs (see LoadLukd).
	DefaultLukdConfig = "/etc/site/lukd/config.yaml"
	// maxConfigFile bounds one file of the lukd configuration,
	// maxSnippets the files of its config.d.
	maxConfigFile = 1 << 20
	maxSnippets   = 256
)

// jobsFile is the part of a file of the lukd configuration lukd run
// reads: the timeouts and the steps of the pipelines (run, env, relay,
// jobs), and the paths that hold data or secrets of lukd (see Lukd.Paths).
// Every other key is left to lukd.
type jobsFile struct {
	Pipeline map[string]*struct {
		// Nodes, so an error names the key.
		Timeout yaml.Node `yaml:"timeout"`
		Steps   []struct {
			Run   yaml.Node `yaml:"run"`
			Env   yaml.Node `yaml:"env"`
			Relay string    `yaml:"relay"`
			Jobs  yaml.Node `yaml:"jobs"`
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

// StepDef is what a step of the lukd configuration runs: a run program
// (Program, with the nested jobs it may ask for and its env), the job of a
// run: {job} step (Job) or of a relay step (Relay); none of them for any
// other step.
type StepDef struct {
	Program string
	Job     string
	Relay   string
	Jobs    []string
	Env     map[string]string
}

// Lukd is what lukd run takes from the lukd configuration: per pipeline
// its steps in order and its timeout (config.DefaultPipelineTimeout when
// unset), per job the pipelines that may run it, sorted, and the paths
// that hold data or secrets of lukd, which a unit must not see (sorted,
// without duplicates).
type Lukd struct {
	Steps     map[string][]StepDef
	Timeout   map[string]time.Duration
	Pipelines map[string][]string
	Paths     []string
}

// Step is step (from 1) of pipeline; false when the configuration has no
// such step.
func (lk *Lukd) Step(pipeline string, step int) (StepDef, bool) {
	ss := lk.Steps[pipeline]
	if step < 1 || step > len(ss) {
		return StepDef{}, false
	}
	return ss[step-1], true
}

func emptyLukd() *Lukd {
	return &Lukd{Steps: map[string][]StepDef{}, Timeout: map[string]time.Duration{}, Pipelines: map[string][]string{}}
}

// stepRun reads the run of a step into d: a string is the program, which
// must be an absolute path, a mapping of exactly job: <name> the job; an
// absent run sets neither.
func stepRun(n *yaml.Node, d *StepDef) error {
	switch {
	case n.Kind == 0:
		return nil
	case n.Kind == yaml.ScalarNode && n.Tag == "!!str" && filepath.IsAbs(n.Value):
		d.Program = n.Value
		return nil
	case n.Kind == yaml.MappingNode && len(n.Content) == 2 && n.Content[0].Value == "job" &&
		n.Content[1].Kind == yaml.ScalarNode && n.Content[1].Tag == "!!str" && n.Content[1].Value != "":
		d.Job = n.Content[1].Value
		return nil
	}
	return errors.New("run must be an absolute path or {job: NAME}")
}

// pipelineTimeout is the timeout of a pipeline: config.DefaultPipelineTimeout
// when absent or 0, else at least 1s and under config.MaxPipelineTimeout.
func pipelineTimeout(n *yaml.Node) (time.Duration, error) {
	var d config.Duration
	if n.Kind != 0 {
		if err := n.Decode(&d); err != nil {
			return 0, err
		}
	}
	if d == 0 {
		return config.DefaultPipelineTimeout, nil
	}
	if time.Duration(d) < time.Second {
		return 0, fmt.Errorf("%v: less than 1s", time.Duration(d))
	}
	if time.Duration(d) >= config.MaxPipelineTimeout {
		return 0, fmt.Errorf("must be under %v", config.MaxPipelineTimeout)
	}
	return time.Duration(d), nil
}

// LoadJobPipelines is the Pipelines of LoadLukd.
func LoadJobPipelines(p, top string, owner uint32) (map[string][]string, error) {
	lk, err := LoadLukd(p, top, owner)
	if err != nil {
		return nil, err
	}
	return lk.Pipelines, nil
}

// LoadLukd reads the steps, the timeouts and the paths of the lukd
// configuration: the main file p and the *.yaml of config.d next to it
// (dotfiles left out, in lexical order), as lukd loads them. The steps
// keep only what lukd run starts (see StepDef). The pipelines of a job
// are those with a step relay: <job> and those with a run step whose
// jobs lists it; the paths are the root of the merged configuration
// (config.DefaultRoot when no file sets it) and those of every file (see
// jobsFile.paths). A missing p (or a missing directory above it) allows
// nothing. Every directory from top down to config.d, p and the snippets
// must pass the checks of run.d (CheckParents, readSafe) for owner; a
// refused or malformed file (a run, env, jobs or timeout of the wrong
// type, a timeout out of range or a reserved env name included), too
// many snippets or a pipeline defined in two files or a step with both
// run and relay (an error of lukd as well) refuse the whole
// configuration.
func LoadLukd(p, top string, owner uint32) (*Lukd, error) {
	dir := filepath.Dir(p)
	if err := CheckParents(dir, top, owner); errors.Is(err, os.ErrNotExist) {
		return emptyLukd(), nil
	} else if err != nil {
		return nil, err
	}
	b, err := readSafe(p, owner, maxConfigFile)
	if errors.Is(err, os.ErrNotExist) {
		return emptyLukd(), nil
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
	lk := emptyLukd()
	rs := lk.Pipelines
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
			lk.Timeout[name] = config.DefaultPipelineTimeout
			if pl == nil {
				continue
			}
			if lk.Timeout[name], err = pipelineTimeout(&pl.Timeout); err != nil {
				return nil, fmt.Errorf("%s: pipeline %s: timeout: %w", f, name, err)
			}
			steps := make([]StepDef, len(pl.Steps))
			for i, s := range pl.Steps {
				bad := func(err error) error { return fmt.Errorf("%s: pipeline %s: step %d: %w", f, name, i+1, err) }
				d := &steps[i]
				if s.Run.Kind != 0 && s.Relay != "" {
					return nil, bad(errors.New("more than one of run and relay"))
				}
				if err := stepRun(&s.Run, d); err != nil {
					return nil, bad(err)
				}
				if s.Env.Kind != 0 {
					if err := s.Env.Decode(&d.Env); err != nil {
						return nil, bad(fmt.Errorf("env: %w", err))
					}
				}
				if s.Jobs.Kind != 0 {
					if err := s.Jobs.Decode(&d.Jobs); err != nil {
						return nil, bad(fmt.Errorf("jobs: %w", err))
					}
				}
				d.Relay = s.Relay
				var jobs []string
				if s.Relay != "" {
					jobs = append(jobs, s.Relay)
				}
				// lukd refuses jobs on any other step.
				if s.Run.Kind != 0 {
					jobs = append(jobs, d.Jobs...)
				}
				// Only a run program asks for nested jobs and has an env.
				if d.Program == "" {
					d.Jobs, d.Env = nil, nil
				}
				// The rule of lukd for the env of a step.
				for _, k := range sortedKeys(d.Env) {
					if strings.HasPrefix(k, "LUK_") {
						return nil, bad(fmt.Errorf("env.%s: LUK_* names are reserved", k))
					}
				}
				// The steps of one pipeline come one after the other: a
				// job it already allows ends in name.
				for _, j := range jobs {
					if ps := rs[j]; len(ps) == 0 || ps[len(ps)-1] != name {
						rs[j] = append(ps, name)
					}
				}
			}
			lk.Steps[name] = steps
		}
	}
	for _, ps := range rs {
		slices.Sort(ps)
	}
	if root = cmp.Or(root, config.DefaultRoot); filepath.IsAbs(root) {
		paths = append(paths, filepath.Clean(root))
	}
	slices.Sort(paths)
	lk.Paths = slices.Compact(paths)
	return lk, nil
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
