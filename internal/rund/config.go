// Package rund is lukd run: the root helper that runs jobs of the admin
// allowlist as other users for luk run steps.
package rund

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"luk/internal/config"
)

const (
	// DefaultConfig holds the global settings (root, peer).
	DefaultConfig = "/etc/site/lukd/run.yaml"
	// DefaultJobs holds one <job>.yaml per job.
	DefaultJobs = "/etc/site/lukd/run.d"
	// DefaultTimeout bounds a job when `timeout` is absent.
	DefaultTimeout = time.Hour
	// JobExt ends the file name of a job.
	JobExt  = ".yaml"
	maxFile = 64 << 10
	// TmpDir is LUK_TMP: /var/tmp of the job, private to its unit.
	TmpDir = "/var/tmp"
	// StateDir holds the state directories, one per job and pipeline
	// (StateDirectory= relative to /var/lib).
	StateDir = "lukd-run"
	// StateLocked and StateShared are the values of `state`.
	StateLocked = "locked"
	StateShared = "shared"
	// maxUser is the length systemd recommends for a user name.
	maxUser = 31
)

var (
	account  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	credName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	envName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	nonUser  = regexp.MustCompile(`[^a-z0-9_-]+`)
)

// Global is run.yaml.
type Global struct {
	Root string `yaml:"root"`
	Peer string `yaml:"peer"`
}

// Job is one file of run.d.
type Job struct {
	User        string            `yaml:"user"`
	Group       string            `yaml:"group"`
	Groups      []string          `yaml:"groups"`
	Command     string            `yaml:"command"`
	Credentials map[string]string `yaml:"credentials"`
	Timeout     config.Duration   `yaml:"timeout"`
	Env         map[string]string `yaml:"env"`
	State       string            `yaml:"state"`
}

// checkSafe refuses a file or directory not owned by owner or writable by
// group or others.
func checkSafe(fi os.FileInfo, owner uint32) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no owner")
	}
	if st.Uid != owner {
		return fmt.Errorf("owned by uid %d, want %d", st.Uid, owner)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return errors.New("writable by group or others")
	}
	return nil
}

// readSafe reads a regular file (no symlink) that passes checkSafe.
func readSafe(p string, owner uint32) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", p)
	}
	if err := checkSafe(fi, owner); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err == nil && len(b) > maxFile {
		err = fmt.Errorf("%s: larger than %d bytes", p, maxFile)
	}
	return b, err
}

// LoadGlobal reads run.yaml; a missing file gives the defaults.
func LoadGlobal(p string, owner uint32) (*Global, error) {
	g := &Global{}
	b, err := readSafe(p, owner)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := config.DecodeStrict(b, g); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	if g.Root == "" {
		g.Root = config.DefaultRoot
	}
	if !filepath.IsAbs(g.Root) {
		return nil, fmt.Errorf("%s: root %q: not absolute", p, g.Root)
	}
	g.Root = filepath.Clean(g.Root)
	return g, nil
}

// PeerUID is the uid allowed to connect: `peer`, else the owner of root.
func (g *Global) PeerUID() (uint32, error) {
	if g.Peer == "" {
		fi, err := os.Stat(g.Root)
		if err != nil {
			return 0, err
		}
		return fi.Sys().(*syscall.Stat_t).Uid, nil
	}
	u, err := user.Lookup(g.Peer)
	if err != nil {
		return 0, fmt.Errorf("peer: %w", err)
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(id), err
}

// Ignored reports whether a file of run.d is not a job: not ending in
// .yaml, a dotfile or an editor or package manager leftover.
func Ignored(name string) bool {
	return strings.HasPrefix(name, ".") || !strings.HasSuffix(name, JobExt) ||
		strings.HasSuffix(name, "~") || strings.HasSuffix(name, ".swp") ||
		strings.Contains(name, ".dpkg-")
}

// Jobs is the allowlist read from run.d: the valid jobs and, per name, why
// a file was refused.
type Jobs struct {
	OK  map[string]*Job
	Bad map[string]error
}

// LoadJobs reads every job file of dir. The directory and the files must be
// owned by owner and not writable by group or others; a refused or
// malformed file disables only its job.
func LoadJobs(dir string, owner uint32) (*Jobs, error) {
	fi, err := os.Lstat(dir)
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
	js := &Jobs{OK: map[string]*Job{}, Bad: map[string]error{}}
	for _, e := range ents {
		if Ignored(e.Name()) {
			continue
		}
		name := strings.TrimSuffix(e.Name(), JobExt)
		if !config.ValidJobName(name) {
			js.Bad[name] = fmt.Errorf("%s: invalid job name", e.Name())
			continue
		}
		j, err := loadJob(filepath.Join(dir, e.Name()), owner)
		if err != nil {
			js.Bad[name] = err
			continue
		}
		js.OK[name] = j
	}
	return js, nil
}

func loadJob(p string, owner uint32) (*Job, error) {
	b, err := readSafe(p, owner)
	if err != nil {
		return nil, err
	}
	j := &Job{}
	if err := config.DecodeStrict(b, j); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if err := j.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return j, nil
}

func (j *Job) validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if j.User != "" && !account.MatchString(j.User) {
		bad("user %q: invalid", j.User)
	}
	if j.Group != "" && !account.MatchString(j.Group) {
		bad("group %q: invalid", j.Group)
	}
	if j.Group != "" && j.User == "" {
		bad("group %q: needs user", j.Group)
	}
	for _, g := range j.Groups {
		if !account.MatchString(g) {
			bad("groups: %q: invalid", g)
		}
	}
	if !filepath.IsAbs(j.Command) || filepath.Clean(j.Command) != j.Command {
		bad("command %q: not a clean absolute path", j.Command)
	}
	for n, p := range j.Credentials {
		if !credName.MatchString(n) {
			bad("credentials.%s: invalid name", n)
		}
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "\x00\n") {
			bad("credentials.%s: %q is not an absolute path", n, p)
		}
	}
	if j.Timeout == 0 {
		j.Timeout = config.Duration(DefaultTimeout)
	}
	if time.Duration(j.Timeout) < time.Second {
		bad("timeout: less than 1s")
	}
	if j.State != "" && j.State != StateLocked && j.State != StateShared {
		bad("state %q: want %s or %s", j.State, StateLocked, StateShared)
	}
	for k, v := range j.Env {
		if !envName.MatchString(k) {
			bad("env.%s: invalid name", k)
		}
		if strings.HasPrefix(k, "LUK_") {
			bad("env.%s: LUK_* names are reserved", k)
		}
		if strings.ContainsAny(v, "\x00\n") {
			bad("env.%s: NUL or newline in the value", k)
		}
	}
	return errors.Join(errs...)
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// SupplementaryGroups is workGroup, the group of the work directory,
// followed by the groups of the job, without duplicates.
func (j *Job) SupplementaryGroups(workGroup string) []string {
	gs := []string{workGroup}
	for _, g := range j.Groups {
		if !slices.Contains(gs, g) {
			gs = append(gs, g)
		}
	}
	return gs
}

// StatePath is LUK_STATE of job on pipeline, the path of
// StateDirectory=lukd-run/<job>/<pipeline>.
func StatePath(job, pipeline string) string {
	return filepath.Join("/var/lib", StateDir, job, pipeline)
}

// DynamicUser is the name of the dynamic user of job on pipeline:
// lukd-<job and pipeline, shortened>-<8 hex of sha256(job/pipeline)>, a
// valid user name of at most 31 characters. The same pair always gets the
// same name, and so the same UID, the owner of its state directory.
func DynamicUser(job, pipeline string) string {
	sum := sha256.Sum256([]byte(job + "/" + pipeline))
	h := hex.EncodeToString(sum[:4])
	r := nonUser.ReplaceAllString(strings.ToLower(job+"-"+pipeline), "_")
	if n := maxUser - len("lukd--") - len(h); len(r) > n {
		r = r[:n]
	}
	return "lukd-" + strings.TrimRight(r, "-") + "-" + h
}

// Argv is the systemd-run command line of job name on work (a step of
// pipeline) as unit. workGroup (a name or a numeric gid) is the group of
// work; without a user the job gets a dynamic user per job and pipeline.
// vars is the LUK_* metadata of work (runstep.Vars), set after the job's env and
// before LUK_JOB, LUK_TMP and LUK_STATE, one --setenv argument each.
func (j *Job) Argv(unit, name, pipeline, work, workGroup string, vars []string) []string {
	a := []string{"systemd-run", "--wait", "--collect", "--pipe", "--quiet", "--expand-environment=no", "--unit=" + unit}
	if j.User != "" {
		a = append(a, "--uid="+j.User)
	} else {
		a = append(a, "-p", "DynamicUser=yes", "-p", "User="+DynamicUser(name, pipeline))
	}
	a = append(a, "--working-directory="+work)
	if j.Group != "" {
		a = append(a, "--gid="+j.Group)
	}
	a = append(a, "-p", "SupplementaryGroups="+strings.Join(j.SupplementaryGroups(workGroup), " "))
	a = append(a, "-p", "PrivateTmp=yes")
	if j.State != "" {
		a = append(a, "-p", "StateDirectory="+StateDir+"/"+name+"/"+pipeline, "-p", "StateDirectoryMode=0700")
	}
	for _, n := range sortedKeys(j.Credentials) {
		a = append(a, "-p", "LoadCredential="+n+":"+j.Credentials[n])
	}
	a = append(a, "-p", "RuntimeMaxSec="+strconv.FormatInt(int64(time.Duration(j.Timeout)/time.Second), 10))
	for _, k := range sortedKeys(j.Env) {
		a = append(a, "--setenv="+k+"="+j.Env[k])
	}
	for _, kv := range vars {
		a = append(a, "--setenv="+kv)
	}
	a = append(a, "--setenv=LUK_JOB="+name, "--setenv=LUK_TMP="+TmpDir)
	if j.State != "" {
		a = append(a, "--setenv=LUK_STATE="+StatePath(name, pipeline))
	}
	return append(a, j.Command, work)
}
