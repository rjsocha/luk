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

	"gopkg.in/yaml.v3"

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
	// RunDir holds the socket of lukd run, the nonce cache and the
	// volatile secrets; a job never sees it.
	RunDir = "/run/luk"
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
	// Config is the main file of the lukd configuration (see LoadJobPipelines).
	Config string `yaml:"config"`
	// Hide lists further absolute paths a job must not see (see Box).
	Hide []string `yaml:"hide"`
}

// Job is one file of run.d. The pipelines that may run it come from the
// lukd configuration (see LoadJobPipelines).
type Job struct {
	User        string            `yaml:"user"`
	Group       string            `yaml:"group"`
	Groups      []string          `yaml:"groups"`
	Command     string            `yaml:"command"`
	Credentials map[string]string `yaml:"credentials"`
	Timeout     config.Duration   `yaml:"timeout"`
	Env         map[string]string `yaml:"env"`
	State       string            `yaml:"state"`
	// RemovedPipelines catches the key replaced by the jobs of the run
	// steps, so the error names the new place.
	// A node, so a null value counts as well.
	RemovedPipelines yaml.Node `yaml:"pipelines"`
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

// CheckParents requires every directory from top (/ when empty) down to
// dir, both included, to be a directory (not a symlink) owned by owner and
// not writable by group or others (checkSafe), so nobody else can replace
// what lies below. dir must be top or below it.
func CheckParents(dir, top string, owner uint32) error {
	if top == "" {
		top = "/"
	}
	rel, err := filepath.Rel(top, filepath.Clean(dir))
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return fmt.Errorf("%s: not under %s", dir, top)
	}
	p := top
	for _, name := range append([]string{""}, strings.Split(rel, string(filepath.Separator))...) {
		if name != "." {
			p = filepath.Join(p, name)
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s: not a directory", p)
		}
		if err := checkSafe(fi, owner); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

// readSafe reads a regular file (no symlink) of at most max bytes that
// passes checkSafe.
func readSafe(p string, owner uint32, max int) ([]byte, error) {
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
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err == nil && len(b) > max {
		err = fmt.Errorf("%s: larger than %d bytes", p, max)
	}
	return b, err
}

// LoadGlobal reads run.yaml; a missing file gives the defaults.
func LoadGlobal(p string, owner uint32) (*Global, error) {
	g := &Global{}
	b, err := readSafe(p, owner, maxFile)
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
	if g.Config == "" {
		g.Config = DefaultLukdConfig
	}
	if !filepath.IsAbs(g.Config) {
		return nil, fmt.Errorf("%s: config %q: not absolute", p, g.Config)
	}
	g.Config = filepath.Clean(g.Config)
	for i, h := range g.Hide {
		if !filepath.IsAbs(h) {
			return nil, fmt.Errorf("%s: hide %q: not absolute", p, h)
		}
		g.Hide[i] = filepath.Clean(h)
	}
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
	b, err := readSafe(p, owner, maxFile)
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
	// A step waits for its job at most the pipeline timeout, which is
	// under config.MaxPipelineTimeout; lukd-run@.service has
	// RuntimeMaxSec above twice that.
	if time.Duration(j.Timeout) >= config.MaxPipelineTimeout {
		bad("timeout: must be under %v", config.MaxPipelineTimeout)
	}
	if j.RemovedPipelines.Kind != 0 {
		bad("pipelines: removed: list the job in jobs of the run step of the lukd configuration, a relay step allows its own job")
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

// SupplementaryGroups is peerGroup, the primary group of the peer that
// owns the work directory, followed by the groups of the job, without
// duplicates.
func (j *Job) SupplementaryGroups(peerGroup string) []string {
	gs := []string{peerGroup}
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

// Box is the sandbox of a job (see Job.Argv): the root of run.yaml, the
// directory of the lukd configuration, further paths to hide (hide of
// run.yaml, Lukd.Paths), the lukd binary that checks the work directory
// inside the unit and the identity of the work directory CheckWork
// accepted.
type Box struct {
	Root    string
	Config  string
	Hide    []string
	Checker string
	Work    Inode
}

// Argv is the systemd-run command line of job name on work (a step of
// pipeline) as unit. peerGroup (a name or a numeric gid) is the primary
// group of the peer; without a user the job gets a dynamic user per job
// and pipeline. vars is the LUK_* metadata of work (runstep.Vars), set
// after the job's env and before LUK_JOB, LUK_TMP and LUK_STATE, one
// --setenv argument each. The job sees nothing of box but work, at the
// same path (see sandbox). The unit runs box.Checker run check-work, which
// checks work inside the namespace and then executes command work in its
// place, with the environment of the unit.
func (j *Job) Argv(box *Box, unit, name, pipeline, work, peerGroup string, vars []string) ([]string, error) {
	sb, err := j.sandbox(box, name, pipeline, work)
	if err != nil {
		return nil, err
	}
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
	a = append(a, "-p", "SupplementaryGroups="+strings.Join(j.SupplementaryGroups(peerGroup), " "))
	a = append(a, "-p", "PrivateTmp=yes")
	a = append(a, sb...)
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
	return append(a, box.Checker, "run", CheckWorkCmd, box.Root, work,
		strconv.FormatUint(box.Work.Dev, 10), strconv.FormatUint(box.Work.Ino, 10), "--", j.Command, work), nil
}

// systemDirs may be neither the root nor the directory of the lukd
// configuration: the job would lose the system below them.
var systemDirs = []string{
	"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root",
	"/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/usr/bin", "/usr/lib", "/usr/local",
	"/usr/sbin", "/usr/share", "/var", "/var/cache", "/var/lib", "/var/log", "/var/tmp",
}

// under reports whether p is d or below it.
func under(p, d string) bool {
	return p == d || strings.HasPrefix(p, d+"/")
}

// sandbox is the part of the unit of a job that hides what the group of
// the peer may read. The directory of the lukd configuration (identity
// key, passwords, TLS settings), RunDir and the paths of box.Hide outside
// both and the root become inaccessible; the root (keys, storages,
// queues, other work directories) an empty read-only tmpfs with only work
// bound back, read-write and at the same path, so LUK_WORK, LUK_IN,
// LUK_OUT and LUK_META stay valid. luk may swap a directory above work
// for a symlink after CheckWork, and systemd binds what the path resolves
// to, for each process of the unit on its own: so the check of work
// inside the namespace is the process of the job itself (see Argv),
// which becomes the command only after it. The processes of other users
// are hidden. The credentials of the job are read by systemd before the
// namespace is set up.
func (j *Job) sandbox(box *Box, name, pipeline, work string) ([]string, error) {
	for _, p := range []string{box.Root, box.Config, work, box.Checker} {
		if err := unitPath(p); err != nil {
			return nil, err
		}
	}
	for _, d := range []struct{ what, path string }{{"root", box.Root}, {"configuration directory", box.Config}} {
		if slices.Contains(systemDirs, d.path) {
			return nil, fmt.Errorf("%s %s: a system directory, a job cannot run without it", d.what, d.path)
		}
	}
	if !strings.HasPrefix(work, box.Root+"/") {
		return nil, fmt.Errorf("work %q: not under %s", work, box.Root)
	}
	hidden := []string{box.Config, RunDir}
	var hide []string
	for _, h := range slices.Sorted(slices.Values(box.Hide)) {
		if slices.ContainsFunc(slices.Concat(hidden, []string{box.Root}), func(d string) bool { return under(h, d) }) {
			continue
		}
		if err := unitPath(h); err != nil {
			return nil, err
		}
		if slices.Contains(systemDirs, h) {
			return nil, fmt.Errorf("hidden path %s: a system directory, a job cannot run without it", h)
		}
		hide = append(hide, h)
		hidden = append(hidden, h)
	}
	keep := map[string]string{"work": work, "command": j.Command, "checker": box.Checker}
	if j.State != "" {
		keep["state directory"] = StatePath(name, pipeline)
	}
	for _, what := range sortedKeys(keep) {
		for _, d := range slices.Concat(hidden, []string{box.Root}) {
			if d == box.Root && what == "work" {
				continue
			}
			if under(keep[what], d) {
				return nil, fmt.Errorf("%s %s: hidden from the job under %s", what, keep[what], d)
			}
		}
	}
	a := []string{"-p", "ProtectProc=invisible"}
	for _, h := range append([]string{box.Config, RunDir}, hide...) {
		a = append(a, "-p", "InaccessiblePaths=-"+h)
	}
	return append(a,
		"-p", "TemporaryFileSystem="+box.Root+":ro",
		"-p", "BindPaths="+work+":"+work+":norbind",
	), nil
}

// unitPath requires p to be a clean absolute path other than / without a
// character systemd-run splits, unquotes or expands in a property
// (white space, quotes, backslash, colon, $, %) or a control character.
func unitPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return fmt.Errorf("path %q: not a clean absolute path below /", p)
	}
	if strings.ContainsFunc(p, func(r rune) bool { return unsafePathRune(r) || strings.ContainsRune(`"'\\:`, r) }) {
		return fmt.Errorf("path %q: control character, white space, quote, backslash, colon, $ or %% in the path", p)
	}
	return nil
}
