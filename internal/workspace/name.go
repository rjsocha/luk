// Package workspace holds the root helpers of lukd run: the names of the
// units, and the helper units that create, own and remove the workspace
// of a unit, a btrfs subvolume <root>/root/job/<unit>, plus the count of
// the workspaces they could not remove. Every helper takes a unit name,
// never a path, and opens everything by descriptor without following a
// symlink.
package workspace

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	// JobDir holds the workspaces: <root>/root/job.
	JobDir = "job"
	// MaxUnit caps the length of a workspace unit name.
	MaxUnit = 240
	// CountDir holds the count of leftover workspaces and its lock.
	CountDir = "/run/luk/workspaces"
	// CountName is the count file in CountDir.
	CountName = "count.json"
	// LockName is the lock file of the count in CountDir.
	LockName = "lock"
)

var unitPattern = regexp.MustCompile(`^lukd-(run|step)-[a-z0-9-]+-[0-9a-f]{12}$`)

// ValidUnit reports whether u names the unit of a workspace: a job unit
// or the unit of a run program.
func ValidUnit(u string) bool { return len(u) <= MaxUnit && unitPattern.MatchString(u) }

// Mangle lowercases s and replaces every character outside [a-z0-9-]
// with '-'.
func Mangle(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, strings.ToLower(s))
}

func random12() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// JobUnit is a fresh unit name for the job job.
func JobUnit(job string) string { return "lukd-run-" + Mangle(job) + "-" + random12() }

// StepUnit is a fresh unit name for the run program of step step of
// pipeline.
func StepUnit(pipeline string, step int) string {
	return "lukd-step-" + Mangle(pipeline) + "-" + strconv.Itoa(step) + "-" + random12()
}

// HelperUnit is a fresh unit name for a helper unit.
func HelperUnit() string { return "lukd-workspace-" + random12() }

// Path is the workspace of unit below root.
func Path(root, unit string) string { return filepath.Join(root, "root", JobDir, unit) }
