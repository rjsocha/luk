package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"

	"luk/internal/config"
	"luk/internal/gpgkeys"
)

// lookupUser resolves the service user to its uid and its gids (primary
// first); replaced by tests.
var lookupUser = func(name string) (int, []int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return 0, nil, err
	}
	gids := []int{}
	for _, id := range append([]string{u.Gid}, ids...) {
		if g, err := strconv.Atoi(id); err == nil && !slices.Contains(gids, g) {
			gids = append(gids, g)
		}
	}
	return uid, gids, nil
}

// inputs lists what lukd reads of cfg: files it opens, and directories it
// lists (they need read and search permission). Paths that do not exist
// are left out: their absence is reported elsewhere, if it matters.
func inputs(cfg *config.Config) (files, dirs []string) {
	dir := filepath.Dir(cfg.Path)
	dirs = []string{
		filepath.Join(dir, config.SnippetDir),
		filepath.Join(dir, config.SSHDir),
		filepath.Join(dir, config.SSHDir, "ca"),
		filepath.Join(dir, config.SSHDir, "ca", "host"),
		filepath.Join(dir, config.SSHDir, "ca", "user"),
	}
	files = append(files, cfg.Files...)
	if cfg.IdentityPath != "" {
		files = append(files, cfg.IdentityPath)
	}
	for _, name := range cfg.ListenNames() {
		t := cfg.Listen[name].TLS
		if t == nil {
			continue
		}
		switch t.Mode {
		case "self", "files":
			files = append(files, t.Cert, t.Key)
		case "acme":
			if t.EAB.KeyFile != "" {
				files = append(files, t.EAB.KeyFile)
			}
		}
	}
	if k := cfg.GPG.Keys; k != "" {
		dirs = append(dirs, k)
		if keys, err := gpgkeys.KeyFiles(k); err == nil {
			files = append(files, keys...)
		}
	}
	if d := cfg.PasswordDir; d != "" {
		for _, n := range cfg.PasswordNames() {
			files = append(files, filepath.Join(d, n))
		}
	}
	seen := map[string]bool{}
	keep := func(p string) bool {
		if p == "" || seen[p] {
			return false
		}
		seen[p] = true
		_, err := os.Stat(p)
		return !errors.Is(err, fs.ErrNotExist)
	}
	files = slices.DeleteFunc(files, func(p string) bool { return !keep(p) })
	dirs = slices.DeleteFunc(dirs, func(p string) bool { return !keep(p) })
	return files, dirs
}

// permits reports whether uid with gids has the permission bits want (4
// read, 1 search) on fi, by the owner, group and other bits; uid 0 has
// them all. ACLs are not read.
func permits(fi fs.FileInfo, uid int, gids []int, want fs.FileMode) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if uid == 0 {
		return true
	}
	perm := fi.Mode().Perm()
	switch {
	case int(st.Uid) == uid:
		perm >>= 6
	case slices.Contains(gids, int(st.Gid)):
		perm >>= 3
	}
	return perm&want == want
}

// unreadable checks that the user uid with gids can read every file and
// list every directory of files and dirs, with search permission on each
// directory above them, and returns one error per problem.
func unreadable(files, dirs []string, name string, uid int, gids []int) []error {
	var errs []error
	seen := map[string]bool{}
	check := func(p string, want fs.FileMode, what string) bool {
		fi, err := os.Stat(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			return false
		}
		if !permits(fi, uid, gids, want) {
			errs = append(errs, fmt.Errorf("%s: not %s by %s", p, what, name))
			return false
		}
		return true
	}
	// above checks the directories above p, each once.
	above := func(p string) bool {
		abs, err := filepath.Abs(p)
		if err != nil {
			errs = append(errs, err)
			return false
		}
		var parents []string
		for d := filepath.Dir(abs); ; d = filepath.Dir(d) {
			parents = append(parents, d)
			if d == filepath.Dir(d) {
				break
			}
		}
		for i := len(parents) - 1; i >= 0; i-- {
			d := parents[i]
			if ok, done := seen[d]; done {
				if !ok {
					return false
				}
				continue
			}
			seen[d] = check(d, 1, "searchable")
			if !seen[d] {
				return false
			}
		}
		return true
	}
	for _, d := range dirs {
		if above(d) {
			check(d, 5, "readable")
		}
	}
	for _, f := range files {
		if above(f) {
			check(f, 4, "readable")
		}
	}
	return errs
}

// checkReadable is the part of lukd check run as root: every input of
// cfg must be readable by the service user, as lukd runs.
func checkReadable(cfg *config.Config, name string) []error {
	uid, gids, err := lookupUser(name)
	if err != nil {
		return []error{fmt.Errorf("service user %s: %w", name, err)}
	}
	files, dirs := inputs(cfg)
	return unreadable(files, dirs, name, uid, gids)
}
