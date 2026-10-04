package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

const reexecEnv = "LUKD_REEXEC"

// geteuid and reexecAs are replaced by tests.
var (
	geteuid  = os.Geteuid
	reexecAs = reexec
)

type ownerAction int

const (
	ownerRun ownerAction = iota
	ownerReexec
	ownerDeny
)

// ownerDecision decides how a command that writes under root proceeds for
// the calling uid: the owner of root runs it, root runs it again as the
// owner (once: reexeced marks the second run), anyone else is refused.
func ownerDecision(uid, owner int, reexeced bool) ownerAction {
	switch {
	case uid == owner:
		return ownerRun
	case uid == 0 && !reexeced:
		return ownerReexec
	}
	return ownerDeny
}

// exitCode ends lukd with the code without printing anything.
type exitCode int

func (e exitCode) Error() string { return "exit status " + strconv.Itoa(int(e)) }

// asOwner lets the command proceed (nil), runs lukd again with the same
// arguments as the owner of root and returns its exit status as exitCode,
// or refuses. root must not be a symlink: the service user may replace a
// directory it owns with a link to one root owns.
func asOwner(cmdName, root string) error {
	fi, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: %s is a symlink", cmdName, root)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: no owner", root)
	}
	owner, gid := int(st.Uid), int(st.Gid)
	name, groups := strconv.Itoa(owner), []uint32(nil)
	if u, err := user.LookupId(strconv.Itoa(owner)); err == nil {
		name = u.Username
		if ids, err := u.GroupIds(); err == nil {
			for _, id := range ids {
				if g, err := strconv.ParseUint(id, 10, 32); err == nil {
					groups = append(groups, uint32(g))
				}
			}
		}
	}
	switch ownerDecision(geteuid(), owner, os.Getenv(reexecEnv) == "1") {
	case ownerRun:
		return nil
	case ownerReexec:
		return reexecAs(uint32(owner), uint32(gid), groups)
	}
	return fmt.Errorf("%s must run as root or as %s (owner of %s)", cmdName, name, root)
}

func reexec(uid, gid uint32, groups []uint32) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	c := exec.Command(exe, os.Args[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Env = append(os.Environ(), reexecEnv+"=1")
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
	err = c.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return exitCode(code)
		}
		return exitCode(1)
	}
	if err != nil {
		return err
	}
	return exitCode(0)
}
