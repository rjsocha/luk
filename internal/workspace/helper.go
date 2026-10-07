package workspace

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"luk/internal/btrfs"
)

// ErrBusy marks a workspace still mounted somewhere (EBUSY): a process
// stuck in I/O or a container holding a bind of it.
var ErrBusy = errors.New("workspace busy")

func busy(err error) error { return fmt.Errorf("%w: %w", ErrBusy, err) }

var errName = errors.New("workspace: invalid unit name")

// isBtrfs is btrfs.IsBtrfsFd, replaced by tests.
var (
	btrfsIsBtrfsFd = btrfs.IsBtrfsFd
	isBtrfs        = btrfsIsBtrfsFd
)

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// OpenChain opens dir from top element by element with
// O_DIRECTORY|O_NOFOLLOW, every element a directory owned by owner and
// not writable by group or others, so nobody else can swap what lies
// below. dir must be a clean absolute path, top or below it.
func OpenChain(top, dir string, owner uint32) (*os.File, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, fmt.Errorf("%s: not a clean absolute path", dir)
	}
	rel, err := filepath.Rel(top, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, fmt.Errorf("%s: not under %s", dir, top)
	}
	fd, err := unix.Open(top, dirFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: top, Err: err}
	}
	p := top
	if err := checkDir(fd, p, owner); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if rel != "." {
		for _, name := range strings.Split(rel, "/") {
			p = filepath.Join(p, name)
			next, err := unix.Openat(fd, name, dirFlags, 0)
			unix.Close(fd)
			if err != nil {
				return nil, &os.PathError{Op: "open", Path: p, Err: err}
			}
			fd = next
			if err := checkDir(fd, p, owner); err != nil {
				unix.Close(fd)
				return nil, err
			}
		}
	}
	return os.NewFile(uintptr(fd), dir), nil
}

// checkDir requires the directory fd at p to be owned by owner and not
// writable by group or others.
func checkDir(fd int, p string, owner uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "stat", Path: p, Err: err}
	}
	if st.Uid != owner {
		return fmt.Errorf("%s: owned by uid %d, want %d", p, st.Uid, owner)
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("%s: writable by group or others", p)
	}
	return nil
}

// Create makes the empty workspace of unit, root:root 0700, below
// <root>/root/job, creating job/ (0711) on demand. Everything is opened by
// descriptor; the path comes from root of run.yaml and the unit name only.
func Create(top, root, unit string, owner uint32) error {
	if !ValidUnit(unit) {
		return errName
	}
	parent, err := OpenChain(top, filepath.Join(root, "root"), owner)
	if err != nil {
		return err
	}
	defer parent.Close()
	group := groupOf(owner)
	if err := checkGroup(int(parent.Fd()), parent.Name(), group); err != nil {
		return err
	}
	jobPath := filepath.Join(root, "root", JobDir)
	made := true
	if err := unix.Mkdirat(int(parent.Fd()), JobDir, 0o711); errors.Is(err, unix.EEXIST) {
		made = false
	} else if err != nil {
		return fmt.Errorf("%s: %w", jobPath, err)
	}
	jfd, err := unix.Openat(int(parent.Fd()), JobDir, dirFlags, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: jobPath, Err: err}
	}
	job := os.NewFile(uintptr(jfd), jobPath)
	defer job.Close()
	// mkdirat honours the umask (0077 in the helper unit), and a setgid
	// parent would pass on its bit: set the mode.
	if made {
		if err := unix.Fchmod(jfd, 0o711); err != nil {
			return fmt.Errorf("%s: %w", jobPath, err)
		}
	}
	if err := checkDir(jfd, jobPath, owner); err != nil {
		return err
	}
	if err := checkGroup(jfd, jobPath, group); err != nil {
		return err
	}
	if ok, err := isBtrfs(int(job.Fd())); err != nil {
		return fmt.Errorf("%s: %w", job.Name(), err)
	} else if !ok {
		return fmt.Errorf("%s: not a btrfs filesystem", job.Name())
	}
	if err := btrfs.CreateSubvolume(int(job.Fd()), unit); err != nil {
		return err
	}
	ws, err := unix.Openat(int(job.Fd()), unit, dirFlags, 0)
	if err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	defer unix.Close(ws)
	// The umask of the helper applies to the new subvolume too.
	if err := unix.Fchown(ws, int(owner), int(group)); err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	if err := unix.Fchmod(ws, 0o700); err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	return nil
}

// groupOf is the group that goes with owner: root's group 0 in
// production, the own group of the user running the tests otherwise.
func groupOf(owner uint32) uint32 {
	if owner == 0 {
		return 0
	}
	return uint32(os.Getgid())
}

// checkGroup requires the directory fd at p to belong to group gid.
func checkGroup(fd int, p string, gid uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "stat", Path: p, Err: err}
	}
	if st.Gid != gid {
		return fmt.Errorf("%s: group %d, want %d", p, st.Gid, gid)
	}
	return nil
}

// Own makes the fresh workspace of unit the unit user's: the UID and GID
// systemd allocated to the unit, mode 0700. The path is the
// WorkingDirectory of the unit, accepted only as <...>/root/job/<unit>
// and opened with the chain rule; the workspace must be a subvolume, still
// root:root (owner and its group in tests) 0700 and empty, so a wrong WorkingDirectory
// never hands another directory to the unit.
func Own(top, unit string, owner uint32, show Show) error {
	if !ValidUnit(unit) {
		return errName
	}
	p, err := show(unit, "UID", "GID", "WorkingDirectory")
	if err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	uid, err := unitID(p, "UID")
	if err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	gid, err := unitID(p, "GID")
	if err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	wd := p["WorkingDirectory"]
	if !filepath.IsAbs(wd) || filepath.Clean(wd) != wd || filepath.Base(wd) != unit ||
		filepath.Base(filepath.Dir(wd)) != JobDir || filepath.Base(filepath.Dir(filepath.Dir(wd))) != "root" {
		return fmt.Errorf("workspace %s: working directory %q is not the workspace of %s", unit, wd, unit)
	}
	ws, err := OpenChain(top, wd, owner)
	if err != nil {
		return err
	}
	defer ws.Close()
	fd := int(ws.Fd())
	if ok, err := btrfs.IsSubvolume(fd); err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	} else if !ok {
		return fmt.Errorf("workspace %s: not a btrfs subvolume", unit)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	if st.Uid != owner || st.Gid != groupOf(owner) || st.Mode&0o7777 != 0o700 {
		return fmt.Errorf("workspace %s: not a fresh workspace (%d:%d %#o)", unit, st.Uid, st.Gid, st.Mode&0o7777)
	}
	if empty, err := emptyDir(fd); err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	} else if !empty {
		return fmt.Errorf("workspace %s: not empty", unit)
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	return nil
}

// unitID is the numeric UID or GID key of a systemctl show; -1, which
// fchown reads as "keep", is refused.
func unitID(p map[string]string, key string) (uint32, error) {
	n, err := strconv.ParseUint(p[key], 10, 32)
	if err != nil || n == 1<<32-1 {
		return 0, fmt.Errorf("unit %s %q: not a number", key, p[key])
	}
	return uint32(n), nil
}

// emptyDir reports whether the directory fd has no entry besides . and
// .. (read through a duplicate of fd).
func emptyDir(fd int) (bool, error) {
	f, err := dupDir(fd)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

func dupDir(fd int) (*os.File, error) {
	d, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(d), "."), nil
}

// Remove deletes the workspace of unit once its unit is inactive: every
// subvolume below it, leaves first, then the workspace, each by its id.
// A missing workspace is no error; a mounted one gives ErrBusy.
func Remove(top, root, unit string, owner uint32, show Show) error {
	if !ValidUnit(unit) {
		return errName
	}
	if err := checkInactive(unit, show); err != nil {
		return err
	}
	job, err := OpenChain(top, filepath.Join(root, "root", JobDir), owner)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer job.Close()
	return destroy(job, unit)
}

func checkInactive(unit string, show Show) error {
	p, err := show(unit, "LoadState", "ActiveState")
	if err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	if !Inactive(p) {
		return fmt.Errorf("workspace %s: unit still active", unit)
	}
	return nil
}

// destroy deletes the workspace unit of the directory job. Destroy by id
// reaches any subvolume of the filesystem, so only the ids found below
// the workspace are destroyed, and the workspace only when it is a
// subvolume directly inside the subvolume of job/; the name must lie on
// the mount of job/, so nothing mounted over it counts (EXDEV).
func destroy(job *os.File, unit string) error {
	jfd := int(job.Fd())
	// openat, not openat2: the seccomp filter of RestrictSUIDSGID=yes
	// refuses openat2 with ENOSYS.
	ws, err := unix.Openat(jfd, unit, dirFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	if err := sameMount(jfd, ws); err != nil {
		unix.Close(ws)
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	ids, err := below(jfd, ws, job.Name())
	unix.Close(ws)
	if err != nil {
		return fmt.Errorf("workspace %s: %w", unit, err)
	}
	for _, id := range ids {
		if err := btrfs.DestroyByID(jfd, id); err != nil {
			err = fmt.Errorf("workspace %s: %w", unit, err)
			if errors.Is(err, unix.EBUSY) {
				return busy(err)
			}
			return err
		}
	}
	return nil
}

// sameMount refuses with EXDEV unless the directories a and b lie on the
// same mount (statx STATX_MNT_ID).
func sameMount(a, b int) error {
	ma, err := mountID(a)
	if err != nil {
		return err
	}
	mb, err := mountID(b)
	if err != nil {
		return err
	}
	if ma != mb {
		return fmt.Errorf("on another mount: %w", unix.EXDEV)
	}
	return nil
}

func mountID(fd int) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st); err != nil {
		return 0, fmt.Errorf("statx: %w", err)
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, errors.New("statx: no mount id")
	}
	return st.Mnt_id, nil
}

// below lists the subvolumes to destroy for the workspace ws in the
// directory job: those inside it, leaves first, then ws itself.
func below(job, ws int, name string) ([]uint64, error) {
	if ok, err := btrfs.IsSubvolume(ws); err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("not a btrfs subvolume")
	}
	id, err := btrfs.SubvolumeID(ws)
	if err != nil {
		return nil, err
	}
	parent, err := btrfs.SubvolumeID(job)
	if err != nil {
		return nil, err
	}
	children, err := btrfs.Children(job, parent)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(children, id) {
		return nil, fmt.Errorf("not a subvolume of %s", name)
	}
	ds, err := btrfs.Descendants(job, id)
	if err != nil {
		return nil, err
	}
	return append(ds, id), nil
}

// Prune removes, as Remove does, every workspace of <root>/root/job whose
// unit is inactive and whose lock (see Hold, below the lock directory
// locks of lukd run) is free, and returns how many it could not remove,
// counting one whose unit is still active without lukd run holding its
// lock; an entry not named like a workspace is logged and left alone. A
// missing job/ leaves nothing.
func Prune(top, root, locks string, owner uint32, show Show, log *slog.Logger) (left int, err error) {
	job, err := OpenChain(top, filepath.Join(root, "root", JobDir), owner)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer job.Close()
	d, err := dupDir(int(job.Fd()))
	if err != nil {
		return 0, err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", job.Name(), err)
	}
	slices.Sort(names)
	for _, name := range names {
		if !ValidUnit(name) {
			log.Info("workspace prune: not a workspace", "name", name)
			continue
		}
		used, err := pruneOne(job, locks, name, show)
		if used {
			log.Info("workspace prune: in use", "unit", name)
			continue
		}
		if err != nil {
			left++
			log.Warn("workspace not removed", "unit", name, "error", err)
		}
	}
	return left, nil
}

// pruneOne removes the workspace name of job unless lukd run holds its
// lock (used); a unit that is not inactive leaves it as an error.
func pruneOne(job *os.File, locks, name string, show Show) (used bool, err error) {
	lock, free, err := tryLock(locks, name)
	if err != nil {
		return false, err
	}
	if !free {
		return true, nil
	}
	if lock != nil {
		defer lock.Close()
	}
	if err := checkInactive(name, show); err != nil {
		return false, err
	}
	return false, destroy(job, name)
}

// helperProperties is the sandbox of every helper unit.
var helperProperties = []string{
	"ProtectSystem=strict",
	"CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER",
	"PrivateNetwork=yes",
	"RestrictAddressFamilies=AF_UNIX",
	"NoNewPrivileges=yes",
	"ProtectHome=yes",
	"PrivateTmp=yes",
	"PrivateDevices=yes",
	"ProtectKernelTunables=yes",
	"ProtectKernelModules=yes",
	"ProtectKernelLogs=yes",
	"ProtectControlGroups=yes",
	"ProtectProc=invisible",
	"RestrictNamespaces=yes",
	"RestrictSUIDSGID=yes",
	"LockPersonality=yes",
	"MemoryDenyWriteExecute=yes",
	"SystemCallArchitectures=native",
	"UMask=0077",
}

// HelperTimeout is RuntimeMaxSec of a create or remove helper unit: a
// helper that hangs (btrfs I/O stuck) is killed then, so it cannot hold
// the slot of a step.
const HelperTimeout = 5 * time.Minute

// HelperArgv is the systemd-run command of the helper unit that runs
// `<lukd> run workspace <action> <unit>`, action create or remove: the
// fixed sandbox, RuntimeMaxSec=HelperTimeout, write access to
// <root>/root for create and to <root>/root/job and the count for remove.
func HelperArgv(lukd, root, action, unit string) []string {
	argv := []string{"systemd-run", "--wait", "--collect", "--quiet", "--unit=" + HelperUnit()}
	for _, p := range helperProperties {
		argv = append(argv, "-p", p)
	}
	argv = append(argv, "-p", "RuntimeMaxSec="+strconv.Itoa(int(HelperTimeout/time.Second)))
	if action == "create" {
		argv = append(argv, "-p", "ReadWritePaths="+filepath.Join(root, "root"))
	} else {
		argv = append(argv, "-p", "ReadWritePaths=-"+filepath.Join(root, "root", JobDir), "-p", "ReadWritePaths=-"+CountDir)
	}
	return append(argv, lukd, "run", "workspace", action, unit)
}
