package workspace

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"luk/internal/btrfs"
)

var me = uint32(os.Getuid())

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// notFound is the show of a unit systemd does not know.
func notFound(string, ...string) (map[string]string, error) {
	return map[string]string{"LoadState": "not-found", "ActiveState": "inactive"}, nil
}

// newRoot makes <top>/luk/root/job (0711) below a fresh top (0755) and
// returns top and <top>/luk.
func newRoot(t *testing.T) (top, root string) {
	t.Helper()
	top = t.TempDir()
	os.Chmod(top, 0o755)
	root = filepath.Join(top, "luk")
	if err := os.MkdirAll(filepath.Join(root, "root", JobDir), 0o711); err != nil {
		t.Fatal(err)
	}
	return top, root
}

func TestOpenChain(t *testing.T) {
	top := t.TempDir()
	os.Chmod(top, 0o755)
	dir := filepath.Join(top, "a", "b")
	os.MkdirAll(dir, 0o711)
	f, err := OpenChain(top, dir, me)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if f, err := OpenChain(top, top, me); err != nil {
		t.Fatalf("top itself: %v", err)
	} else {
		f.Close()
	}
	os.Chmod(filepath.Join(top, "a"), 0o777)
	if _, err := OpenChain(top, dir, me); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("writable: %v", err)
	}
	os.Chmod(filepath.Join(top, "a"), 0o755)
	link := filepath.Join(top, "l")
	os.Symlink(dir, link)
	if _, err := OpenChain(top, filepath.Join(link), me); err == nil {
		t.Fatal("symlink followed")
	}
	os.Symlink(filepath.Join(top, "a"), filepath.Join(top, "m"))
	if _, err := OpenChain(top, filepath.Join(top, "m", "b"), me); err == nil {
		t.Fatal("symlink in the middle followed")
	}
	if _, err := OpenChain(top, dir, me+1); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("owner: %v", err)
	}
	for _, d := range []string{"a/b", filepath.Dir(top), top + "/a/../a/b", top + "/a/b/"} {
		if _, err := OpenChain(top, d, me); err == nil {
			t.Errorf("%q opened", d)
		}
	}
	if _, err := OpenChain(top, filepath.Join(top, "none"), me); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}

func TestCreateRefusesNonBtrfs(t *testing.T) {
	isBtrfs = func(int) (bool, error) { return false, nil }
	t.Cleanup(func() { isBtrfs = btrfsIsBtrfsFd })
	top := t.TempDir()
	os.Chmod(top, 0o755)
	root := filepath.Join(top, "luk")
	os.MkdirAll(filepath.Join(root, "root"), 0o711)
	err := Create(top, root, "lukd-run-a-0123456789ab", me)
	if err == nil || !strings.Contains(err.Error(), "not a btrfs filesystem") {
		t.Fatalf("got %v", err)
	}
	fi, err := os.Lstat(filepath.Join(root, "root", "job"))
	if err != nil || fi.Mode().Perm() != 0o711 {
		t.Fatalf("job/ not made 0711: %v %v", fi, err)
	}
}

func TestHelpersRefuseNames(t *testing.T) {
	for _, u := range []string{"", "../x", "lukd-run-a", "/etc"} {
		if err := Create("/", "/var/lib/luk", u, 0); err == nil || err.Error() != "workspace: invalid unit name" {
			t.Errorf("create %q: %v", u, err)
		}
		if err := Remove("/", "/var/lib/luk", u, 0, nil); err == nil || err.Error() != "workspace: invalid unit name" {
			t.Errorf("remove %q: %v", u, err)
		}
		if err := Own("/", u, 0, nil); err == nil || err.Error() != "workspace: invalid unit name" {
			t.Errorf("own %q: %v", u, err)
		}
	}
}

func TestRemoveRefusesActiveUnit(t *testing.T) {
	show := func(string, ...string) (map[string]string, error) {
		return map[string]string{"LoadState": "loaded", "ActiveState": "deactivating"}, nil
	}
	err := Remove("/", "/var/lib/luk", "lukd-run-a-0123456789ab", 0, show)
	if err == nil || err.Error() != "workspace lukd-run-a-0123456789ab: unit still active" {
		t.Fatalf("got %v", err)
	}
}

func TestRemoveMissingAndPlainDirectory(t *testing.T) {
	top, root := newRoot(t)
	unit := "lukd-run-a-0123456789ab"
	if err := Remove(top, root, unit, me, notFound); err != nil {
		t.Fatalf("missing workspace: %v", err)
	}
	if err := Remove(top, filepath.Join(top, "none"), unit, me, notFound); err != nil {
		t.Fatalf("missing job/: %v", err)
	}
	os.Mkdir(Path(root, unit), 0o700)
	err := Remove(top, root, unit, me, notFound)
	if err == nil || err.Error() != "workspace "+unit+": not a btrfs subvolume" {
		t.Fatalf("plain directory: %v", err)
	}
	if _, err := os.Lstat(Path(root, unit)); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(root, "root"), 0o775)
	if err := Remove(top, root, unit, me, notFound); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("chain: %v", err)
	}
}

func TestPruneLeavesOtherEntries(t *testing.T) {
	top, root := newRoot(t)
	job := filepath.Join(root, "root", JobDir)
	os.WriteFile(filepath.Join(job, "other"), nil, 0o600)
	os.Mkdir(filepath.Join(job, "lukd-run-a-0123456789ab"), 0o700)
	os.Mkdir(filepath.Join(job, "lukd-run-b-0123456789ab"), 0o700)
	show := func(u string, _ ...string) (map[string]string, error) {
		if u == "lukd-run-b-0123456789ab" {
			return map[string]string{"LoadState": "loaded", "ActiveState": "active"}, nil
		}
		return notFound(u)
	}
	left, err := Prune(top, root, me, show, quiet)
	if err != nil || left != 1 {
		t.Fatalf("left %d: %v", left, err)
	}
	for _, n := range []string{"other", "lukd-run-a-0123456789ab", "lukd-run-b-0123456789ab"} {
		if _, err := os.Lstat(filepath.Join(job, n)); err != nil {
			t.Fatal(err)
		}
	}
	if left, err := Prune(top, filepath.Join(top, "none"), me, show, quiet); err != nil || left != 0 {
		t.Fatalf("missing job/: %d %v", left, err)
	}
}

func TestOwnRefusals(t *testing.T) {
	top, root := newRoot(t)
	unit := "lukd-run-a-0123456789ab"
	ws := Path(root, unit)
	os.Mkdir(ws, 0o700)
	uid := strconv.Itoa(os.Getuid())
	for wd, want := range map[string]string{
		"":                              "is not the workspace of",
		"luk/root/job/" + unit:          "is not the workspace of",
		ws + "/":                        "is not the workspace of",
		ws + "/.":                       "is not the workspace of",
		root + "/root/job/x/../" + unit: "is not the workspace of",
		root + "/root/job/lukd-run-b-0123456789ab": "is not the workspace of",
		root + "/root/other/" + unit:               "is not the workspace of",
		root + "/data/job/" + unit:                 "is not the workspace of",
		ws:                                         "not a btrfs subvolume",
	} {
		show := func(string, ...string) (map[string]string, error) {
			return map[string]string{"UID": uid, "GID": uid, "WorkingDirectory": wd}, nil
		}
		if err := Own(top, unit, me, show); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", wd, err)
		}
	}
	for _, id := range []string{"", "[not set]", "-1", "4294967295", "1x"} {
		show := func(string, ...string) (map[string]string, error) {
			return map[string]string{"UID": id, "GID": uid, "WorkingDirectory": ws}, nil
		}
		if err := Own(top, unit, me, show); err == nil || !strings.Contains(err.Error(), "UID") {
			t.Errorf("UID %q: %v", id, err)
		}
	}
	os.Chmod(filepath.Join(root, "root", JobDir), 0o717)
	show := func(string, ...string) (map[string]string, error) {
		return map[string]string{"UID": uid, "GID": uid, "WorkingDirectory": ws}, nil
	}
	if err := Own(top, unit, me, show); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("chain: %v", err)
	}
}

func TestHelperArgv(t *testing.T) {
	got := HelperArgv("/usr/bin/lukd", "/var/lib/luk", "remove", "lukd-run-a-0123456789ab")
	if got[0] != "systemd-run" || !slices.Contains(got, "--wait") || !slices.Contains(got, "--collect") || !slices.Contains(got, "--quiet") {
		t.Fatalf("%q", got)
	}
	if !strings.HasPrefix(got[4], "--unit=lukd-workspace-") {
		t.Fatalf("%q", got[4])
	}
	for _, p := range []string{
		"ProtectSystem=strict", "ReadWritePaths=-/var/lib/luk/root/job", "ReadWritePaths=-/run/luk/workspaces",
		"CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH",
		"PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX",
		"NoNewPrivileges=yes", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
		"ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes",
		"ProtectControlGroups=yes", "ProtectProc=invisible", "RestrictNamespaces=yes",
		"RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
		"SystemCallArchitectures=native", "UMask=0077",
	} {
		if i := slices.Index(got, p); i < 1 || got[i-1] != "-p" {
			t.Errorf("missing -p %s", p)
		}
	}
	if tail := got[len(got)-5:]; !slices.Equal(tail, []string{"/usr/bin/lukd", "run", "workspace", "remove", "lukd-run-a-0123456789ab"}) {
		t.Fatalf("%q", tail)
	}
	create := HelperArgv("/usr/bin/lukd", "/var/lib/luk", "create", "lukd-run-a-0123456789ab")
	if !slices.Contains(create, "ReadWritePaths=/var/lib/luk/root") || slices.Contains(create, "ReadWritePaths=-/run/luk/workspaces") {
		t.Fatalf("%q", create)
	}
	if got[4] == HelperArgv("/usr/bin/lukd", "/var/lib/luk", "remove", "lukd-run-a-0123456789ab")[4] {
		t.Fatal("helper unit names repeat")
	}
}

func TestErrBusy(t *testing.T) {
	if !errors.Is(busy(errors.New("x")), ErrBusy) {
		t.Fatal("busy does not wrap ErrBusy")
	}
}

// btrfsDir is the opt-in test directory on btrfs: LUK_TEST_BTRFS, as root.
func btrfsDir(t *testing.T) string {
	t.Helper()
	d := os.Getenv("LUK_TEST_BTRFS")
	if d == "" {
		t.Skip("LUK_TEST_BTRFS not set")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	return d
}

// btrfsRoot makes <dir>/luk/root (0711) in a fresh directory below
// LUK_TEST_BTRFS and returns <dir>, the top of the chain rule, and
// <dir>/luk.
func btrfsRoot(t *testing.T) (top, root string) {
	t.Helper()
	dir, err := os.MkdirTemp(btrfsDir(t), "luk-workspace-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0o755)
	root = filepath.Join(dir, "luk")
	if err := os.MkdirAll(filepath.Join(root, "root"), 0o711); err != nil {
		t.Fatal(err)
	}
	return dir, root
}

func subvolume(t *testing.T, dir, name string) {
	t.Helper()
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := btrfs.CreateSubvolume(int(d.Fd()), name); err != nil {
		t.Fatal(err)
	}
}

func owner(t *testing.T, p string) (uid, gid uint32, perm os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid, fi.Mode().Perm()
}

// jobTree fills the workspace ws the way a job of uid 4321 could: a
// directory of its own, nested subvolumes inside it, everything 0700 and
// owned by the job.
func jobTree(t *testing.T, ws string) {
	t.Helper()
	d := filepath.Join(ws, "d")
	os.Mkdir(d, 0o700)
	subvolume(t, d, "nested")
	subvolume(t, filepath.Join(d, "nested"), "deeper")
	os.WriteFile(filepath.Join(d, "nested", "deeper", "f"), []byte("x"), 0o600)
	for _, p := range []string{ws, d, filepath.Join(d, "nested"), filepath.Join(d, "nested", "deeper"), filepath.Join(d, "nested", "deeper", "f")} {
		os.Chown(p, 4321, 4321)
		os.Chmod(p, 0o700)
	}
}

func TestCreateRemoveOnBtrfs(t *testing.T) {
	top, root := btrfsRoot(t)
	unit := JobUnit("ws")
	if err := Create(top, root, unit, 0); err != nil {
		t.Fatal(err)
	}
	if uid, gid, perm := owner(t, filepath.Join(root, "root", JobDir)); uid != 0 || gid != 0 || perm != 0o711 {
		t.Fatalf("job/ %d:%d %v", uid, gid, perm)
	}
	ws := Path(root, unit)
	if uid, gid, perm := owner(t, ws); uid != 0 || gid != 0 || perm != 0o700 {
		t.Fatalf("workspace %d:%d %v", uid, gid, perm)
	}
	if err := Create(top, root, unit, 0); err == nil {
		t.Fatal("created twice")
	}
	jobTree(t, ws)
	if err := Remove(top, root, unit, 0, notFound); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(ws); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace left: %v", err)
	}
}

func TestRemoveOnlyBelowItsWorkspace(t *testing.T) {
	top, root := btrfsRoot(t)
	a, b := JobUnit("a"), JobUnit("b")
	for _, u := range []string{a, b} {
		if err := Create(top, root, u, 0); err != nil {
			t.Fatal(err)
		}
	}
	subvolume(t, Path(root, b), "keep")
	jobTree(t, Path(root, a))
	if err := Remove(top, root, a, 0, notFound); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(Path(root, b), "keep")); err != nil {
		t.Fatalf("other workspace touched: %v", err)
	}
	// A subvolume mounted over the name of a workspace is not a
	// subvolume of job/: refused, and nothing is destroyed.
	c := JobUnit("c")
	os.Mkdir(Path(root, c), 0o700)
	if err := unix.Mount(filepath.Join(Path(root, b), "keep"), Path(root, c), "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(Path(root, c), unix.MNT_DETACH)
	if err := Remove(top, root, c, 0, notFound); err == nil || err.Error() != "workspace "+c+": not a subvolume of "+filepath.Join(root, "root", JobDir) {
		t.Fatalf("bind mount: %v", err)
	}
	unix.Unmount(Path(root, c), unix.MNT_DETACH)
	if _, err := os.Lstat(filepath.Join(Path(root, b), "keep")); err != nil {
		t.Fatalf("mounted subvolume destroyed: %v", err)
	}
	if err := Remove(top, root, b, 0, notFound); err != nil {
		t.Fatal(err)
	}
}

func TestOwnOnBtrfs(t *testing.T) {
	top, root := btrfsRoot(t)
	unit := JobUnit("own")
	if err := Create(top, root, unit, 0); err != nil {
		t.Fatal(err)
	}
	ws := Path(root, unit)
	t.Cleanup(func() { Remove(top, root, unit, 0, notFound) })
	show := func(u string, props ...string) (map[string]string, error) {
		if u != unit || !slices.Equal(props, []string{"UID", "GID", "WorkingDirectory"}) {
			t.Fatalf("show %s %v", u, props)
		}
		return map[string]string{"UID": "61234", "GID": "61235", "WorkingDirectory": ws}, nil
	}
	refuse := func(want string) {
		t.Helper()
		if err := Own(top, unit, 0, show); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want %q: %v", want, err)
		}
	}
	os.Chmod(ws, 0o750)
	refuse("not a fresh workspace")
	os.Chmod(ws, 0o700)
	os.Chown(ws, 0, 1)
	refuse("not a fresh workspace")
	os.Chown(ws, 0, 0)
	os.Mkdir(filepath.Join(ws, "x"), 0o700)
	refuse("not empty")
	os.Remove(filepath.Join(ws, "x"))
	if err := Own(top, unit, 0, show); err != nil {
		t.Fatal(err)
	}
	if uid, gid, perm := owner(t, ws); uid != 61234 || gid != 61235 || perm != 0o700 {
		t.Fatalf("workspace %d:%d %v", uid, gid, perm)
	}
	refuse("owned by uid 61234")
	plain := JobUnit("plain")
	os.Mkdir(Path(root, plain), 0o700)
	show2 := func(string, ...string) (map[string]string, error) {
		return map[string]string{"UID": "61234", "GID": "61235", "WorkingDirectory": Path(root, plain)}, nil
	}
	if err := Own(top, plain, 0, show2); err == nil || !strings.Contains(err.Error(), "not a btrfs subvolume") {
		t.Fatalf("plain: %v", err)
	}
}

func TestPruneOnBtrfs(t *testing.T) {
	top, root := btrfsRoot(t)
	units := []string{JobUnit("a"), StepUnit("p", 1)}
	for _, u := range units {
		if err := Create(top, root, u, 0); err != nil {
			t.Fatal(err)
		}
	}
	jobTree(t, Path(root, units[0]))
	job := filepath.Join(root, "root", JobDir)
	os.WriteFile(filepath.Join(job, "other"), nil, 0o600)
	left, err := Prune(top, root, 0, notFound, quiet)
	if err != nil || left != 0 {
		t.Fatalf("left %d: %v", left, err)
	}
	for _, u := range units {
		if _, err := os.Lstat(Path(root, u)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left: %v", u, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(job, "other")); err != nil {
		t.Fatal(err)
	}
}
