package store

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/wire"
)

const permT0 = 1_790_000_000

func ip(n int) *int { return &n }

// permLocal is a storage of the endpoint drop with the permanent names
// rev/hosts.krl, builds/* (max 2) and one under path permanent.
func permLocal(t *testing.T) Local {
	t.Helper()
	fixedNow(t, permT0+1000)
	return Local{Base: t.TempDir(), Conflict: "version", Dedup: true, Hardlink: true, MaxLinks: 100,
		Permanent: map[string]*config.Permanent{"drop": {Path: "permanent", Names: map[string]*config.PermanentName{
			"rev/hosts.krl": {}, "builds/*": {Max: ip(2)}, "one": {}}}}}
}

// permSidecar is a version of name received at sec and accepted at sec
// (in nanoseconds).
func permSidecar(name, content string, sec int64, expires string) Sidecar {
	return permAccepted(name, content, sec, sec*int64(time.Second), expires)
}

// permAccepted is a version of name received at sec with the acceptance
// order acc.
func permAccepted(name, content string, sec, acc int64, expires string) Sidecar {
	sz := int64(len(content))
	return Sidecar{ID: fmt.Sprint(content, "@", sec), Sender: "alice", Endpoint: "drop", Received: time.Unix(sec, 0).UTC().Format(time.RFC3339), Accepted: acc,
		Size: sz, SHA256: shaOf(content), Expires: expires, OwnerKey: "key:alice", PermanentPath: "permanent",
		Client: wire.Meta{File: "hosts.krl", Source: wire.SourceFile, Size: &sz, SHA256: shaOf(content), Portal: wire.PortalDirect, Permanent: name}}
}

func putPerm(t *testing.T, l Local, rel, name, content string, sec int64, expires string) (Stored, error) {
	t.Helper()
	return l.Store(srcFile(t, t.TempDir(), content), rel, permSidecar(name, content, sec, expires))
}

func mustPermSC(t *testing.T, l Local, rel, content string, sc Sidecar) Stored {
	t.Helper()
	res, err := l.Store(srcFile(t, t.TempDir(), content), rel, sc)
	if err != nil {
		t.Fatalf("put %s (%s): %v", rel, sc.Client.Permanent, err)
	}
	return res
}

func mustPerm(t *testing.T, l Local, rel, name, content string, sec int64) Stored {
	t.Helper()
	res, err := putPerm(t, l, rel, name, content, sec, "")
	if err != nil {
		t.Fatalf("put %s (%s): %v", rel, name, err)
	}
	return res
}

// checkPerm reads the permanent URL name rel and wants content, the
// version stored as target.
func checkPerm(t *testing.T, l Local, rel, target, content string) {
	t.Helper()
	f, sc, err := l.Open(rel)
	if err != nil {
		t.Fatalf("open %s: %v", rel, err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	if string(b) != content || sc.AliasOf != target || sc.SHA256 != shaOf(content) || sc.Size != int64(len(content)) {
		t.Fatalf("%s: %q of %q (sha %s), want %q of %q", rel, b, sc.AliasOf, sc.SHA256, content, target)
	}
}

func checkNoPerm(t *testing.T, l Local, rel string) {
	t.Helper()
	if f, _, err := l.Open(rel); !errors.Is(err, fs.ErrNotExist) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("open %s: %v, want not exist", rel, err)
	}
}

func permEntries(t *testing.T, l Local, key string) []string {
	t.Helper()
	des, err := os.ReadDir(filepath.Join(l.Base, PermanentDir, key))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range des {
		out = append(out, d.Name())
	}
	return out
}

// onlyCurrent wants the directory of the name key to hold its current
// version, nothing else.
func onlyCurrent(t *testing.T, l Local, key string) {
	t.Helper()
	if got := permEntries(t, l, key); !slices.Equal(got, []string{permCurrent}) {
		t.Fatalf("%s: entries %v", key, got)
	}
}

func TestPermanentLastPublished(t *testing.T) {
	l := permLocal(t)
	const url = "permanent/rev/hosts.krl"
	checkNoPerm(t, l, url)
	mustPerm(t, l, "r1", "rev/hosts.krl", "v1", permT0+1)
	checkPerm(t, l, url, "r1", "v1")
	res := mustPerm(t, l, "r2", "rev/hosts.krl", "v2", permT0+2)
	checkPerm(t, l, url, "r2", "v2")
	// A new version removes the previous one.
	if len(res.Replaced) != 1 || res.Replaced[0].Name != "r1" || res.Superseded != nil {
		t.Fatalf("replaced %+v superseded %+v, want r1", res.Replaced, res.Superseded)
	}
	if got := storedNames(t, l); !slices.Equal(got, []string{"r2"}) {
		t.Fatalf("stored %v", got)
	}
	onlyCurrent(t, l, "permanent/rev/hosts.krl")
	// An older version stored late is superseded: stored, then removed.
	res = mustPerm(t, l, "r0", "rev/hosts.krl", "v0", permT0)
	if res.Superseded == nil || res.Superseded.Name != "r0" || len(res.Replaced) != 0 {
		t.Fatalf("late version: replaced %+v superseded %+v", res.Replaced, res.Superseded)
	}
	checkPerm(t, l, url, "r2", "v2")
	if got := storedNames(t, l); !slices.Equal(got, []string{"r2"}) {
		t.Fatalf("stored after a late version %v", got)
	}
	// Removing the current version leaves the name empty: 404, never an
	// older version.
	if err := l.Remove("r2"); err != nil {
		t.Fatal(err)
	}
	checkNoPerm(t, l, url)
	if got := permEntries(t, l, "permanent/rev/hosts.krl"); len(got) != 0 {
		t.Fatalf("entries of an empty name %v", got)
	}
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	checkNoPerm(t, l, url)
	list, err := l.PermanentList()
	if err != nil || len(list) != 1 || list[0].Current != "" || list[0].Name != "rev/hosts.krl" || list[0].Path != "permanent" || list[0].Orphan {
		t.Fatalf("list of an empty name %+v %v", list, err)
	}
	// An empty name takes any version, also one accepted before the
	// version that went.
	if res := mustPerm(t, l, "r1b", "rev/hosts.krl", "v1b", permT0+1); res.Superseded != nil || len(res.Replaced) != 0 {
		t.Fatalf("empty name: replaced %+v superseded %+v", res.Replaced, res.Superseded)
	}
	checkPerm(t, l, url, "r1b", "v1b")
	onlyCurrent(t, l, "permanent/rev/hosts.krl")
	// A later version takes the name again.
	mustPerm(t, l, "r3", "rev/hosts.krl", "v3", permT0+3)
	checkPerm(t, l, url, "r3", "v3")
	onlyCurrent(t, l, "permanent/rev/hosts.krl")
}

// TestPermanentAcceptanceOrder stores versions received in one second in
// another order than they were accepted: the last accepted is current
// and the others go, whatever the order of the stores and their ids.
func TestPermanentAcceptanceOrder(t *testing.T) {
	for _, order := range [][]int{{2, 0, 1}, {1, 2, 0}, {0, 1, 2}, {2, 1, 0}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			l := permLocal(t)
			base := int64(permT0+5) * int64(time.Second)
			// The ids sort against the acceptance order.
			contents := []string{"zz", "mm", "aa"}
			for _, i := range order {
				sc := permAccepted("one", contents[i], permT0+5, base+int64(i)*1000, "")
				mustPermSC(t, l, fmt.Sprint("v", i), contents[i], sc)
			}
			checkPerm(t, l, "permanent/one", "v2", "aa")
			if got := storedNames(t, l); !slices.Equal(got, []string{"v2"}) {
				t.Fatalf("stored %v", got)
			}
			onlyCurrent(t, l, "permanent/one")
		})
	}
}

// TestPermanentExpiredIs404 expires the current version: 404 at once,
// before any maintenance, and no fallback afterwards either.
func TestPermanentExpiredIs404(t *testing.T) {
	l := permLocal(t)
	const url = "permanent/one"
	mustPerm(t, l, "a", "one", "old", permT0+1)
	exp := time.Unix(permT0+2000, 0).UTC().Format(time.RFC3339)
	if _, err := putPerm(t, l, "b", "one", "new", permT0+2, exp); err != nil {
		t.Fatal(err)
	}
	checkPerm(t, l, url, "b", "new")
	fixedNow(t, permT0+3000)
	checkNoPerm(t, l, url)
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	checkNoPerm(t, l, url)
	if got := permEntries(t, l, "permanent/one"); len(got) != 0 {
		t.Fatalf("entries %v", got)
	}
	if got := storedNames(t, l); len(got) != 0 {
		t.Fatalf("stored %v", got)
	}
}

// TestPermanentExpiredCurrentReplaced stores a version accepted before
// the current one after the current one expired, before any maintenance:
// an expired current counts as none, so it is published.
func TestPermanentExpiredCurrentReplaced(t *testing.T) {
	l := permLocal(t)
	exp := time.Unix(permT0+2000, 0).UTC().Format(time.RFC3339)
	if _, err := putPerm(t, l, "b", "one", "new", permT0+2, exp); err != nil {
		t.Fatal(err)
	}
	fixedNow(t, permT0+3000)
	if res := mustPerm(t, l, "a", "one", "old", permT0+1); res.Superseded != nil {
		t.Fatalf("superseded by an expired current: %+v", res)
	}
	checkPerm(t, l, "permanent/one", "a", "old")
	onlyCurrent(t, l, "permanent/one")
	if got := storedNames(t, l); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("stored %v", got)
	}
}

// TestPermanentExpiryPass removes the expired current version through the
// expiry pass: the name goes with it.
func TestPermanentExpiryPass(t *testing.T) {
	l := permLocal(t)
	exp := time.Unix(permT0+2000, 0).UTC().Format(time.RFC3339)
	if _, err := putPerm(t, l, "b", "one", "new", permT0+2, exp); err != nil {
		t.Fatal(err)
	}
	fixedNow(t, permT0+3000)
	if err := l.RemoveExpired("b", "new@"+fmt.Sprint(permT0+2), exp); err != nil {
		t.Fatal(err)
	}
	checkNoPerm(t, l, "permanent/one")
	if got := permEntries(t, l, "permanent/one"); len(got) != 0 {
		t.Fatalf("entries %v", got)
	}
}

func TestPermanentTTLUpdateRepublishes(t *testing.T) {
	l := permLocal(t)
	mustPerm(t, l, "a", "one", "x", permT0+1)
	exp := time.Unix(permT0+5000, 0).UTC().Format(time.RFC3339)
	if _, err := l.Update("a", "x@"+fmt.Sprint(permT0+1), func(sc *Sidecar) error { sc.Expires = exp; return nil }); err != nil {
		t.Fatal(err)
	}
	f, sc, err := l.Open("permanent/one")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if sc.Expires != exp {
		t.Fatalf("expires %q, want %q", sc.Expires, exp)
	}
}

// TestPermanentStoreAgain stores the current version again (its store run
// again after an interruption): it stays current.
func TestPermanentStoreAgain(t *testing.T) {
	l := permLocal(t)
	sc := permSidecar("one", "x", permT0+1, "")
	mustPermSC(t, l, "a", "x", sc)
	res := mustPermSC(t, l, "a", "x", sc)
	if res.Superseded != nil || len(res.Replaced) != 0 {
		t.Fatalf("stored again %+v %v", res, storedNames(t, l))
	}
	checkPerm(t, l, "permanent/one", "a", "x")
	onlyCurrent(t, l, "permanent/one")
}

func TestPermanentAdmission(t *testing.T) {
	l := permLocal(t)
	mustPerm(t, l, "b1", "builds/a", "1", permT0+1)
	mustPerm(t, l, "b2", "builds/b", "2", permT0+2)
	var pr *PermanentRefused
	if _, err := putPerm(t, l, "b3", "builds/c", "3", permT0+3, ""); !errors.As(err, &pr) || !strings.Contains(err.Error(), "limit of 2") {
		t.Fatalf("third name: %v", err)
	}
	// A new version of a name the pattern holds is fine.
	mustPerm(t, l, "b4", "builds/a", "4", permT0+4)
	checkPerm(t, l, "permanent/builds/a", "b4", "4")
	if _, err := putPerm(t, l, "x", "other", "5", permT0+5, ""); !errors.As(err, &pr) || !strings.Contains(err.Error(), "not allocated") {
		t.Fatalf("unallocated name: %v", err)
	}
	if got := storedNames(t, l); !slices.Equal(got, []string{"b2", "b4"}) {
		t.Fatalf("stored %v", got)
	}
	live, err := l.PermanentNames("drop")
	if err != nil || len(live) != 2 || !live["builds/a"] || !live["builds/b"] {
		t.Fatalf("live %v %v", live, err)
	}
	if err := l.AdmitPermanent(permSidecar("builds/c", "", 0, ""), live); !errors.As(err, &pr) {
		t.Fatalf("admit: %v", err)
	}
	// Stored names under the path are reserved.
	if _, err := putAt(t, l, "permanent/x", "y", permT0+6); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stored under the path: %v", err)
	}
	if _, err := putAt(t, l, "permanent", "y", permT0+6); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stored at the path: %v", err)
	}
}

// TestPermanentSwitchAtomic interleaves reads with the switch: before the
// exchange a reader gets the old version whole, after it the new one, a
// file opened before keeps its version, and a version directory opened
// before the exchange is read whole until it is removed.
func TestPermanentSwitchAtomic(t *testing.T) {
	l := permLocal(t)
	const url = "permanent/one"
	mustPerm(t, l, "a", "one", "old-content", permT0+1)
	held, _, err := l.Open(url)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	r, err := os.OpenRoot(l.Base)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var oldDir *os.Root
	steps := 0
	old := hookPermanent
	hookPermanent = func(step int) {
		steps++
		switch step {
		case 1:
			// Prepared, not switched: the old version, whole.
			checkPerm(t, l, url, "a", "old-content")
			if oldDir, err = r.OpenRoot(permDirOf("permanent/one") + "/" + permCurrent); err != nil {
				t.Fatal(err)
			}
		case 2:
			// Switched, the old directory not removed yet.
			checkPerm(t, l, url, "b", "new")
			f, sc, err := openVersion(oldDir)
			if err != nil {
				t.Fatalf("old directory: %v", err)
			}
			b, _ := io.ReadAll(f)
			f.Close()
			if string(b) != "old-content" || sc.AliasOf != "a" {
				t.Fatalf("old directory: %q of %q", b, sc.AliasOf)
			}
		}
	}
	t.Cleanup(func() { hookPermanent = old })
	mustPerm(t, l, "b", "one", "new", permT0+2)
	if steps != 2 {
		t.Fatalf("hook steps %d", steps)
	}
	checkPerm(t, l, url, "b", "new")
	if b, _ := io.ReadAll(held); string(b) != "old-content" {
		t.Fatalf("download in progress: %q", b)
	}
	// The old directory went: a reader holding it retries.
	if _, _, err := openVersion(oldDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("removed old directory: %v", err)
	}
	oldDir.Close()
	onlyCurrent(t, l, "permanent/one")
}

// TestPermanentCrash leaves the state of a crash before and after the
// exchange: readers see one version whole, and the next taker of the base
// lock removes the leftover, publishes the version accepted last and
// removes the other one.
func TestPermanentCrash(t *testing.T) {
	for _, step := range []int{1, 2} {
		t.Run(fmt.Sprint("step", step), func(t *testing.T) {
			l := permLocal(t)
			const url = "permanent/one"
			mustPerm(t, l, "a", "one", "old", permT0+1)
			old := hookPermanent
			hookPermanent = func(s int) {
				if s == step {
					panic("crash")
				}
			}
			func() {
				defer func() { recover() }()
				putPerm(t, l, "b", "one", "new", permT0+2, "")
			}()
			hookPermanent = old
			if step == 1 {
				checkPerm(t, l, url, "a", "old")
			} else {
				checkPerm(t, l, url, "b", "new")
			}
			// After the exchange the old version is left beside current (a
			// panic before it runs the cleanup of publish, a crash would
			// not: TestPermanentLeftoverRemovedUnderLock covers that).
			if got := permEntries(t, l, "permanent/one"); step == 2 && len(got) != 2 {
				t.Fatalf("entries after the crash %v", got)
			}
			if err := l.Reconcile(); err != nil {
				t.Fatal(err)
			}
			checkPerm(t, l, url, "b", "new")
			onlyCurrent(t, l, "permanent/one")
			if got := storedNames(t, l); !slices.Equal(got, []string{"b"}) {
				t.Fatalf("stored after reconcile %v", got)
			}
		})
	}
}

// TestPermanentLeftoverRemovedUnderLock: a current.<random> next to a
// valid current is a crash leftover by definition (publishes run under
// the base lock) and goes before the next version is prepared.
func TestPermanentLeftoverRemovedUnderLock(t *testing.T) {
	l := permLocal(t)
	mustPerm(t, l, "a", "one", "old", permT0+1)
	stale := filepath.Join(l.Base, PermanentDir, "permanent/one", "current.0123456789abcdef")
	if err := os.Mkdir(stale, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, permData), []byte("junk"), 0o640); err != nil {
		t.Fatal(err)
	}
	checkPerm(t, l, "permanent/one", "a", "old")
	old := hookPermanent
	hookPermanent = func(step int) {
		if step == 1 {
			if _, err := os.Lstat(stale); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("leftover still there before the exchange: %v", err)
			}
		}
	}
	t.Cleanup(func() { hookPermanent = old })
	mustPerm(t, l, "b", "one", "new", permT0+2)
	onlyCurrent(t, l, "permanent/one")
}

// TestPermanentConcurrent publishes versions of one name at once: they
// apply one after the other, the one accepted last wins and the others
// go.
func TestPermanentConcurrent(t *testing.T) {
	l := permLocal(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			if _, err := putPerm(t, l, fmt.Sprint("v", i), "one", fmt.Sprint("c", i), permT0+int64(i), ""); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	checkPerm(t, l, "permanent/one", "v7", "c7")
	onlyCurrent(t, l, "permanent/one")
	if got := storedNames(t, l); !slices.Equal(got, []string{"v7"}) {
		t.Fatalf("stored %v", got)
	}
}

func TestPermanentNoExchange(t *testing.T) {
	l := permLocal(t)
	mustPerm(t, l, "a", "one", "old", permT0+1)
	old := exchange
	exchange = func(int, string, string) error { return fmt.Errorf("%w (test)", ErrNoExchange) }
	t.Cleanup(func() { exchange = old })
	if _, err := putPerm(t, l, "b", "one", "new", permT0+2, ""); !errors.Is(err, ErrNoExchange) {
		t.Fatalf("publish: %v", err)
	}
	checkPerm(t, l, "permanent/one", "a", "old")
	onlyCurrent(t, l, "permanent/one")
	if err := ProbeExchange(l.Base); !errors.Is(err, ErrNoExchange) {
		t.Fatalf("probe: %v", err)
	}
	exchange = old
	if err := ProbeExchange(l.Base); err != nil {
		t.Fatalf("probe: %v", err)
	}
}

func TestPermanentOrphans(t *testing.T) {
	l := permLocal(t)
	mustPerm(t, l, "a", "one", "x", permT0+1)
	mustPerm(t, l, "b", "rev/hosts.krl", "y", permT0+2)
	// The entry of one goes: an orphan, not served, never removed by
	// lukd itself.
	delete(l.Permanent["drop"].Names, "one")
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	checkNoPerm(t, l, "permanent/one")
	checkPerm(t, l, "permanent/rev/hosts.krl", "b", "y")
	list, err := l.PermanentList()
	if err != nil {
		t.Fatal(err)
	}
	want := []PermanentInfo{
		{Key: "permanent/one", Path: "permanent", Name: "one", Current: "a", ID: "x@" + fmt.Sprint(permT0+1), Received: time.Unix(permT0+1, 0).UTC().Format(time.RFC3339), Orphan: true},
		{Key: "permanent/rev/hosts.krl", Path: "permanent", Name: "rev/hosts.krl", Current: "b", ID: "y@" + fmt.Sprint(permT0+2), Received: time.Unix(permT0+2, 0).UTC().Format(time.RFC3339)},
	}
	if !slices.Equal(list, want) {
		t.Fatalf("list %+v\nwant %+v", list, want)
	}
	// The version of an orphan stays an ordinary file; removing it leaves
	// the orphan alone.
	if err := l.Remove("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(l.Base, PermanentDir, "permanent/one/current")); err != nil {
		t.Fatalf("orphan removed: %v", err)
	}
	if err := l.PruneOrphan("permanent/rev/hosts.krl"); err == nil {
		t.Fatal("pruned an allocated name")
	}
	if err := l.PruneOrphan("permanent/one"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(l.Base, PermanentDir, "permanent/one")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("orphan left: %v", err)
	}
	if err := l.PruneOrphan("permanent/one"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("second prune: %v", err)
	}
	// A new path is a new, empty namespace: the old one is an orphan.
	l.Permanent["drop"].Path = "p2"
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	checkNoPerm(t, l, "p2/rev/hosts.krl")
	if list, _ := l.PermanentList(); len(list) != 1 || !list[0].Orphan || list[0].Key != "permanent/rev/hosts.krl" {
		t.Fatalf("after the path change %+v", list)
	}
}

// TestPermanentNestedNames keeps a name and a name below it apart.
func TestPermanentNestedNames(t *testing.T) {
	l := permLocal(t)
	l.Permanent["drop"].Names["a"] = &config.PermanentName{}
	l.Permanent["drop"].Names["a/b"] = &config.PermanentName{}
	mustPerm(t, l, "x", "a", "A", permT0+1)
	mustPerm(t, l, "y", "a/b", "AB", permT0+2)
	checkPerm(t, l, "permanent/a", "x", "A")
	checkPerm(t, l, "permanent/a/b", "y", "AB")
	if err := l.Remove("x"); err != nil {
		t.Fatal(err)
	}
	checkNoPerm(t, l, "permanent/a")
	checkPerm(t, l, "permanent/a/b", "y", "AB")
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	checkPerm(t, l, "permanent/a/b", "y", "AB")
	// The empty name a is the directory of a/b: nothing to prune.
	if err := l.PruneEmpty("permanent/a/b"); err == nil {
		t.Fatal("pruned a name with a current version")
	}
	if err := l.PruneEmpty("permanent/a"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("prune of a: %v", err)
	}
	if got := permEntries(t, l, "permanent/a"); !slices.Equal(got, []string{"b"}) {
		t.Fatalf("entries of a %v", got)
	}
	checkPerm(t, l, "permanent/a/b", "y", "AB")
	// The empty name takes any version.
	mustPerm(t, l, "z", "a", "Z", permT0)
	checkPerm(t, l, "permanent/a", "z", "Z")
	if err := l.Remove("z"); err != nil {
		t.Fatal(err)
	}
	// A name without a nested one leaves an empty directory, pruned with
	// the empty directories above it.
	if err := l.Remove("y"); err != nil {
		t.Fatal(err)
	}
	if err := l.PruneEmpty("permanent/a/b"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(l.Base, PermanentDir, "permanent")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("permanent/ kept: %v", err)
	}
}
