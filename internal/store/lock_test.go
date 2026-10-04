package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// otherProcess holds the base lock through its own open file description,
// as a second lukd process does, and bumps the generation like a mutation.
type otherProcess struct {
	t *testing.T
	f *os.File
}

func lockAsOther(t *testing.T, base string) *otherProcess {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(base, LockName), os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	o := &otherProcess{t: t, f: f}
	o.bump()
	return o
}

func (o *otherProcess) bump() {
	fi, err := o.f.Stat()
	if err != nil {
		o.t.Fatal(err)
	}
	if err := o.f.Truncate(fi.Size() + 1); err != nil {
		o.t.Fatal(err)
	}
}

func (o *otherProcess) release() {
	o.bump()
	syscall.Flock(int(o.f.Fd()), syscall.LOCK_UN)
	o.f.Close()
}

func blocked(t *testing.T, what string, fn func() error) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		t.Fatalf("%s did not wait for the other process: %v", what, err)
	case <-time.After(200 * time.Millisecond):
	}
	return done
}

func finished(t *testing.T, what string, done chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s still blocked", what)
	}
}

func TestMutationsWaitForOtherProcess(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "a", "one", 1, "")
	mustPut(t, l, "b", "two", 2, "")
	mustPut(t, l, "c", "six", 3, "")
	for _, m := range []struct {
		name string
		fn   func() error
	}{
		{"put", func() error { _, err := putAlias(t, l, "d", "ten", 4, ""); return err }},
		{"remove", func() error { return l.Remove("a") }},
		{"claim", func() error { _, err := l.Claim("b", "id-two", nil); return err }},
		{"reconcile", l.Reconcile},
	} {
		o := lockAsOther(t, l.Base)
		done := blocked(t, m.name, m.fn)
		o.release()
		finished(t, m.name, done)
	}
	if n := catalogNames(readCatalog(t, l)); fmt.Sprint(n) != "[c d]" {
		t.Fatalf("catalog %v", n)
	}
}

func TestOpenWaitsWhileOtherProcessMutates(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPut(t, l, "a", "one", 1, "")
	o := lockAsOther(t, l.Base)
	done := blocked(t, "open", func() error {
		f, _, err := l.Open("a")
		if err == nil {
			f.Close()
		}
		return err
	})
	o.release()
	finished(t, "open", done)
	if got, sc := readAll(t, l, "a"); got != "one" || sc.ID != "id-one" {
		t.Fatalf("%q %+v", got, sc)
	}
}

func TestReconcileRebuildsAfterOtherProcessRemoval(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "a", "one", 1, "")
	mustPut(t, l, "b", "two", 2, "")
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	o := lockAsOther(t, l.Base)
	for _, p := range []string{l.phys("b"), sidecarRel(l.phys("b"))} {
		if err := os.Remove(filepath.Join(l.Base, p)); err != nil {
			t.Fatal(err)
		}
	}
	o.release()
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if n := catalogNames(readCatalog(t, l)); fmt.Sprint(n) != "[a]" {
		t.Fatalf("catalog after the other process removed b: %v", n)
	}
}

func lockGen(t *testing.T, base string) int64 {
	t.Helper()
	fi, err := os.Stat(filepath.Join(base, LockName))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func TestCatalogBuiltByOtherProcessIsFresh(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "a", "one", 1, "")
	if c := readCatalog(t, l); c.Generation != lockGen(t, l.Base) {
		t.Fatalf("catalog generation %d, lock %d", c.Generation, lockGen(t, l.Base))
	}
	catalogFresh.Delete(l.key())
	fi, err := os.Stat(filepath.Join(l.Base, catalogFile))
	if err != nil {
		t.Fatal(err)
	}
	gen := lockGen(t, l.Base)
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(l.Base, catalogFile))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fi, after) || lockGen(t, l.Base) != gen {
		t.Fatal("catalog rebuilt although current")
	}
}

func TestNoopClaimAndRemoveKeepGeneration(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "a", "one", 1, "")
	gen := lockGen(t, l.Base)
	if _, err := l.Claim("a", "other", nil); err == nil {
		t.Fatal("claimed with a wrong id")
	}
	if err := l.RemoveIf("a", "other"); err == nil {
		t.Fatal("removed with a wrong id")
	}
	if got := lockGen(t, l.Base); got != gen {
		t.Fatalf("generation %d, want %d", got, gen)
	}
}

func TestLockFileReplacedWhileWaiting(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPut(t, l, "a", "one", 1, "")
	o := lockAsOther(t, l.Base)
	done := blocked(t, "put", func() error { _, err := putAlias(t, l, "b", "two", 2, ""); return err })
	p := filepath.Join(l.Base, LockName)
	if err := os.Rename(p, p+".old"); err != nil {
		t.Fatal(err)
	}
	o2 := lockAsOther(t, l.Base)
	o.release()
	select {
	case err := <-done:
		t.Fatalf("put ran under the lock of a replaced file: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	o2.release()
	finished(t, "put", done)
}
