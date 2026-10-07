package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
)

func setHold(t *testing.T, l Local, rel, id string, on bool) {
	t.Helper()
	if _, err := l.Amend(rel, id, func(sc *Sidecar) error { sc.Hold = on; return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestHoldRefusesRemoval(t *testing.T) {
	l := Local{Base: t.TempDir(), Shard: 1}
	sc := sidecar("id")
	sc.Expires = "2026-10-01T00:00:00Z"
	if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "f", sc); err != nil {
		t.Fatal(err)
	}
	setHold(t, l, "f", "id", true)
	if got, _ := readAll(t, l, "f"); got != "hello" {
		t.Fatalf("content %q", got)
	}
	if _, got := readAll(t, l, "f"); !got.Hold || got.Expires != sc.Expires {
		t.Fatalf("sidecar %+v", got)
	}
	for what, err := range map[string]error{
		"Remove":        l.Remove("f"),
		"RemoveIf":      l.RemoveIf("f", "id"),
		"RemoveExpired": l.RemoveExpired("f", "id", sc.Expires),
		"Replace":       l.Replace(srcFile(t, t.TempDir(), "other"), "f", "id", func(*Sidecar) error { return nil }),
	} {
		if !errors.Is(err, ErrOnHold) {
			t.Errorf("%s: %v, want ErrOnHold", what, err)
		}
	}
	if got, _ := readAll(t, l, "f"); got != "hello" {
		t.Fatalf("content after refusals %q", got)
	}
	// The expiry of a file on hold may change.
	if _, err := l.Update("f", "id", func(sc *Sidecar) error { sc.Expires = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, got := readAll(t, l, "f"); !got.Hold || got.Expires != "" {
		t.Fatalf("sidecar after ttl %+v", got)
	}
	setHold(t, l, "f", "id", false)
	if err := l.RemoveIf("f", "id"); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, filepath.Join(l.Base, l.phys("f")))
}

func TestHoldConflictReplace(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "replace"}
	if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "f", sidecar("id")); err != nil {
		t.Fatal(err)
	}
	setHold(t, l, "f", "id", true)
	if _, err := l.Put(srcFile(t, t.TempDir(), "other"), "f", sidecar("id2")); !errors.Is(err, ErrOnHold) {
		t.Fatalf("overwrite: %v, want ErrOnHold", err)
	}
	if got, sc := readAll(t, l, "f"); got != "hello" || sc.ID != "id" {
		t.Fatalf("%q %+v", got, sc)
	}
	setHold(t, l, "f", "id", false)
	if _, err := l.Put(srcFile(t, t.TempDir(), "other"), "f", sidecar("id2")); err != nil {
		t.Fatal(err)
	}
	if got, _ := readAll(t, l, "f"); got != "other" {
		t.Fatalf("content after release %q", got)
	}
}

// A file kept as a version by a newer upload of its name stays on hold.
func TestHoldVersioned(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "version"}
	if _, err := l.Put(srcFile(t, t.TempDir(), "hello"), "f", sidecar("id")); err != nil {
		t.Fatal(err)
	}
	setHold(t, l, "f", "id", true)
	sc := sidecar("id2")
	sc.Received = "2026-09-30T11:00:00Z"
	if _, err := l.Put(srcFile(t, t.TempDir(), "other"), "f", sc); err != nil {
		t.Fatal(err)
	}
	old := ""
	if err := l.Walk(func(rel string, sc Sidecar) error {
		if sc.ID == "id" {
			old = rel
		}
		return nil
	}); err != nil || old == "" || old == "f" {
		t.Fatalf("version %q %v", old, err)
	}
	if got, vsc := readAll(t, l, old); got != "hello" || !vsc.Hold {
		t.Fatalf("version %q %+v", got, vsc)
	}
	if _, cur := readAll(t, l, "f"); cur.Hold {
		t.Fatal("the new upload took the hold")
	}
	if err := l.RemoveIf(old, "id"); !errors.Is(err, ErrOnHold) {
		t.Fatalf("version removed: %v", err)
	}
}

func TestAmendAliased(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "version", Catalog: true}
	s := Series{"nightly", "db1-prod", "db.sql"}
	putSeries(t, l, "prod/1", s, "2026-10-01T06:00:00Z", "prod/latest")
	putSeries(t, l, "prod/2", s, "2026-10-02T06:00:00Z", "prod/latest")
	checkAlias(t, l, "prod/latest", "prod/2", "prod/2")
	set := func(sc *Sidecar) error { sc.Expires, sc.Hold = "2027-01-01T00:00:00Z", true; return nil }
	if _, err := l.Update("prod/2", "id-prod/2", set); !errors.Is(err, ErrAliased) {
		t.Fatalf("Update: %v, want ErrAliased", err)
	}
	// The alias follows its target, and only its target.
	if _, err := l.Amend("prod/1", "id-prod/1", set); err != nil {
		t.Fatal(err)
	}
	if _, a := readAll(t, l, "prod/latest"); a.Hold || a.Expires != "" {
		t.Fatalf("alias took the sidecar of an older file: %+v", a)
	}
	sc, err := l.Amend("prod/2", "id-prod/2", set)
	if err != nil || !sc.Hold || sc.AliasOf != "" {
		t.Fatalf("%+v %v", sc, err)
	}
	checkAlias(t, l, "prod/latest", "prod/2", "prod/2")
	if _, a := readAll(t, l, "prod/latest"); !a.Hold || a.Expires != "2027-01-01T00:00:00Z" || a.ID != "id-prod/2" {
		t.Fatalf("alias sidecar %+v", a)
	}
	if _, got := readAll(t, l, "prod/2"); !got.Hold || got.AliasOf != "" {
		t.Fatalf("target sidecar %+v", got)
	}
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	checkAlias(t, l, "prod/latest", "prod/2", "prod/2")
}

func TestRetentionHold(t *testing.T) {
	st := &config.Storage{Retention: []config.Retention{{Keep: config.Keep{Last: 1}}}}
	s := Series{"nightly", "db1", "db.sql"}
	plan := func(l Local) string {
		t.Helper()
		plans, err := l.RetentionPlan(st, time.Now())
		if err != nil || len(plans) != 1 {
			t.Fatalf("%+v %v", plans, err)
		}
		var out []string
		for _, f := range plans[0].Files {
			out = append(out, fmt.Sprintf("%s:%v:%v:%s", f.Name, f.Keep, f.Hold, strings.Join(f.Reasons, ",")))
		}
		return strings.Join(out, " ")
	}
	for _, c := range []struct {
		hold, want string
		removed    []string
	}{
		// The held copy takes no place of the series: it keeps its newest
		// copy beside it.
		{"d/3", "d/3:true:true:hold d/2:true:false:last d/1:false:false:", []string{"d/1"}},
		{"d/1", "d/3:true:false:last d/2:false:false: d/1:true:true:hold", []string{"d/2"}},
	} {
		l := Local{Base: t.TempDir(), Conflict: "version"}
		putSeries(t, l, "d/3", s, "2026-10-03T06:00:00Z", "")
		putSeries(t, l, "d/2", s, "2026-10-02T06:00:00Z", "")
		putSeries(t, l, "d/1", s, "2026-10-01T06:00:00Z", "")
		setHold(t, l, c.hold, "id-"+c.hold, true)
		if got := plan(l); got != c.want {
			t.Errorf("hold %s: plan %s, want %s", c.hold, got, c.want)
		}
		var removed []string
		if err := l.Retain(st, time.Now(), func(_ SeriesPlan, f RetainedFile) { removed = append(removed, f.Name) }); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(removed, c.removed) {
			t.Errorf("hold %s: removed %v, want %v", c.hold, removed, c.removed)
		}
		mustExist(t, filepath.Join(l.Base, DataDir, c.hold))
		// Released, the copy is one of the series again.
		setHold(t, l, c.hold, "id-"+c.hold, false)
		removed = nil
		if err := l.Retain(st, time.Now(), func(_ SeriesPlan, f RetainedFile) { removed = append(removed, f.Name) }); err != nil {
			t.Fatal(err)
		}
		if len(removed) != 1 {
			t.Errorf("hold %s: removed after release %v", c.hold, removed)
		}
		mustExist(t, filepath.Join(l.Base, DataDir, "d/3"))
	}
}

// A version of a permanent name on hold outlives the version replacing it.
func TestHoldPermanentVersion(t *testing.T) {
	l := permLocal(t)
	mustPerm(t, l, "v1", "one", "a", permT0)
	setHold(t, l, "v1", fmt.Sprint("a@", permT0), true)
	checkPerm(t, l, "permanent/one", "v1", "a")
	res := mustPerm(t, l, "v2", "one", "b", permT0+10)
	if len(res.Replaced) != 0 {
		t.Fatalf("replaced %+v", res.Replaced)
	}
	checkPerm(t, l, "permanent/one", "v2", "b")
	if got, sc := readAll(t, l, "v1"); got != "a" || !sc.Hold {
		t.Fatalf("held version %q %+v", got, sc)
	}
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	checkPerm(t, l, "permanent/one", "v2", "b")
	mustExist(t, filepath.Join(l.Base, DataDir, "v1"))
}
