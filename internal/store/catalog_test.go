package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"text/template"
	"time"

	"luk/internal/config"
	"luk/internal/wire"
)

type catalogDoc struct {
	Version    int    `json:"version"`
	Generated  string `json:"generated"`
	Generation int64  `json:"generation"`
	Files      []struct {
		Name    string          `json:"name"`
		Size    int64           `json:"size"`
		SHA256  string          `json:"sha256"`
		Created string          `json:"created"`
		Sender  *string         `json:"sender"`
		Tags    []string        `json:"tags"`
		Meta    json.RawMessage `json:"meta"`
	} `json:"files"`
	Latest map[string]string `json:"latest"`
}

func readCatalog(t *testing.T, l Local) catalogDoc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(l.Base, catalogFile))
	if err != nil {
		t.Fatal(err)
	}
	var c catalogDoc
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return c
}

func catalogNames(c catalogDoc) []string {
	var n []string
	for _, f := range c.Files {
		n = append(n, f.Name)
	}
	return n
}

// putAlias stores content at rel, received at minute m, declaring alias.
func putAlias(t *testing.T, l Local, rel, content string, m int, alias string) (string, error) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	sc := sidecar("id-" + content)
	sc.SHA256, sc.Size = shaOf(content), int64(len(content))
	sc.Received = time.Date(2026, 9, 30, 10, m, 0, 0, time.UTC).Format(time.RFC3339)
	if alias != "" {
		sc.Meta = json.RawMessage(fmt.Sprintf(`{"alias":%q}`, alias))
	}
	return l.Put(src, rel, sc)
}

func mustPut(t *testing.T, l Local, rel, content string, m int, alias string) string {
	t.Helper()
	got, err := putAlias(t, l, rel, content, m, alias)
	if err != nil {
		t.Fatalf("put %s: %v", rel, err)
	}
	return got
}

func checkAlias(t *testing.T, l Local, alias, target, content string) {
	t.Helper()
	got, sc := readAll(t, l, alias)
	if got != content || sc.AliasOf != target {
		t.Fatalf("alias %s: %q of %q, want %q of %q", alias, got, sc.AliasOf, content, target)
	}
	if l.Catalog {
		if c := readCatalog(t, l); c.Latest[alias] != target {
			t.Fatalf("catalog latest %v, want %s -> %s", c.Latest, alias, target)
		}
	}
}

func checkNoAlias(t *testing.T, l Local, alias string) {
	t.Helper()
	for _, p := range []string{filepath.Join(l.Base, DataDir, alias), l.SidecarPath(alias)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if l.Catalog {
		if c := readCatalog(t, l); len(c.Latest) != 0 {
			t.Fatalf("catalog latest %v", c.Latest)
		}
	}
}

func TestFromConfig(t *testing.T) {
	l := FromConfig(&config.Storage{Base: "/b", Conflict: "reject", Catalog: true, Shard: 2})
	if !reflect.DeepEqual(l, Local{Base: "/b", Conflict: "reject", Catalog: true, Shard: 2, Dedup: true, Hardlink: true, MaxLinks: config.DefaultLinksMax}) {
		t.Fatalf("%+v", l)
	}
	off := false
	if l := FromConfig(&config.Storage{Base: "/b", Conflict: "version", Dedup: &off}); l.Dedup {
		t.Fatalf("dedup false: %+v", l)
	}
	if l := FromConfig(&config.Storage{Base: "/b", Hardlink: &off}); l.Hardlink {
		t.Fatalf("hardlink false: %+v", l)
	}
}

func TestCatalogAfterPutsAndRemovals(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "b/two", "second", 2, "")
	src := filepath.Join(t.TempDir(), "src")
	os.WriteFile(src, []byte("first"), 0o600)
	sc := sidecar("id1")
	sc.SHA256, sc.Size, sc.Meta = shaOf("first"), 5, json.RawMessage(`{"k":1}`)
	if _, err := l.Put(src, "a/one", sc); err != nil {
		t.Fatal(err)
	}
	c := readCatalog(t, l)
	if c.Version != 1 || c.Generated == "" || c.Latest == nil || fmt.Sprint(catalogNames(c)) != "[a/one b/two]" {
		t.Fatalf("%+v", c)
	}
	f := c.Files[0]
	if f.Size != 5 || f.SHA256 != shaOf("first") || f.Created != sc.Received || f.Sender != nil ||
		fmt.Sprint(f.Tags) != "[t]" || string(f.Meta) != `{"k":1}` {
		t.Fatalf("%+v", f)
	}
	if string(c.Files[1].Meta) != "{}" {
		t.Fatalf("empty meta %s", c.Files[1].Meta)
	}
	if err := l.Remove("a/one"); err != nil {
		t.Fatal(err)
	}
	if n := catalogNames(readCatalog(t, l)); fmt.Sprint(n) != "[b/two]" {
		t.Fatalf("after remove %v", n)
	}
	if err := l.RemoveIf("b/two", "id-second"); err != nil {
		t.Fatal(err)
	}
	if c := readCatalog(t, l); len(c.Files) != 0 || c.Files == nil {
		t.Fatalf("after RemoveIf %+v", c)
	}
	mustPut(t, l, "c", "third", 3, "")
	if _, err := l.Claim("c", "id-third", nil); err != nil {
		t.Fatal(err)
	}
	if c := readCatalog(t, l); len(c.Files) != 0 {
		t.Fatalf("after claim %+v", c)
	}
	if sw, err := l.Sweep(-time.Hour, time.Now()); err != nil || len(sw.Removed) != 0 {
		t.Fatalf("sweep %+v %v", sw, err)
	}
	readCatalog(t, l)
}

func TestNoCatalogWhenDisabled(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPut(t, l, "catalog.json", "x", 1, "")
	if _, err := os.Stat(filepath.Join(l.Base, catalogFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestCatalogReservedName(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	if _, err := putAlias(t, l, "catalog.json", "x", 1, ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("catalog.json: %v", err)
	}
	mustPut(t, l, "d/catalog.json", "x", 1, "")
	mustPut(t, l, "catalog", "y", 2, "")
	if n := catalogNames(readCatalog(t, l)); fmt.Sprint(n) != "[catalog d/catalog.json]" {
		t.Fatalf("%v", n)
	}
	tm := template.Must(template.New("").Parse("{{.File}}"))
	if _, err := l.Render(tm, Vars{File: "catalog.json"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("render: %v", err)
	}
	if got, err := l.Render(tm, Vars{File: "x"}); err != nil || got != "x" {
		t.Fatalf("render %q %v", got, err)
	}
	if got, err := (Local{Base: l.Base}).Render(tm, Vars{File: "catalog.json"}); err != nil || got != "catalog.json" {
		t.Fatalf("render without catalog %q %v", got, err)
	}
}

// TestNestedReserved: the names a nested expose serves are reserved in
// the storage of the outer expose: as a stored path, a rendered path and
// an alias; a name merely starting the same way is not.
func TestNestedReserved(t *testing.T) {
	l := Local{Base: t.TempDir(), Nested: []string{"volatile/"}}
	for _, rel := range []string{"volatile", "volatile/x", "volatile/x/y"} {
		if _, err := putAlias(t, l, rel, "x", 1, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", rel, err)
		}
		if p, ok := l.Nests(rel); !ok || p != "volatile/" {
			t.Errorf("nests %s: %q %v", rel, p, ok)
		}
	}
	for _, rel := range []string{"volatilex", "a/volatile/x"} {
		mustPut(t, l, rel, "y", 2, "")
		if _, ok := l.Nests(rel); ok {
			t.Errorf("nests %s", rel)
		}
	}
	if _, err := putAlias(t, l, "z", "z", 3, "volatile/a"); !errors.Is(err, ErrInvalid) {
		t.Errorf("alias: %v", err)
	}
	tm := template.Must(template.New("").Parse("volatile/{{.File}}"))
	if _, err := l.Render(tm, Vars{File: "f"}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "nested expose under volatile/") {
		t.Fatalf("render: %v", err)
	}
}

func TestAliasFollowsNewest(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "d1/db.sql", "one", 1, "latest/db.sql")
	checkAlias(t, l, "latest/db.sql", "d1/db.sql", "one")
	mustPut(t, l, "d2/db.sql", "two", 2, "latest/db.sql")
	checkAlias(t, l, "latest/db.sql", "d2/db.sql", "two")
	mustPut(t, l, "d0/db.sql", "zero", 0, "latest/db.sql")
	checkAlias(t, l, "latest/db.sql", "d2/db.sql", "two")
	c := readCatalog(t, l)
	if fmt.Sprint(catalogNames(c)) != "[d0/db.sql d1/db.sql d2/db.sql]" {
		t.Fatalf("aliases listed as files: %v", catalogNames(c))
	}
	fi1, _ := os.Stat(filepath.Join(l.Base, DataDir, "latest/db.sql"))
	fi2, _ := os.Stat(filepath.Join(l.Base, DataDir, "d2/db.sql"))
	if !os.SameFile(fi1, fi2) {
		t.Fatal("alias is not a hardlink of its target")
	}
	var walked []string
	l.Walk(func(rel string, sc Sidecar) error {
		walked = append(walked, rel)
		return nil
	})
	if fmt.Sprint(walked) != "[d0/db.sql d1/db.sql d2/db.sql latest/db.sql]" {
		t.Fatalf("walk %v", walked)
	}
}

func TestAliasRepointsOnRemoval(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "d1", "one", 1, "cur")
	mustPut(t, l, "d2", "two", 2, "cur")
	mustPut(t, l, "d3", "three", 3, "cur")
	mustPut(t, l, "other", "x", 4, "")
	if err := l.Remove("d1"); err != nil {
		t.Fatal(err)
	}
	checkAlias(t, l, "cur", "d3", "three")
	if err := l.RemoveIf("d3", "id-three"); err != nil {
		t.Fatal(err)
	}
	checkAlias(t, l, "cur", "d2", "two")
	if _, err := l.Claim("d2", "id-two", nil); err != nil {
		t.Fatal(err)
	}
	checkNoAlias(t, l, "cur")
}

func TestAliasWithoutCatalog(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPut(t, l, "d1", "one", 1, "cur")
	mustPut(t, l, "d2", "two", 2, "cur")
	checkAlias(t, l, "cur", "d2", "two")
	if err := l.Remove("d2"); err != nil {
		t.Fatal(err)
	}
	checkAlias(t, l, "cur", "d1", "one")
	if err := l.Remove("d1"); err != nil {
		t.Fatal(err)
	}
	checkNoAlias(t, l, "cur")
}

func TestClaimThroughAlias(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "d1", "one", 1, "cur")
	mustPut(t, l, "d2", "two", 2, "cur")
	_, sc := readAll(t, l, "cur")
	claimed, err := l.Claim("cur", sc.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(l.Base, claimed)); string(b) != "two" {
		t.Fatalf("claimed %q", b)
	}
	if _, err := os.Lstat(filepath.Join(l.Base, DataDir, "d2")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target kept: %v", err)
	}
	checkAlias(t, l, "cur", "d1", "one")
}

func TestAliasReplaceTarget(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "replace", Catalog: true}
	mustPut(t, l, "d1", "one", 1, "cur")
	mustPut(t, l, "d2", "two", 2, "cur")
	mustPut(t, l, "d2", "old", 0, "cur")
	checkAlias(t, l, "cur", "d1", "one")
	mustPut(t, l, "d2", "newer", 5, "cur")
	checkAlias(t, l, "cur", "d2", "newer")
	mustPut(t, l, "d2", "plain", 6, "")
	checkAlias(t, l, "cur", "d1", "one")
	if _, err := putAlias(t, l, "cur", "x", 5, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("put over an alias: %v", err)
	}
	checkAlias(t, l, "cur", "d1", "one")
}

func TestAliasInvalid(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "real", "r", 1, "")
	for _, a := range []string{"../x", ".", "a/..", "/abs", "a//b", "a/", "catalog.json", "real"} {
		if _, err := putAlias(t, l, "self", "c-"+a, 2, a); err == nil {
			t.Errorf("alias %q accepted", a)
		}
		if _, err := os.Lstat(filepath.Join(l.Base, DataDir, "self")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("alias %q: file stored", a)
		}
	}
	src := filepath.Join(t.TempDir(), "src")
	os.WriteFile(src, []byte("x"), 0o600)
	sc := sidecar("idn")
	sc.Meta = json.RawMessage(`{"alias":1}`)
	if _, err := l.Put(src, "n", sc); err == nil {
		t.Fatal("non-string alias accepted")
	}
	if got, _ := readAll(t, l, "real"); got != "r" {
		t.Fatalf("real file %q", got)
	}
}

func TestAliasConcurrentPuts(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := putAlias(t, l, fmt.Sprintf("f%02d", i), fmt.Sprintf("c%02d", i), (i*7)%12, "cur"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// minute (i*7)%12 is largest (11) for i=5.
	checkAlias(t, l, "cur", "f05", "c05")
	if c := readCatalog(t, l); len(c.Files) != 12 {
		t.Fatalf("catalog %d files", len(c.Files))
	}
}

func TestReconcileBuildsCatalog(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if c := readCatalog(t, l); len(c.Files) != 0 {
		t.Fatalf("%+v", c)
	}
	if err := (Local{Base: filepath.Join(l.Base, "missing"), Catalog: true}).Reconcile(); err != nil {
		t.Fatal(err)
	}
	f, err := l.OpenCatalog()
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := (Local{Base: l.Base}).OpenCatalog(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disabled: %v", err)
	}
}

func TestBatchDefersCatalog(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "a", "one", 1, "")
	mustPut(t, l, "b", "two", 2, "")
	if err := l.Batch().RemoveIf("a", "id-one"); err != nil {
		t.Fatal(err)
	}
	if n := catalogNames(readCatalog(t, l)); fmt.Sprint(n) != "[a b]" {
		t.Fatalf("rebuilt in batch: %v", n)
	}
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if n := catalogNames(readCatalog(t, l)); fmt.Sprint(n) != "[b]" {
		t.Fatalf("after reconcile %v", n)
	}
}

func TestAliasOwnPathIsNoop(t *testing.T) {
	fixedNow(t, 1790000000)
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "x", "one", 1, "x")
	ts := strconv.FormatInt(time.Date(2026, 9, 30, 10, 1, 0, 0, time.UTC).Unix(), 10)
	if got := mustPut(t, l, "x", "two", 2, "x"); got != "x" {
		t.Fatalf("stored %s", got)
	}
	for _, rel := range []string{"x", "x." + ts} {
		if _, sc := readAll(t, l, rel); sc.AliasOf != "" {
			t.Fatalf("%s became an alias", rel)
		}
	}
	if c := readCatalog(t, l); len(c.Latest) != 0 || len(c.Files) != 2 {
		t.Fatalf("%+v", c)
	}
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, _ := readAll(t, l, "x"); got != "two" {
		t.Fatalf("x %q", got)
	}
}

func TestPrivateNotInCatalog(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "pub", "p", 1, "")
	for name, mod := range map[string]func(*Sidecar){
		"once":   func(sc *Sidecar) { sc.Client.Once = true },
		"reveal": func(sc *Sidecar) { sc.Client.Portal = wire.PortalReveal },
		"dl":     func(sc *Sidecar) { sc.Client.Portal = wire.PortalDownload },
	} {
		src := filepath.Join(t.TempDir(), "src")
		os.WriteFile(src, []byte(name), 0o600)
		sc := sidecar("id-" + name)
		mod(&sc)
		if _, err := l.Put(src, name, sc); err != nil {
			t.Fatal(err)
		}
		sc.Meta = json.RawMessage(`{"alias":"cur"}`)
		if _, err := l.Put(src, name+"-a", sc); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s alias: %v", name, err)
		}
	}
	c := readCatalog(t, l)
	if fmt.Sprint(catalogNames(c)) != "[pub]" || len(c.Latest) != 0 {
		t.Fatalf("%+v", c)
	}
}

func TestOpenConsistentWithAliasMove(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPut(t, l, "d1", "one", 1, "cur")
	type got struct {
		content string
		sc      Sidecar
		err     error
	}
	res := make(chan got, 1)
	old := hookAliasSidecar
	hookAliasSidecar = func() {
		go func() {
			f, sc, err := l.Open("cur")
			if err != nil {
				res <- got{err: err}
				return
			}
			defer f.Close()
			b, _ := io.ReadAll(f)
			res <- got{string(b), sc, nil}
		}()
		time.Sleep(50 * time.Millisecond)
	}
	t.Cleanup(func() { hookAliasSidecar = old })
	mustPut(t, l, "d2", "two", 2, "cur")
	g := <-res
	if g.err != nil || shaOf(g.content) != g.sc.SHA256 {
		t.Fatalf("content %q with the sidecar of %s: %v", g.content, g.sc.AliasOf, g.err)
	}
}

func TestClaimRefusesOtherFile(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "replace"}
	mustPut(t, l, "x", "one", 1, "")
	f, sc, err := l.Open("x")
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := f.Stat()
	f.Close()
	src := filepath.Join(t.TempDir(), "src")
	os.WriteFile(src, []byte("other"), 0o600)
	nsc := sc
	nsc.SHA256 = shaOf("other")
	if _, err := l.Put(src, "x", nsc); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Claim("x", sc.ID, fi); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("claimed a replaced file: %v", err)
	}
	f, _, _ = l.Open("x")
	fi, _ = f.Stat()
	f.Close()
	if _, err := l.Claim("x", sc.ID, fi); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileRepairsAliases(t *testing.T) {
	setup := func(t *testing.T) Local {
		l := Local{Base: t.TempDir(), Catalog: true}
		mustPut(t, l, "d1", "one", 1, "cur")
		mustPut(t, l, "d2", "two", 2, "cur")
		return l
	}
	p := func(l Local, rel string) string { return filepath.Join(l.Base, DataDir, rel) }
	cases := map[string]struct {
		breakIt      func(t *testing.T, l Local)
		target, want string
	}{
		"data missing": {func(t *testing.T, l Local) { os.Remove(p(l, "cur")) }, "d2", "two"},
		"target gone": {func(t *testing.T, l Local) {
			os.Remove(p(l, "d2"))
			os.Remove(l.SidecarPath("d2"))
		}, "d1", "one"},
		"stale data": {func(t *testing.T, l Local) {
			os.Remove(p(l, "cur"))
			os.Link(p(l, "d1"), p(l, "cur"))
		}, "d2", "two"},
		"alias missing": {func(t *testing.T, l Local) {
			os.Remove(p(l, "cur"))
			os.Remove(l.SidecarPath("cur"))
		}, "d2", "two"},
		"not the newest": {func(t *testing.T, l Local) {
			b, _ := os.ReadFile(l.SidecarPath("d1"))
			var sc Sidecar
			json.Unmarshal(b, &sc)
			sc.AliasOf = "d1"
			b, _ = json.Marshal(sc)
			os.WriteFile(l.SidecarPath("cur"), b, 0o640)
			os.Remove(p(l, "cur"))
			os.Link(p(l, "d1"), p(l, "cur"))
		}, "d2", "two"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			l := setup(t)
			c.breakIt(t, l)
			if err := l.Reconcile(); err != nil {
				t.Fatal(err)
			}
			checkAlias(t, l, "cur", c.target, c.want)
		})
	}
	t.Run("undeclared", func(t *testing.T) {
		l := setup(t)
		for _, rel := range []string{"d1", "d2"} {
			b, _ := os.ReadFile(l.SidecarPath(rel))
			var sc Sidecar
			json.Unmarshal(b, &sc)
			sc.Meta = nil
			b, _ = json.Marshal(sc)
			os.WriteFile(l.SidecarPath(rel), b, 0o640)
		}
		if err := l.Reconcile(); err != nil {
			t.Fatal(err)
		}
		checkNoAlias(t, l, "cur")
	})
}

func TestReconcileAliasOnStoredPath(t *testing.T) {
	fixedNow(t, 1790000000)
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "latest.tar", "one", 1, "latest.tar")
	if got := mustPut(t, l, "latest.tar", "two", 2, "latest.tar"); got != "latest.tar" {
		t.Fatalf("stored %s", got)
	}
	before, err := os.Stat(filepath.Join(l.Base, catalogFile))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := l.Reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.Stat(filepath.Join(l.Base, catalogFile))
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("catalog rebuilt: %v", err)
	}
	if got, sc := readAll(t, l, "latest.tar"); got != "two" || sc.AliasOf != "" {
		t.Fatalf("latest.tar %q alias_of %q", got, sc.AliasOf)
	}
}

func TestReconcileSkipsBaseWithoutAliases(t *testing.T) {
	l := Local{Base: t.TempDir()}
	mustPut(t, l, "a", "one", 1, "")
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if has, ok := aliasBases.Load(l.key()); !ok || has.(bool) {
		t.Fatalf("flag %v %v", has, ok)
	}
	mustPut(t, l, "b", "two", 2, "cur")
	os.Remove(filepath.Join(l.Base, DataDir, "cur"))
	if err := l.Reconcile(); err != nil {
		t.Fatal(err)
	}
	checkAlias(t, l, "cur", "b", "two")
}

func TestCatalogSkipsUnreadableSidecar(t *testing.T) {
	l := Local{Base: t.TempDir(), Catalog: true}
	mustPut(t, l, "a", "one", 1, "")
	mustPut(t, l, "b", "two", 2, "")
	if err := os.WriteFile(l.SidecarPath("b"), []byte("{"), 0o640); err != nil {
		t.Fatal(err)
	}
	mustPut(t, l, "c", "three", 3, "")
	if n := catalogNames(readCatalog(t, l)); fmt.Sprint(n) != "[a c]" {
		t.Fatalf("catalog %v", n)
	}
	ino := func() uint64 {
		fi, err := os.Stat(filepath.Join(l.Base, catalogFile))
		if err != nil {
			t.Fatal(err)
		}
		return fi.Sys().(*syscall.Stat_t).Ino
	}
	before := ino()
	for range 2 {
		if err := l.Reconcile(); err == nil || !strings.Contains(err.Error(), "b.json") {
			t.Fatalf("reconcile: %v", err)
		}
	}
	if ino() != before {
		t.Fatal("catalog rebuilt for the same unreadable sidecar")
	}
}
