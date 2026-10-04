package server

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"luk/internal/pipeline"
	"luk/internal/queue"
	"luk/internal/store"
	"luk/internal/wire"
)

// maxLinksFixture is the dedup fixture with links.max 3 on the drop
// storage and the link actions on /drop.
func maxLinksFixture(t *testing.T) (*fixture, ssh.Signer) {
	t.Helper()
	return dedupFixture(t, func(s string) string {
		s = strings.Replace(s, `respond: url, storage: drop}`, allLinks, 1)
		return strings.Replace(s, `drop: {type: local, base: s/drop,`, `drop: {type: local, links: {max: 3}, base: s/drop,`, 1)
	})
}

// tooMany wants the 429 of links.max 3 before any body byte is read.
func tooMany(t *testing.T, f *fixture, signer ssh.Signer, body []byte) {
	t.Helper()
	n := 0
	rec, _ := f.do(t, req{signer: signer, path: "/drop", meta: fileMeta(body), body: body, tamper: countBody(&n)})
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"limit of 3 links to the same content reached"`) || n != 0 {
		t.Fatalf("%d, read %d: %s", rec.Code, n, rec.Body)
	}
}

func (f *fixture) owned(content []byte, owner string) int {
	l := store.Local{Base: filepath.Join(f.root, "s/drop"), Hardlink: true}
	return l.Owned(fileMeta(content).SHA256, owner)
}

func TestLinksMax(t *testing.T) {
	f, anna := maxLinksFixture(t)
	body := []byte("linked often")
	var urls []string
	for range 3 {
		r, _ := f.put(t, f.user, fileMeta(body), body)
		urls = append(urls, r.URL)
	}
	// Not stored yet: the queued uploads count.
	tooMany(t, f, f.user, body)
	f.settle(t)
	tooMany(t, f, f.user, body)
	if n := f.owned(body, "key:robert.socha"); n != 3 {
		t.Fatalf("robert.socha owns %d names", n)
	}
	// Another identity is counted on its own.
	if r, _ := f.put(t, anna, fileMeta(body), body); r.Deduplicated {
		t.Fatalf("anna: %+v", r)
	}
	f.settle(t)
	// A removed name no longer counts.
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: urls[0]}), http.StatusOK)
	if r, n := f.put(t, f.user, fileMeta(body), body); n != 0 || !r.Deduplicated {
		t.Fatalf("after a removal, read %d: %+v", n, r)
	}
	f.settle(t)
	tooMany(t, f, f.user, body)
	// Other content is not limited by it.
	other := []byte("other content")
	f.put(t, f.user, fileMeta(other), other)
}

func TestLinksMaxAtStore(t *testing.T) {
	f, _ := maxLinksFixture(t)
	body := []byte("streamed again")
	for range 3 {
		f.put(t, f.user, fileMeta(body), body)
	}
	f.settle(t)
	// A stream signs no sha256: accepted, refused by the store step.
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin}, body: body, chunked: true})
	receipt(t, rec, http.StatusCreated)
	f.settle(t)
	if n := f.owned(body, "key:robert.socha"); n != 3 {
		t.Fatalf("robert.socha owns %d names", n)
	}
	failed, err := pipeline.ListFailed(f.srv.config())
	if err != nil || len(failed) != 1 || len(failed[0].Meta.Failed) != 1 ||
		!strings.Contains(failed[0].Meta.Failed[0].Error, "limit of 3 links to the same content reached") {
		t.Fatalf("failed %+v: %v", failed, err)
	}
}

func TestLinksMaxDefault(t *testing.T) {
	f, _ := dedupFixture(t, nil)
	if l := store.FromConfig(f.srv.config().Storage["drop"]); l.MaxLinks != 100 {
		t.Fatalf("max %d", l.MaxLinks)
	}
}

// storeEntry stores the queued upload id into the storages sns as its
// store step does and leaves its queue entry: the moment after the store,
// before the dispatcher removes the entry (or while later steps run).
func (f *fixture) storeEntry(t *testing.T, id string, sns ...string) {
	t.Helper()
	pending, err := queue.Pending(f.srv.config().Endpoint["drop"].Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range pending {
		if e.ID != id {
			continue
		}
		j, err := pipeline.LoadJob(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, sn := range sns {
			st := f.srv.config().Storage[sn]
			l := store.FromConfig(st)
			rel, err := l.Render(st.PathTemplate(), j.Vars.For(sn))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.Store(filepath.Join(j.Entry.Dir, "payload"), rel, j.Sidecar); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	t.Fatalf("no queue entry %s", id)
}

// limitOfTwo wants the 429 of links.max 2.
func limitOfTwo(t *testing.T, f *fixture, body []byte) {
	t.Helper()
	rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: fileMeta(body), body: body})
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "limit of 2 links to the same content reached") {
		t.Fatalf("%d: %s", rec.Code, rec.Body)
	}
}

// A stored upload whose queue entry is still there takes one link of the
// limit, not two: in one storage, in a fan-out to several, and while the
// steps after the store run.
func TestLinksMaxStoredAndQueuedCountOnce(t *testing.T) {
	for name, mod := range map[string]func(string) string{
		"one storage": nil,
		"fan-out": func(s string) string {
			s = strings.Replace(s, `drop: {endpoint: [drop], steps: [{store: drop}]}`, `drop: {endpoint: [drop], steps: [{store: [drop, copy]}]}`, 1)
			return strings.Replace(s, "expose:\n", "  copy: {type: local, links: {max: 2}, base: s/copy, path: \"{{ .Random }}\"}\nexpose:\n", 1)
		},
		"steps after the store": func(s string) string {
			return strings.Replace(s, `drop: {endpoint: [drop], steps: [{store: drop}]}`, `drop: {endpoint: [drop], steps: [{store: drop}, {run: /bin/true}]}`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := dedupFixture(t, func(s string) string {
				s = strings.Replace(s, `drop: {type: local, base: s/drop,`, `drop: {type: local, links: {max: 2}, base: s/drop,`, 1)
				if mod != nil {
					s = mod(s)
				}
				return s
			})
			stores := []string{"drop"}
			if name == "fan-out" {
				stores = append(stores, "copy")
			}
			body := []byte("same content")
			r, _ := f.put(t, f.user, fileMeta(body), body)
			// The first storage only: the fan-out is half done.
			f.storeEntry(t, r.ID, stores[0])
			r, _ = f.put(t, f.user, fileMeta(body), body)
			f.storeEntry(t, r.ID, stores...)
			limitOfTwo(t, f, body)
			if n := f.owned(body, "key:robert.socha"); n != 2 {
				t.Fatalf("robert.socha owns %d names", n)
			}
		})
	}
}
