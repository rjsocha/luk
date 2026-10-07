package server

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/wire"
)

// tagTTLFixture has the policy tags ttl-3d (3d everywhere) and ttl-7d (7d,
// 2d in drop), and a drop of ttl.max 14d.
func tagTTLFixture(t *testing.T) *fixture {
	t.Helper()
	return linkFixture(t, func(s string) string {
		s = strings.Replace(s, "ttl: {user: true, max: 7d}", "ttl: {user: true, min: 1h, max: 14d, tag: {ttl-7d: 2d}}", 1)
		return s + "tag:\n  ttl-3d: {ttl: 3d}\n  ttl-7d: {ttl: 7d}\n"
	})
}

func TestTagTTLStored(t *testing.T) {
	const d = 24 * time.Hour
	f := tagTTLFixture(t)
	archive := filepath.Join(f.root, "data", "s/archive")
	for _, tc := range []struct {
		file string
		tags []string
		ttl  string
		d    time.Duration
	}{
		{"tagged", []string{"prod", "ttl-3d"}, "3d", 3 * d},
		{"shortest", []string{"prod", "ttl-3d", "ttl-7d"}, "3d", 3 * d},
		{"plain", []string{"prod"}, "", 0},
	} {
		body := []byte(tc.file)
		m := fileMeta(body, tc.tags...)
		m.File = tc.file
		before := time.Now()
		rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: body})
		out := receipt(t, rec, http.StatusAccepted)
		if out.TTL != tc.ttl || out.TTLNote != "" || out.TTLMin != "" || out.TTLMax != tc.ttl {
			t.Errorf("%s: answer %+v, want ttl and ttl_max %q", tc.file, out, tc.ttl)
		}
		f.settle(t)
		sc := sidecarOf(t, archive, tc.file)
		if tc.d == 0 {
			if sc.Expires != "" {
				t.Errorf("%s: sidecar expires %q, want none", tc.file, sc.Expires)
			}
			continue
		}
		expiresAbout(t, tc.file, sc.Expires, before, tc.d)
	}
}

func TestTagTTLClient(t *testing.T) {
	const d = 24 * time.Hour
	f := tagTTLFixture(t)
	for _, tc := range []struct {
		name      string
		tags      []string
		ask       string
		ttl, note string
		max       string
		d         time.Duration
	}{
		{"no client ttl", []string{"ttl-3d"}, "", "3d", "", "3d", 3 * d},
		{"inside", []string{"ttl-3d"}, "1d", "1d", "", "3d", d},
		{"above the tag", []string{"ttl-3d"}, "10d", "3d", wire.TTLCapped, "3d", 3 * d},
		{"max", []string{"ttl-3d"}, wire.TTLMax, "3d", "", "3d", 3 * d},
		{"below min", []string{"ttl-3d"}, "1m", "1h", wire.TTLRaised, "3d", time.Hour},
		{"storage value", []string{"ttl-7d"}, "", "2d", "", "2d", 2 * d},
		{"no policy tag", []string{"prod"}, "", "14d", "", "14d", 14 * d},
		{"no policy tag, above max", nil, "30d", "14d", wire.TTLCapped, "14d", 14 * d},
	} {
		before := time.Now()
		rec, _ := f.do(t, req{signer: f.user, path: "/drop", meta: wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Tags: tc.tags, TTL: tc.ask}, body: []byte(tc.name)})
		out := receipt(t, rec, http.StatusCreated)
		if out.TTL != tc.ttl || out.TTLNote != tc.note || out.TTLMin != "1h" || out.TTLMax != tc.max {
			t.Errorf("%s: answer %+v, want ttl %q note %q max %q", tc.name, out, tc.ttl, tc.note, tc.max)
		}
		expiresAbout(t, tc.name, out.Expires, before, tc.d)
		f.settle(t)
		if sc := f.dropSidecar(t, out.URL); sc.Expires != out.Expires {
			t.Errorf("%s: sidecar expires %q, answer %q", tc.name, sc.Expires, out.Expires)
		}
	}
}

func TestTagTTLLink(t *testing.T) {
	const d = 24 * time.Hour
	f := tagTTLFixture(t)
	tagged := f.drop(t, f.user, wire.Meta{Tags: []string{"ttl-3d"}, TTL: "1h"}, "tagged")
	plain := f.drop(t, f.user, wire.Meta{TTL: "1h"}, "plain")
	for _, tc := range []struct {
		link, ask string
		ttl, note string
		d         time.Duration
	}{
		{tagged, "2d", "2d", "", 2 * d},
		{tagged, "10d", "3d", wire.TTLCapped, 3 * d},
		{tagged, wire.TTLMax, "3d", "", 3 * d},
		{plain, "10d", "10d", "", 10 * d},
		{plain, wire.TTLMax, "14d", "", 14 * d},
	} {
		want := "14d"
		if tc.link == tagged {
			want = "3d"
		}
		before := time.Now()
		a := linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, ttl: tc.ask, link: tc.link}), http.StatusOK)
		if a.TTL != tc.ttl || a.TTLNote != tc.note || a.TTLMin != "1h" || a.TTLMax != want {
			t.Errorf("%s: %+v, want ttl %q note %q max %q", tc.ask, a, tc.ttl, tc.note, want)
		}
		expiresAbout(t, tc.ask, a.Expires, before, tc.d)
		if sc := f.dropSidecar(t, tc.link); sc.Expires != a.Expires {
			t.Errorf("%s: sidecar expires %q, answer %q", tc.ask, sc.Expires, a.Expires)
		}
	}
}
