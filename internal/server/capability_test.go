package server

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"luk/internal/wire"
)

// capabilityFixture grants every capability of /drop to some identities
// only: robert.socha (user), other, and the certificates of hosts.
func capabilityFixture(t *testing.T) *privateFixture {
	t.Helper()
	return newPrivateFixture(t, func(s string) string {
		return strings.Replace(s, `private: {owner: ['*'], any: ['*']}, link: {remove: ['*'], list: ['*']}`,
			`private: {owner: [robert.socha], any: ['hosts:*']}, link: {remove: [robert.socha], ttl: [other], replace: [robert.socha], list: [other]}, pretty: {allow: [other]}`, 1)
	})
}

// TestCapabilitiesListing: the listing shows each signer what it is
// granted, nothing of the lists.
func TestCapabilitiesListing(t *testing.T) {
	f := capabilityFixture(t)
	drop := func(got wire.EndpointList) wire.EndpointInfo {
		for _, e := range got.Endpoints {
			if e.Name == "drop" {
				return e
			}
		}
		t.Fatalf("no drop in %+v", got)
		return wire.EndpointInfo{}
	}
	for name, c := range map[string]struct {
		got     wire.EndpointInfo
		pretty  bool
		private wire.PrivateModes
		link    wire.LinkActions
	}{
		"user":  {drop(decodeList(t, f.list(t, listReq{signer: f.user}))), false, wire.PrivateModes{Owner: true}, wire.LinkActions{Remove: true, Replace: true}},
		"other": {drop(decodeList(t, f.list(t, listReq{signer: f.other}))), true, wire.PrivateModes{}, wire.LinkActions{TTL: true, List: true}},
		"host":  {drop(decodeList(t, f.list(t, listReq{signer: f.hostCert(t)}))), false, wire.PrivateModes{Any: true}, wire.LinkActions{}},
	} {
		if c.got.Pretty != c.pretty || c.got.Secret || !reflect.DeepEqual(c.got.Private, c.private) || !reflect.DeepEqual(c.got.Link, c.link) {
			t.Errorf("%s: %+v", name, c.got)
		}
	}
}

// TestCapabilitiesUpload: a capability not granted to the signer is
// refused before the body as on an endpoint without it.
func TestCapabilitiesUpload(t *testing.T) {
	f := capabilityFixture(t)
	for name, c := range map[string]struct {
		meta wire.Meta
		msg  string
	}{
		"pretty":  {wire.Meta{PrettyURL: true}, "does not offer pretty URLs"},
		"mutable": {wire.Meta{Mutable: true}, "link.replace"},
		"private": {wire.Meta{Access: wire.AccessPrivate}, "private.owner"},
		"any":     {wire.Meta{Access: wire.AccessAny}, "private.any"},
	} {
		signer := f.user
		if name == "mutable" || name == "private" {
			signer = f.other
		}
		m := c.meta
		m.Portal, m.Source = wire.PortalDirect, wire.SourceStdin
		rec, _ := f.do(t, req{signer: signer, path: "/drop", meta: m, chunked: true})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), c.msg) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	f.drop(t, f.other, wire.Meta{PrettyURL: true}, "pretty")
	f.drop(t, f.user, wire.Meta{Mutable: true}, "mutable")
	f.drop(t, f.user, wire.Meta{Access: wire.AccessPrivate}, "private")
	f.drop(t, f.hostCert(t), wire.Meta{Access: wire.AccessAny}, "any")
}

// TestCapabilitiesLinks: each link action checks its list for the signer.
func TestCapabilitiesLinks(t *testing.T) {
	f := capabilityFixture(t)
	mine := f.drop(t, f.user, wire.Meta{}, "mine")
	theirs := f.drop(t, f.other, wire.Meta{}, "theirs")
	forbidden := func(what string, code int, body string) {
		t.Helper()
		if code != http.StatusForbidden || !strings.Contains(body, "does not allow link") {
			t.Errorf("%s: %d %s", what, code, body)
		}
	}
	rec := f.link(t, linkReq{signer: f.user, action: wire.LinkList})
	forbidden("user list", rec.Code, rec.Body.String())
	rec = f.link(t, linkReq{signer: f.other, action: wire.LinkRemove, link: theirs})
	forbidden("other remove", rec.Code, rec.Body.String())
	rec = f.link(t, linkReq{signer: f.user, action: wire.LinkTTL, link: mine, ttl: "1h"})
	forbidden("user ttl", rec.Code, rec.Body.String())
	if rec := f.link(t, linkReq{signer: f.other, action: wire.LinkList}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), theirs) {
		t.Fatalf("other list: %d %s", rec.Code, rec.Body)
	}
	linkAnswer(t, f.link(t, linkReq{signer: f.other, action: wire.LinkTTL, link: theirs, ttl: "1h"}), http.StatusOK)
	linkAnswer(t, f.link(t, linkReq{signer: f.user, action: wire.LinkRemove, link: mine}), http.StatusOK)
}

// TestSecretAllow: a reveal upload of a signer secret.allow does not grant
// goes through the endpoint queue and pipelines, as without secret.
func TestSecretAllow(t *testing.T) {
	other := newSigner(t)
	f := newSecretFixture(t, func(s string) string {
		s = strings.Replace(s, `keys: [{name: robert.socha, key: "`, `keys: [{name: other, key: "`+pubLine(other.PublicKey())+`"}, {name: robert.socha, key: "`, 1)
		return strings.Replace(s, `allow: [robert.socha], respond: url, storage: drop, secret: {allow: ['*']`,
			`allow: [robert.socha, other], respond: url, storage: drop, secret: {allow: [robert.socha]`, 1)
	})
	out := receipt(t, mustDo(t, f.fixture, secretMeta("mine"), "mine"), http.StatusCreated)
	if !strings.HasPrefix(out.URL, "https://lukd.vm:8443/d/volatile/") {
		t.Fatalf("granted: %s", out.URL)
	}
	rec, _ := f.do(t, req{signer: other, path: "/drop", meta: secretMeta("theirs"), body: []byte("theirs")})
	out = receipt(t, rec, http.StatusCreated)
	if strings.HasPrefix(out.URL, "https://lukd.vm:8443/d/volatile/") {
		t.Fatalf("not granted: %s", out.URL)
	}
	f.settle(t)
	if got, err := os.ReadFile(filepath.Join(f.root, "s/drop/file", path.Base(out.URL))); err != nil || string(got) != "theirs" {
		t.Fatalf("stored %q %v", got, err)
	}
	if n := f.runs(t); n != 1 {
		t.Fatalf("run step ran %d times", n)
	}
	got := decodeList(t, f.list(t, listReq{signer: other}))
	if len(got.Endpoints) != 1 || got.Endpoints[0].Secret || got.Endpoints[0].SecretTTL != nil {
		t.Fatalf("other listing %+v", got)
	}
	if got := decodeList(t, f.list(t, listReq{signer: f.user})); !got.Endpoints[len(got.Endpoints)-1].Secret {
		t.Fatalf("user listing %+v", got)
	}
}
