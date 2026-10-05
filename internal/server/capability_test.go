package server

import (
	"crypto/rand"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

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
	drop := func(got wire.EndpointList) wire.EndpointInfo { return dropInfo(t, got) }
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
		rec, _ := f.do(t, req{signer: signer, path: "/drop", meta: m})
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
// is refused before the body; it never reaches the disk.
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
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "does not keep secrets in RAM") {
		t.Fatalf("not granted: %d %s", rec.Code, rec.Body)
	}
	f.settle(t)
	if n := f.runs(t); n != 0 {
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

// backupFixture restricts the backup hostname on /drop: robert.socha may
// send any, the certificates of hosts and the plain key other only one
// of their own principals.
func backupFixture(t *testing.T, hostname string) *privateFixture {
	t.Helper()
	return newPrivateFixture(t, func(s string) string {
		return strings.Replace(s, `link: {remove: ['*'], list: ['*']}}`, `link: {remove: ['*'], list: ['*']}, backup: {hostname: `+hostname+`}}`, 1)
	})
}

// hostCertWith is a host certificate of the fixture CA with principals.
func (f *fixture) hostCertWith(t *testing.T, keyID string, principals ...string) ssh.Signer {
	t.Helper()
	host := newSigner(t)
	c := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, KeyId: keyID, ValidPrincipals: principals, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, f.hostCA); err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(c, host)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// backupMeta is the meta of luk send --backup from hostname.
func backupMeta(hostname string) wire.Meta {
	return wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Backup: &wire.Backup{Hostname: hostname, Path: "/var/backups/dump"}}
}

// TestBackupHostnameUpload: with backup.hostname an upload carrying a
// hostname passes for any, or for principal when the hostname is a
// principal of the certificate; else 403 before the body, naming no list.
func TestBackupHostnameUpload(t *testing.T) {
	f := backupFixture(t, `{any: [robert.socha], principal: ['hosts:*', other]}`)
	db1 := f.hostCertWith(t, "db1", "db1.example.net", "db1")
	f.drop(t, f.user, backupMeta("anything.example.org"), "any")
	f.drop(t, db1, backupMeta("db1.example.net"), "principal")
	f.drop(t, db1, backupMeta("DB1.Example.NET"), "principal, case")
	f.drop(t, f.other, wire.Meta{}, "plain key without --backup")
	f.drop(t, f.hostCertWith(t, "web1"), wire.Meta{}, "certificate without --backup")
	for name, c := range map[string]struct {
		signer   ssh.Signer
		hostname string
	}{
		"principal mismatch":     {db1, "web1.example.net"},
		"plain key in principal": {f.other, "other"},
		"no principals":          {f.hostCertWith(t, "web1"), "web1"},
	} {
		rec, _ := f.do(t, req{signer: c.signer, path: "/drop", meta: backupMeta(c.hostname)})
		body := rec.Body.String()
		if rec.Code != http.StatusForbidden || !strings.Contains(body, `backup hostname \"`+c.hostname+`\" not allowed for this key`) ||
			strings.Contains(body, "robert.socha") || strings.Contains(body, "hosts") {
			t.Errorf("%s: %d %s", name, rec.Code, body)
		}
	}
}

// TestBackupHostnameBothLists: a signer in any and principal sends any
// hostname; one in neither sends none.
func TestBackupHostnameBothLists(t *testing.T) {
	f := backupFixture(t, `{any: [robert.socha], principal: [robert.socha]}`)
	f.drop(t, f.user, backupMeta("db9.example.net"), "both")
	rec, _ := f.do(t, req{signer: f.other, path: "/drop", meta: backupMeta("other")})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("neither: %d %s", rec.Code, rec.Body)
	}
	if e := dropInfo(t, decodeList(t, f.list(t, listReq{signer: f.user}))); e.BackupHostname != wire.BackupHostAny {
		t.Fatalf("both: %+v", e)
	}
}

// TestBackupHostnameNoBlock: without backup.hostname anyone the endpoint
// admits sends any hostname, and the listing has no backup_hostname.
func TestBackupHostnameNoBlock(t *testing.T) {
	f := newPrivateFixture(t, nil)
	f.drop(t, f.other, backupMeta("db9.example.net"), "plain")
	f.drop(t, f.hostCertWith(t, "web1"), backupMeta("db9.example.net"), "certificate")
	rec := f.list(t, listReq{signer: f.other})
	if strings.Contains(rec.Body.String(), "backup_hostname") {
		t.Fatalf("listing: %s", rec.Body)
	}
}

// TestBackupHostnameListing: the listing tells each signer how it may use
// --backup, nothing of the lists.
func TestBackupHostnameListing(t *testing.T) {
	f := backupFixture(t, `{any: [robert.socha], principal: ['hosts:*']}`)
	for name, c := range map[string]struct {
		signer ssh.Signer
		want   string
	}{
		"any":       {f.user, wire.BackupHostAny},
		"principal": {f.hostCertWith(t, "db1", "db1"), wire.BackupHostPrincipal},
		"none":      {f.other, wire.BackupHostNone},
	} {
		rec := f.list(t, listReq{signer: c.signer})
		if dropInfo(t, decodeList(t, rec)).BackupHostname != c.want || strings.Contains(rec.Body.String(), "robert.socha") {
			t.Errorf("%s: %s", name, rec.Body)
		}
	}
}

// dropInfo is the drop endpoint of a listing.
func dropInfo(t *testing.T, got wire.EndpointList) wire.EndpointInfo {
	t.Helper()
	for _, e := range got.Endpoints {
		if e.Name == "drop" {
			return e
		}
	}
	t.Fatalf("no drop in %+v", got)
	return wire.EndpointInfo{}
}
