// Package auth maps a verified SSH key to an identity and decides access.
package auth

import (
	"bytes"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/config"
	"luk/internal/sshsig"
	"luk/internal/wire"
)

type Authenticator struct {
	keys map[string]string // marshaled key -> name
	cas  []config.CA
}

func New(a config.Auth) *Authenticator {
	keys := map[string]string{}
	for _, k := range a.Keys {
		for _, pub := range k.Parsed {
			keys[string(pub.Marshal())] = k.Name
		}
	}
	return &Authenticator{keys: keys, cas: a.CA}
}

// Resolve returns the identity of an already verified signing key.
func (a *Authenticator) Resolve(pub ssh.PublicKey, now time.Time) (*wire.Identity, error) {
	if c, ok := pub.(*ssh.Certificate); ok {
		return a.resolveCert(c, now)
	}
	if name, ok := a.keys[string(pub.Marshal())]; ok {
		return &wire.Identity{Name: name, Type: "key", Fingerprint: ssh.FingerprintSHA256(pub)}, nil
	}
	return nil, fmt.Errorf("unknown key %s", ssh.FingerprintSHA256(pub))
}

func (a *Authenticator) resolveCert(c *ssh.Certificate, now time.Time) (*wire.Identity, error) {
	var mismatch error
	for _, ca := range a.cas {
		if !slices.ContainsFunc(ca.Parsed, func(k ssh.PublicKey) bool { return bytes.Equal(c.SignatureKey.Marshal(), k.Marshal()) }) {
			continue
		}
		want := uint32(ssh.HostCert)
		if ca.Type == "user" {
			want = ssh.UserCert
		}
		if c.CertType != want {
			mismatch = fmt.Errorf("certificate %q is not a %s certificate (CA %s)", c.KeyId, ca.Type, ca.Name)
			continue
		}
		checker := &ssh.CertChecker{
			Clock: func() time.Time { return now },
			IsRevoked: func(c *ssh.Certificate) bool {
				return slices.Contains(ca.Revoked.KeyIDs, c.KeyId) || slices.Contains(ca.Revoked.Serials, c.Serial)
			},
		}
		// CheckCert verifies the CA signature in any format the key
		// supports; SHA-1 formats and weak certified keys are refused here.
		if c.Signature == nil {
			return nil, fmt.Errorf("certificate %q: no signature", c.KeyId)
		}
		if err := sshsig.CheckFormat(c.Signature.Format); err != nil {
			return nil, fmt.Errorf("certificate %q: %w", c.KeyId, err)
		}
		if err := sshsig.CheckKey(c.Key); err != nil {
			return nil, fmt.Errorf("certificate %q: %w", c.KeyId, err)
		}
		// CheckCert wants a principal; any listed one proves nothing extra,
		// principals are matched later by the endpoint's allow.
		principal := ""
		if len(c.ValidPrincipals) > 0 {
			principal = c.ValidPrincipals[0]
		}
		if err := checker.CheckCert(principal, c); err != nil {
			return nil, fmt.Errorf("certificate %q: %w", c.KeyId, err)
		}
		return &wire.Identity{
			Name:        ca.Name + ":" + c.KeyId,
			Type:        "certificate",
			CA:          ca.Name,
			KeyID:       c.KeyId,
			Principals:  c.ValidPrincipals,
			Serial:      c.Serial,
			Fingerprint: ssh.FingerprintSHA256(c.Key),
		}, nil
	}
	if mismatch != nil {
		return nil, mismatch
	}
	return nil, fmt.Errorf("certificate %q signed by an unknown CA %s", c.KeyId, ssh.FingerprintSHA256(c.SignatureKey))
}

// Owner is what a portal page shows as the sender of id (unless
// no_owner): the identity name of a plain key, or the type of the CA
// ("host" or "user") of a certificate, never anything from the key or
// certificate itself.
func (a *Authenticator) Owner(id *wire.Identity) string {
	if id.Type == "key" {
		return id.Name
	}
	for _, ca := range a.cas {
		if ca.Name == id.CA {
			return ca.Type
		}
	}
	return ""
}

// OwnerKey is the owner of what id uploads, for managing its link: the
// identity name of a plain key (every key of that identity is the owner),
// or the CA name and the Key ID of a certificate. It is derived from the
// authenticated identity only.
func OwnerKey(id *wire.Identity) string {
	if id.Type == "key" {
		return "key:" + id.Name
	}
	return "cert:" + id.CA + ":" + id.KeyID
}

// Allowed reports whether id matches an entry of an allow list (of an
// endpoint, of an expose with auth.ssh, of a quota class): a key name,
// "<ca>:<glob>" over the certificate principals, where "*" also admits
// certificates without principals, "<ca>#<glob>" over the certificate Key
// ID, or AllowAll. id is resolved against the current configuration, so
// AllowAll admits every identity it knows.
func Allowed(id *wire.Identity, allow []string) bool {
	for _, e := range allow {
		if e == AllowAll {
			return true
		}
		i := strings.IndexAny(e, ":#")
		if i < 0 {
			if id.Type == "key" && id.Name == e {
				return true
			}
			continue
		}
		ca, sep, glob := e[:i], e[i], e[i+1:]
		if id.Type != "certificate" || id.CA != ca {
			continue
		}
		if sep == '#' {
			if ok, _ := path.Match(glob, id.KeyID); ok {
				return true
			}
			continue
		}
		if glob == "*" {
			return true
		}
		for _, p := range id.Principals {
			if ok, _ := path.Match(glob, p); ok {
				return true
			}
		}
	}
	return false
}

// AllowAll in an allow list admits every identity lukd knows: every plain
// key and every certificate of every CA.
const AllowAll = "*"
