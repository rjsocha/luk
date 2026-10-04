// Package gpgkeys finds the OpenPGP public keys of encryption recipients:
// from a directory of armored keys, or through the Web Key Directory with
// a local cache.
package gpgkeys

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

const (
	// MaxBody bounds a WKD answer.
	MaxBody = 1 << 20
	// Timeout bounds one WKD request.
	Timeout = 10 * time.Second
	// DefaultFresh is how long a cached WKD key is used without a refetch.
	DefaultFresh = 24 * time.Hour
)

// ErrNotFound is a WKD answer of 404: the address publishes no key.
var ErrNotFound = errors.New("no key published (404)")

// Resolver looks up recipients. Dir holds the key files (KeyFiles) of `key`
// recipients; Cache holds the WKD keys as <address>.pgp, fresh for Fresh.
// BaseURL, when set, replaces https://<host> of both WKD methods (tests).
type Resolver struct {
	Dir     string
	Cache   string
	Fresh   time.Duration
	Client  *http.Client
	BaseURL string
	Now     func() time.Time
}

// Recipient is the usable keys of one address. Notes are warnings worth
// logging even when the recipient is usable (a stale cache, an unreadable
// key file).
type Recipient struct {
	Address  string
	Entities []*openpgp.Entity
	Notes    []string
}

// Fingerprints are the uppercase hex fingerprints of the primary keys.
func (r Recipient) Fingerprints() []string {
	var out []string
	for _, e := range r.Entities {
		out = append(out, Fingerprint(e))
	}
	return out
}

func Fingerprint(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Key finds addr in the key files of Dir; it never uses the network.
func (r *Resolver) Key(addr string) (Recipient, error) {
	rc := Recipient{Address: addr}
	if r.Dir == "" {
		return rc, errors.New("no key directory configured")
	}
	files, err := KeyFiles(r.Dir)
	if err != nil {
		return rc, err
	}
	var all []*openpgp.Entity
	for _, f := range files {
		ents, err := readFile(f)
		if err != nil {
			rc.Notes = append(rc.Notes, fmt.Sprintf("%s: %v", f, err))
			continue
		}
		all = append(all, ents...)
	}
	return r.pick(rc, all, "in "+r.Dir)
}

// KeyExts are the extensions of the key files in a key directory, armored
// or binary alike.
var KeyExts = []string{".asc", ".gpg", ".pgp", ".key"}

// KeyFiles returns the key files of dir, sorted.
func KeyFiles(dir string) ([]string, error) {
	var out []string
	for _, ext := range KeyExts {
		m, err := filepath.Glob(filepath.Join(dir, "*"+ext))
		if err != nil {
			return nil, err
		}
		out = append(out, m...)
	}
	sort.Strings(out)
	return out, nil
}

func readFile(p string) ([]*openpgp.Entity, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBody {
		return nil, fmt.Errorf("larger than %d bytes", MaxBody)
	}
	return parse(b)
}

// parse reads a binary key ring, or an armored one.
func parse(b []byte) ([]*openpgp.Entity, error) {
	var el openpgp.EntityList
	var err error
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN")) {
		el, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
	} else {
		el, err = openpgp.ReadKeyRing(bytes.NewReader(b))
	}
	if err != nil {
		return nil, err
	}
	if len(el) == 0 {
		return nil, errors.New("no key")
	}
	return el, nil
}

// pick keeps the entities usable for addr, deduplicated by fingerprint.
func (r *Resolver) pick(rc Recipient, ents []*openpgp.Entity, where string) (Recipient, error) {
	now := r.now()
	seen := map[string]bool{}
	var reasons []string
	matched := false
	for _, e := range ents {
		if !hasAddress(e, rc.Address) {
			continue
		}
		matched = true
		fp := Fingerprint(e)
		if err := Usable(e, rc.Address, now); err != nil {
			reasons = append(reasons, fp+": "+err.Error())
			continue
		}
		if !seen[fp] {
			seen[fp] = true
			rc.Entities = append(rc.Entities, e)
		}
	}
	switch {
	case len(rc.Entities) > 0:
		return rc, nil
	case !matched:
		return rc, fmt.Errorf("no key with user id %s %s", rc.Address, where)
	default:
		return rc, fmt.Errorf("no usable key: %s", strings.Join(reasons, "; "))
	}
}

func uidAddress(id *openpgp.Identity) string {
	if id.UserId == nil {
		return ""
	}
	if id.UserId.Email != "" {
		return strings.ToLower(id.UserId.Email)
	}
	if a, err := mail.ParseAddress(id.UserId.Id); err == nil {
		return strings.ToLower(a.Address)
	}
	return ""
}

func hasAddress(e *openpgp.Entity, addr string) bool {
	for _, id := range e.Identities {
		if uidAddress(id) == addr {
			return true
		}
	}
	return false
}

// Usable reports why e cannot encrypt to addr at now: no valid (self-signed,
// not revoked, not expired) user id with the address, a revoked or expired
// key, or no valid encryption-capable (sub)key.
func Usable(e *openpgp.Entity, addr string, now time.Time) error {
	if e.Revoked(now) {
		return errors.New("key revoked")
	}
	uid := false
	var uidErr error
	for _, id := range e.Identities {
		if uidAddress(id) != addr {
			continue
		}
		if _, err := id.Verify(now, nil); err != nil {
			uidErr = err
			continue
		}
		uid = true
	}
	if !uid {
		if uidErr != nil {
			return fmt.Errorf("user id %s not valid: %v", addr, uidErr)
		}
		return fmt.Errorf("no user id %s", addr)
	}
	if _, err := e.EncryptionKeyWithError(now, nil); err != nil {
		return fmt.Errorf("no valid encryption key: %v", err)
	}
	return nil
}

// WKD finds addr through the Web Key Directory, with the cache: a cached
// key younger than Fresh is used as is; an older one is refetched and used
// again, with a note, when the fetch fails for any reason but a 404.
func (r *Resolver) WKD(ctx context.Context, addr string) (Recipient, error) {
	rc := Recipient{Address: addr}
	if r.Cache == "" {
		return rc, errors.New("no WKD cache directory")
	}
	cached := filepath.Join(r.Cache, addr+".pgp")
	fresh := r.Fresh
	if fresh <= 0 {
		fresh = DefaultFresh
	}
	fi, statErr := os.Stat(cached)
	if statErr == nil && r.now().Sub(fi.ModTime()) < fresh {
		if ents, err := readFile(cached); err == nil {
			return r.pick(rc, ents, "in the WKD cache")
		}
	}
	data, err := r.fetch(ctx, addr)
	var ents []*openpgp.Entity
	if err == nil {
		if ents, err = parse(data); err != nil {
			err = fmt.Errorf("WKD key: %w", err)
		}
	}
	if err == nil {
		if werr := r.store(cached, data); werr != nil {
			rc.Notes = append(rc.Notes, "WKD cache not written: "+werr.Error())
		}
		return r.pick(rc, ents, "from WKD")
	}
	if errors.Is(err, ErrNotFound) || statErr != nil {
		return rc, err
	}
	stale, rerr := readFile(cached)
	if rerr != nil {
		return rc, fmt.Errorf("%v; cached key: %v", err, rerr)
	}
	rc.Notes = append(rc.Notes, fmt.Sprintf("WKD fetch failed, using the cached key from %s: %v", fi.ModTime().UTC().Format(time.RFC3339), err))
	return r.pick(rc, stale, "in the WKD cache")
}

func (r *Resolver) store(p string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), ".wkd-*")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		now := r.now()
		err = os.Chtimes(f.Name(), now, now)
	}
	if err == nil {
		err = os.Rename(f.Name(), p)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// fetch uses the advanced method; only when its host does not answer
// (no HTTP response) the direct method.
func (r *Resolver) fetch(ctx context.Context, addr string) ([]byte, error) {
	adv, dir, err := r.urls(addr)
	if err != nil {
		return nil, err
	}
	b, aerr := r.get(ctx, adv)
	var answered *answerError
	if aerr == nil || errors.Is(aerr, ErrNotFound) || errors.As(aerr, &answered) {
		return b, aerr
	}
	b, derr := r.get(ctx, dir)
	if derr == nil || errors.Is(derr, ErrNotFound) {
		return b, derr
	}
	return nil, fmt.Errorf("advanced: %v; direct: %v", aerr, derr)
}

// answerError is a failure after an HTTP answer other than 404.
type answerError struct{ msg string }

func (e *answerError) Error() string { return e.msg }

func (r *Resolver) urls(addr string) (string, string, error) {
	if r.BaseURL == "" {
		a, err := AdvancedURL(addr)
		if err != nil {
			return "", "", err
		}
		d, err := DirectURL(addr)
		return a, d, err
	}
	local, domain, hash, err := split(addr)
	if err != nil {
		return "", "", err
	}
	base := strings.TrimSuffix(r.BaseURL, "/")
	q := "?l=" + url.QueryEscape(local)
	return base + "/.well-known/openpgpkey/" + domain + "/hu/" + hash + q,
		base + "/.well-known/openpgpkey/hu/" + hash + q, nil
}

func (r *Resolver) get(ctx context.Context, u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c := r.Client
	if c == nil {
		c = &http.Client{Timeout: Timeout}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, &answerError{fmt.Sprintf("%s: %s", u, resp.Status)}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return nil, &answerError{fmt.Sprintf("%s: %v", u, err)}
	}
	if len(b) > MaxBody {
		return nil, &answerError{fmt.Sprintf("%s: answer larger than %d bytes", u, MaxBody)}
	}
	return b, nil
}

func split(addr string) (local, domain, hash string, err error) {
	i := strings.LastIndexByte(addr, '@')
	if i <= 0 || i == len(addr)-1 {
		return "", "", "", fmt.Errorf("%q: not an e-mail address", addr)
	}
	local, domain = addr[:i], strings.ToLower(addr[i+1:])
	return local, domain, Hash(local), nil
}

// AdvancedURL is the WKD advanced method URL of addr.
func AdvancedURL(addr string) (string, error) {
	local, domain, hash, err := split(addr)
	if err != nil {
		return "", err
	}
	return "https://openpgpkey." + domain + "/.well-known/openpgpkey/" + domain + "/hu/" + hash + "?l=" + url.QueryEscape(local), nil
}

// DirectURL is the WKD direct method URL of addr.
func DirectURL(addr string) (string, error) {
	local, domain, hash, err := split(addr)
	if err != nil {
		return "", err
	}
	return "https://" + domain + "/.well-known/openpgpkey/hu/" + hash + "?l=" + url.QueryEscape(local), nil
}

// Hash is the z-base-32 encoded SHA-1 of the lowercased local part.
func Hash(local string) string {
	sum := sha1.Sum([]byte(strings.ToLower(local)))
	return zbase32(sum[:])
}

const zbase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

func zbase32(b []byte) string {
	var sb strings.Builder
	var acc uint32
	bits := 0
	for _, c := range b {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(zbase32Alphabet[(acc>>bits)&31])
		}
	}
	if bits > 0 {
		sb.WriteByte(zbase32Alphabet[(acc<<(5-bits))&31])
	}
	return sb.String()
}

// Config is the packet config for encryption at now.
func Config(now time.Time) *packet.Config {
	return &packet.Config{Time: func() time.Time { return now }}
}
