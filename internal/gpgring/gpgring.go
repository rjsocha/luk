// Package gpgring finds the OpenPGP public key of an encryption recipient
// in the GnuPG keyring of the user, through the gpg program: gpg judges the
// validity of the key and exports it, and never sees the content.
package gpgring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"luk/internal/gpgkeys"
)

var (
	fingerprintRE = regexp.MustCompile(`^(0x)?([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$`)
	addressRE     = regexp.MustCompile(`^[^\s<>@]+@[^\s<>@]+$`)
	escapeRE      = regexp.MustCompile(`\\x[0-9A-Fa-f]{2}`)
)

// key is one public key of a colon listing: the fingerprint of the primary
// key, its validity (field 2), its capabilities (field 12) and its user ids.
type key struct {
	fingerprint, validity, caps string
	uids                        []uid
}

// uid is the validity and the lowercased e-mail address of a user id.
type uid struct{ validity, address string }

// parseColons reads the output of gpg --list-keys --with-colons.
func parseColons(b []byte) []key {
	var keys []key
	primary := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 10 {
			continue
		}
		switch f[0] {
		case "pub":
			k := key{validity: f[1]}
			if len(f) > 11 {
				k.caps = f[11]
			}
			keys, primary = append(keys, k), true
		case "sub":
			primary = false
		case "fpr":
			if primary && len(keys) > 0 && keys[len(keys)-1].fingerprint == "" {
				keys[len(keys)-1].fingerprint = strings.ToUpper(f[9])
			}
		case "uid":
			if len(keys) > 0 {
				k := &keys[len(keys)-1]
				k.uids = append(k.uids, uid{f[1], address(f[9])})
			}
		}
	}
	return keys
}

// address is the lowercased e-mail address of a user id field, empty
// without one.
func address(field string) string {
	id := escapeRE.ReplaceAllStringFunc(field, func(s string) string {
		n, _ := strconv.ParseUint(s[2:], 16, 8)
		return string(rune(n))
	})
	if i, j := strings.LastIndexByte(id, '<'), strings.LastIndexByte(id, '>'); i >= 0 && j > i {
		id = id[i+1 : j]
	}
	if !addressRE.MatchString(id) {
		return ""
	}
	return strings.ToLower(id)
}

var validities = map[string]string{
	"o": "unknown", "-": "unknown", "": "unknown", "q": "undefined", "n": "never", "m": "marginal",
	"i": "invalid", "d": "disabled", "r": "revoked", "e": "expired", "f": "full", "u": "ultimate",
}

// usable tells whether a key of this validity and these capabilities can be
// a recipient: gpg holds it valid, it is enabled and it can encrypt.
func usable(validity, caps string) bool {
	return (validity == "f" || validity == "u") && !strings.Contains(caps, "D") && strings.Contains(caps, "E")
}

// Recipient is a recipient Find accepts: an e-mail address, or, for an
// address with several usable keys, each fingerprint described by the
// address.
type Recipient struct{ Name, Description string }

// recipients lists what Find accepts of keys, sorted by name.
func recipients(keys []key) []Recipient {
	of := map[string][]string{}
	for _, k := range keys {
		seen := map[string]bool{}
		for _, u := range k.uids {
			if u.address != "" && !seen[u.address] && usable(u.validity, k.caps) {
				seen[u.address] = true
				of[u.address] = append(of[u.address], k.fingerprint)
			}
		}
	}
	var list []Recipient
	for addr, fprs := range of {
		if len(fprs) == 1 {
			list = append(list, Recipient{Name: addr})
			continue
		}
		for _, f := range fprs {
			list = append(list, Recipient{f, addr})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// pick returns the fingerprint of the one key of keys that gpg holds valid
// (validity full or ultimate) for who, an address or a fingerprint, and
// that is enabled and can encrypt.
func pick(keys []key, who string) (string, error) {
	var valid, reasons []string
	signable := false
	for _, k := range keys {
		validity := k.validity
		if !fingerprintRE.MatchString(who) {
			matched := false
			validity = ""
			for _, u := range k.uids {
				if u.address != who {
					continue
				}
				if matched = true; validity != "f" && validity != "u" {
					validity = u.validity
				}
			}
			if !matched {
				continue
			}
		}
		switch {
		case validity != "f" && validity != "u":
			name, ok := validities[validity]
			if !ok {
				name = validity
			}
			reasons = append(reasons, k.fingerprint+": validity "+name)
			signable = signable || validity == "" || !strings.Contains("idre", validity)
		case strings.Contains(k.caps, "D"):
			reasons = append(reasons, k.fingerprint+": disabled")
		case !strings.Contains(k.caps, "E"):
			reasons = append(reasons, k.fingerprint+": no encryption key")
		default:
			valid = append(valid, k.fingerprint)
		}
	}
	switch {
	case len(valid) == 1:
		return valid[0], nil
	case len(valid) > 1:
		return "", fmt.Errorf("%d valid keys of %s in the gpg keyring (%s): name one by its fingerprint", len(valid), who, strings.Join(valid, ", "))
	case len(reasons) == 0:
		return "", fmt.Errorf("no key of %s in the gpg keyring", who)
	}
	hint := ""
	if signable {
		hint = "; gpg holds a key valid once it is signed (gpg --sign-key or --lsign-key)"
	}
	return "", fmt.Errorf("no valid key of %s in the gpg keyring: %s%s", who, strings.Join(reasons, "; "), hint)
}

var errNoGPG = errors.New("gpg not found in PATH")

// gpg runs gpg and returns its standard output.
func gpg(ctx context.Context, args ...string) ([]byte, error) {
	var out, errs bytes.Buffer
	cmd := exec.CommandContext(ctx, "gpg", append([]string{"--batch", "--no-tty"}, args...)...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdout, cmd.Stderr = &out, &errs
	err := cmd.Run()
	if errors.Is(err, exec.ErrNotFound) {
		return nil, errNoGPG
	}
	if err != nil {
		return out.Bytes(), fmt.Errorf("gpg: %v: %s", err, strings.TrimSpace(errs.String()))
	}
	return out.Bytes(), nil
}

// Available tells whether the gpg program is in PATH.
func Available() bool {
	_, err := exec.LookPath("gpg")
	return err == nil
}

// Recipients lists the recipients Find accepts from the GnuPG keyring of
// the user.
func Recipients(ctx context.Context) ([]Recipient, error) {
	list, err := gpg(ctx, "--with-colons", "--list-keys")
	if err != nil {
		return nil, err
	}
	return recipients(parseColons(list)), nil
}

// Find returns the public key of who, an e-mail address or a fingerprint,
// from the GnuPG keyring of the user. The key must be the only one gpg
// holds valid (validity full or ultimate) for who.
func Find(ctx context.Context, who string) (*openpgp.Entity, error) {
	var spec string
	switch {
	case fingerprintRE.MatchString(who):
		who = strings.ToUpper(strings.TrimPrefix(who, "0x"))
		spec = who
	case addressRE.MatchString(who):
		who = strings.ToLower(who)
		spec = "<" + who + ">"
	default:
		return nil, fmt.Errorf("%q: not an e-mail address or a fingerprint", who)
	}
	// gpg fails when no key matches; pick words that case.
	list, err := gpg(ctx, "--with-colons", "--list-keys", "--", spec)
	if err != nil && !strings.Contains(err.Error(), "No public key") {
		return nil, err
	}
	fpr, perr := pick(parseColons(list), who)
	if perr != nil {
		return nil, perr
	}
	data, err := gpg(ctx, "--export", "--", fpr)
	if err != nil {
		return nil, err
	}
	ents, err := gpgkeys.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("key %s exported by gpg: %w", fpr, err)
	}
	now := time.Now()
	for _, e := range ents {
		if gpgkeys.Fingerprint(e) != fpr {
			continue
		}
		if e.Revoked(now) {
			return nil, fmt.Errorf("key %s: revoked", fpr)
		}
		if _, err := e.EncryptionKeyWithError(now, nil); err != nil {
			return nil, fmt.Errorf("key %s: no valid encryption key: %v", fpr, err)
		}
		return e, nil
	}
	return nil, fmt.Errorf("key %s: not in the gpg export", fpr)
}
