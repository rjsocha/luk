package channel

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ErrTLSPin is returned for a TLS SPKI pin given where a lukd key is
// expected: endpoints authenticate lukd by the channel, not by TLS.
var ErrTLSPin = errors.New("an endpoint pin is the lukd key: run luk scan URL")

const (
	keySize    = 32
	keyLen     = 43
	digestSize = 12
	wordGroups = digestSize / 2
	consonants = "bdfghjklmnprstvz"
	vowels     = "aiou"
)

// keyEncoding has a single string form per key: Strict refuses non-zero
// trailing bits, so two different strings never match the same key.
var keyEncoding = base64.RawURLEncoding.Strict()

// Pin is a trusted lukd identity: a full key or the 96-bit words digest.
type Pin struct {
	key    []byte
	digest [digestSize]byte
	full   bool
}

// ParsePin parses the 43-character key or the six-word form.
func ParsePin(s string) (Pin, error) {
	if strings.HasPrefix(s, "sha256//") {
		return Pin{}, ErrTLSPin
	}
	// The length tells the forms apart: base64url has "-" in its alphabet.
	if len(s) != keyLen {
		d, err := parseWords(s)
		if err != nil {
			return Pin{}, err
		}
		return Pin{digest: d}, nil
	}
	k, err := keyEncoding.DecodeString(s)
	if err != nil || len(k) != keySize {
		return Pin{}, fmt.Errorf("channel: pin %q is not a base64url key", s)
	}
	return Pin{key: k, full: true}, nil
}

// ParsePins parses a comma-separated list, the form of a URL fragment.
func ParsePins(fragment string) ([]Pin, error) {
	if fragment == "" {
		return nil, nil
	}
	var ps []Pin
	for s := range strings.SplitSeq(fragment, ",") {
		p, err := ParsePin(s)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p)
	}
	return ps, nil
}

// Matches reports whether key is the pinned identity.
func (p Pin) Matches(key []byte) bool {
	if p.full {
		return subtle.ConstantTimeCompare(p.key, key) == 1
	}
	d := digest(key)
	return subtle.ConstantTimeCompare(p.digest[:], d[:]) == 1
}

// Words is the short form of a key: six proquint groups of the first 96
// bits of its SHA-256.
func Words(key []byte) string {
	d := digest(key)
	return proquint(d[:])
}

// KeyString is the full form of a key: base64url without padding.
func KeyString(key []byte) string {
	return keyEncoding.EncodeToString(key)
}

// FormatPin renders key in a --pin-format: "words" or "key".
func FormatPin(key []byte, format string) (string, error) {
	switch format {
	case "words":
		return Words(key), nil
	case "key":
		return KeyString(key), nil
	}
	return "", fmt.Errorf("channel: unknown pin format %q (words or key)", format)
}

func digest(key []byte) [digestSize]byte {
	h := sha256.Sum256(key)
	return [digestSize]byte(h[:digestSize])
}

// proquint is store.Proquint, copied so that the protocol package does not
// pull in the store and its dependencies.
func proquint(b []byte) string {
	groups := make([]string, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		w := uint16(b[i])<<8 | uint16(b[i+1])
		groups = append(groups, string([]byte{
			consonants[w>>12], vowels[w>>10&3], consonants[w>>6&15], vowels[w>>4&3], consonants[w&15],
		}))
	}
	return strings.Join(groups, "-")
}

func parseWords(s string) ([digestSize]byte, error) {
	var d [digestSize]byte
	groups := strings.Split(s, "-")
	if len(groups) != wordGroups {
		return d, fmt.Errorf("channel: pin %q is neither a 43-character key nor %d words", s, wordGroups)
	}
	for i, g := range groups {
		if len(g) != 5 {
			return d, fmt.Errorf("channel: pin %q: %q is not a proquint word", s, g)
		}
		var w uint16
		for j := range len(g) {
			set, bits := consonants, 4
			if j%2 == 1 {
				set, bits = vowels, 2
			}
			x := strings.IndexByte(set, g[j])
			if x < 0 {
				return d, fmt.Errorf("channel: pin %q: %q is not a proquint word", s, g)
			}
			w = w<<bits | uint16(x)
		}
		d[2*i], d[2*i+1] = byte(w>>8), byte(w)
	}
	return d, nil
}
