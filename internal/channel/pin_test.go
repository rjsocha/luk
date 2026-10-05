package channel

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"luk/internal/store"
)

func TestPins(t *testing.T) {
	k, _ := GenerateKey()
	full, words := KeyString(k.Public), Words(k.Public)
	if len(full) != 43 || strings.Count(words, "-") != 5 {
		t.Fatalf("%q %q", full, words)
	}
	for _, s := range []string{full, words} {
		p, err := ParsePin(s)
		if err != nil || !p.Matches(k.Public) {
			t.Fatalf("%q: %v", s, err)
		}
	}
	other, _ := GenerateKey()
	ps, err := ParsePins(KeyString(other.Public) + "," + words)
	if err != nil || len(ps) != 2 || ps[0].Matches(k.Public) || !ps[1].Matches(k.Public) {
		t.Fatalf("list: %v", err)
	}
	if _, err := ParsePin("sha256//AAAA"); !errors.Is(err, ErrTLSPin) {
		t.Fatalf("tls pin: %v", err)
	}
	for _, bad := range []string{"", "abc", "lusab-babad", full + "A", "lusab-babad-gutih-tugad-hajop-kizox"} {
		if _, err := ParsePin(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestWordsInverse(t *testing.T) {
	for i := range 200 {
		b := make([]byte, digestSize)
		rand.Read(b)
		if i == 0 {
			clear(b)
		}
		w := proquint(b)
		if w != store.Proquint(b) {
			t.Fatalf("%x: %q differs from store %q", b, w, store.Proquint(b))
		}
		d, err := parseWords(w)
		if err != nil || !bytes.Equal(d[:], b) {
			t.Fatalf("%q: %x %v", w, d, err)
		}
	}
}
