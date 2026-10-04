package client

import (
	"strconv"
	"strings"
	"unicode"
)

// Printable is s from a server made safe to print as text: every control
// character (C0, DEL, C1), line or paragraph separator and bidirectional
// formatting character is replaced with its Go escape, so a server or
// another identity can neither drive the terminal nor add a line to the
// output. JSON output needs none of this.
func Printable(s string) string {
	if !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if unsafeRune(r) {
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	switch {
	case unicode.IsControl(r), r == '\u2028', r == '\u2029':
		return true
	case r >= '\u202a' && r <= '\u202e', r >= '\u2066' && r <= '\u2069', r == '\u200e', r == '\u200f', r == '\u061c':
		return true
	}
	return false
}

// maxMessage is the most runes of a server error message kept.
const maxMessage = 256

// message is a server error message as printed: Printable, cut to
// maxMessage runes.
func message(s string) string {
	s = Printable(s)
	if r := []rune(s); len(r) > maxMessage {
		s = string(r[:maxMessage-3]) + "..."
	}
	return s
}
