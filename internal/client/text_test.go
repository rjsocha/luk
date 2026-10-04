package client

import (
	"strings"
	"testing"
)

func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"plain name.txt":         "plain name.txt",
		"zażółć":                 "zażółć",
		"a\nb\tc\rd":             `a\nb\tc\rd`,
		"\x1b]0;x\x07\x7f":       `\x1b]0;x\a\x7f`,
		"\u009b2J":               `\u009b2J`,
		"l\u2028p\u2029":         `l\u2028p\u2029`,
		"\u202eevil\u2066\u200f": `\u202eevil\u2066\u200f`,
	} {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, want %q", in, got, want)
		}
	}
	if got := message(strings.Repeat("é", 300)); len([]rune(got)) != maxMessage || !strings.HasSuffix(got, "...") {
		t.Errorf("message cut: %d runes %q", len([]rune(got)), got)
	}
	if got := message("short\n"); got != `short\n` {
		t.Errorf("message %q", got)
	}
}
