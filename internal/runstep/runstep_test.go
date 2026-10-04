package runstep

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestValidName(t *testing.T) {
	for n, want := range map[string]bool{
		"a.txt": true, "": false, ".hidden": false, "a/b": false, "a\x00": false,
		"db.sql\nmeta.json": false, "a\tb": false, "a\x1b[2J": false, "a\x7f": false, "a\u0085": false, "zażółć": true, "a b": true,
		strings.Repeat("x", 255): true, strings.Repeat("x", 256): false,
	} {
		if ValidName(n) != want {
			t.Errorf("%q: want %v", n, want)
		}
	}
}

func TestCheckMeta(t *testing.T) {
	got, err := CheckMeta([]byte("{ \"kind\" : \"x\" }"))
	if err != nil || string(got) != `{"kind":"x"}` {
		t.Fatalf("%s %v", got, err)
	}
	for _, b := range []string{"[]", "null", "1", "{", ""} {
		if _, err := CheckMeta([]byte(b)); err == nil {
			t.Errorf("%q accepted", b)
		}
	}
	big := `{"a":"` + strings.Repeat("x", MaxMeta) + `"}`
	if _, err := CheckMeta([]byte(big)); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("big: %v", err)
	}
}

func TestFailText(t *testing.T) {
	if got := FailText([]byte("  a\x1b[2J\tb\nc\x7f\xff \n")); got != "a [2J\tb\nc �" {
		t.Fatalf("%q", got)
	}
	got := FailText([]byte(strings.Repeat("x", MaxFail-1) + "étail"))
	if len(got) != MaxFail-1 || !utf8.ValidString(got) {
		t.Fatalf("cap: %d", len(got))
	}
}
