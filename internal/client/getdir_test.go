package client

import (
	"net/url"
	"testing"
)

func TestChildURL(t *testing.T) {
	dir, err := url.Parse("https://h:8443/v/a%20b/?x=1")
	if err != nil {
		t.Fatal(err)
	}
	u := ChildURL(dir, "2026/r 1%#?.txt")
	if got := u.String(); got != "https://h:8443/v/a%20b/2026/r%201%25%23%3F.txt" {
		t.Fatalf("%s", got)
	}
	if u.Path != "/v/a b/2026/r 1%#?.txt" || dir.Path != "/v/a b/" {
		t.Fatalf("path %q, dir %q", u.Path, dir.Path)
	}
}

func TestValidListName(t *testing.T) {
	for _, n := range []string{"a", "a/b", ".bashrc", "..x", "x..", "a b/ż.txt"} {
		if err := ValidListName(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	for _, n := range []string{"", "/a", "a/", "a//b", ".", "..", "a/../b", "./a", "a\x00b", "a\nb", "a‮b", "\xff"} {
		if err := ValidListName(n); err == nil {
			t.Errorf("%q valid", n)
		}
	}
}
