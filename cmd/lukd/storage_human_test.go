package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintStorageHuman(t *testing.T) {
	files := []storageFile{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	for i, n := range []int64{1536, 4 << 20, 512} {
		files[i].Size = n
	}
	sizes := func(human bool) string {
		t.Helper()
		var b bytes.Buffer
		if err := printStorage(&b, files, false, false, human); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n")[1:] {
			got = append(got, strings.Fields(l)[1])
		}
		return strings.Join(got, ",")
	}
	if got := sizes(false); got != "1536,4194304,512" {
		t.Errorf("bytes: %s", got)
	}
	if got := sizes(true); got != "1.5K,4M,512" {
		t.Errorf("human: %s", got)
	}
}
