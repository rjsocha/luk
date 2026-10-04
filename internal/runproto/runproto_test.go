package runproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	f := NewFrameWriter(&b)
	io.WriteString(f.Stream(Stdout), "out")
	io.WriteString(f.Stream(Stderr), "err")
	big := bytes.Repeat([]byte("z"), MaxFrame+3)
	f.Stream(Stdout).Write(big)
	f.Exit(42)
	want := []struct {
		typ byte
		n   int
	}{{Stdout, 3}, {Stderr, 3}, {Stdout, MaxFrame}, {Stdout, 3}, {Exit, 2}}
	for i, w := range want {
		typ, p, err := ReadFrame(&b)
		if err != nil || typ != w.typ || len(p) != w.n {
			t.Fatalf("frame %d: %q %d %v", i, typ, len(p), err)
		}
		if typ == Exit {
			if c, err := ExitCode(p); err != nil || c != 42 {
				t.Fatalf("exit %d %v", c, err)
			}
		}
	}
	if _, _, err := ReadFrame(&b); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestReadFrameRejects(t *testing.T) {
	hdr := func(typ byte, n uint32) []byte {
		b := []byte{typ, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], n)
		return b
	}
	for name, in := range map[string][]byte{
		"type":      append(hdr('q', 1), 'a'),
		"too large": hdr(Stdout, MaxFrame+1),
		"exit size": hdr(Exit, 100),
		"truncated": append(hdr(Stdout, 4), 'a'),
		"header":    {Stdout, 0},
	} {
		if _, _, err := ReadFrame(bytes.NewReader(in)); err == nil || err == io.EOF {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, p := range []string{"", "x", "-1", "256"} {
		if _, err := ExitCode([]byte(p)); err == nil {
			t.Errorf("exit %q accepted", p)
		}
	}
}

func TestReadRequest(t *testing.T) {
	read := func(s string) (Request, error) {
		return ReadRequest(bufio.NewReaderSize(strings.NewReader(s), MaxRequest))
	}
	r, err := read(string(Request{Job: "s3", Work: "/w"}.Encode()))
	if err != nil || r.Job != "s3" || r.Work != "/w" {
		t.Fatalf("%+v %v", r, err)
	}
	long := `{"job":"s3","work":"/` + strings.Repeat("a", MaxRequest) + "\"}\n"
	for name, in := range map[string]string{
		"oversized":  long,
		"bad json":   "{job}\n",
		"no newline": `{"job":"a","work":"/w"}`,
		"unknown":    `{"job":"a","work":"/w","user":"root"}` + "\n",
		"trailing":   `{"job":"a","work":"/w"} {}` + "\n",
	} {
		if _, err := read(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := read(long); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized: %v", err)
	}
}
