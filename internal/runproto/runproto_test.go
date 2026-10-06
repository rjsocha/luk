package runproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"maps"
	"strconv"
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
	if err != nil || r.Job != "s3" || r.Work != "/w" || len(r.Env) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	env := map[string]string{"LUK_TAGS": "a<b>&c", "LUK_NAME": `x "y" \z`, "LUK_HOSTNAME": ""}
	b := Request{Job: "s3", Work: "/w", Env: env}.Encode()
	if !bytes.Contains(b, []byte("a<b>&c")) {
		t.Fatalf("HTML escaped: %s", b)
	}
	if r, err = read(string(b)); err != nil || !maps.Equal(r.Env, env) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = read(`{"work":"/w","env":{},"job":"a"}` + "\n"); err != nil || r.Job != "a" || r.Work != "/w" {
		t.Fatalf("%+v %v", r, err)
	}
	long := `{"job":"s3","work":"/` + strings.Repeat("a", MaxRequest) + "\"}\n"
	many := `{"job":"a","work":"/w","env":{`
	for i := range MaxEnv + 1 {
		if i > 0 {
			many += ","
		}
		many += `"LUK_` + strconv.Itoa(i) + `":"v"`
	}
	many += "}}\n"
	for name, in := range map[string]string{
		"oversized":      long,
		"bad json":       "{job}\n",
		"no newline":     `{"job":"a","work":"/w"}`,
		"empty":          "\n",
		"unknown":        `{"job":"a","work":"/w","user":"root"}` + "\n",
		"trailing":       `{"job":"a","work":"/w"} {}` + "\n",
		"trailing junk":  `{"job":"a","work":"/w"}x` + "\n",
		"array":          `[{"job":"a","work":"/w"}]` + "\n",
		"string":         `"x"` + "\n",
		"null":           "null\n",
		"no job":         `{"work":"/w"}` + "\n",
		"no work":        `{"job":"a"}` + "\n",
		"dup job":        `{"job":"a","work":"/w","job":"b"}` + "\n",
		"dup work":       `{"job":"a","work":"/w","work":"/x"}` + "\n",
		"dup env":        `{"job":"a","work":"/w","env":{},"env":{}}` + "\n",
		"dup env key":    `{"job":"a","work":"/w","env":{"LUK_TAGS":"a","LUK_TAGS":"b"}}` + "\n",
		"job number":     `{"job":1,"work":"/w"}` + "\n",
		"job null":       `{"job":null,"work":"/w"}` + "\n",
		"job object":     `{"job":{"a":"b"},"work":"/w"}` + "\n",
		"work array":     `{"job":"a","work":["/w"]}` + "\n",
		"env string":     `{"job":"a","work":"/w","env":"x"}` + "\n",
		"env null":       `{"job":"a","work":"/w","env":null}` + "\n",
		"env array":      `{"job":"a","work":"/w","env":["a"]}` + "\n",
		"env nested":     `{"job":"a","work":"/w","env":{"LUK_TAGS":{"a":"b"}}}` + "\n",
		"env list":       `{"job":"a","work":"/w","env":{"LUK_TAGS":["a"]}}` + "\n",
		"env number":     `{"job":"a","work":"/w","env":{"LUK_TAGS":1}}` + "\n",
		"env null value": `{"job":"a","work":"/w","env":{"LUK_TAGS":null}}` + "\n",
		"env bool":       `{"job":"a","work":"/w","env":{"LUK_TAGS":true}}` + "\n",
		"too many env":   many,
		"invalid utf-8":  `{"job":"a","work":"/w\xff"}` + "\n",
		"open object":    `{"job":"a","work":"/w"` + "\n",
	} {
		if r, err := read(in); err == nil {
			t.Errorf("%s accepted: %+v", name, r)
		}
	}
	if _, err := read(long); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized: %v", err)
	}
}

// The largest request a client sends with a sanitized environment (six
// free-form values of at most 1 KiB, LUK_FILE <work>/in/<name>) and a
// work path of PATH_MAX fits MaxRequest even when every byte needs
// escaping.
func TestLargestRequestFits(t *testing.T) {
	work := "/" + strings.Repeat(`\`, 4095)
	env := map[string]string{"LUK_FILE": work + "/in/" + strings.Repeat(`\`, 255)}
	for i := range 6 {
		env["LUK_NAME_"+strconv.Itoa(i)] = strings.Repeat(`"`, 1<<10)
	}
	b := Request{Job: strings.Repeat("j", 64), Work: work, Env: env}.Encode()
	if len(b) > MaxRequest {
		t.Fatalf("%d bytes", len(b))
	}
	if r, err := ReadRequest(bufio.NewReaderSize(bytes.NewReader(b), MaxRequest)); err != nil || !maps.Equal(r.Env, env) {
		t.Fatalf("%v", err)
	}
}
