package runproto

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

func TestDecodeStepRequest(t *testing.T) {
	ok := map[string]StepRequest{
		`{"pipeline":"p","step":2,"id":"20261006T100000Z-0a1b2c3d","env":{"LUK_NAME":"x"}}`: {Pipeline: "p", Step: 2, ID: "20261006T100000Z-0a1b2c3d", Env: map[string]string{"LUK_NAME": "x"}},
		`{"pipeline":"p","step":1,"id":"i","job":"s3-upload"}`:                              {Pipeline: "p", Step: 1, ID: "i", Job: "s3-upload"},
	}
	for line, want := range ok {
		got, err := decodeStepRequest([]byte(line + "\n"))
		if err != nil || got.Pipeline != want.Pipeline || got.Step != want.Step || got.ID != want.ID || got.Job != want.Job || !maps.Equal(got.Env, want.Env) {
			t.Errorf("%s: %+v %v", line, got, err)
		}
	}
	for line, want := range map[string]string{
		`{"pipeline":"p","step":"1","id":"i"}`:              "step: not a step number",
		`{"pipeline":"p","step":1.5,"id":"i"}`:              "step: not a step number",
		`{"pipeline":"p","step":0,"id":"i"}`:                "step: not a step number",
		`{"pipeline":"p","step":-1,"id":"i"}`:               "step: not a step number",
		`{"pipeline":"p","step":1e1,"id":"i"}`:              "step: not a step number",
		`{"pipeline":"p","step":null,"id":"i"}`:             "step: not a step number",
		`{"pipeline":"p","step":1}`:                         "pipeline, step and id required",
		`{"pipeline":"p","step":1,"id":"i","work":"x"}`:     `unknown key "work"`,
		`{"pipeline":"p","pipeline":"q","step":1,"id":"i"}`: `key "pipeline" repeated`,
		`{"pipeline":"p","step":1,"id":"i","env":{"a":1}}`:  "env: a: not a string",
		`{"pipeline":"p","step":1,"id":"i","job":null}`:     "job: not a string",
		`{"pipeline":"p","step":1,"id":"i"} {}`:             "trailing data",
		"{\"pipeline\":\"p\xff\",\"step\":1,\"id\":\"i\"}":  "not valid UTF-8",
	} {
		if _, err := decodeStepRequest([]byte(line + "\n")); err == nil || err.Error() != want {
			t.Errorf("%s: want %q, got %v", line, want, err)
		}
	}
}

func TestStepRequestRoundTrip(t *testing.T) {
	r := StepRequest{Pipeline: "p", Step: 3, ID: "i", Job: "j", Env: map[string]string{"LUK_TAGS": "a<b>&c"}}
	b := r.Encode()
	if !bytes.Contains(b, []byte("a<b>&c")) || b[len(b)-1] != '\n' {
		t.Fatalf("%s", b)
	}
	got, err := decodeStepRequest(b)
	if err != nil || got.Pipeline != r.Pipeline || got.Step != r.Step || got.ID != r.ID || got.Job != r.Job || !maps.Equal(got.Env, r.Env) {
		t.Fatalf("%+v %v", got, err)
	}
	if b := (StepRequest{Pipeline: "p", Step: 1, ID: "i"}).Encode(); bytes.Contains(b, []byte("job")) {
		t.Fatalf("empty job encoded: %s", b)
	}
}

func TestStartedFrame(t *testing.T) {
	var b bytes.Buffer
	NewFrameWriter(&b).Started()
	typ, p, err := ReadFrame(&b)
	if err != nil || typ != Started || len(p) != 0 {
		t.Fatalf("%q %q %v", typ, p, err)
	}
	b.Reset()
	WriteFrame(&b, Started, []byte("x"))
	if _, _, err := ReadFrame(&b); err == nil || err.Error() != "frame 's' of 1 bytes" {
		t.Fatalf("s frame with a payload: %v", err)
	}
}

// unixPair is a connected SOCK_STREAM pair as *net.UnixConn.
func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var c [2]*net.UnixConn
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		fc, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		c[i] = fc.(*net.UnixConn)
		t.Cleanup(func() { c[i].Close() })
	}
	return c[0], c[1]
}

// filePair is a connected SOCK_STREAM pair as *os.File.
func filePair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b")
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestReadStepRequest(t *testing.T) {
	srv, cli := unixPair(t)
	ch, peer := filePair(t)
	req := StepRequest{Pipeline: "p", Step: 1, ID: "i", Env: map[string]string{"LUK_NAME": "x"}}
	line := req.Encode()
	// The line in two writes, the descriptor with the second one.
	cli.Write(line[:5])
	rights := unix.UnixRights(int(ch.Fd()))
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(10 * time.Millisecond)
		cli.WriteMsgUnix(line[5:], rights, nil)
	}()
	r, f, err := ReadStepRequest(srv)
	<-done
	if err != nil || r.Pipeline != "p" || r.Step != 1 || r.ID != "i" || r.Env["LUK_NAME"] != "x" {
		t.Fatalf("%+v %v", r, err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := peer.Read(b[:]); err != nil || b[0] != 'z' {
		t.Fatalf("%q %v", b, err)
	}
}

func TestReadStepRequestNeedsSocket(t *testing.T) {
	srv, cli := unixPair(t)
	f, _ := os.Open(os.DevNull)
	defer f.Close()
	cli.WriteMsgUnix(StepRequest{Pipeline: "p", Step: 1, ID: "i"}.Encode(), unix.UnixRights(int(f.Fd())), nil)
	if _, _, err := ReadStepRequest(srv); err == nil || err.Error() != "request: descriptor is not a unix socket" {
		t.Fatalf("got %v", err)
	}
	srv2, cli2 := unixPair(t)
	cli2.Write(StepRequest{Pipeline: "p", Step: 1, ID: "i"}.Encode())
	if _, _, err := ReadStepRequest(srv2); err == nil || err.Error() != "request: without its descriptor" {
		t.Fatalf("got %v", err)
	}
}

func TestReadStepRequestRefuses(t *testing.T) {
	ch, ch2 := filePair(t)
	line := StepRequest{Pipeline: "p", Step: 1, ID: "i"}.Encode()
	for name, c := range map[string]struct {
		data   []byte
		rights []byte
		want   string
	}{
		"two descriptors": {line, unix.UnixRights(int(ch.Fd()), int(ch2.Fd())), "request: more than one descriptor"},
		"after the line":  {append(slices.Clone(line), 'x'), unix.UnixRights(int(ch.Fd())), "request: data after the request line"},
		"malformed":       {[]byte("{}\n"), unix.UnixRights(int(ch.Fd())), "request: pipeline, step and id required"},
		"too large":       {bytes.Repeat([]byte(" "), MaxRequest+1), unix.UnixRights(int(ch.Fd())), "request larger than 32768 bytes"},
		"no newline":      {line[:len(line)-1], unix.UnixRights(int(ch.Fd())), "read request: unexpected EOF"},
	} {
		srv, cli := unixPair(t)
		go func() {
			cli.WriteMsgUnix(c.data, c.rights, nil)
			cli.CloseWrite()
		}()
		if _, f, err := ReadStepRequest(srv); err == nil || err.Error() != c.want || f != nil {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestAskStep(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "run.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan StepRequest, 1)
	go func() {
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close()
		r, f, err := ReadStepRequest(c)
		if err != nil {
			NewFrameWriter(c).Stream(Stderr).Write([]byte(err.Error()))
			return
		}
		f.Close()
		got <- r
		w := NewFrameWriter(c)
		w.Started()
		w.Stream(Stdout).Write([]byte("out"))
		w.Stream(Stderr).Write([]byte("err"))
		w.Exit(3)
	}()
	ch, _ := filePair(t)
	var stdout, stderr bytes.Buffer
	started := 0
	req := StepRequest{Pipeline: "p", Step: 2, ID: "i", Job: "j"}
	err = AskStep(context.Background(), sock, req, ch, func() { started++ }, &stdout, &stderr)
	var ee ExitError
	if !errors.As(err, &ee) || ee != 3 || started != 1 || stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("%v started %d %q %q", err, started, stdout.String(), stderr.String())
	}
	if r := <-got; r.Pipeline != "p" || r.Step != 2 || r.ID != "i" || r.Job != "j" {
		t.Fatalf("%+v", r)
	}
}

func TestAskStepCancelled(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "run.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	closed := make(chan bool, 1)
	go func() {
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close()
		_, f, err := ReadStepRequest(c)
		if err == nil {
			f.Close()
		}
		NewFrameWriter(c).Started()
		_, err = c.Read(make([]byte, 1))
		closed <- err == io.EOF
	}()
	ch, _ := filePair(t)
	ctx, cancel := context.WithCancel(context.Background())
	err = AskStep(ctx, sock, StepRequest{Pipeline: "p", Step: 1, ID: "i"}, ch, cancel, io.Discard, io.Discard)
	if err == nil || err.Error() != "interrupted, job stopped" || !<-closed {
		t.Fatalf("%v", err)
	}
}
