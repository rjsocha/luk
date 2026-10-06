package jobchan

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDecodeRules(t *testing.T) {
	good := []string{
		`{"t":"meta"}`, `{"t":"in","name":"db.sql"}`, `{"t":"go"}`,
		`{"t":"status","status":0}`, `{"t":"status","status":3,"fail":"no space"}`,
		`{"t":"out","name":"a"}`, `{"t":"refuse","name":"x","reason":"not a regular file"}`,
		`{"t":"end"}`, `{"t":"job","job":"s3-upload"}`, `{"t":"stop"}`,
		`{"t":"o","data":"aGk="}`, `{"t":"e","data":""}`, `{"t":"exit","status":1}`,
		`{"t":"refused","reason":"another job of this step is running"}`,
	}
	for _, s := range good {
		if _, err := Decode([]byte(s + "\n")); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := map[string]string{
		`{"t":"go"}`: "no newline",
		`{"t":"go"}` + "\n" + `{"t":"go"}` + "\n":    "trailing",
		`{"t":"nope"}` + "\n":                        "unknown frame",
		`{"t":"in"}` + "\n":                          "needs a name",
		`{"t":"status"}` + "\n":                      "needs a status",
		`{"t":"exit"}` + "\n":                        "needs a status",
		`{"t":"job"}` + "\n":                         "needs a job",
		`{"t":"go","x":1}` + "\n":                    "unknown field",
		`{"t":"in","name":"a","data":"aGk="}` + "\n": "data",
		"\xff\n":     "UTF-8",
		`[1]` + "\n": "object",
	}
	for s, want := range bad {
		if _, err := Decode([]byte(s)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", s, want, err)
		}
	}
}

func TestEncodeLimit(t *testing.T) {
	if _, err := Encode(Frame{T: TStdout, Data: make([]byte, MaxPacket)}); err == nil {
		t.Fatal("frame over 64 KiB encoded")
	}
	b, err := Encode(Frame{T: TStatus, Status: Status(0)})
	if err != nil || string(b) != `{"t":"status","status":0}`+"\n" {
		t.Fatalf("%q %v", b, err)
	}
}

func pair(t *testing.T) (a, b *Conn) {
	t.Helper()
	a, f, err := Pair()
	if err != nil {
		t.Fatal(err)
	}
	b, err = FromFile(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func tempFile(t *testing.T, data string) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte(data), 0o400)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestSendRecvFile(t *testing.T) {
	a, b := pair(t)
	if err := a.Send(Frame{T: TIn, Name: "x"}, tempFile(t, "hello")); err != nil {
		t.Fatal(err)
	}
	f, file, err := b.Recv()
	if err != nil || f.T != TIn || f.Name != "x" || file == nil {
		t.Fatalf("%+v %v %v", f, file, err)
	}
	defer file.Close()
	got, _ := io.ReadAll(file)
	if string(got) != "hello" {
		t.Fatalf("%q", got)
	}
	a.Close()
	if _, _, err := b.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("after close: %v", err)
	}
}

func TestFileRules(t *testing.T) {
	a, b := pair(t)
	if err := a.Send(Frame{T: TGo}, tempFile(t, "x")); err == nil {
		t.Fatal("descriptor sent on go")
	}
	if err := a.Send(Frame{T: TIn, Name: "x"}, nil); err == nil {
		t.Fatal("in sent without a descriptor")
	}
	// A peer that breaks the rules on its own: raw packets.
	raw := func(line string, fds ...int) {
		t.Helper()
		var oob []byte
		if len(fds) > 0 {
			oob = unix.UnixRights(fds...)
		}
		if _, _, err := a.c.WriteMsgUnix([]byte(line), oob, nil); err != nil {
			t.Fatal(err)
		}
	}
	f1, f2 := tempFile(t, "1"), tempFile(t, "2")
	raw(`{"t":"in","name":"a"}`+"\n", int(f1.Fd()), int(f2.Fd()))
	if _, _, err := b.Recv(); err == nil || !strings.Contains(err.Error(), "more than one descriptor") {
		t.Fatalf("two descriptors: %v", err)
	}
	raw(`{"t":"go"}`+"\n", int(f1.Fd()))
	if _, _, err := b.Recv(); err == nil || !strings.Contains(err.Error(), "takes no descriptor") {
		t.Fatalf("descriptor on go: %v", err)
	}
	raw(`{"t":"in","name":"a"}` + "\n")
	if _, _, err := b.Recv(); err == nil || !strings.Contains(err.Error(), "without its descriptor") {
		t.Fatalf("in without descriptor: %v", err)
	}
	raw(`{"t":"o","data":"` + strings.Repeat("A", MaxPacket) + `"}` + "\n")
	if _, _, err := b.Recv(); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversize: %v", err)
	}
}

func TestRecvDeadline(t *testing.T) {
	_, b := pair(t)
	b.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := b.Recv(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

// The socket of the wrapper may lie deeper than sun_path allows: listen
// and dial go through /proc/self/fd of the directory.
func TestListenDialInLongPath(t *testing.T) {
	dir := t.TempDir()
	for len(dir) < 200 {
		dir = filepath.Join(dir, strings.Repeat("d", 40))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	l, err := ListenIn(d, "run.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan Frame, 1)
	go func() {
		c, err := Accept(l)
		if err != nil {
			return
		}
		f, _, _ := c.Recv()
		done <- f
		c.Close()
	}()
	c, err := DialIn(d, "run.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Send(Frame{T: TJob, Job: "s3-upload"}, nil); err != nil {
		t.Fatal(err)
	}
	if f := <-done; f.T != TJob || f.Job != "s3-upload" {
		t.Fatalf("%+v", f)
	}
}

func openFds(t *testing.T) int {
	t.Helper()
	e, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(e)
}

// A refused packet closes every descriptor it carried.
func TestRefusedPacketClosesDescriptors(t *testing.T) {
	a, b := pair(t)
	f1, f2, f3 := tempFile(t, "1"), tempFile(t, "2"), tempFile(t, "3")
	before := openFds(t)
	for _, p := range []struct {
		line string
		fds  []int
	}{
		{`{"t":"in","name":"a"}` + "\n", []int{int(f1.Fd()), int(f2.Fd())}},
		{`{"t":"in","name":"a"}` + "\n", []int{int(f1.Fd()), int(f2.Fd()), int(f3.Fd())}},
		{`{"t":"go"}` + "\n", []int{int(f1.Fd())}},
		{`{"t":"nope"}` + "\n", []int{int(f1.Fd())}},
		{`{"t":"o","data":"` + strings.Repeat("A", MaxPacket) + `"}` + "\n", []int{int(f1.Fd())}},
	} {
		if _, _, err := a.c.WriteMsgUnix([]byte(p.line), unix.UnixRights(p.fds...), nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := b.Recv(); err == nil {
			t.Fatalf("%.40q accepted", p.line)
		}
	}
	if after := openFds(t); after != before {
		t.Fatalf("descriptors: %d before, %d after", before, after)
	}
}

func TestFromFileNotSeqpacket(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f0, f1 := os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b")
	defer f0.Close()
	defer f1.Close()
	if _, err := FromFile(f0); err == nil || !strings.Contains(err.Error(), "not a SOCK_SEQPACKET socket") {
		t.Fatalf("got %v", err)
	}
}

func TestListenInUnlinksOnClose(t *testing.T) {
	dir := t.TempDir()
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	l, err := ListenIn(d, "run.sock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "run.sock")); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, err := os.Lstat(filepath.Join(dir, "run.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("after close: %v", err)
	}
}
