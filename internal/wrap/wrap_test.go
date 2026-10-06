package wrap

import (
	"bytes"
	"context"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"luk/internal/jobchan"
)

func script(t *testing.T, body string) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	p := filepath.Join(t.TempDir(), "cmd")
	os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755)
	return p
}

func file(t *testing.T, name, data string) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	os.WriteFile(p, []byte(data), 0o440)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

type result struct {
	frames []jobchan.Frame
	files  map[string]string
	code   int
	stderr string
}

// run starts a wrapper on a fresh workspace with the inputs, sends them
// as lukd process does and collects what comes back.
func run(t *testing.T, cmd string, inputs map[string]string) result {
	t.Helper()
	proc, remote, err := jobchan.Pair()
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	ch, _ := jobchan.FromFile(remote)
	remote.Close()
	ws := filepath.Join(t.TempDir(), "ws")
	os.Mkdir(ws, 0o700)
	var stderr bytes.Buffer
	w := &Wrapper{Ch: ch, Workspace: ws, Argv: []string{cmd, ws}, Stdout: io.Discard, Stderr: &stderr}
	code := make(chan int, 1)
	go func() { code <- w.Run(context.Background()); ch.Close() }()
	proc.Send(jobchan.Frame{T: jobchan.TMeta}, file(t, "meta.json", `{"pipeline":"p"}`))
	for _, n := range slices.Sorted(maps.Keys(inputs)) {
		proc.Send(jobchan.Frame{T: jobchan.TIn, Name: n}, file(t, "x", inputs[n]))
	}
	proc.Send(jobchan.Frame{T: jobchan.TGo}, nil)
	r := result{files: map[string]string{}}
	for {
		f, fd, err := proc.Recv()
		if err != nil {
			break
		}
		r.frames = append(r.frames, f)
		if fd != nil {
			b, _ := io.ReadAll(fd)
			fd.Close()
			r.files[f.Name] = string(b)
		}
		if f.T == jobchan.TEnd {
			break
		}
	}
	r.code = <-code
	r.stderr = stderr.String()
	return r
}

func TestInputsAndResults(t *testing.T) {
	cmd := script(t, `set -e
test "$1" = "$PWD"
test -d tmp && test -d .luk && test -S .luk/run.sock
test "$(stat -c %a in/db.sql)" = 400
test "$(cat meta.json)" = '{"pipeline":"p"}'
tr a-z A-Z < in/db.sql > out/DB.SQL
printf '{"kind":"dump"}' > out/DB.SQL.meta.json
`)
	r := run(t, cmd, map[string]string{"db.sql": "select"})
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if r.frames[0].T != jobchan.TStatus || *r.frames[0].Status != 0 {
		t.Fatalf("%+v", r.frames)
	}
	if r.files["DB.SQL"] != "SELECT" || r.files["DB.SQL.meta.json"] != `{"kind":"dump"}` {
		t.Fatalf("%v", r.files)
	}
}

func TestFailText(t *testing.T) {
	cmd := script(t, "printf 'disk\\001full\\n' > fail\nexit 3\n")
	r := run(t, cmd, nil)
	st := r.frames[0]
	if r.code != 3 || st.T != jobchan.TStatus || *st.Status != 3 || st.Fail != "disk full" {
		t.Fatalf("%d %+v", r.code, r.frames)
	}
}

func TestFailIgnoredOnSuccessAndFifo(t *testing.T) {
	r := run(t, script(t, "echo no > fail\necho ok > out/a\n"), nil)
	if r.code != 0 || r.frames[0].Fail != "" {
		t.Fatalf("%d %+v", r.code, r.frames)
	}
	r = run(t, script(t, "mkfifo fail\nexit 2\n"), nil)
	if r.code != 2 || *r.frames[0].Status != 2 || r.frames[0].Fail != "" {
		t.Fatalf("%d %+v", r.code, r.frames)
	}
}

func TestNotRegularResultsRefused(t *testing.T) {
	for what, body := range map[string]string{
		"fifo":    "mkfifo out/x\n",
		"symlink": "ln -s /etc/passwd out/x\n",
		"dir":     "mkdir out/x\n",
	} {
		cmd := script(t, "echo ok > out/a\n"+body)
		r := run(t, cmd, nil)
		var outs, refuses int
		for _, f := range r.frames {
			switch f.T {
			case jobchan.TOut:
				outs++
			case jobchan.TRefuse:
				refuses++
				if f.Name != "x" || f.Reason != "not a regular file" {
					t.Errorf("%s: %+v", what, f)
				}
			}
		}
		if outs != 0 || refuses != 1 || r.code == 0 {
			t.Errorf("%s: outs %d refuses %d exit %d", what, outs, refuses, r.code)
		}
	}
}

func TestInvalidResultName(t *testing.T) {
	r := run(t, script(t, "echo ok > out/a\necho ok > \"out/b$(printf '\\377')\"\n"), nil)
	last := r.frames[len(r.frames)-2]
	if r.code != 1 || last.T != jobchan.TRefuse || last.Name != "b?" || last.Reason != "invalid name" {
		t.Fatalf("%d %+v", r.code, r.frames)
	}
}

func TestResultsCapped(t *testing.T) {
	r := run(t, script(t, "i=0\nwhile [ $i -lt 1030 ]; do : > out/f$i; i=$((i+1)); done\n"), nil)
	outs := 0
	for _, f := range r.frames {
		if f.T == jobchan.TOut {
			outs++
		}
	}
	if outs != jobchan.MaxFiles+1 || r.frames[len(r.frames)-1].T != jobchan.TEnd {
		t.Fatalf("outs %d", outs)
	}
}

func TestBadInputNameNotStarted(t *testing.T) {
	cmd := script(t, "touch started\n")
	r := run(t, cmd, map[string]string{".hidden": "x"})
	if r.code != 1 || !strings.Contains(r.stderr, "lukd: job not started: ") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestInputNotRegularNotStarted(t *testing.T) {
	proc, remote, _ := jobchan.Pair()
	defer proc.Close()
	ch, _ := jobchan.FromFile(remote)
	remote.Close()
	ws := filepath.Join(t.TempDir(), "ws")
	os.Mkdir(ws, 0o700)
	var stderr bytes.Buffer
	w := &Wrapper{Ch: ch, Workspace: ws, Argv: []string{script(t, "touch started\n"), ws}, Stdout: io.Discard, Stderr: &stderr}
	done := make(chan int, 1)
	go func() { done <- w.Run(context.Background()) }()
	dir, _ := os.Open(t.TempDir())
	defer dir.Close()
	proc.Send(jobchan.Frame{T: jobchan.TMeta}, file(t, "meta.json", "{}"))
	proc.Send(jobchan.Frame{T: jobchan.TIn, Name: "d"}, dir)
	if code := <-done; code != 1 || stderr.String() != "lukd: job not started: input \"d\": not a regular file\n" {
		t.Fatalf("%d %q", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(ws, "started")); err == nil {
		t.Fatal("command started")
	}
}

func TestCancelKillsGroup(t *testing.T) {
	proc, remote, _ := jobchan.Pair()
	defer proc.Close()
	ch, _ := jobchan.FromFile(remote)
	remote.Close()
	ws := filepath.Join(t.TempDir(), "ws")
	os.Mkdir(ws, 0o700)
	ctx, cancel := context.WithCancel(context.Background())
	w := &Wrapper{Ch: ch, Workspace: ws, Argv: []string{script(t, "sleep 30 &\necho $! > tmp/pid\nwait\n"), ws}, Stdout: io.Discard, Stderr: io.Discard}
	done := make(chan int, 1)
	go func() { done <- w.Run(ctx) }()
	proc.Send(jobchan.Frame{T: jobchan.TMeta}, file(t, "meta.json", "{}"))
	proc.Send(jobchan.Frame{T: jobchan.TGo}, nil)
	waitDir(t, filepath.Join(ws, ".luk", "run.sock")).Close()
	cancel()
	select {
	case code := <-done:
		if code != 128+9 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("not killed")
	}
	b, err := os.ReadFile(filepath.Join(ws, "tmp", "pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	for end := time.Now().Add(5 * time.Second); syscall.Kill(pid, 0) == nil; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("background child %d still alive", pid)
		}
	}
}

func TestCommandNotAbsolute(t *testing.T) {
	for _, argv := range [][]string{nil, {"sh", "-c", "true"}} {
		var stderr bytes.Buffer
		w := &Wrapper{Workspace: t.TempDir(), Argv: argv, Stdout: io.Discard, Stderr: &stderr}
		if code := w.Run(context.Background()); code != 1 || stderr.String() != "lukd: job not started: the command is not an absolute path\n" {
			t.Fatalf("%v: %d %q", argv, code, stderr.String())
		}
	}
}

// relayStart starts a wrapper running cmd, sends it the inputs and go and
// returns the channel end of lukd process, the directory of the socket
// and the end of Run.
func relayStart(t *testing.T, ctx context.Context, cmd string) (*jobchan.Conn, *os.File, chan int) {
	t.Helper()
	proc, remote, _ := jobchan.Pair()
	t.Cleanup(func() { proc.Close() })
	ch, _ := jobchan.FromFile(remote)
	remote.Close()
	ws := filepath.Join(t.TempDir(), "ws")
	os.Mkdir(ws, 0o700)
	w := &Wrapper{Ch: ch, Workspace: ws, Argv: []string{cmd, ws}, Stdout: io.Discard, Stderr: io.Discard}
	done := make(chan int, 1)
	go func() {
		code := w.Run(ctx)
		ch.Close()
		done <- code
	}()
	proc.Send(jobchan.Frame{T: jobchan.TMeta}, file(t, "meta.json", "{}"))
	proc.Send(jobchan.Frame{T: jobchan.TGo}, nil)
	dir := waitDir(t, filepath.Join(ws, ".luk", "run.sock"))
	t.Cleanup(func() { dir.Close() })
	return proc, dir, done
}

func TestNestedJobRelayed(t *testing.T) {
	// The command asks for a nested job through .luk/run.sock as luk-job
	// does; the test plays lukd process on the channel.
	ctx, cancel := context.WithCancel(context.Background())
	proc, dir, done := relayStart(t, ctx, script(t, "sleep 5\n"))
	job, err := jobchan.DialIn(dir, "run.sock")
	if err != nil {
		t.Fatal(err)
	}
	job.Send(jobchan.Frame{T: jobchan.TJob, Job: "s3-upload"}, nil)
	job.Send(jobchan.Frame{T: jobchan.TIn, Name: "a"}, file(t, "a", "A"))
	job.Send(jobchan.Frame{T: jobchan.TGo}, nil)
	for _, want := range []string{jobchan.TJob, jobchan.TIn, jobchan.TGo} {
		f, fd, err := proc.Recv()
		if err != nil || f.T != want {
			t.Fatalf("want %s, got %+v %v", want, f, err)
		}
		if fd != nil {
			fd.Close()
		}
	}
	second, _ := jobchan.DialIn(dir, "run.sock")
	second.Send(jobchan.Frame{T: jobchan.TJob, Job: "other"}, nil)
	if f, _, err := second.Recv(); err != nil || f.T != jobchan.TRefused || f.Reason != "another job of this step is running" {
		t.Fatalf("%+v %v", f, err)
	}
	proc.Send(jobchan.Frame{T: jobchan.TStdout, Data: []byte("hi")}, nil)
	proc.Send(jobchan.Frame{T: jobchan.TOut, Name: "r"}, file(t, "r", "R"))
	proc.Send(jobchan.Frame{T: jobchan.TExit, Status: jobchan.Status(0)}, nil)
	for _, want := range []string{jobchan.TStdout, jobchan.TOut, jobchan.TExit} {
		f, fd, err := job.Recv()
		if err != nil || f.T != want {
			t.Fatalf("want %s, got %+v %v", want, f, err)
		}
		if fd != nil {
			if b, _ := io.ReadAll(fd); string(b) != "R" {
				t.Fatalf("out %q", b)
			}
			fd.Close()
		}
	}
	job.Close()
	// The next one is relayed again, once the first hung up.
	var third *jobchan.Conn
	for end := time.Now().Add(5 * time.Second); third == nil; {
		c, err := jobchan.DialIn(dir, "run.sock")
		if err != nil || time.Now().After(end) {
			t.Fatalf("third: %v", err)
		}
		c.Send(jobchan.Frame{T: jobchan.TJob, Job: "again"}, nil)
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if f, _, err := c.Recv(); err == nil && f.T == jobchan.TRefused {
			c.Close()
			continue
		}
		c.SetReadDeadline(time.Time{})
		third = c
	}
	if f, _, err := proc.Recv(); err != nil || f.T != jobchan.TJob || f.Job != "again" {
		t.Fatalf("%+v %v", f, err)
	}
	proc.Send(jobchan.Frame{T: jobchan.TRefused, Reason: "no"}, nil)
	if f, _, err := third.Recv(); err != nil || f.T != jobchan.TRefused || f.Reason != "no" {
		t.Fatalf("%+v %v", f, err)
	}
	cancel()
	<-done
}

func TestLukJobGoneStopsNested(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proc, dir, done := relayStart(t, ctx, script(t, "sleep 5\n"))
	job, err := jobchan.DialIn(dir, "run.sock")
	if err != nil {
		t.Fatal(err)
	}
	job.Send(jobchan.Frame{T: jobchan.TJob, Job: "j"}, nil)
	job.Send(jobchan.Frame{T: jobchan.TGo}, nil)
	for _, want := range []string{jobchan.TJob, jobchan.TGo} {
		if f, _, err := proc.Recv(); err != nil || f.T != want {
			t.Fatalf("want %s, got %+v %v", want, f, err)
		}
	}
	job.Close()
	if f, _, err := proc.Recv(); err != nil || f.T != jobchan.TStop {
		t.Fatalf("want stop, got %+v %v", f, err)
	}
	// Still draining: a second request waits for the exit of the first.
	second, _ := jobchan.DialIn(dir, "run.sock")
	if f, _, err := second.Recv(); err != nil || f.T != jobchan.TRefused {
		t.Fatalf("%+v %v", f, err)
	}
	proc.Send(jobchan.Frame{T: jobchan.TStdout, Data: []byte("dropped")}, nil)
	proc.Send(jobchan.Frame{T: jobchan.TExit, Status: jobchan.Status(143)}, nil)
	cancel()
	<-done
}

func TestCommandEndStopsNested(t *testing.T) {
	// The command leaves while its nested job runs: the wrapper stops the
	// job, closes the connection of luk-job, drains the job until its exit
	// and sends the results, which lukd process still reads after the
	// wrapper is gone.
	proc, dir, done := relayStart(t, context.Background(), script(t, "while ! test -e go; do sleep 0.05; done\n"))
	job, err := jobchan.DialIn(dir, "run.sock")
	if err != nil {
		t.Fatal(err)
	}
	job.Send(jobchan.Frame{T: jobchan.TJob, Job: "j"}, nil)
	job.Send(jobchan.Frame{T: jobchan.TGo}, nil)
	for _, want := range []string{jobchan.TJob, jobchan.TGo} {
		if f, _, err := proc.Recv(); err != nil || f.T != want {
			t.Fatalf("want %s, got %+v %v", want, f, err)
		}
	}
	os.WriteFile(filepath.Join(filepath.Dir(dir.Name()), "go"), nil, 0o600)
	if f, _, err := proc.Recv(); err != nil || f.T != jobchan.TStop {
		t.Fatalf("want stop, got %+v %v", f, err)
	}
	if _, _, err := job.Recv(); err != io.EOF {
		t.Fatalf("luk-job: %v", err)
	}
	// The wrapper still reads these: without a drain it would be gone
	// (EPIPE) or leave them unread (a reset before status).
	if err := proc.Send(jobchan.Frame{T: jobchan.TStderr, Data: []byte("stopped")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := proc.Send(jobchan.Frame{T: jobchan.TExit, Status: jobchan.Status(143)}, nil); err != nil {
		t.Fatal(err)
	}
	if code := <-done; code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{jobchan.TStatus, jobchan.TEnd} {
		if f, _, err := proc.Recv(); err != nil || f.T != want {
			t.Fatalf("want %s, got %+v %v", want, f, err)
		}
	}
}

// waitDir waits until the socket exists and opens its directory.
func waitDir(t *testing.T, sock string) *os.File {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("no %s", sock)
		}
	}
	dir, err := os.Open(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestNoDescriptorLeft(t *testing.T) {
	count := func() int {
		e, _ := os.ReadDir("/proc/self/fd")
		return len(e)
	}
	cmd := script(t, "echo ok > out/a\necho ok > out/b\nmkfifo out/c\n")
	before := count()
	t.Run("run", func(t *testing.T) {
		run(t, cmd, map[string]string{"x": "1", "y": "2"})
	})
	// Fewer is fine: earlier tests may still close theirs.
	if after := count(); after > before {
		t.Fatalf("descriptors: %d before, %d after", before, after)
	}
}
