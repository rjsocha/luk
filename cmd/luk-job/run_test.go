package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"luk/internal/jobchan"
)

// fakeWrapper listens on <ws>/.luk/run.sock as the wrapper does and plays
// lukd process with answer.
func fakeWrapper(t *testing.T, answer func(c *jobchan.Conn, req []jobchan.Frame)) string {
	t.Helper()
	ws := newWork(t, map[string]string{"in.txt": "abc"})
	os.Mkdir(filepath.Join(ws, ".luk"), 0o700)
	d, _ := os.Open(filepath.Join(ws, ".luk"))
	t.Cleanup(func() { d.Close() })
	l, err := jobchan.ListenIn(d, "run.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := jobchan.Accept(l)
		if err != nil {
			return
		}
		defer c.Close()
		var req []jobchan.Frame
		for {
			f, fd, err := c.Recv()
			if err != nil {
				return
			}
			if fd != nil {
				fd.Close()
			}
			req = append(req, f)
			if f.T == jobchan.TGo {
				break
			}
		}
		answer(c, req)
	}()
	return ws
}

func tmpFile(t *testing.T, data string) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestRunRelaysOutputAndExit(t *testing.T) {
	ws := fakeWrapper(t, func(c *jobchan.Conn, req []jobchan.Frame) {
		if req[0].T != jobchan.TJob || req[0].Job != "s3-upload" || len(req) != 2 {
			c.Send(jobchan.Frame{T: jobchan.TRefused, Reason: fmt.Sprint(req)}, nil)
			return
		}
		c.Send(jobchan.Frame{T: jobchan.TStdout, Data: []byte("out\n")}, nil)
		c.Send(jobchan.Frame{T: jobchan.TStderr, Data: []byte("err\n")}, nil)
		c.Send(jobchan.Frame{T: jobchan.TExit, Status: jobchan.Status(3)}, nil)
	})
	code, stdout, stderr := runJob(t, "run", "--work", ws, "--job", "s3-upload")
	if code != 3 || stdout != "out\n" || stderr != "err\n" {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
}

func TestRunExitZero(t *testing.T) {
	ws := fakeWrapper(t, func(c *jobchan.Conn, _ []jobchan.Frame) {
		c.Send(jobchan.Frame{T: jobchan.TExit, Status: jobchan.Status(0)}, nil)
	})
	if code, _, stderr := runJob(t, "run", "--work", ws, "--job", "j"); code != 0 {
		t.Fatalf("%d %q", code, stderr)
	}
}

func TestRunFilesAndOut(t *testing.T) {
	out := t.TempDir()
	ws := fakeWrapper(t, func(c *jobchan.Conn, req []jobchan.Frame) {
		var names []string
		for _, f := range req {
			if f.T == jobchan.TIn {
				names = append(names, f.Name)
			}
		}
		if !slices.Equal(names, []string{"in.txt", "in.txt.meta.json"}) {
			c.Send(jobchan.Frame{T: jobchan.TRefused, Reason: fmt.Sprint(names)}, nil)
			return
		}
		r := tmpFile(t, "result")
		c.Send(jobchan.Frame{T: jobchan.TOut, Name: "r"}, r)
		c.Send(jobchan.Frame{T: jobchan.TExit, Status: jobchan.Status(0)}, nil)
	})
	in := filepath.Join(ws, "in", "in.txt")
	os.WriteFile(in+".meta.json", []byte(`{"a":1}`), 0o440)
	code, _, stderr := runJob(t, "run", "--work", ws, "--job", "j", "--file", in, "--file", in+".meta.json", "--out", out)
	if code != 0 {
		t.Fatalf("%d %s", code, stderr)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "r")); string(b) != "result" {
		t.Fatalf("%q", b)
	}
	if ents, _ := os.ReadDir(out); len(ents) != 1 {
		t.Fatalf("%v", ents)
	}
}

func TestRunRefusals(t *testing.T) {
	ws := newWork(t, map[string]string{"a": "1"})
	link := filepath.Join(t.TempDir(), "l")
	os.Symlink(filepath.Join(ws, "in", "a"), link)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--file", link}, "not a regular file"},
		{[]string{"--file", filepath.Join(ws, "in")}, "not a regular file"},
		{[]string{"--file", filepath.Join(ws, "in", "a"), "--file", filepath.Join(ws, "in", "a")}, "twice"},
		{[]string{"--out", filepath.Join(ws, "missing")}, "--out"},
		{[]string{"--out", filepath.Join(ws, "meta.json")}, "not a directory"},
	} {
		code, _, stderr := runJob(t, append([]string{"run", "--work", ws, "--job", "j"}, c.args...)...)
		if code != 1 || !strings.Contains(stderr, c.want) {
			t.Errorf("%q: %d %q", c.args, code, stderr)
		}
	}
	wantFail(t, "required flag", "run", "--work", ws)
}

func TestRunWithoutOutRefusesResults(t *testing.T) {
	ws := fakeWrapper(t, func(c *jobchan.Conn, _ []jobchan.Frame) {
		c.Send(jobchan.Frame{T: jobchan.TOut, Name: "x"}, tmpFile(t, "x"))
		c.Send(jobchan.Frame{T: jobchan.TExit, Status: jobchan.Status(0)}, nil)
	})
	code, _, stderr := runJob(t, "run", "--work", ws, "--job", "j")
	if code != 1 || !strings.Contains(stderr, "job j wrote out/x") {
		t.Fatalf("%d %q", code, stderr)
	}
}

func TestRunAnotherJobRunning(t *testing.T) {
	ws := fakeWrapper(t, func(c *jobchan.Conn, _ []jobchan.Frame) {
		c.Send(jobchan.Frame{T: jobchan.TRefused, Reason: "another job of this step is running"}, nil)
	})
	code, _, stderr := runJob(t, "run", "--work", ws, "--job", "j")
	if code != 1 || !strings.Contains(stderr, "luk-job run: another job of this step is running") {
		t.Fatalf("%d %q", code, stderr)
	}
}

func TestRunOutExistingNameRefused(t *testing.T) {
	out := t.TempDir()
	os.WriteFile(filepath.Join(out, "r"), nil, 0o600)
	ws := fakeWrapper(t, func(c *jobchan.Conn, _ []jobchan.Frame) {
		c.Send(jobchan.Frame{T: jobchan.TOut, Name: "r"}, tmpFile(t, "new"))
		c.Send(jobchan.Frame{T: jobchan.TExit, Status: jobchan.Status(0)}, nil)
	})
	code, _, stderr := runJob(t, "run", "--work", ws, "--job", "j", "--out", out)
	if code != 1 || !strings.Contains(stderr, "exists") {
		t.Fatalf("%d %q", code, stderr)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "r")); len(b) != 0 {
		t.Fatal("existing file replaced")
	}
	if ents, _ := os.ReadDir(out); len(ents) != 1 {
		t.Fatalf("temporary file left: %v", ents)
	}
}

func TestRunConnectionErrors(t *testing.T) {
	ws := fakeWrapper(t, func(*jobchan.Conn, []jobchan.Frame) {})
	wantFail(t, "luk-job run: connection closed before the exit status", "run", "--work", ws, "--job", "j")
	ws = fakeWrapper(t, func(c *jobchan.Conn, _ []jobchan.Frame) {
		c.Send(jobchan.Frame{T: jobchan.TGo}, nil)
	})
	wantFail(t, `luk-job run: unexpected frame "go"`, "run", "--work", ws, "--job", "j")
	ws = newWork(t, nil)
	wantFail(t, "luk-job run: ", "run", "--work", ws, "--job", "j")
}

func TestRunCancelClosesConnection(t *testing.T) {
	closed := make(chan struct{})
	ws := fakeWrapper(t, func(c *jobchan.Conn, _ []jobchan.Frame) {
		c.Send(jobchan.Frame{T: jobchan.TStdout, Data: []byte("started\n")}, nil)
		for {
			if _, _, err := c.Recv(); err == io.EOF {
				close(closed)
				return
			} else if err != nil {
				return
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	var out strings.Builder
	errc := make(chan error, 1)
	go func() { errc <- askRun(ctx, ws, "a", nil, "", &out, io.Discard) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("connection not closed")
	}
	if err := <-errc; err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("%v", err)
	}
}
