package main

import (
	"bufio"
	"context"
	"io"
	"maps"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/runproto"
)

// fakeRund serves one connection with handle and returns the socket path
// and the request it read.
func fakeRund(t *testing.T, handle func(c net.Conn, fw *runproto.FrameWriter)) (string, chan runproto.Request) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "run.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	reqs := make(chan runproto.Request, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r, err := runproto.ReadRequest(bufio.NewReaderSize(c, runproto.MaxRequest))
		if err != nil {
			t.Error(err)
			return
		}
		reqs <- r
		handle(c, runproto.NewFrameWriter(c))
	}()
	return sock, reqs
}

func TestRunRelays(t *testing.T) {
	w := newWork(t, map[string]string{"x": "1"})
	sock, reqs := fakeRund(t, func(_ net.Conn, fw *runproto.FrameWriter) {
		io.WriteString(fw.Stream(runproto.Stdout), "out1\n")
		io.WriteString(fw.Stream(runproto.Stderr), "err1\n")
		io.WriteString(fw.Stream(runproto.Stdout), "out2\n")
		fw.Exit(7)
	})
	code, out, errs := runJob(t, "run", "--job", "s3-upload", "--socket", sock)
	if code != 7 || out != "out1\nout2\n" || errs != "err1\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	if r := <-reqs; r.Job != "s3-upload" || r.Work != w {
		t.Fatalf("%+v", r)
	}
}

func TestRunExitZero(t *testing.T) {
	newWork(t, nil)
	sock, _ := fakeRund(t, func(_ net.Conn, fw *runproto.FrameWriter) { fw.Exit(0) })
	if code, _, errs := runJob(t, "run", "--job", "a", "--socket", sock); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
}

func TestRunErrors(t *testing.T) {
	newWork(t, nil)
	wantFail(t, "required flag", "run")
	wantFail(t, "run:", "run", "--job", "a", "--socket", filepath.Join(t.TempDir(), "none"))
	sock, _ := fakeRund(t, func(net.Conn, *runproto.FrameWriter) {})
	wantFail(t, "connection closed before the exit status", "run", "--job", "a", "--socket", sock)
	sock, _ = fakeRund(t, func(c net.Conn, _ *runproto.FrameWriter) { c.Write([]byte("garbage")) })
	wantFail(t, "unknown frame type", "run", "--job", "a", "--socket", sock)
}

func TestRunCancelClosesConnection(t *testing.T) {
	w := newWork(t, nil)
	closed := make(chan struct{})
	sock, _ := fakeRund(t, func(c net.Conn, fw *runproto.FrameWriter) {
		io.WriteString(fw.Stream(runproto.Stdout), "started\n")
		io.Copy(io.Discard, c)
		close(closed)
	})
	ctx, cancel := context.WithCancel(context.Background())
	var out strings.Builder
	errc := make(chan error, 1)
	go func() { errc <- askRun(ctx, sock, "a", w, &out, io.Discard) }()
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

// luk-job run passes on the metadata of its environment, cleaned, and
// nothing else.
func TestRunSendsMetadata(t *testing.T) {
	w := newWork(t, map[string]string{"x": "1"})
	for k, v := range map[string]string{
		"LUK_SENDER": "robert.socha", "LUK_TAGS": "a,b", "LUK_FILE": w + "/in/x", "LUK_NAME": "x",
		"LUK_HOSTNAME": "db1\nLUK_ROOT=/", "LUK_ROOT": "/evil", "LUK_STEP": "9", "LUK_JOB": "x", "LD_PRELOAD": "/x.so",
	} {
		t.Setenv(k, v)
	}
	sock, reqs := fakeRund(t, func(_ net.Conn, fw *runproto.FrameWriter) { fw.Exit(0) })
	if code, _, errs := runJob(t, "run", "--job", "s3-upload", "--socket", sock); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	want := map[string]string{"LUK_SENDER": "robert.socha", "LUK_TAGS": "a,b", "LUK_FILE": w + "/in/x", "LUK_NAME": "x"}
	if r := <-reqs; !maps.Equal(r.Env, want) {
		t.Fatalf("%q", r.Env)
	}
}
