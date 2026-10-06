package pipeline

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"luk/internal/runproto"
	"luk/internal/runstep"
	"luk/internal/status"
	"luk/internal/wire"
)

// fakeRund makes relay steps connect to a socket served by handle, one
// connection at a time.
func fakeRund(t *testing.T, handle func(r runproto.Request, c net.Conn, fw *runproto.FrameWriter)) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "run.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	old := runSocket
	runSocket = sock
	t.Cleanup(func() { runSocket = old })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			r, err := runproto.ReadRequest(bufio.NewReaderSize(c, runproto.MaxRequest))
			if err != nil {
				t.Error(err)
				c.Close()
				continue
			}
			handle(r, c, runproto.NewFrameWriter(c))
			c.Close()
		}
	}()
}

func (e *env) debugDispatcher() *Dispatcher {
	return NewDispatcher(e.cfg, e.q, slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

func findStep(recs []map[string]any, msg string, step int) map[string]any {
	for _, r := range recs {
		if r["msg"] == msg && r["step"] == float64(step) {
			return r
		}
	}
	return nil
}

func TestRelayPassesSetOn(t *testing.T) {
	s1 := script(t, `set -e
echo converted
tr a-z A-Z < "$LUK_IN/f.txt" > "$LUK_OUT/up.txt"
printf '{"kind": "upper"}' > "$LUK_OUT/up.txt.meta.json"
`)
	type seen struct {
		req   runproto.Request
		in    string
		meta  bool
		empty bool
	}
	got := make(chan seen, 1)
	fakeRund(t, func(r runproto.Request, _ net.Conn, fw *runproto.FrameWriter) {
		var sn seen
		sn.req = r
		ents, _ := os.ReadDir(filepath.Join(r.Work, "in"))
		for _, e := range ents {
			sn.in += e.Name() + " "
		}
		sn.meta = exists(filepath.Join(r.Work, "meta.json"))
		outs, err := os.ReadDir(filepath.Join(r.Work, "out"))
		sn.empty = err == nil && len(outs) == 0
		got <- sn
		io.WriteString(fw.Stream(runproto.Stdout), "uploaded\n")
		io.WriteString(fw.Stream(runproto.Stderr), "2 files\n")
		fw.Exit(0)
	})
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - relay: s3-upload\n      - store: a\n", s1))
	d := e.debugDispatcher()
	j := e.enqueue(t, "id1", "up", "p")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	recs := e.logs.records(t)
	if find(recs, "pipeline done", "p") == nil {
		t.Fatalf("logs %v", recs)
	}
	sn := <-got
	if sn.req.Job != "s3-upload" || sn.req.Work != filepath.Join(e.root, "work", "id1", "p", "2") ||
		sn.in != "up.txt up.txt.meta.json " || !sn.meta || !sn.empty {
		t.Fatalf("job saw %+v", sn)
	}
	sc := e.sidecar(t, "a/.db/meta/robert.socha/up.txt.json")
	if string(sc.Meta) != `{"kind":"upper"}` || sc.Produced != "up.txt" || sc.SHA256 != sha("DATA-ID1") {
		t.Fatalf("sidecar %+v meta %s", sc, sc.Meta)
	}
	if r := findStep(recs, "step output", 2); r == nil || r["level"] != "DEBUG" || r["output"] != "uploaded\n2 files\n" {
		t.Fatalf("relay output %v", recs)
	}
	if r := findStep(recs, "step output", 1); r == nil || r["output"] != "converted\n" {
		t.Fatalf("run output %v", recs)
	}
	gone(t, filepath.Join(e.root, "work", "id1"))
	gone(t, j.Entry.Dir)
}

func TestRelayOnUploadLastStep(t *testing.T) {
	fakeRund(t, func(r runproto.Request, _ net.Conn, fw *runproto.FrameWriter) {
		b, _ := os.ReadFile(filepath.Join(r.Work, "in", "f.txt"))
		io.WriteString(fw.Stream(runproto.Stdout), string(b))
		fw.Exit(0)
	})
	e := newRunEnv(t, "    steps:\n      - store: a\n      - relay: s3-upload\n")
	d := e.debugDispatcher()
	if err := d.Submit(e.enqueue(t, "id1", "up", "p")); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	recs := e.logs.records(t)
	if find(recs, "pipeline done", "p") == nil {
		t.Fatalf("logs %v", recs)
	}
	if r := findStep(recs, "step output", 2); r == nil || r["output"] != "data-id1" {
		t.Fatalf("logs %v", recs)
	}
	if got := e.read(t, "a/file/robert.socha/f.txt"); got != "data-id1" {
		t.Fatalf("f.txt %q", got)
	}
}

func TestRelayOutputNotLoggedAtInfo(t *testing.T) {
	fakeRund(t, func(_ runproto.Request, _ net.Conn, fw *runproto.FrameWriter) {
		io.WriteString(fw.Stream(runproto.Stdout), "quiet\n")
		fw.Exit(0)
	})
	e := newRunEnv(t, "    steps:\n      - relay: s3-upload\n      - store: a\n")
	e.runOne(t, "id1")
	recs := e.logs.records(t)
	if find(recs, "pipeline done", "p") == nil || findStep(recs, "step output", 1) != nil {
		t.Fatalf("logs %v", recs)
	}
}

func TestRelayFailures(t *testing.T) {
	cases := map[string]struct {
		handle func(r runproto.Request, c net.Conn, fw *runproto.FrameWriter)
		err    string
		output string
	}{
		"exit status": {func(_ runproto.Request, _ net.Conn, fw *runproto.FrameWriter) {
			io.WriteString(fw.Stream(runproto.Stdout), "partial\n")
			io.WriteString(fw.Stream(runproto.Stderr), "bucket gone\n")
			fw.Exit(3)
		}, "relay s3-upload: exit status 3", "partial\nbucket gone\n"},
		"refused": {func(_ runproto.Request, _ net.Conn, fw *runproto.FrameWriter) {
			io.WriteString(fw.Stream(runproto.Stderr), "lukd run: unknown job s3-upload")
			fw.Exit(1)
		}, "relay s3-upload: exit status 1", "lukd run: unknown job s3-upload"},
		"closed": {func(runproto.Request, net.Conn, *runproto.FrameWriter) {},
			"relay s3-upload: connection closed before the exit status", ""},
		"protocol": {func(_ runproto.Request, c net.Conn, _ *runproto.FrameWriter) { c.Write([]byte("garbage")) },
			"relay s3-upload: unknown frame type", ""},
		"wrote out": {func(r runproto.Request, _ net.Conn, fw *runproto.FrameWriter) {
			os.WriteFile(filepath.Join(r.Work, "out", "x"), nil, 0o640)
			fw.Exit(0)
		}, "relay s3-upload: relay step wrote out/x", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fakeRund(t, c.handle)
			e := newRunEnv(t, "    steps:\n      - relay: s3-upload\n      - store: a\n")
			st := status.New(status.Path(e.root))
			d := e.dispatcher()
			d.SetStatus(st)
			if err := d.Submit(e.enqueue(t, "f1", "up", "p")); err != nil {
				t.Fatal(err)
			}
			d.Wait()
			r := find(e.logs.records(t), "pipeline failed", "p")
			if r == nil || r["step"] != float64(1) || !strings.HasPrefix(fmt.Sprint(r["error"]), c.err) {
				t.Fatalf("logs %v", e.logs.records(t))
			}
			if c.output != "" && r["output"] != c.output {
				t.Fatalf("output %q", r["output"])
			}
			es := st.Entries()
			if len(es) != 1 || es[0].FailedStep != 1 || !strings.HasPrefix(es[0].Error, c.err) || !strings.HasSuffix(es[0].Error, c.output) {
				t.Fatalf("entries %+v", es)
			}
			if ents, _ := os.ReadDir(filepath.Join(e.root, "a", "file")); len(ents) != 0 {
				t.Fatalf("stored %v", ents)
			}
		})
	}
}

func TestRelayNoSocket(t *testing.T) {
	old := runSocket
	runSocket = filepath.Join(t.TempDir(), "none")
	t.Cleanup(func() { runSocket = old })
	e := newRunEnv(t, "    steps:\n      - relay: s3-upload\n      - store: a\n")
	e.runOne(t, "n1")
	r := find(e.logs.records(t), "pipeline failed", "p")
	if r == nil || !strings.HasPrefix(fmt.Sprint(r["error"]), "relay s3-upload: dial unix ") {
		t.Fatalf("logs %v", e.logs.records(t))
	}
}

// blockingRund serves a job that prints started and runs until the
// connection is closed, which closed then reports.
func blockingRund(t *testing.T) (started, closed chan struct{}) {
	started, closed = make(chan struct{}), make(chan struct{})
	fakeRund(t, func(_ runproto.Request, c net.Conn, fw *runproto.FrameWriter) {
		io.WriteString(fw.Stream(runproto.Stdout), "started\n")
		close(started)
		io.Copy(io.Discard, c)
		close(closed)
	})
	return started, closed
}

func TestRelayTimeoutClosesConnection(t *testing.T) {
	_, closed := blockingRund(t)
	e := newRunEnv(t, "    timeout: 300ms\n    steps:\n      - relay: s3-upload\n      - store: a\n")
	start := time.Now()
	e.runOne(t, "t1")
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("took %v", el)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("connection not closed")
	}
	r := find(e.logs.records(t), "pipeline failed", "p")
	if r == nil || fmt.Sprint(r["error"]) != "relay s3-upload: timeout after 300ms" || r["output"] != "started\n" {
		t.Fatalf("logs %v", e.logs.records(t))
	}
}

func TestCloseInterruptsRelay(t *testing.T) {
	started, closed := blockingRund(t)
	e := newRunEnv(t, "    steps:\n      - relay: s3-upload\n      - store: a\n")
	d := e.dispatcher()
	j := e.enqueue(t, "i1", "up", "p")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("job did not start")
	}
	d.Close()
	d.Wait()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("connection not closed")
	}
	if !exists(filepath.Join(j.Entry.Dir, "meta.json")) {
		t.Fatal("queue entry removed")
	}
	recs := e.logs.records(t)
	if find(recs, "pipeline failed", "p") != nil || find(recs, "pipeline interrupted", "p") == nil {
		t.Fatalf("logs %v", recs)
	}
}

// A relay step passes on the metadata of its work directory: lukd run
// derives from it and the path the environment a run step there has.
func TestRelaySendsMetadata(t *testing.T) {
	type seen struct{ job, run []string }
	got := make(chan seen, 1)
	var root string
	fakeRund(t, func(r runproto.Request, _ net.Conn, fw *runproto.FrameWriter) {
		run, err := runstep.WorkEnv(r.Work, root)
		if err != nil {
			t.Error(err)
		}
		got <- seen{runstep.Vars(r.Work, root, r.Env), run}
		fw.Exit(0)
	})
	e := newRunEnv(t, "    steps:\n      - relay: s3-upload\n      - store: a\n")
	root = e.root
	d := e.dispatcher()
	j := e.enqueueWith(t, "id1", "up", func(j *Job) {
		j.Vars.Tags, j.Vars.Hostname = []string{"daily"}, "db1"
		j.Sidecar.Client.Tags, j.Sidecar.Client.Backup = j.Vars.Tags, &wire.Backup{Hostname: "db1"}
	}, "p")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	sn := <-got
	if !slices.Equal(sn.job, sn.run) || !slices.Contains(sn.job, "LUK_TAGS=daily") {
		t.Fatalf("\n job %q\n run %q", sn.job, sn.run)
	}
}
