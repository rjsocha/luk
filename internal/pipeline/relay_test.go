package pipeline

import (
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"luk/internal/jobchan"
	"luk/internal/rund/rundtest"
	"luk/internal/runproto"
	"luk/internal/status"
	"luk/internal/wire"
)

// fakeRund serves runSocket instead of the lukd run of e: for each request
// it answers s, reads the inputs up to go and hands the channel and the
// connection to unit, whose result is the exit status.
func fakeRund(t *testing.T, e *env, unit func(ch *jobchan.Conn, c *net.UnixConn, fw *runproto.FrameWriter) int) {
	t.Helper()
	e.startRund = nil
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: runSocket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		l.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.AcceptUnix()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_, f, err := runproto.ReadStepRequest(c)
				if err != nil {
					t.Error(err)
					return
				}
				ch, err := jobchan.FromFile(f)
				f.Close()
				if err != nil {
					t.Error(err)
					return
				}
				defer ch.Close()
				fw := runproto.NewFrameWriter(c)
				fw.Started()
				for {
					fr, fd, err := ch.Recv()
					if fd != nil {
						fd.Close()
					}
					if err != nil {
						t.Error(err)
						return
					}
					if fr.T == jobchan.TGo {
						break
					}
				}
				code := unit(ch, c, fw)
				ch.Close()
				fw.Exit(code)
			}()
		}
	}()
}

func (e *env) debugDispatcher() *Dispatcher {
	e.rund()
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
	seen := filepath.Join(t.TempDir(), "seen")
	s1 := script(t, `set -e
echo converted
tr a-z A-Z < "$LUK_IN/f.txt" > "$LUK_OUT/up.txt"
printf '{"kind": "upper"}' > "$LUK_OUT/up.txt.meta.json"
`)
	job := script(t, `set -e
ls "$LUK_IN" | tr '\n' ' ' > "$SEEN"
test -f "$LUK_META"
test -z "$(ls -A "$LUK_OUT")"
echo uploaded
echo "2 files" >&2
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - relay: s3-upload\n      - store: a\n", s1))
	e.jobs["s3-upload"] = rundtest.Unit{Argv: []string{job}, Env: []string{"SEEN=" + seen}}
	e.requests = make(chan runproto.StepRequest, 2)
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
	<-e.requests
	if r := <-e.requests; r.Pipeline != "p" || r.Step != 2 || r.ID != "id1" || r.Job != "" {
		t.Fatalf("request %+v", r)
	}
	if b, err := os.ReadFile(seen); err != nil || string(b) != "up.txt up.txt.meta.json " {
		t.Fatalf("job saw %q %v", b, err)
	}
	sc := e.sidecar(t, "a/.db/meta/robert.socha/up.txt.json")
	if string(sc.Meta) != `{"kind":"upper"}` || sc.Produced != "up.txt" || sc.SHA256 != sha("DATA-ID1") {
		t.Fatalf("sidecar %+v meta %s", sc, sc.Meta)
	}
	// stdout and stderr of a unit are two streams: their order is not kept.
	if r := findStep(recs, "step output", 2); r == nil || r["level"] != "DEBUG" ||
		r["output"] != "uploaded\n2 files\n" && r["output"] != "2 files\nuploaded\n" {
		t.Fatalf("relay output %v", recs)
	}
	if r := findStep(recs, "step output", 1); r == nil || r["output"] != "converted\n" {
		t.Fatalf("run output %v", recs)
	}
	gone(t, filepath.Join(e.root, "data", "work", "id1"))
	gone(t, j.Entry.Dir)
}

func TestRelayOnUploadLastStep(t *testing.T) {
	job := script(t, `cat "$LUK_IN/f.txt"
`)
	e := newRunEnv(t, "    steps:\n      - store: a\n      - relay: s3-upload\n")
	e.jobs["s3-upload"] = rundtest.Unit{Argv: []string{job}}
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
	e := newRunEnv(t, "    steps:\n      - relay: s3-upload\n      - store: a\n")
	e.jobs["s3-upload"] = rundtest.Unit{Argv: []string{script(t, "echo quiet\n")}}
	e.runOne(t, "id1")
	recs := e.logs.records(t)
	if find(recs, "pipeline done", "p") == nil || findStep(recs, "step output", 1) != nil {
		t.Fatalf("logs %v", recs)
	}
}

func TestRelayFailures(t *testing.T) {
	cases := map[string]struct {
		job    string // the script of the job; empty: none in run.d
		fake   func(ch *jobchan.Conn, c *net.UnixConn, fw *runproto.FrameWriter) int
		err    string
		output string
	}{
		"exit status": {job: "echo partial >&2\necho bucket gone >&2\nexit 3\n",
			err: "relay s3-upload: exit status 3", output: "partial\nbucket gone\n"},
		"refused": {err: "relay s3-upload: exit status 1", output: "lukd run: job \"s3-upload\": unknown\n"},
		"closed": {fake: func(_ *jobchan.Conn, c *net.UnixConn, _ *runproto.FrameWriter) int { c.Close(); return 0 },
			err: "relay s3-upload: connection closed before the exit status"},
		"protocol": {fake: func(_ *jobchan.Conn, c *net.UnixConn, _ *runproto.FrameWriter) int {
			c.Write([]byte("garbage"))
			c.Close()
			return 0
		}, err: "relay s3-upload: unknown frame type"},
		"wrote out": {job: "echo x > \"$LUK_OUT/x\"\n", err: "relay s3-upload: relay step wrote out/x"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newRunEnv(t, "    steps:\n      - relay: s3-upload\n      - store: a\n")
			switch {
			case c.fake != nil:
				fakeRund(t, e, c.fake)
			case c.job != "":
				e.jobs["s3-upload"] = rundtest.Unit{Argv: []string{script(t, c.job)}}
			}
			st := status.New(status.Path(e.cfg.DataDir()))
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
			if ents, _ := os.ReadDir(filepath.Join(e.root, "data", "a", "file")); len(ents) != 0 {
				t.Fatalf("stored %v", ents)
			}
		})
	}
}

func TestRelayNoSocket(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - relay: s3-upload\n      - store: a\n")
	runSocket = filepath.Join(t.TempDir(), "none")
	e.runOne(t, "n1")
	r := find(e.logs.records(t), "pipeline failed", "p")
	if r == nil || !strings.HasPrefix(fmt.Sprint(r["error"]), "relay s3-upload: dial unix ") {
		t.Fatalf("logs %v", e.logs.records(t))
	}
}

// blockingJob makes s3-upload of e a job that prints started, writes its
// pid to the returned file and runs until it is killed.
func blockingJob(t *testing.T, e *env) (pidfile string) {
	pidfile = filepath.Join(t.TempDir(), "pid")
	job := script(t, `echo started
echo $$ > "$PIDFILE.tmp"; mv "$PIDFILE.tmp" "$PIDFILE"
sleep 30
`)
	e.jobs["s3-upload"] = rundtest.Unit{Argv: []string{job}, Env: []string{"PIDFILE=" + pidfile}}
	return pidfile
}

func TestRelayTimeoutStopsJob(t *testing.T) {
	e := newRunEnv(t, "    timeout: 1s\n    steps:\n      - relay: s3-upload\n      - store: a\n")
	pidfile := blockingJob(t, e)
	start := time.Now()
	e.runOne(t, "t1")
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("took %v", el)
	}
	waitDead(t, childPid(t, pidfile))
	r := find(e.logs.records(t), "pipeline failed", "p")
	if r == nil || fmt.Sprint(r["error"]) != "relay s3-upload: timeout after 1s" || r["output"] != "started\n" {
		t.Fatalf("logs %v", e.logs.records(t))
	}
}

func TestCloseInterruptsRelay(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - relay: s3-upload\n      - store: a\n")
	pidfile := blockingJob(t, e)
	d := e.dispatcher()
	j := e.enqueue(t, "i1", "up", "p")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); !exists(pidfile); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("job did not start")
		}
	}
	d.Close()
	d.Wait()
	waitDead(t, childPid(t, pidfile))
	if !exists(filepath.Join(j.Entry.Dir, "meta.json")) {
		t.Fatal("queue entry removed")
	}
	recs := e.logs.records(t)
	if find(recs, "pipeline failed", "p") != nil || find(recs, "pipeline interrupted", "p") == nil {
		t.Fatalf("logs %v", recs)
	}
}

// A relay step passes on the metadata of its set in the request; the job
// gets it as its environment.
func TestRelaySendsMetadata(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "env")
	e := newRunEnv(t, "    steps:\n      - relay: s3-upload\n      - store: a\n")
	e.jobs["s3-upload"] = rundtest.Unit{Argv: []string{script(t, "env > \"$SEEN\"\n")}, Env: []string{"SEEN=" + seen}}
	e.requests = make(chan runproto.StepRequest, 1)
	d := e.dispatcher()
	j := e.enqueueWith(t, "id1", "up", func(j *Job) {
		j.Vars.Tags, j.Vars.Hostname = []string{"daily"}, "db1"
		j.Sidecar.Client.Tags, j.Sidecar.Client.Backup = j.Vars.Tags, &wire.Backup{Hostname: "db1"}
	}, "p")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	want := map[string]string{
		"LUK_SENDER": "robert.socha", "LUK_ENDPOINT": "up", "LUK_FILE": "f.txt", "LUK_NAME": "f.txt",
		"LUK_TAGS": "daily", "LUK_HOSTNAME": "db1", "LUK_ORIGIN": "db1",
	}
	if r := <-e.requests; r.Pipeline != "p" || r.Step != 1 || r.ID != "id1" || r.Job != "" || !maps.Equal(r.Env, want) {
		t.Fatalf("request %+v", r)
	}
	b, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	m := envLines(string(b))
	if m["LUK_TAGS"] != "daily" || m["LUK_ORIGIN"] != "db1" || m["LUK_FILE"] != m["LUK_IN"]+"/f.txt" || m["LUK_ID"] != "id1" {
		t.Fatalf("env %v", m)
	}
}
