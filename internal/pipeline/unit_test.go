package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"luk/internal/jobchan"
	"luk/internal/rund/rundtest"
)

func TestRunJobStepProducesSet(t *testing.T) {
	dump := script(t, "printf dump > \"$LUK_OUT/db.sql\"\n")
	e := newRunEnv(t, "    steps:\n      - run: {job: db-dump}\n      - store: a\n")
	e.jobs["db-dump"] = rundtest.Unit{Argv: []string{dump}}
	e.runOne(t, "20261006T100000Z-0a1b2c3d")
	if got := e.read(t, "a/file/robert.socha/db.sql"); got != "dump" {
		t.Fatalf("%q", got)
	}
}

func TestRunJobStepErrorNamesJob(t *testing.T) {
	fail := script(t, "exit 4\n")
	e := newRunEnv(t, "    steps:\n      - run: {job: db-dump}\n")
	e.jobs["db-dump"] = rundtest.Unit{Argv: []string{fail}}
	e.runOne(t, "20261006T100000Z-0a1b2c3d")
	if st := e.lastFailure(t); !strings.Contains(st, "run job db-dump: exit status 4") {
		t.Fatalf("%q", st)
	}
}

func TestTimeoutCountsFromStarted(t *testing.T) {
	hold := make(chan struct{})
	e := newRunEnvHold(t, "    timeout: 1s\n    steps:\n      - run: "+script(t, "echo x > \"$LUK_OUT/x\"\n")+"\n      - store: a\n", hold)
	d := e.dispatcher()
	j := e.enqueue(t, "20261006T100000Z-0a1b2c3d", "up", "p")
	d.Submit(j)
	time.Sleep(1500 * time.Millisecond) // longer than the timeout, waiting for a slot
	if u := d.Units(time.Now()); u.Waiting != 1 || u.Running != 0 || u.OldestWait < 1 {
		t.Fatalf("%+v", u)
	}
	close(hold)
	d.Wait()
	if !exists(filepath.Join(e.root, "data", "a", "file", "robert.socha", "x")) {
		t.Fatalf("step failed: the slot wait counted toward the timeout: %v", e.logs.records(t))
	}
	if u := d.Units(time.Now()); u.Waiting != 0 || u.Running != 0 || u.OldestWait != 0 {
		t.Fatalf("%+v", u)
	}
}

func TestUnitsCountsRunning(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	s := script(t, `echo $$ > "$PIDFILE.tmp"; mv "$PIDFILE.tmp" "$PIDFILE"
sleep 30
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        env: {PIDFILE: %s}\n", s, pidfile))
	d := e.dispatcher()
	d.Submit(e.enqueue(t, "u1", "up", "p"))
	for deadline := time.Now().Add(5 * time.Second); !exists(pidfile); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("step did not start")
		}
	}
	if u := d.Units(time.Now()); u.Running != 1 || u.Waiting != 0 {
		t.Fatalf("%+v", u)
	}
	d.Close()
	d.Wait()
}

func TestCloseWhileWaitingForSlotInterrupts(t *testing.T) {
	hold := make(chan struct{})
	e := newRunEnvHold(t, "    steps:\n      - run: /bin/true\n", hold)
	d := e.dispatcher()
	j := e.enqueue(t, "20261006T100000Z-0a1b2c3d", "up", "p")
	d.Submit(j)
	time.Sleep(200 * time.Millisecond)
	d.Close()
	d.Wait()
	if !exists(filepath.Join(j.Entry.Dir, "meta.json")) {
		t.Fatal("entry removed: the pipeline failed instead of being interrupted")
	}
}

func TestResultsOwnedAndMode(t *testing.T) {
	s := script(t, "echo r > \"$LUK_OUT/r\"\nchmod 0600 \"$LUK_OUT/r\"\n")
	e := newRunEnv(t, "    steps:\n      - run: "+s+"\n      - store: a\n")
	e.runOne(t, "20261006T100000Z-0a1b2c3d")
	fi, err := os.Stat(filepath.Join(e.root, "data", "a", "file", "robert.socha", "r"))
	if err != nil || fi.Mode().Perm() != 0o440 {
		t.Fatalf("%v %v", fi, err)
	}
}

// fakeResults makes the unit of e answer with status 0 and then send what
// send does.
func fakeResults(t *testing.T, e *env, send func(ch *jobchan.Conn)) {
	fakeRund(t, e, func(u *fakeUnit) int {
		if err := u.ch.Send(jobchan.Frame{T: jobchan.TStatus, Status: jobchan.Status(0)}, nil); err != nil {
			t.Error(err)
		}
		send(u.ch)
		return 0
	})
}

func regularFile(t *testing.T, data string) *os.File {
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

// The checks of lukd process on the results, whatever the wrapper sends.
func TestUnitResultChecks(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	out := func(ch *jobchan.Conn, name string, f *os.File) {
		if err := ch.Send(jobchan.Frame{T: jobchan.TOut, Name: name}, f); err != nil {
			t.Error(err)
		}
	}
	end := func(ch *jobchan.Conn) { ch.Send(jobchan.Frame{T: jobchan.TEnd}, nil) }
	cases := map[string]struct {
		send func(ch *jobchan.Conn)
		err  string
	}{
		"fifo": {func(ch *jobchan.Conn) {
			f, err := os.OpenFile(fifo, os.O_RDWR, 0)
			if err != nil {
				t.Error(err)
				return
			}
			defer f.Close()
			out(ch, "p", f)
			end(ch)
		}, `out: "p": not a regular file`},
		"socket": {func(ch *jobchan.Conn) {
			a, b, err := jobchan.Pair()
			if err != nil {
				t.Error(err)
				return
			}
			defer a.Close()
			defer b.Close()
			out(ch, "s", b)
			end(ch)
		}, `out: "s": not a regular file`},
		"invalid name": {func(ch *jobchan.Conn) { out(ch, ".h", regularFile(t, "x")); end(ch) }, `out: ".h": invalid name`},
		"sent twice": {func(ch *jobchan.Conn) {
			out(ch, "f", regularFile(t, "x"))
			out(ch, "f", regularFile(t, "y"))
			end(ch)
		}, `out: "f": sent twice`},
		"too many": {func(ch *jobchan.Conn) {
			f := regularFile(t, "x")
			for i := range jobchan.MaxFiles + 1 {
				if ch.Send(jobchan.Frame{T: jobchan.TOut, Name: fmt.Sprintf("f%d", i)}, f) != nil {
					return
				}
			}
			end(ch)
		}, "out: more than 1024 entries"},
		"refused": {func(ch *jobchan.Conn) {
			ch.Send(jobchan.Frame{T: jobchan.TRefuse, Name: "d", Reason: "not a regular file"}, nil)
			end(ch)
		}, `out: "d": not a regular file`},
		"closed": {func(ch *jobchan.Conn) { out(ch, "f", regularFile(t, "x")) }, "channel closed before the results"},
		"no result": {func(ch *jobchan.Conn) {
			out(ch, "f", regularFile(t, "x"))
			time.Sleep(time.Second)
			end(ch)
		}, "no result for 200ms"},
	}
	old := resultGap
	resultGap = 200 * time.Millisecond
	t.Cleanup(func() { resultGap = old })
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newRunEnv(t, "    steps:\n      - run: /bin/true\n      - store: a\n")
			fakeResults(t, e, c.send)
			e.runOne(t, "r1")
			if got := e.lastFailure(t); got != "run /bin/true: "+c.err {
				t.Fatalf("error %q", got)
			}
			if ents, _ := os.ReadDir(filepath.Join(e.root, "data", "a", "file")); len(ents) != 0 {
				t.Fatalf("stored %v", ents)
			}
		})
	}
}

// The inputs reach the unit by descriptor: meta.json first, then the files
// of the set with their meta files in name order, then go.
func TestUnitGetsInputs(t *testing.T) {
	got := make(chan []input, 1)
	e := newRunEnv(t, "    steps:\n      - run: /bin/true\n      - run: /bin/true\n        tee: true\n")
	fakeRund(t, e, func(u *fakeUnit) int {
		send := func(f jobchan.Frame, fd *os.File) {
			if err := u.ch.Send(f, fd); err != nil {
				t.Error(err)
			}
		}
		send(jobchan.Frame{T: jobchan.TStatus, Status: jobchan.Status(0)}, nil)
		if u.req.Step == 1 {
			send(jobchan.Frame{T: jobchan.TOut, Name: "b"}, regularFile(t, "bb"))
			send(jobchan.Frame{T: jobchan.TOut, Name: "a"}, regularFile(t, "aa"))
			send(jobchan.Frame{T: jobchan.TOut, Name: "a.meta.json"}, regularFile(t, `{"k": "v"}`))
		} else {
			got <- u.inputs
		}
		send(jobchan.Frame{T: jobchan.TEnd}, nil)
		return 0
	})
	e.runOne(t, "g1")
	if find(e.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	in := <-got
	want := []input{{"in", "a", "aa"}, {"in", "a.meta.json", `{"k":"v"}`}, {"in", "b", "bb"}, {t: "go"}}
	if len(in) != 5 || in[0].t != "meta" || !strings.Contains(in[0].data, `"step":2`) || !slices.Equal(in[1:], want) {
		t.Fatalf("%+v", in)
	}
}

// Placing a result is lukd's own work: a slow clone does not count as
// silence of the unit, also when the unit has already ended.
func TestSlowPlaceIsNotSilence(t *testing.T) {
	old, oldGap := place, resultGap
	resultGap = 100 * time.Millisecond
	place = func(dir *os.File, name string, src *os.File, mode os.FileMode, noReplace bool) error {
		time.Sleep(300 * time.Millisecond)
		return old(dir, name, src, mode, noReplace)
	}
	t.Cleanup(func() { place, resultGap = old, oldGap })
	e := newRunEnv(t, "    steps:\n      - run: /bin/true\n      - store: a\n")
	fakeResults(t, e, func(ch *jobchan.Conn) {
		ch.Send(jobchan.Frame{T: jobchan.TOut, Name: "f1"}, regularFile(t, "one"))
		ch.Send(jobchan.Frame{T: jobchan.TOut, Name: "f2"}, regularFile(t, "two"))
		ch.Send(jobchan.Frame{T: jobchan.TEnd}, nil)
	})
	e.runOne(t, "s1")
	if find(e.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	if e.read(t, "a/file/robert.socha/f1") != "one" || e.read(t, "a/file/robert.socha/f2") != "two" {
		t.Fatal("results not stored")
	}
}

func TestStepErrorTexts(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Minute: "1m", 2 * time.Minute: "2m", 90 * time.Second: "1m30s",
		10 * time.Second: "10s", 200 * time.Millisecond: "200ms"} {
		if got := formatGap(d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
	for name, want := range map[string]string{".h": ".h", "f.txt": "f.txt", "a\nb": `"a\nb"`, "x\x1b[2J": `"x\x1b[2J"`} {
		if got := printableName(name); got != want {
			t.Errorf("%q: %q, want %q", name, got, want)
		}
	}
}
