package pipeline

import (
	"io"
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

func TestNestedJobResultsIntoOut(t *testing.T) {
	upper := script(t, "tr a-z A-Z < \"$LUK_FILE\" > \"$LUK_OUT/up\"\necho job-out\n")
	prog := script(t, `set -e
luk-job run --job upper --file "$LUK_IN/f.txt" --out "$LUK_TMP"
mv "$LUK_TMP/up" "$LUK_OUT/up"
`)
	e := newRunEnv(t, "    steps:\n      - run: "+prog+"\n        jobs: [upper]\n      - store: a\n")
	e.jobs["upper"] = rundtest.Unit{Argv: []string{upper}}
	e.runOne(t, "20261006T100000Z-0a1b2c3d")
	if got := e.read(t, "a/file/robert.socha/up"); got != "DATA-20261006T100000Z-0A1B2C3D" {
		t.Fatalf("%q", got)
	}
}

func TestNestedJobWithoutOutMustWriteNothing(t *testing.T) {
	writes := script(t, "echo x > \"$LUK_OUT/x\"\n")
	prog := script(t, "luk-job run --job w || exit 9\n")
	e := newRunEnv(t, "    steps:\n      - run: "+prog+"\n        jobs: [w]\n")
	e.jobs["w"] = rundtest.Unit{Argv: []string{writes}}
	e.runOne(t, "20261006T100000Z-0a1b2c3d")
	if st := e.lastFailure(t); !strings.Contains(st, "exit status 9") {
		t.Fatalf("%q", st)
	}
}

// lukd process refuses a job the step does not list, as lukd run would.
func TestNestedJobNotListedRefused(t *testing.T) {
	prog := script(t, "luk-job run --job other 2> \"$LUK_TMP/err\" || cp \"$LUK_TMP/err\" fail; exit 1\n")
	e := newRunEnv(t, "    steps:\n      - run: "+prog+"\n        jobs: [w]\n")
	e.jobs["other"] = rundtest.Unit{Argv: []string{"/bin/true"}}
	e.runOne(t, "20261006T100000Z-0a1b2c3d")
	if st := e.lastFailure(t); !strings.Contains(st, "luk-job run: job other: not allowed for pipeline p step 1") {
		t.Fatalf("%q", st)
	}
}

func TestNestedJobGetsStepSetByDefault(t *testing.T) {
	list := script(t, "ls \"$LUK_IN\" > \"$LUK_OUT/list\"\n")
	prog := script(t, "luk-job run --job l --out \"$LUK_TMP\" && mv \"$LUK_TMP/list\" \"$LUK_OUT/list\"\n")
	e := newRunEnv(t, "    steps:\n      - run: "+prog+"\n        jobs: [l]\n      - store: a\n")
	e.jobs["l"] = rundtest.Unit{Argv: []string{list}}
	e.runOne(t, "20261006T100000Z-0a1b2c3d")
	if got := e.read(t, "a/file/robert.socha/list"); got != "f.txt\n" {
		t.Fatalf("%q", got)
	}
}

// answer is what lukd process sent back for a nested job.
type answer struct {
	stdout, stderr string
	outs           []input
	status         *int
	refused        string
}

// readAnswer reads the frames of a nested job up to its exit or refused.
func readAnswer(t *testing.T, ch *jobchan.Conn) answer {
	t.Helper()
	var a answer
	for {
		f, fd, err := ch.Recv()
		if err != nil {
			t.Errorf("answer: %v", err)
			return a
		}
		switch f.T {
		case jobchan.TStdout:
			a.stdout += string(f.Data)
		case jobchan.TStderr:
			a.stderr += string(f.Data)
		case jobchan.TOut:
			b, _ := io.ReadAll(fd)
			fd.Close()
			a.outs = append(a.outs, input{"out", f.Name, string(b)})
		case jobchan.TExit:
			a.status = f.Status
			return a
		case jobchan.TRefused:
			a.refused = f.Reason
			return a
		default:
			t.Errorf("answer: frame %+v", f)
		}
	}
}

func finish(ch *jobchan.Conn) {
	ch.Send(jobchan.Frame{T: jobchan.TStatus, Status: jobchan.Status(0)}, nil)
	ch.Send(jobchan.Frame{T: jobchan.TEnd}, nil)
}

// The output of a nested job reaches the wrapper in frames of at most
// 32 KiB, its results with their descriptors, its exit status last; the
// job gets meta.json, the in frames and go, and the metadata of its set.
func TestNestedRelay(t *testing.T) {
	big := strings.Repeat("x", 100<<10)
	e := newRunEnv(t, "    steps:\n      - run: /bin/true\n        jobs: [w]\n        tee: true\n")
	got := make(chan answer, 1)
	nested := make(chan *fakeUnit, 1)
	fakeRund(t, e, func(u *fakeUnit) int {
		if u.req.Job == "w" {
			nested <- u
			io.WriteString(u.fw.Stream('o'), big)
			io.WriteString(u.fw.Stream('e'), "warn\n")
			u.ch.Send(jobchan.Frame{T: jobchan.TStatus, Status: jobchan.Status(0)}, nil)
			u.ch.Send(jobchan.Frame{T: jobchan.TOut, Name: "r"}, regularFile(t, "result"))
			u.ch.Send(jobchan.Frame{T: jobchan.TEnd}, nil)
			return 0
		}
		u.ch.Send(jobchan.Frame{T: jobchan.TJob, Job: "w"}, nil)
		u.ch.Send(jobchan.Frame{T: jobchan.TIn, Name: "a"}, regularFile(t, "aa"))
		u.ch.Send(jobchan.Frame{T: jobchan.TGo}, nil)
		got <- readAnswer(t, u.ch)
		// A stop that crossed the exit is dropped.
		u.ch.Send(jobchan.Frame{T: jobchan.TStop}, nil)
		finish(u.ch)
		return 0
	})
	e.runOne(t, "n1")
	if find(e.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	a := <-got
	if a.stdout != big || a.stderr != "warn\n" || a.status == nil || *a.status != 0 || !slices.Equal(a.outs, []input{{"out", "r", "result"}}) {
		t.Fatalf("%.80q %q %v %v", a.stdout, a.stderr, a.status, a.outs)
	}
	u := <-nested
	if len(u.inputs) != 3 || u.inputs[0].t != "meta" || u.inputs[1] != (input{"in", "a", "aa"}) || u.req.Env["LUK_FILE"] != "a" {
		t.Fatalf("%+v %v", u.inputs, u.req.Env)
	}
}

// A result the wrapper of the job refused fails the job with a message.
func TestNestedRefusedResult(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - run: /bin/true\n        jobs: [w]\n")
	got := make(chan answer, 1)
	fakeRund(t, e, func(u *fakeUnit) int {
		if u.req.Job == "w" {
			u.ch.Send(jobchan.Frame{T: jobchan.TStatus, Status: jobchan.Status(0)}, nil)
			u.ch.Send(jobchan.Frame{T: jobchan.TRefuse, Name: "p", Reason: "not a regular file"}, nil)
			u.ch.Send(jobchan.Frame{T: jobchan.TEnd}, nil)
			return 0
		}
		u.ch.Send(jobchan.Frame{T: jobchan.TJob, Job: "w"}, nil)
		u.ch.Send(jobchan.Frame{T: jobchan.TGo}, nil)
		got <- readAnswer(t, u.ch)
		finish(u.ch)
		return 0
	})
	e.runOne(t, "n1")
	a := <-got
	if a.stderr != "lukd: job w: out: \"p\": not a regular file\n" || a.status == nil || *a.status != 1 {
		t.Fatalf("%q %v", a.stderr, a.status)
	}
}

// A job the step does not list is refused; the frames that follow it are
// checked and dropped, and the step goes on.
func TestNestedNotAllowedDropsRest(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - run: /bin/true\n        jobs: [w]\n      - store: a\n")
	reason := make(chan string, 1)
	fakeRund(t, e, func(u *fakeUnit) int {
		ch := u.ch
		ch.Send(jobchan.Frame{T: jobchan.TJob, Job: "state"}, nil)
		ch.Send(jobchan.Frame{T: jobchan.TIn, Name: "x"}, regularFile(t, "x"))
		ch.Send(jobchan.Frame{T: jobchan.TGo}, nil)
		reason <- readAnswer(t, ch).refused
		ch.Send(jobchan.Frame{T: jobchan.TStop}, nil)
		ch.Send(jobchan.Frame{T: jobchan.TStatus, Status: jobchan.Status(0)}, nil)
		ch.Send(jobchan.Frame{T: jobchan.TOut, Name: "r"}, regularFile(t, "result"))
		ch.Send(jobchan.Frame{T: jobchan.TEnd}, nil)
		return 0
	})
	e.runOne(t, "n1")
	if r := <-reason; r != "job state: not allowed for pipeline p step 1" {
		t.Fatalf("reason %q", r)
	}
	if got := e.read(t, "a/file/robert.socha/r"); got != "result" {
		t.Fatalf("r %q", got)
	}
}

// A stop makes lukd process close the connection of the job to lukd run
// and answer exit 1; the status that follows ends the step as usual.
func TestNestedStop(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - run: /bin/true\n        jobs: [w]\n        tee: true\n")
	running := make(chan struct{})
	gone := make(chan struct{})
	got := make(chan answer, 1)
	fakeRund(t, e, func(u *fakeUnit) int {
		if u.req.Job == "w" {
			close(running)
			io.Copy(io.Discard, u.c)
			close(gone)
			return 0
		}
		u.ch.Send(jobchan.Frame{T: jobchan.TJob, Job: "w"}, nil)
		u.ch.Send(jobchan.Frame{T: jobchan.TGo}, nil)
		<-running
		u.ch.Send(jobchan.Frame{T: jobchan.TStop}, nil)
		got <- readAnswer(t, u.ch)
		finish(u.ch)
		return 0
	})
	e.runOne(t, "n1")
	if find(e.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	if a := <-got; a.status == nil || *a.status != 1 || a.stdout != "" || a.stderr != "" {
		t.Fatalf("%+v", a)
	}
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection of the job stayed open")
	}
}

// A stop before go answers exit 1 at once.
func TestNestedStopBeforeGo(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - run: /bin/true\n        jobs: [w]\n")
	got := make(chan answer, 1)
	fakeRund(t, e, func(u *fakeUnit) int {
		u.ch.Send(jobchan.Frame{T: jobchan.TJob, Job: "w"}, nil)
		u.ch.Send(jobchan.Frame{T: jobchan.TIn, Name: "a"}, regularFile(t, "aa"))
		u.ch.Send(jobchan.Frame{T: jobchan.TStop}, nil)
		got <- readAnswer(t, u.ch)
		finish(u.ch)
		return 0
	})
	e.runOne(t, "n1")
	if a := <-got; a.status == nil || *a.status != 1 {
		t.Fatalf("%+v", a)
	}
}

// The nested frames of the wrapper are checked; a violation fails the
// step and stops the job.
func TestNestedProtocolErrors(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	type send func(t *testing.T, ch *jobchan.Conn)
	job := func(name string) send {
		return func(_ *testing.T, ch *jobchan.Conn) { ch.Send(jobchan.Frame{T: jobchan.TJob, Job: name}, nil) }
	}
	in := func(name string) send {
		return func(t *testing.T, ch *jobchan.Conn) {
			ch.Send(jobchan.Frame{T: jobchan.TIn, Name: name}, regularFile(t, "x"))
		}
	}
	frame := func(typ string) send {
		return func(_ *testing.T, ch *jobchan.Conn) { ch.Send(jobchan.Frame{T: typ}, nil) }
	}
	inFifo := func(_ *testing.T, ch *jobchan.Conn) {
		f, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer f.Close()
		ch.Send(jobchan.Frame{T: jobchan.TIn, Name: "f"}, f)
	}
	for _, c := range []struct {
		name  string
		sends []send
		err   string
	}{
		{"in without job", []send{in("a")}, `unexpected frame "in"`},
		{"stop without job", []send{frame(jobchan.TStop)}, `unexpected frame "stop"`},
		{"invalid name", []send{job("w"), in(".a")}, `job w: in: ".a": invalid name`},
		{"twice", []send{job("w"), in("a"), in("a")}, `job w: in: "a": sent twice`},
		{"fifo", []send{job("w"), inFifo}, `job w: in: "f": not a regular file`},
		{"refused, then invalid name", []send{job("x"), in("a/b")}, `job x: in: "a/b": invalid name`},
		{"in after go", []send{job("x"), frame(jobchan.TGo), in("a")}, `unexpected frame "in"`},
		{"go twice", []send{job("x"), frame(jobchan.TGo), frame(jobchan.TGo)}, `unexpected frame "go"`},
		{"second job", []send{job("w"), frame(jobchan.TGo), job("w")}, "nested job w while job w runs"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newRunEnv(t, "    steps:\n      - run: /bin/true\n        jobs: [w]\n")
			fakeRund(t, e, func(u *fakeUnit) int {
				if u.req.Job != "" {
					io.Copy(io.Discard, u.c)
					return 1
				}
				for _, s := range c.sends {
					s(t, u.ch)
				}
				finish(u.ch)
				// Read the answers until lukd process closes: closing
				// with frames unread would reset its reads.
				for {
					_, fd, err := u.ch.Recv()
					if err != nil {
						return 0
					}
					closeFile(fd)
				}
			})
			e.runOne(t, "n1")
			if got := e.lastFailure(t); got != "run /bin/true: "+c.err {
				t.Fatalf("%q", got)
			}
		})
	}
}

// A connection to lukd run that ends without the exit status fails the
// job with a message.
func TestNestedConnectionError(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - run: /bin/true\n        jobs: [w]\n        tee: true\n")
	got := make(chan answer, 1)
	fakeRund(t, e, func(u *fakeUnit) int {
		if u.req.Job == "w" {
			u.c.Close()
			return 0
		}
		u.ch.Send(jobchan.Frame{T: jobchan.TJob, Job: "w"}, nil)
		u.ch.Send(jobchan.Frame{T: jobchan.TGo}, nil)
		got <- readAnswer(t, u.ch)
		finish(u.ch)
		return 0
	})
	e.runOne(t, "n1")
	if a := <-got; a.stderr != "lukd: job w: connection closed before the exit status\n" || a.status == nil || *a.status != 1 {
		t.Fatalf("%q %v", a.stderr, a.status)
	}
}
