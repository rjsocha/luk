// Package rundtest serves the lukd run socket in-process for tests: it
// reads step requests with their channel, answers s, runs the real
// wrapper (internal/wrap) on a temporary workspace as the test user and
// streams the output frames, as lukd run and a unit would.
package rundtest

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"sync"
	"testing"

	"luk/internal/config"
	"luk/internal/jobchan"
	"luk/internal/runproto"
	"luk/internal/runstep"
	"luk/internal/wrap"
)

// Unit is what a request runs.
type Unit struct {
	Argv []string // command and its arguments; the workspace is appended
	Env  []string // before the LUK_* variables
}

type Server struct {
	Socket string
	// Resolve maps a request to its unit, or refuses it with a reason
	// (answered as lukd run does: e "lukd run: <reason>", x 1).
	Resolve func(r runproto.StepRequest) (Unit, error)
	// Hold, when set, delays the s frame until it is closed (a unit slot).
	Hold chan struct{}
	// Requests receives every request; it must have room for them all
	// (a full channel fails the test rather than blocking).
	Requests chan runproto.StepRequest

	base string
	wg   sync.WaitGroup
}

// Start serves s.Socket until the end of the test, which waits for the
// requests in progress.
func Start(t *testing.T, s *Server) {
	t.Helper()
	s.base = t.TempDir()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		l.Close()
		s.wg.Wait()
	})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := l.AcceptUnix()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serve(t, c)
			}()
		}
	}()
}

func (s *Server) serve(t *testing.T, c *net.UnixConn) {
	defer c.Close()
	fw := runproto.NewFrameWriter(c)
	refuse := func(err error) {
		io.WriteString(fw.Stream(runproto.Stderr), "lukd run: "+err.Error()+"\n")
		fw.Exit(1)
	}
	req, ch, err := runproto.ReadStepRequest(c)
	if err != nil {
		refuse(err)
		return
	}
	defer ch.Close()
	if s.Requests != nil {
		select {
		case s.Requests <- req:
		default:
			t.Errorf("request %+v: Requests is full", req)
		}
	}
	u, err := s.Resolve(req)
	if err != nil {
		refuse(err)
		return
	}
	gone := make(chan struct{})
	go func() { io.Copy(io.Discard, c); close(gone) }()
	if s.Hold != nil {
		select {
		case <-s.Hold:
		case <-gone:
			return
		}
	}
	fw.Started()
	ws, err := os.MkdirTemp(s.base, "ws-")
	if err != nil {
		t.Error(err)
		return
	}
	conn, err := jobchan.FromFile(ch)
	if err != nil {
		t.Error(err)
		return
	}
	env := append(slices.Clone(u.Env), runstep.UnitVars(ws, req.ID, req.Pipeline, req.Step, req.Env)...)
	if req.Job != "" {
		env = append(env, "LUK_JOB="+req.Job)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-gone:
			cancel()
		case <-ctx.Done():
		}
	}()
	w := &wrap.Wrapper{Ch: conn, Workspace: ws, Argv: append(slices.Clone(u.Argv), ws), Env: env,
		Stdout: fw.Stream(runproto.Stdout), Stderr: fw.Stream(runproto.Stderr)}
	code := w.Run(ctx)
	conn.Close()
	fw.Exit(code)
}

// FromConfig resolves requests as lukd run does with the pipelines of
// cfg and the jobs of run.d: a run program runs with PATH (the test's
// own), LANG and the step env; a run: {job} or relay step and a nested
// job a run program step lists in jobs run jobs[name].
func FromConfig(cfg *config.Config, jobs map[string]Unit) func(runproto.StepRequest) (Unit, error) {
	return func(r runproto.StepRequest) (Unit, error) {
		p, n := r.Pipeline, r.Step
		no := fmt.Errorf("pipeline %s step %d: not a run or relay step", p, n)
		if r.Job != "" {
			no = fmt.Errorf("job %s: not allowed for pipeline %s step %d", r.Job, p, n)
		}
		pl := cfg.Pipeline[p]
		if pl == nil || n < 1 || n > len(pl.Steps) {
			return Unit{}, no
		}
		s := pl.Steps[n-1]
		name := r.Job
		switch {
		case r.Job != "":
			if s.Run.Program == "" || !slices.Contains(s.Jobs, r.Job) {
				return Unit{}, no
			}
		case s.Run.Program != "":
			env := []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8"}
			for _, k := range slices.Sorted(maps.Keys(s.Env)) {
				env = append(env, k+"="+s.Env[k])
			}
			return Unit{Argv: []string{s.Run.Program}, Env: env}, nil
		case s.Run.Job != "":
			name = s.Run.Job
		case s.Relay != "":
			name = s.Relay
		default:
			return Unit{}, no
		}
		u, ok := jobs[name]
		if !ok {
			return Unit{}, fmt.Errorf("job %q: unknown", name)
		}
		return u, nil
	}
}
