package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"luk/internal/tlsself"
)

type countingReader struct {
	n *atomic.Int64
	r *strings.Reader
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func TestRejectedBeforeBody(t *testing.T) {
	ts, _ := testServer(t, newSigner(t).PublicKey(), false)
	var read atomic.Int64
	body := strings.Repeat("x", 1<<20)
	o := fileOpts(t, ts.URL+"/backup", newSigner(t), []byte(body)) // stranger key
	o.Body = countingReader{n: &read, r: strings.NewReader(body)}
	_, err := Upload(context.Background(), o)
	var re *RejectedError
	if !errors.As(err, &re) || re.Status != 401 {
		t.Fatalf("%v", err)
	}
	if read.Load() != 0 {
		t.Fatalf("client read %d body bytes before the rejection", read.Load())
	}
}

func TestNoRedirect(t *testing.T) {
	var hits atomic.Int64
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, ts.URL+"/again", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(ts.Close)
	o := fileOpts(t, ts.URL+"/backup", newSigner(t), []byte("hello"))
	if _, err := Upload(context.Background(), o); err == nil {
		t.Fatal("expected an error")
	}
	if hits.Load() != 1 {
		t.Fatalf("server saw %d requests", hits.Load())
	}
}

func shortContinue(t *testing.T) {
	old := expectContinueTimeout
	expectContinueTimeout = 100 * time.Millisecond
	t.Cleanup(func() { expectContinueTimeout = old })
}

func newTestServer(t *testing.T, h2 bool, h http.Handler) (*httptest.Server, string) {
	t.Helper()
	if !h2 {
		ts := httptest.NewServer(h)
		t.Cleanup(ts.Close)
		return ts, ""
	}
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, tlsself.Pin(ts.Certificate())
}

func uploadWithin(t *testing.T, o Options, d time.Duration) (*Answer, error) {
	t.Helper()
	type result struct {
		resp *Answer
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := Upload(context.Background(), o)
		done <- result{resp, err}
	}()
	select {
	case r := <-done:
		return r.resp, r.err
	case <-time.After(d):
		t.Fatalf("Upload did not return within %s", d)
		return nil, nil
	}
}

var protocols = []struct {
	name string
	h2   bool
}{{"http1", false}, {"http2", true}}

func TestLateRejectionSendsNoBody(t *testing.T) {
	shortContinue(t)
	for _, proto := range protocols {
		for _, status := range []int{401, 403, 422} {
			t.Run(proto.name+"/"+strconv.Itoa(status), func(t *testing.T) {
				ts, pin := newTestServer(t, proto.h2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(400 * time.Millisecond)
					if r.ProtoMajor == 1 {
						w.Header().Set("Connection", "close")
					}
					http.Error(w, `{"error":"no"}`, status)
				}))
				var read atomic.Int64
				body := strings.Repeat("x", 1<<20)
				o := fileOpts(t, ts.URL+"/backup", newSigner(t), []byte(body))
				o.Body = countingReader{n: &read, r: strings.NewReader(body)}
				o.Pin = pin
				_, err := uploadWithin(t, o, 5*time.Second)
				var re *RejectedError
				if !errors.As(err, &re) || re.Status != status {
					t.Fatalf("%v", err)
				}
				if read.Load() != 0 {
					t.Fatalf("client read %d body bytes before the late rejection", read.Load())
				}
			})
		}
	}
}

func TestLateContinueUploads(t *testing.T) {
	shortContinue(t)
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			s := newSigner(t)
			lukd := testHandler(t, s.PublicKey())
			ts, pin := newTestServer(t, proto.h2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(400 * time.Millisecond)
				lukd.ServeHTTP(w, r)
			}))
			o := fileOpts(t, ts.URL+"/backup", s, []byte(strings.Repeat("y", 1<<20)))
			o.Pin = pin
			resp, err := uploadWithin(t, o, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Receipt.Size != 1<<20 {
				t.Fatalf("%+v", resp)
			}
		})
	}
}

type slowReader struct{ n int }

func (s *slowReader) Read(p []byte) (int, error) {
	if s.n == 0 {
		return 0, io.EOF
	}
	time.Sleep(10 * time.Millisecond)
	p[0] = 'z'
	s.n--
	return 1, nil
}

func TestDecisionTimeoutSparesLongUpload(t *testing.T) {
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			s := newSigner(t)
			ts, pin := newTestServer(t, proto.h2, testHandler(t, s.PublicKey()))
			o := fileOpts(t, ts.URL+"/backup", s, []byte(strings.Repeat("z", 60)))
			o.Body = &slowReader{n: 60}
			o.Pin = pin
			o.DecisionTimeout = 200 * time.Millisecond
			start := time.Now()
			if _, err := uploadWithin(t, o, 5*time.Second); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d < 500*time.Millisecond {
				t.Fatalf("upload took only %s", d)
			}
		})
	}
}

func TestNegativeDecisionTimeout(t *testing.T) {
	s := newSigner(t)
	ts, _ := testServer(t, s.PublicKey(), false)
	o := fileOpts(t, ts.URL+"/backup", s, []byte("hello"))
	o.DecisionTimeout = -time.Second
	if _, err := Upload(context.Background(), o); err == nil || !strings.Contains(err.Error(), "decision timeout") {
		t.Fatalf("%v", err)
	}
}

func TestDecisionTimeoutSendsNoBody(t *testing.T) {
	shortContinue(t)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(release) })
	var read atomic.Int64
	body := strings.Repeat("x", 1<<20)
	o := fileOpts(t, ts.URL+"/backup", newSigner(t), []byte(body))
	o.Body = countingReader{n: &read, r: strings.NewReader(body)}
	o.DecisionTimeout = 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := Upload(ctx, o)
	if err == nil || !strings.Contains(err.Error(), "decision") {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("gave up after %s", d)
	}
	if read.Load() != 0 {
		t.Fatalf("client read %d body bytes without a decision", read.Load())
	}
}

func TestRedirectWithMatchingHashIsNotSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusTemporaryRedirect)
		io.WriteString(w, `{"server":{"sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}}`)
	}))
	t.Cleanup(ts.Close)
	_, err := Upload(context.Background(), fileOpts(t, ts.URL+"/backup", newSigner(t), []byte("hello")))
	var re *RejectedError
	if err == nil || errors.As(err, &re) || !strings.Contains(err.Error(), "307") {
		t.Fatalf("%v", err)
	}
}
