package client

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"luk/internal/tlsself"
	"luk/internal/wire"
)

// earlyHints answers 103 Early Hints, then holds the request for hold (or
// until it ends) before the final status.
func earlyHints(hold time.Duration, status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		select {
		case <-time.After(hold):
		case <-r.Context().Done():
			return
		}
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
		}
		http.Error(w, `{"error":"no"}`, status)
	})
}

// A 1xx answer other than 100 is no decision: the timer still ends the wait.
func TestEarlyHintsAreNoDecision(t *testing.T) {
	shortContinue(t)
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			ts, pin := newTestServer(t, proto.h2, earlyHints(3*time.Second, 403))
			o := fileOpts(t, ts.URL+"/backup", newSigner(t), []byte("hello"))
			o.Pin = pin
			o.DecisionTimeout = 200 * time.Millisecond
			start := time.Now()
			_, err := uploadWithin(t, o, 5*time.Second)
			var te *TransferError
			if !errors.As(err, &te) || te.Reason != NoDecision {
				t.Fatalf("%v", err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("gave up after %s", d)
			}
		})
	}
}

// A final answer after 103 within the timeout is the decision.
func TestRejectionAfterEarlyHints(t *testing.T) {
	shortContinue(t)
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			ts, pin := newTestServer(t, proto.h2, earlyHints(300*time.Millisecond, 401))
			o := fileOpts(t, ts.URL+"/backup", newSigner(t), []byte("hello"))
			o.Pin = pin
			o.DecisionTimeout = 2 * time.Second
			_, err := uploadWithin(t, o, 5*time.Second)
			var re *RejectedError
			if !errors.As(err, &re) || re.Status != 401 {
				t.Fatalf("%v", err)
			}
		})
	}
}

// The first bytes of a status line are not a decision either: only the
// complete headers of a final answer are.
func TestPartialHeadersAreNoDecision(t *testing.T) {
	shortContinue(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-"))
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				br.ReadByte()
			}()
		}
	}()
	o := fileOpts(t, "http://"+ln.Addr().String()+"/backup", newSigner(t), []byte("hello"))
	o.DecisionTimeout = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = Upload(ctx, o)
	var te *TransferError
	if !errors.As(err, &te) || te.Reason != NoDecision {
		t.Fatalf("%v", err)
	}
}

// A timestamp refused as out of the window carries the offset of the local
// clock from the Date of the answer, for an upload and a signed get; other
// rejections carry none.
func TestClockOffset(t *testing.T) {
	reason := wire.ErrTimestampWindow
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", time.Now().Add(-2*time.Minute).UTC().Format(http.TimeFormat))
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
		}
		http.Error(w, `{"error":"`+reason+`"}`, http.StatusUnauthorized)
	}))
	t.Cleanup(ts.Close)
	check := func(what string, err error, want bool) {
		t.Helper()
		var re *RejectedError
		if !errors.As(err, &re) || re.Status != http.StatusUnauthorized {
			t.Fatalf("%s: %v", what, err)
		}
		if !want {
			if re.ClockOffset != nil {
				t.Fatalf("%s: offset %v", what, *re.ClockOffset)
			}
			return
		}
		if re.ClockOffset == nil || *re.ClockOffset < 119*time.Second || *re.ClockOffset > 121*time.Second {
			t.Fatalf("%s: offset %v", what, re.ClockOffset)
		}
	}
	_, err := Upload(context.Background(), fileOpts(t, ts.URL+"/up", newSigner(t), []byte("hello")))
	check("upload", err, true)
	u, _ := url.Parse(ts.URL + "/d/x")
	_, err = Get(context.Background(), GetOptions{URL: u, Signer: newSigner(t)})
	check("get", err, true)
	reason = "timestamp before server start"
	_, err = Upload(context.Background(), fileOpts(t, ts.URL+"/up", newSigner(t), []byte("hello")))
	check("other", err, false)
}

// hold keeps a request open until it ends.
func hold(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }

func wantReason(t *testing.T, err error, reason Reason, start time.Time) *TransferError {
	t.Helper()
	var te *TransferError
	if !errors.As(err, &te) || te.Reason != reason {
		t.Fatalf("%v, want reason %d", err, reason)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("gave up after %s", d)
	}
	return te
}

// A GET, a HEAD and the endpoint listing without answer headers end
// after the decision timeout.
func TestGetNoAnswer(t *testing.T) {
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			ts := httptest.NewUnstartedServer(http.HandlerFunc(hold))
			ts.EnableHTTP2 = proto.h2
			ts.StartTLS()
			defer ts.Close()
			u, _ := url.Parse(ts.URL + "/x")
			o := GetOptions{URL: u, Pin: tlsself.Pin(ts.Certificate()), Signer: newSigner(t), DecisionTimeout: 200 * time.Millisecond}
			start := time.Now()
			_, err := HeadFile(context.Background(), o)
			te := wantReason(t, err, NoAnswer, start)
			if te.Error() != "the server gave no answer within 200ms" {
				t.Fatalf("%q", te.Error())
			}
			start = time.Now()
			_, err = Get(context.Background(), o)
			wantReason(t, err, NoAnswer, start)
			start = time.Now()
			_, err = ListEndpoints(context.Background(), o)
			wantReason(t, err, NoAnswer, start)
		})
	}
}

// A download that stops in the middle ends after the idle timeout; a slow
// reader of a download that arrived is not cut.
func TestGetStalled(t *testing.T) {
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/small" {
					w.Write(make([]byte, 64<<10))
					return
				}
				w.Header().Set("Content-Length", "8388608")
				w.Write(make([]byte, 1<<20))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			ts.EnableHTTP2 = proto.h2
			ts.StartTLS()
			defer ts.Close()
			u, _ := url.Parse(ts.URL + "/x")
			o := GetOptions{URL: u, Pin: tlsself.Pin(ts.Certificate()), Signer: newSigner(t), IdleTimeout: 200 * time.Millisecond}
			start := time.Now()
			d, err := Get(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			n, err := io.Copy(io.Discard, d)
			d.Close()
			te := wantReason(t, err, Stalled, start)
			if n != 1<<20 || te.Error() != "no progress for 200ms after 1.0 MiB of 8.0 MiB" {
				t.Fatalf("%d %q", n, te.Error())
			}

			o.URL, _ = url.Parse(ts.URL + "/small")
			if d, err = Get(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			time.Sleep(300 * time.Millisecond)
			buf := make([]byte, 16<<10)
			for {
				_, err := d.Read(buf)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("slow reader: %v", err)
				}
				time.Sleep(300 * time.Millisecond)
			}
		})
	}
}

// An upload whose body the server stops taking, or whose answer does not
// come after the body, ends after the idle timeout.
func TestUploadStalled(t *testing.T) {
	shortContinue(t)
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			ts, pin := newTestServer(t, proto.h2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/after" {
					io.Copy(io.Discard, r.Body)
					<-r.Context().Done()
					return
				}
				// Stop taking the body; the rest is read once the client
				// has given up, which ends the handler.
				io.ReadFull(r.Body, make([]byte, 1<<20))
				select {
				case <-r.Context().Done():
				case <-time.After(time.Second):
				}
				io.Copy(io.Discard, r.Body)
			}))
			o := fileOpts(t, ts.URL+"/after", newSigner(t), []byte("hello"))
			o.Pin = pin
			o.IdleTimeout = 200 * time.Millisecond
			start := time.Now()
			_, err := uploadWithin(t, o, 5*time.Second)
			te := wantReason(t, err, Stalled, start)
			if te.Error() != "no progress for 200ms after 5 B of 5 B" {
				t.Fatalf("%q", te.Error())
			}

			o = fileOpts(t, ts.URL+"/body", newSigner(t), make([]byte, 64<<20))
			o.Pin = pin
			o.IdleTimeout = 200 * time.Millisecond
			start = time.Now()
			_, err = uploadWithin(t, o, 5*time.Second)
			if te = wantReason(t, err, Stalled, start); te.Done < 1<<20 || te.Done == te.Total {
				t.Fatalf("%v", te)
			}
		})
	}
}

// A slow source is luk waiting for itself, not for the server: it never
// trips the idle timeout.
func TestUploadSlowSourceNotStalled(t *testing.T) {
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			ts, pin := newTestServer(t, proto.h2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h := sha256.New()
				n, _ := io.Copy(h, r.Body)
				w.WriteHeader(http.StatusAccepted)
				fmt.Fprintf(w, `{"id":"x","sha256":"%x","size":%d}`, h.Sum(nil), n)
			}))
			o := fileOpts(t, ts.URL+"/backup", newSigner(t), []byte("zzz"))
			left := 3
			o.Body = readFunc(func(p []byte) (int, error) {
				if left == 0 {
					return 0, io.EOF
				}
				time.Sleep(300 * time.Millisecond)
				p[0] = 'z'
				left--
				return 1, nil
			})
			o.Pin = pin
			o.IdleTimeout = 100 * time.Millisecond
			if _, err := uploadWithin(t, o, 5*time.Second); err != nil {
				t.Fatal(err)
			}
		})
	}
}
