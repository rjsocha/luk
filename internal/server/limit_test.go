package server

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/sshsig"
	"luk/internal/wire"
)

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// closed reports whether the peer closed c within d.
func closed(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, c)
	return err == nil || !isTimeout(err)
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func TestLimitListener(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := LimitListener(raw, 2)
	defer ln.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	addr := ln.Addr().String()
	c1, c2 := dial(t, addr), dial(t, addr)
	s1, s2 := <-accepted, <-accepted
	c3 := dial(t, addr)
	if !closed(c3, time.Second) {
		t.Fatal("connection over the limit was not closed")
	}
	if closed(c1, 100*time.Millisecond) || closed(c2, 100*time.Millisecond) {
		t.Fatal("admitted connection closed")
	}
	s1.Close()
	s1.Close() // a second Close must not free another slot
	c4 := dial(t, addr)
	s4 := <-accepted
	defer s4.Close()
	c5 := dial(t, addr)
	if !closed(c5, time.Second) {
		t.Fatal("slot freed twice")
	}
	if closed(c4, 100*time.Millisecond) {
		t.Fatal("connection in the freed slot closed")
	}
	s2.Close()
}

// trickler returns a sender that uploads the first chunks bytes of body one
// per gap to path, then stalls for good when chunks is short of the body.
func trickler(t *testing.T, f *fixture, ts *httptest.Server, path string, body []byte) func(chunks int, gap time.Duration) (*http.Response, error) {
	return func(chunks int, gap time.Duration) (*http.Response, error) {
		pr, pw := io.Pipe()
		go func() {
			for i := 0; i < chunks; i++ {
				if i > 0 {
					time.Sleep(gap)
				}
				if _, err := pw.Write(body[i : i+1]); err != nil {
					return
				}
			}
			if chunks < len(body) {
				time.Sleep(10 * time.Second)
			}
			pw.Close()
		}()
		req := f.signed(t, path, body, pr)
		req.URL.Host = ts.Listener.Addr().String()
		return http.DefaultClient.Do(req)
	}
}

func TestBodyIdleTimeout(t *testing.T) {
	f := newFixture(t)
	f.srv.config().Endpoint["backup"].Limits.Body.Idle = config.Duration(300 * time.Millisecond)
	ts := httptest.NewServer(f.handler())
	defer ts.Close()

	body := bytes.Repeat([]byte("x"), 10)
	send := trickler(t, f, ts, "/backup", body)

	// steady trickle, longer in total than the idle timeout
	resp, err := send(10, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("slow but steady: %d %s", resp.StatusCode, b)
	}

	// stall after part of the body; other content, not deduplicated
	send = trickler(t, f, ts, "/backup", bytes.Repeat([]byte("y"), 10))
	start := time.Now()
	resp, err = send(3, 5*time.Second)
	if err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestTimeout || !strings.Contains(string(b), "no body data for 300ms") {
			t.Fatalf("stalled: %d %s", resp.StatusCode, b)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("stalled upload lasted %s", d)
	}
}

func TestBodyTotalTimeout(t *testing.T) {
	f := newFixture(t)
	f.srv.config().Endpoint["backup"].Limits.Body.Timeout = config.Duration(400 * time.Millisecond)
	ts := httptest.NewServer(f.handler())
	defer ts.Close()

	body := bytes.Repeat([]byte("x"), 10)
	send := trickler(t, f, ts, "/backup", body)

	// steady, well inside the idle timeout, but slower in total than the limit
	start := time.Now()
	resp, err := send(10, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout || !strings.Contains(string(b), "body not received within 400ms") {
		t.Fatalf("too slow: %d %s", resp.StatusCode, b)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("slow upload lasted %s", d)
	}

	// fast enough
	resp, err = send(10, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("within total: %d %s", resp.StatusCode, b)
	}
}

func TestBodyIdlePerEndpoint(t *testing.T) {
	f := newFixture(t)
	f.srv.config().Endpoint["backup"].Limits.Body.Idle = config.Duration(150 * time.Millisecond)
	f.srv.config().Endpoint["drop"].Limits.Body.Idle = config.Duration(2 * time.Second)
	ts := httptest.NewServer(f.handler())
	defer ts.Close()

	body := bytes.Repeat([]byte("x"), 5)
	for path, want := range map[string]int{"/backup": http.StatusRequestTimeout, "/drop": http.StatusCreated} {
		resp, err := trickler(t, f, ts, path, body)(5, 400*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s: %d %s, want %d", path, resp.StatusCode, b, want)
		}
	}
}

func TestHeaderTimeout(t *testing.T) {
	f := newFixture(t)
	ts := httptest.NewUnstartedServer(f.handler())
	ts.Config.ReadHeaderTimeout = 300 * time.Millisecond
	ts.Start()
	defer ts.Close()
	c := dial(t, ts.Listener.Addr().String())
	fmt.Fprint(c, "PUT /back")
	start := time.Now()
	if !closed(c, 3*time.Second) {
		t.Fatal("stalled header was not disconnected")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("disconnected after %s", d)
	}
}

func (f *fixture) signed(t *testing.T, path string, body []byte, rd io.Reader) *http.Request {
	t.Helper()
	meta := fileMeta(body, "prod")
	if err := meta.Normalize(); err != nil {
		t.Fatal(err)
	}
	metaS, err := wire.EncodeMeta(meta)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := wire.NewNonce()
	sig, err := sshsig.Sign(f.user, wire.Namespace, wire.CanonicalText("lukd.test", path, ts, nonce, metaS))
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{
		Method: http.MethodPut,
		URL:    &url.URL{Scheme: "http", Host: "127.0.0.1", Path: path},
		Host:   "lukd.test",
		Body:   io.NopCloser(rd),
		Header: http.Header{
			wire.HeaderMeta:      {metaS},
			wire.HeaderTimestamp: {ts},
			wire.HeaderNonce:     {nonce},
			wire.HeaderSignature: {base64.StdEncoding.EncodeToString(sig.Marshal())},
		},
	}
}
