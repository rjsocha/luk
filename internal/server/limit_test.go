package server

import (
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"
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
