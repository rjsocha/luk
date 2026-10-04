package expose

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/store"
)

// A client that requests a file larger than the socket buffers and stops
// reading is cut after limits.conn.idle without progress; the handler
// returns instead of holding the connection and the open file.
func TestStalledDownloadCut(t *testing.T) {
	e := newEnv(t, nil)
	e.cfg.Limits.Conn.Idle = config.Duration(300 * time.Millisecond)
	e.h = New(e.cfg, e.log(), func() time.Time { return e.now }, "l", nil)
	const size = 64 << 20
	e.put(t, "big", strings.Repeat("x", size), store.Sidecar{})
	done := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.h.ServeHTTP(w, r)
		done <- struct{}{}
	}))
	defer ts.Close()
	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET /d/big HTTP/1.1\r\nHost: x\r\n\r\n")
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the handler still writes to a client that reads nothing")
	}
	// What arrived is the header and less than the file.
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 || n >= size {
		t.Fatalf("%d, %d bytes", resp.StatusCode, n)
	}
}

// A slow client that keeps reading is never cut.
func TestSlowDownloadNotCut(t *testing.T) {
	e := newEnv(t, nil)
	e.cfg.Limits.Conn.Idle = config.Duration(time.Second)
	e.h = New(e.cfg, e.log(), func() time.Time { return e.now }, "l", nil)
	const size = 16 << 20
	e.put(t, "big", strings.Repeat("x", size), store.Sidecar{})
	ts := httptest.NewServer(e.h)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/d/big")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var n int64
	buf := make([]byte, 1<<20)
	start := time.Now()
	for {
		// Whole chunks: a short Read followed by the pause would read
		// slower than intended on a slow machine.
		k, err := io.ReadFull(resp.Body, buf)
		n += int64(k)
		if err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if n != size || time.Since(start) < time.Second {
		t.Fatalf("%d bytes in %s", n, time.Since(start))
	}
}

// The auth.basic checks run at most GOMAXPROCS at once; one waiting for a
// slot gives up with its request.
func TestBasicAuthBounded(t *testing.T) {
	for range cap(bcryptSlots) {
		bcryptSlots <- struct{}{}
	}
	defer func() {
		for range cap(bcryptSlots) {
			<-bcryptSlots
		}
	}()
	rt := &route{users: map[string][]byte{"dev": []byte("$2y$05$TpFzQdt1oY6UgSKCZGgt8eCbBXDAuiQxNl13XDuDnYKUSuIC9O79W")}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := httptest.NewRequestWithContext(ctx, "GET", "/d/x", nil)
	r.SetBasicAuth("dev", "dev")
	if rt.authorized(r) {
		t.Fatal("authorized without a slot")
	}
}
