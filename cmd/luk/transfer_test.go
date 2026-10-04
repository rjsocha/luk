package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"luk/internal/tlsself"
)

const bodySize = 8 << 20

// fakeInterrupt replaces Ctrl-C by the returned cancel.
func fakeInterrupt(t *testing.T) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	old := interruptContext
	interruptContext = func() (context.Context, context.CancelFunc) { return ctx, func() {} }
	t.Cleanup(func() { interruptContext = old; cancel() })
	return cancel
}

// partServer reads 1 MiB of an upload, or writes 1 MiB of an 8 MiB
// download, then calls then.
func partServer(t *testing.T, tls bool, then func(r *http.Request)) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			io.ReadFull(r.Body, make([]byte, 1<<20))
		} else {
			w.Header().Set("Content-Length", "8388608")
			w.Write(make([]byte, 1<<20))
			w.(http.Flusher).Flush()
		}
		then(r)
	})
	var ts *httptest.Server
	if tls {
		ts = httptest.NewTLSServer(h)
	} else {
		ts = httptest.NewServer(h)
	}
	t.Cleanup(ts.Close)
	return ts
}

// waitDone blocks the handler until the client gives up: an upload ends
// its body, a download its request.
func waitDone(r *http.Request) {
	if r.Method == http.MethodPut {
		io.Copy(io.Discard, r.Body)
		return
	}
	<-r.Context().Done()
}

// abort breaks the connection (HTTP/1) or the stream (HTTP/2).
func abort(*http.Request) { panic(http.ErrAbortHandler) }

func sendBig(t *testing.T, url string) (int, string) {
	t.Helper()
	key, _ := newKeyFile(t)
	code, _, errs := runLuk(t, "send", "-e", url, "-k", key, "--file", namedFile(t, "big", strings.Repeat("x", bodySize)))
	return code, errs
}

func getBig(t *testing.T, ts *httptest.Server, flags ...string) (int, string) {
	t.Helper()
	key, _ := newKeyFile(t)
	u := ts.URL + "/x#" + tlsself.Pin(ts.Certificate())
	code, _, errs := runLuk(t, append([]string{"get", u, "-k", key}, flags...)...)
	return code, errs
}

func checkMessage(t *testing.T, code int, errs string, wantCode int, want string) {
	t.Helper()
	if code != wantCode || !regexp.MustCompile(`^`+want+`\n$`).MatchString(errs) || strings.Contains(errs, `Put "`) || strings.Contains(errs, `Get "`) {
		t.Fatalf("exit %d, stderr %q; want %d, %s", code, errs, wantCode, want)
	}
}

const someBytes = `[0-9.]+ (B|KiB|MiB)`

func TestSendInterrupted(t *testing.T) {
	tempConfig(t)
	cancel := fakeInterrupt(t)
	ts := partServer(t, false, func(r *http.Request) { cancel(); waitDone(r) })
	code, errs := sendBig(t, ts.URL)
	checkMessage(t, code, errs, 130, `luk: interrupted after `+someBytes+` of 8\.0 MiB`)
}

func TestSendConnectionClosed(t *testing.T) {
	tempConfig(t)
	ts := partServer(t, false, abort)
	code, errs := sendBig(t, ts.URL)
	checkMessage(t, code, errs, 3, `luk: connection closed after `+someBytes+` of 8\.0 MiB: .+`)
}

func TestSendUnreachable(t *testing.T) {
	tempConfig(t)
	addr := freeAddr(t)
	code, errs := sendBig(t, "http://"+addr)
	checkMessage(t, code, errs, 3, `luk: cannot reach `+regexp.QuoteMeta(addr)+`: connection refused`)
}

func TestGetInterrupted(t *testing.T) {
	tempConfig(t)
	cancel := fakeInterrupt(t)
	ts := partServer(t, true, func(r *http.Request) {
		// Lets the client read the first part.
		time.Sleep(200 * time.Millisecond)
		cancel()
		waitDone(r)
	})
	code, errs := getBig(t, ts, "-o", t.TempDir()+"/out")
	checkMessage(t, code, errs, 130, `luk: interrupted after `+someBytes+` of 8\.0 MiB`)
}

func TestGetConnectionClosed(t *testing.T) {
	tempConfig(t)
	ts := partServer(t, true, abort)
	code, errs := getBig(t, ts, "-o", t.TempDir()+"/out")
	checkMessage(t, code, errs, 3, `luk: connection closed after `+someBytes+` of 8\.0 MiB: .+`)
}

func TestGetUnreachable(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	addr := freeAddr(t)
	code, _, errs := runLuk(t, "get", "luk://"+addr+"/x", "-k", key, "-o", t.TempDir()+"/out")
	checkMessage(t, code, errs, 3, `luk: cannot reach `+regexp.QuoteMeta(addr)+`: connection refused`)
}

func TestGetPinMismatch(t *testing.T) {
	tempConfig(t)
	key, _ := newKeyFile(t)
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	u := ts.URL + "/x#sha256//" + strings.Repeat("A", 43) + "="
	code, _, errs := runLuk(t, "get", u, "-k", key, "-o", t.TempDir()+"/out")
	checkMessage(t, code, errs, 3, `luk: cannot reach 127\.0\.0\.1:[0-9]+: server certificate pin mismatch .+`)
}

func TestGetInplaceInterrupted(t *testing.T) {
	tempConfig(t)
	cancel := fakeInterrupt(t)
	ts := partServer(t, true, func(r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		cancel()
		waitDone(r)
	})
	o := filepath.Join(t.TempDir(), "out")
	code, errs := getBig(t, ts, "-o", o, "--inplace")
	checkMessage(t, code, errs, 130, `luk: interrupted after `+someBytes+` of 8\.0 MiB; `+regexp.QuoteMeta(o)+` is partial`)
	if fi, err := os.Stat(o); err != nil || fi.Size() == 0 || fi.Size() >= bodySize {
		t.Fatalf("partial file %v %v", fi, err)
	}
}

func TestGetInplaceConnectionClosed(t *testing.T) {
	tempConfig(t)
	ts := partServer(t, true, abort)
	o := filepath.Join(t.TempDir(), "out")
	code, errs := getBig(t, ts, "-o", o, "--inplace")
	checkMessage(t, code, errs, 3, `luk: connection closed after `+someBytes+` of 8\.0 MiB: .+; `+regexp.QuoteMeta(o)+` is partial`)
	if fi, err := os.Stat(o); err != nil || fi.Size() == 0 {
		t.Fatalf("partial file %v %v", fi, err)
	}
}
