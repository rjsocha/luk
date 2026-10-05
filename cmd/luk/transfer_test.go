package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"luk/internal/channel"
	"luk/internal/channel/chantest"
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

// partServer writes 1 MiB of an 8 MiB download, then calls then.
func partServer(t *testing.T, tls bool, then func(r *http.Request)) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "8388608")
		w.Write(make([]byte, 1<<20))
		w.(http.Flusher).Flush()
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

// waitDone blocks the handler until the client gives up the download.
func waitDone(r *http.Request) { <-r.Context().Done() }

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

// Ctrl-C while a part goes ends the upload with the bytes lukd verified.
func TestSendInterrupted(t *testing.T) {
	tempConfig(t)
	cancel := fakeInterrupt(t)
	srv := chantest.New(t)
	srv.Op = func(channel.Request, []byte) *chantest.Answer { return nil }
	srv.Part = func(w http.ResponseWriter, r *http.Request, n channel.Nonce) bool {
		if n.Number == 0 {
			return true
		}
		cancel()
		<-r.Context().Done()
		return false
	}
	code, errs := sendBig(t, srv.URL+"#"+srv.Pin())
	checkMessage(t, code, errs, 130, `luk: interrupted after `+someBytes+` of 8\.0 MiB`)
	if srv.Count(channel.KindAbort) != 1 {
		t.Fatalf("%d aborts", srv.Count(channel.KindAbort))
	}
}

func TestSendUnreachable(t *testing.T) {
	tempConfig(t)
	addr := freeAddr(t)
	code, errs := sendBig(t, "http://"+addr+"#"+goodPin)
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
