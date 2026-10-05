package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"luk/internal/channel"
	"luk/internal/channel/chantest"
	"luk/internal/wire"
)

// shortWaits makes the waits for the answer to an OP and to a COMPLETE
// short.
func shortWaits(t *testing.T) {
	oldOp, oldComplete := opWait, completeWait
	opWait, completeWait = 200*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { opWait, completeWait = oldOp, oldComplete })
}

// never is released when the test ends: a handler waiting on it answers
// nothing until then. Call it after the server started, so it is released
// before the server closes.
func never(t *testing.T) <-chan struct{} {
	ch := make(chan struct{})
	t.Cleanup(func() { close(ch) })
	return ch
}

func wantNoAnswer(t *testing.T, what string, err error, wait time.Duration) {
	t.Helper()
	var te *TransferError
	if !errors.As(err, &te) || te.Reason != NoAnswer || te.Wait != wait {
		t.Fatalf("%s: %v", what, err)
	}
}

// The answer to an OP that never comes ends the operation after opWait,
// whatever the operation.
func TestOpNoAnswer(t *testing.T) {
	shortWaits(t)
	srv := chantest.New(t)
	release := never(t)
	srv.Op = func(channel.Request, []byte) *chantest.Answer {
		<-release
		return nil
	}
	o := fakeOpts(t, srv, patterned(3<<16))
	_, err := Upload(context.Background(), o)
	wantNoAnswer(t, "upload", err, opWait)
	lo := Options{URL: srv.URL + "/drop", Pins: o.Pins, Signer: o.Signer}
	_, err = Link(context.Background(), LinkOptions{Options: lo, Link: "https://h/d/a", Action: wire.LinkRemove})
	wantNoAnswer(t, "link remove", err, opWait)
	_, err = LinkList(context.Background(), lo)
	wantNoAnswer(t, "link list", err, opWait)
	u, _ := url.Parse(srv.URL)
	_, err = ListEndpoints(context.Background(), u, o.Pins, o.Signer)
	wantNoAnswer(t, "endpoint listing", err, opWait)
}

// A COMPLETE without an answer within completeWait goes again as a new
// attempt, which gets the answer.
func TestCompleteNoAnswerRetried(t *testing.T) {
	shortWaits(t)
	var release <-chan struct{}
	var completes atomic.Int32
	srv := fakeParts(t, func(_ channel.Nonce, content []byte) chantest.Answer {
		if completes.Add(1) == 1 {
			<-release
		}
		return receipt(content)
	})
	// Released before the server closes: cleanups run last first.
	release = never(t)
	if _, err := Upload(context.Background(), fakeOpts(t, srv, patterned(3<<16))); err != nil {
		t.Fatal(err)
	}
	if n := srv.Count(channel.KindComplete); n != 2 {
		t.Fatalf("%d completes", n)
	}
}

// A COMPLETE that is never answered fails the upload after its attempts,
// as a transfer error.
func TestCompleteNoAnswer(t *testing.T) {
	shortWaits(t)
	var release <-chan struct{}
	srv := fakeParts(t, func(_ channel.Nonce, content []byte) chantest.Answer {
		<-release
		return receipt(content)
	})
	release = never(t)
	_, err := Upload(context.Background(), fakeOpts(t, srv, patterned(3<<16)))
	wantNoAnswer(t, "complete", err, completeWait)
	if n := srv.Count(channel.KindComplete); n != partAttempts {
		t.Fatalf("%d completes", n)
	}
}

// A part refused in the clear with 413 (a proxy body limit) is not sent
// again: the error names the proxy.
func TestPartProxyTooLarge(t *testing.T) {
	srv := fakeParts(t, func(_ channel.Nonce, content []byte) chantest.Answer { return receipt(content) })
	srv.Part = func(w http.ResponseWriter, r *http.Request, n channel.Nonce) bool {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		io.WriteString(w, "<html>413 Request Entity Too Large</html>")
		return false
	}
	_, err := Upload(context.Background(), fakeOpts(t, srv, patterned(3<<16)))
	if err == nil || !strings.Contains(err.Error(), "proxy") || !strings.Contains(err.Error(), "64.0 KiB") {
		t.Fatalf("%v", err)
	}
	if srv.Count(channel.KindPart) != 1 || srv.Count(channel.KindAbort) != 1 {
		t.Fatalf("%d parts, %d aborts", srv.Count(channel.KindPart), srv.Count(channel.KindAbort))
	}
}

// A 404 unknown session to the OP (a session evicted before its OP) is
// dialed once more with a new handshake and signature, not more.
func TestOpRedial(t *testing.T) {
	for _, lost := range []int32{1, 2} {
		srv := fakeParts(t, func(_ channel.Nonce, content []byte) chantest.Answer { return receipt(content) })
		var ops atomic.Int32
		srv.Message = func(w http.ResponseWriter, r *http.Request, n channel.Nonce) bool {
			if n.Kind == channel.KindOp && ops.Add(1) <= lost {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, `{"error":"unknown session"}`)
				return false
			}
			return true
		}
		_, err := Upload(context.Background(), fakeOpts(t, srv, patterned(3<<16)))
		var te *TransportError
		switch {
		case lost == 1 && err != nil:
			t.Fatalf("one lost OP: %v", err)
		case lost == 2 && (!errors.As(err, &te) || te.Status != http.StatusNotFound):
			t.Fatalf("two lost OPs: %v", err)
		case srv.Count(channel.KindOp) != 2:
			t.Fatalf("lost %d: %d OPs", lost, srv.Count(channel.KindOp))
		}
	}
}

// A 409 older attempt to a part is no failure: the part goes again as a
// newer attempt, however often.
func TestPartOlderAttemptIgnored(t *testing.T) {
	srv := fakeParts(t, func(_ channel.Nonce, content []byte) chantest.Answer { return receipt(content) })
	srv.PartAnswer = func(n channel.Nonce, _ []byte) *chantest.Answer {
		if n.Number == 1 && n.Attempt <= partAttempts {
			return &chantest.Answer{Status: http.StatusConflict, Body: wire.ErrorResponse{Error: "older attempt"}}
		}
		return nil
	}
	if _, err := Upload(context.Background(), fakeOpts(t, srv, patterned(3<<16))); err != nil {
		t.Fatal(err)
	}
}

// --bwlimit below the rate lukd asks of a part fails before any part.
func TestBWLimitBelowRate(t *testing.T) {
	srv := fakeParts(t, func(_ channel.Nonce, content []byte) chantest.Answer { return receipt(content) })
	srv.Rate = 64 << 10
	o := fakeOpts(t, srv, patterned(3<<16))
	o.BWLimit = 32 << 10
	_, err := Upload(context.Background(), o)
	if err == nil || err.Error() != "--bwlimit 32.0 KiB/s is below the minimum rate of this endpoint (64.0 KiB/s)" {
		t.Fatalf("%v", err)
	}
	if srv.Count(channel.KindPart) != 0 || srv.Count(channel.KindAbort) != 1 {
		t.Fatalf("%d parts, %d aborts", srv.Count(channel.KindPart), srv.Count(channel.KindAbort))
	}
}

// The workers of an upload are as many as --parallel and the offer allow,
// and so few that each gets the rate lukd asks of a part under --bwlimit.
func TestPartsWorkers(t *testing.T) {
	for _, c := range []struct {
		parallel, offer int
		bwlimit, rate   int64
		want            int
	}{
		{0, 4, 0, 64 << 10, 1},
		{8, 4, 0, 64 << 10, 4},
		{4, 4, 128 << 10, 64 << 10, 2},
		{4, 4, 100 << 10, 64 << 10, 1},
		{4, 4, 1 << 20, 64 << 10, 4},
		{4, 4, 64 << 10, 0, 4},
	} {
		if got := partsWorkers(c.parallel, c.offer, c.bwlimit, c.rate); got != c.want {
			t.Errorf("%+v: %d", c, got)
		}
	}
}

// A handshake answer that does not finish, as when a proxy on the way
// rewrites the path, hints at the proxy.
func TestDialHandshakeHint(t *testing.T) {
	srv := chantest.New(t)
	target, _ := url.Parse(srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	direct := rp.Director
	rp.Director = func(r *http.Request) {
		direct(r)
		r.URL.Path = "/elsewhere"
	}
	proxy := httptest.NewServer(rp)
	t.Cleanup(proxy.Close)
	_, err := Dial(context.Background(), DialOptions{URL: mustURL(t, proxy.URL+"/backup"), Pins: mustPins(t, srv.Pin())})
	if err == nil || !strings.HasPrefix(err.Error(), "the handshake failed: was the Host or path changed on the way (a proxy)?") {
		t.Fatalf("%v", err)
	}
}
