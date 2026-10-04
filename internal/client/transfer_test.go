package client

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNoDecisionMessage(t *testing.T) {
	shortContinue(t)
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			release := make(chan struct{})
			ts, pin := newTestServer(t, proto.h2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			t.Cleanup(func() { close(release) })
			o := fileOpts(t, ts.URL+"/backup", newSigner(t), []byte("hello"))
			o.Pin = pin
			o.DecisionTimeout = time.Second
			_, err := uploadWithin(t, o, 5*time.Second)
			var te *TransferError
			if !errors.As(err, &te) || te.Reason != NoDecision || err.Error() != "the server gave no decision within 1s" {
				t.Fatalf("%v", err)
			}
		})
	}
}

func TestConnectionClosedMidBody(t *testing.T) {
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			ts, pin := newTestServer(t, proto.h2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.ReadFull(r.Body, make([]byte, 1<<20))
				panic(http.ErrAbortHandler)
			}))
			o := fileOpts(t, ts.URL+"/backup", newSigner(t), make([]byte, 8<<20))
			o.Pin = pin
			_, err := uploadWithin(t, o, 5*time.Second)
			var te *TransferError
			if !errors.As(err, &te) || te.Reason != Closed || te.Done == 0 ||
				!strings.HasPrefix(err.Error(), "connection closed after ") || !strings.Contains(err.Error(), " of 8.0 MiB: ") || strings.Contains(err.Error(), `Put "`) {
				t.Fatalf("%v", err)
			}
		})
	}
}

func TestTransferText(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{{60 * time.Second, "60s"}, {90 * time.Second, "90s"}, {1500 * time.Millisecond, "1.5s"}} {
		if got := seconds(c.d); got != c.want {
			t.Errorf("%s: %q", c.d, got)
		}
	}
	e := &TransferError{Reason: Interrupted, Done: 13002342, Total: -1}
	if e.Error() != "interrupted after 12.4 MiB" {
		t.Errorf("%q", e.Error())
	}
}
