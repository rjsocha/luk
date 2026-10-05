package client

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"luk/internal/channel"
)

func TestNoDecisionMessage(t *testing.T) {
	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			release := make(chan struct{})
			ts := newTestServer(t, proto.h2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-release:
				case <-r.Context().Done():
				}
			}))
			t.Cleanup(func() { close(release) })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := LinkList(ctx, Options{URL: ts.URL + "/backup", Signer: newSigner(t), DecisionTimeout: time.Second})
			var te *TransferError
			if !errors.As(err, &te) || te.Reason != NoDecision || err.Error() != "the server gave no decision within 1s" {
				t.Fatalf("%v", err)
			}
		})
	}
}

// A part whose connection breaks every time ends the upload with the
// bytes lukd verified.
func TestConnectionClosedMidBody(t *testing.T) {
	e := newPartsEnv(t)
	e.setHook(func(w http.ResponseWriter, r *http.Request, _ [16]byte, n channel.Nonce) bool {
		if n.Kind == channel.KindPart && n.Number == 1 {
			panic(http.ErrAbortHandler)
		}
		return true
	})
	_, err := Upload(context.Background(), e.file("/backup", make([]byte, 8<<20)))
	var te *TransferError
	if !errors.As(err, &te) || te.Reason != Closed || te.Done != testPartSize ||
		!strings.HasPrefix(err.Error(), "connection closed after 128.0 KiB of 8.0 MiB: ") || strings.Contains(err.Error(), `Post "`) {
		t.Fatalf("%v", err)
	}
	if left := e.staged(t); len(left) != 0 {
		t.Fatalf("staging left: %v", left)
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
