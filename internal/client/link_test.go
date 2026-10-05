package client

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"luk/internal/channel"
	"luk/internal/channel/chantest"
	"luk/internal/wire"
)

// Remove, ttl and list are each one OP in a channel of their own, with
// the link headers and the luk-link@v2 signature.
func TestLinkThroughChannel(t *testing.T) {
	srv := chantest.New(t)
	var mu sync.Mutex
	var got []channel.Request
	srv.Op = func(req channel.Request, _ []byte) *chantest.Answer {
		mu.Lock()
		got = append(got, req)
		mu.Unlock()
		if req.Header.Get(wire.HeaderLinkAction) == wire.LinkList {
			return &chantest.Answer{Status: http.StatusOK, Body: wire.LinkListAnswer{Links: []wire.LinkEntry{{URL: "https://h/d/a"}}}}
		}
		return &chantest.Answer{Status: http.StatusOK, Body: wire.LinkAnswer{URL: req.Header.Get(wire.HeaderLink), Removed: true}}
	}
	o := Options{URL: srv.URL + "/drop", Pins: mustPins(t, srv.Pin()), Signer: newSigner(t)}
	ls, err := LinkList(context.Background(), o)
	if err != nil || len(ls.Links) != 1 || ls.Links[0].URL != "https://h/d/a" {
		t.Fatalf("list: %+v %v", ls, err)
	}
	a, err := Link(context.Background(), LinkOptions{Options: o, Link: "https://h/d/a", Action: wire.LinkTTL, TTL: "1d"})
	if err != nil || a.URL != "https://h/d/a" {
		t.Fatalf("ttl: %+v %v", a, err)
	}
	if _, err := Link(context.Background(), LinkOptions{Options: o, Link: "https://h/d/a", Action: wire.LinkRemove}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if n := srv.Count(channel.KindOp); n != 3 {
		t.Fatalf("%d OPs", n)
	}
	for i, want := range []struct{ method, link, action string }{
		{http.MethodGet, "", wire.LinkList}, {http.MethodPatch, "https://h/d/a", wire.LinkTTL}, {http.MethodDelete, "https://h/d/a", wire.LinkRemove},
	} {
		r := got[i]
		if r.Method != want.method || r.Target != "/drop" || r.Header.Get(wire.HeaderLink) != want.link || r.Header.Get(wire.HeaderLinkAction) != want.action ||
			r.Header.Get(wire.HeaderMeta) == "" || r.Header.Get(wire.HeaderSignature) == "" {
			t.Errorf("%d: %+v", i, r)
		}
	}

	// A refusal inside the channel is a RejectedError; a key of another
	// lukd is refused at the handshake.
	srv.Op = func(channel.Request, []byte) *chantest.Answer {
		return &chantest.Answer{Status: http.StatusNotFound, Body: wire.ErrorResponse{Error: "link not found"}}
	}
	_, err = Link(context.Background(), LinkOptions{Options: o, Link: "https://h/d/a", Action: wire.LinkRemove})
	var re *RejectedError
	if !errors.As(err, &re) || re.Status != http.StatusNotFound || re.Message != "link not found" {
		t.Fatalf("refused: %v", err)
	}
	other, _ := channel.GenerateKey()
	o.Pins = mustPins(t, channel.Words(other.Public))
	_, err = LinkList(context.Background(), o)
	var pm *PinMismatchError
	if !errors.As(err, &pm) {
		t.Fatalf("wrong pin: %v", err)
	}
	if _, err := Link(context.Background(), LinkOptions{Options: o, Link: "https://h/d/a", Action: wire.LinkRemove}); !errors.As(err, &pm) {
		t.Fatalf("wrong pin: %v", err)
	}
	o.Pins = nil
	if _, err := LinkList(context.Background(), o); !errors.Is(err, ErrNoPin) {
		t.Fatalf("no pin: %v", err)
	}
}

// A scan reports the key of lukd without a pin; the endpoint listing goes
// through the channel with that key as the pin.
func TestScanAndListEndpoints(t *testing.T) {
	for _, tlsOn := range []bool{false, true} {
		s := newSigner(t)
		ts, k, n := chanTestServer(t, s.PublicKey(), tlsOn)
		u := mustURL(t, ts.URL+"/drop")
		key, err := Scan(context.Background(), u)
		if err != nil || !bytes.Equal(key, k.Public) {
			t.Fatalf("tls %v: scan %v", tlsOn, err)
		}
		pins := mustPins(t, channel.KeyString(key))
		l, err := ListEndpoints(context.Background(), u, pins, s)
		if err != nil || len(l.Endpoints) != 2 {
			t.Fatalf("tls %v: list %+v %v", tlsOn, l, err)
		}
		if h, tr := n.handshakes.Load(), n.transports.Load(); h != 2 || tr != 1 {
			t.Fatalf("tls %v: %d handshakes, %d messages", tlsOn, h, tr)
		}
		_, err = ListEndpoints(context.Background(), u, pins, newSigner(t))
		var re *RejectedError
		if !errors.As(err, &re) || re.Status != http.StatusUnauthorized {
			t.Fatalf("tls %v: stranger %v", tlsOn, err)
		}
		other, _ := channel.GenerateKey()
		_, err = ListEndpoints(context.Background(), u, mustPins(t, channel.Words(other.Public)), s)
		var pm *PinMismatchError
		if !errors.As(err, &pm) {
			t.Fatalf("tls %v: wrong pin %v", tlsOn, err)
		}
	}
}
