package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/sshsig"
	"luk/internal/wire"
)

// chanCounts counts the channel requests a test server got, by type.
type chanCounts struct{ handshakes, transports atomic.Int32 }

// chanTestServer is the lukd of the client tests with an identity key,
// over TLS or plain HTTP.
func chanTestServer(t *testing.T, user ssh.PublicKey, tlsOn bool) (*httptest.Server, channel.Key, *chanCounts) {
	t.Helper()
	k, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := newLukd(t, user)
	srv.SetIdentity(k)
	h := srv.Handler("127.0.0.1:0")
	n := &chanCounts{}
	count := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") == channel.ContentType {
			b, _ := io.ReadAll(r.Body)
			switch {
			case len(b) > 0 && b[0] == 0x01:
				n.handshakes.Add(1)
			case len(b) > 0 && b[0] == 0x02:
				n.transports.Add(1)
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		h.ServeHTTP(w, r)
	})
	var ts *httptest.Server
	if tlsOn {
		ts = httptest.NewTLSServer(count)
	} else {
		ts = httptest.NewServer(count)
	}
	t.Cleanup(ts.Close)
	return ts, k, n
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustPins(t *testing.T, s string) []channel.Pin {
	t.Helper()
	ps, err := channel.ParsePins(s)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

// signed sets the signature headers of text signed under ns on h.
func signed(t *testing.T, s ssh.Signer, h http.Header, ns string, text func(ts, nonce string) []byte) http.Header {
	t.Helper()
	if h == nil {
		h = http.Header{}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := wire.NewNonce()
	sig, err := sshsig.Sign(s, ns, text(ts, nonce))
	if err != nil {
		t.Fatal(err)
	}
	h.Set(wire.HeaderTimestamp, ts)
	h.Set(wire.HeaderNonce, nonce)
	h.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
	return h
}

// listOp is the signed endpoint listing OP of c on u.
func listOp(t *testing.T, s ssh.Signer, c *Channel, u *url.URL) channel.Request {
	t.Helper()
	return channel.Request{Method: http.MethodGet, Target: wire.EndpointsPath, Header: signed(t, s, nil, wire.ListNamespace,
		func(ts, nonce string) []byte {
			return wire.ListCanonicalText(http.MethodGet, strings.ToLower(u.Host), wire.EndpointsPath, ts, nonce, c.H())
		})}
}

func dialPins(t *testing.T, tlsOn bool) {
	s := newSigner(t)
	ts, k, n := chanTestServer(t, s.PublicKey(), tlsOn)
	u := mustURL(t, ts.URL+wire.EndpointsPath)
	ctx := context.Background()
	words := channel.Words(k.Public)
	other, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, pins := range []string{words, channel.KeyString(k.Public), channel.Words(other.Public) + "," + words} {
		c, err := Dial(ctx, DialOptions{URL: u, Pins: mustPins(t, pins)})
		if err != nil {
			t.Fatalf("%s: %v", pins, err)
		}
		if !bytes.Equal(c.PeerKey(), k.Public) {
			t.Fatalf("%s: peer key", pins)
		}
		r, err := c.Do(ctx, listOp(t, s, c, u), nil)
		if err != nil {
			t.Fatalf("%s: %v", pins, err)
		}
		var list wire.EndpointList
		if r.Status != http.StatusOK || json.Unmarshal(r.Body, &list) != nil || len(list.Endpoints) != 2 {
			t.Fatalf("%s: %d %s", pins, r.Status, r.Body)
		}
	}

	hs, tr := n.handshakes.Load(), n.transports.Load()
	_, err = Dial(ctx, DialOptions{URL: u, Pins: mustPins(t, channel.Words(other.Public))})
	var pm *PinMismatchError
	if !errors.As(err, &pm) || !bytes.Equal(pm.Got, k.Public) || !strings.Contains(err.Error(), words) {
		t.Fatalf("wrong pin: %v", err)
	}
	if n.handshakes.Load() != hs+1 || n.transports.Load() != tr {
		t.Fatalf("wrong pin: %d handshakes, %d transport requests after it", n.handshakes.Load()-hs, n.transports.Load()-tr)
	}

	if _, err := Dial(ctx, DialOptions{URL: u}); !errors.Is(err, ErrNoPin) {
		t.Fatalf("no pin: %v", err)
	}
	if n.handshakes.Load() != hs+1 {
		t.Fatal("no pin: a handshake was sent")
	}
	if _, err := PinsFor(&Config{}, u, "sha256//x"); !errors.Is(err, channel.ErrTLSPin) {
		t.Fatalf("sha256 pin: %v", err)
	}

	c, err := Dial(ctx, DialOptions{URL: u, Discover: true})
	if err != nil || !bytes.Equal(c.PeerKey(), k.Public) {
		t.Fatalf("discover: %v", err)
	}
}

func TestDialPins(t *testing.T) { dialPins(t, true) }

func TestDialPlainHTTP(t *testing.T) { dialPins(t, false) }

// hookNet replaces the resolver and the dialer of Dial for one test.
func hookNet(t *testing.T, lookup func(ctx context.Context, network, host string) ([]netip.Addr, error), dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	t.Helper()
	ol, od := lookupNetIP, dialContext
	lookupNetIP, dialContext = lookup, dial
	t.Cleanup(func() { lookupNetIP, dialContext = ol, od })
}

func TestDialOneAddress(t *testing.T) {
	s := newSigner(t)
	ts, k, _ := chanTestServer(t, s.PublicKey(), true)
	port := mustURL(t, ts.URL).Port()
	var mu sync.Mutex
	var lookups []string
	var dials []string
	var d net.Dialer
	hookNet(t, func(_ context.Context, _, host string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		lookups = append(lookups, host)
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}, nil
	}, func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, addr)
		mu.Unlock()
		return d.DialContext(ctx, network, addr)
	})
	ctx := context.Background()
	c, err := Dial(ctx, DialOptions{URL: mustURL(t, "https://LUKD.test:"+port+"/drop"), Pins: mustPins(t, channel.Words(k.Public))})
	if err != nil {
		t.Fatal(err)
	}
	// Each refused PART closes its connection, so every request dials.
	for i := range 3 {
		var te *TransportError
		if _, err := c.Send(ctx, channel.Nonce{Kind: channel.KindPart, Number: uint32(i)}, strings.NewReader("x")); !errors.As(err, &te) {
			t.Fatalf("%v", err)
		}
	}
	mu.Lock()
	if len(lookups) != 1 || lookups[0] != "lukd.test" {
		t.Fatalf("lookups %v", lookups)
	}
	if len(dials) < 2 {
		t.Fatalf("dials %v", dials)
	}
	for _, a := range dials {
		if a != "127.0.0.1:"+port {
			t.Fatalf("dials %v", dials)
		}
	}
	mu.Unlock()
	if _, err := Dial(ctx, DialOptions{URL: mustURL(t, ts.URL+"/drop"), Pins: mustPins(t, channel.Words(k.Public))}); err != nil || len(lookups) != 1 {
		t.Fatalf("IP literal: %v, lookups %v", err, lookups)
	}
}

// TestChannelUploadParts runs an upload in one part: the OP through Do,
// the PART and the COMPLETE through Send.
func TestChannelUploadParts(t *testing.T) {
	s := newSigner(t)
	ts, k, _ := chanTestServer(t, s.PublicKey(), false)
	u := mustURL(t, ts.URL+"/drop")
	ctx := context.Background()
	c, err := Dial(ctx, DialOptions{URL: u, Pins: mustPins(t, channel.Words(k.Public))})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello parts")
	size := int64(len(data))
	sum := sha256.Sum256(data)
	meta := wire.Meta{Portal: wire.PortalDirect, File: "a.txt", Source: wire.SourceFile, Size: &size, SHA256: hex.EncodeToString(sum[:])}
	if err := meta.Normalize(); err != nil {
		t.Fatal(err)
	}
	metaS, err := wire.EncodeMeta(meta)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set(wire.HeaderMeta, metaS)
	op := channel.Request{Method: http.MethodPut, Target: "/drop", Header: signed(t, s, h, wire.Namespace, func(ts, nonce string) []byte {
		return wire.CanonicalText(strings.ToLower(u.Host), "/drop", ts, nonce, metaS, c.H())
	})}
	r, err := c.Do(ctx, op, nil)
	if err != nil || r.Status != http.StatusOK {
		t.Fatalf("create: %v %+v", err, r)
	}
	if _, err := c.Do(ctx, op, nil); err == nil {
		t.Fatal("second OP sent")
	}
	part := channel.Nonce{Kind: channel.KindPart}
	if r, err = c.Send(ctx, part, bytes.NewReader(data)); err != nil || r.Status != http.StatusOK {
		t.Fatalf("part: %v %+v", err, r)
	}
	if _, err := c.Send(ctx, part, bytes.NewReader(data)); err == nil {
		t.Fatal("a nonce sent twice")
	}
	if _, err := c.Send(ctx, channel.Nonce{Kind: channel.KindOp}, nil); err == nil {
		t.Fatal("an OP through Send")
	}
	if _, err := c.Send(ctx, channel.Nonce{Kind: channel.KindPart, Number: 1, Attempt: 4096}, nil); err == nil {
		t.Fatal("an attempt over 12 bits")
	}
	r, err = c.Send(ctx, channel.Nonce{Kind: channel.KindComplete}, nil)
	if err != nil || r.Status != http.StatusCreated {
		t.Fatalf("complete: %v %+v", err, r)
	}
	var out wire.Created
	if err := json.Unmarshal(r.Body, &out); err != nil || out.Size != size || out.SHA256 != meta.SHA256 {
		t.Fatalf("%v %s", err, r.Body)
	}
}

func TestChannelTransportError(t *testing.T) {
	s := newSigner(t)
	ts, k, _ := chanTestServer(t, s.PublicKey(), false)
	ctx := context.Background()
	c, err := Dial(ctx, DialOptions{URL: mustURL(t, ts.URL+"/drop"), Pins: mustPins(t, channel.Words(k.Public))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Send(ctx, channel.Nonce{Kind: channel.KindPart, Number: 1}, strings.NewReader("x"))
	var te *TransportError
	if !errors.As(err, &te) || te.Status != http.StatusNotFound || te.Message == "" {
		t.Fatalf("%v", err)
	}
}

func TestDialNotLukd(t *testing.T) {
	for _, h := range []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) },
		func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", http.StatusNotFound) },
		func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) },
	} {
		ts := httptest.NewServer(h)
		t.Cleanup(ts.Close)
		_, err := Dial(context.Background(), DialOptions{URL: mustURL(t, ts.URL+"/drop"), Discover: true})
		var te *TransportError
		if !errors.As(err, &te) || !strings.Contains(err.Error(), "not answered by lukd") || !strings.Contains(err.Error(), "HTTP "+strconv.Itoa(te.Status)) {
			t.Fatalf("%v", err)
		}
	}
}

func TestPinsFor(t *testing.T) {
	k, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	words, key := channel.Words(k.Public), channel.KeyString(k.Public)
	cfg := &Config{Endpoint: map[string]EndpointConfig{
		"a": {URL: "https://H.example:8443/drop", Pins: []string{words}},
		"b": {URL: "http://h.example/drop"},
	}}
	for _, c := range []struct {
		url, fragment string
		want          int
	}{
		{"https://h.example:8443/other", "", 1},
		{"https://h.example:8443/other", key + "," + words, 2},
		{"https://h.example/drop", "", 0},
		{"http://h.example:8443/drop", "", 0},
		{"http://h.example/drop", "", 0},
	} {
		ps, err := PinsFor(cfg, mustURL(t, c.url), c.fragment)
		if err != nil || len(ps) != c.want {
			t.Fatalf("%+v: %d pins, %v", c, len(ps), err)
		}
		for _, p := range ps {
			if !p.Matches(k.Public) {
				t.Fatalf("%+v: a pin does not match", c)
			}
		}
	}
}
