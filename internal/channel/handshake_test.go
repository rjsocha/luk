package channel

import (
	"bytes"
	"io"
	"testing"

	"github.com/flynn/noise"
)

func TestHandshake(t *testing.T) {
	k, _ := GenerateKey()
	ch, req, err := NewClientHandshake("drop.example.com", "/drop")
	if err != nil || len(req) != 33 || req[0] != 0x01 {
		t.Fatalf("%v %d", err, len(req))
	}
	ss, resp, err := ServerHandshake(k, "drop.example.com", "/drop", req)
	if err != nil || len(resp) != 1+32+48+16 || resp[0] != 0x01 {
		t.Fatalf("%v %d", err, len(resp))
	}
	cs, peer, err := ch.Finish(resp)
	if err != nil || !bytes.Equal(peer, k.Public) || !bytes.Equal(cs.H(), ss.H()) || cs.ID() != ss.ID() {
		t.Fatalf("finish: %v", err)
	}
	// Another path: the prologue differs, the client cannot finish.
	ch2, req2, _ := NewClientHandshake("drop.example.com", "/drop")
	_, resp2, err := ServerHandshake(k, "drop.example.com", "/other", req2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ch2.Finish(resp2); err == nil {
		t.Fatal("prologue mismatch finished")
	}
}

func TestHandshakeTransport(t *testing.T) {
	k, _ := GenerateKey()
	ch, req, _ := NewClientHandshake("drop.example.com:8443", "/drop")
	ss, resp, err := ServerHandshake(k, "drop.example.com:8443", "/drop", req)
	if err != nil {
		t.Fatal(err)
	}
	cs, _, err := ch.Finish(resp)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ch.Finish(resp); err == nil {
		t.Fatal("finished twice")
	}
	n := Nonce{Kind: KindOp}
	var wire bytes.Buffer
	if err := cs.SealRequest(&wire, n, bytes.NewReader([]byte("ping"))); err != nil {
		t.Fatal(err)
	}
	id, got, hdr, err := ParseRequestHeader(&wire)
	if err != nil || id != ss.ID() {
		t.Fatalf("header: %v", err)
	}
	if b, err := io.ReadAll(ss.OpenRequest(&wire, hdr, got)); err != nil || string(b) != "ping" {
		t.Fatalf("request %q %v", b, err)
	}
	wire.Reset()
	w, err := ss.SealResponse(&wire, got)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("pong"))
	w.Close()
	rc, err := cs.OpenResponse(&wire, n)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(rc); err != nil || string(b) != "pong" {
		t.Fatalf("response %q %v", b, err)
	}
}

func TestHandshakeRefused(t *testing.T) {
	k, _ := GenerateKey()
	_, req, _ := NewClientHandshake("h", "/p")
	for _, bad := range [][]byte{nil, req[:32], append(bytes.Clone(req), 0), append([]byte{0x02}, req[1:]...)} {
		if _, _, err := ServerHandshake(k, "h", "/p", bad); err == nil {
			t.Fatalf("%x accepted", bad)
		}
	}
	ch, req, _ := NewClientHandshake("h", "/p")
	_, resp, _ := ServerHandshake(k, "h", "/p", req)
	bad := bytes.Clone(resp)
	bad[0] = 0x02
	if _, _, err := ch.Finish(bad); err == nil {
		t.Fatal("response type 0x02 accepted")
	}
}

func TestPrologue(t *testing.T) {
	if got := string(Prologue("drop.example.com:8443", "/drop")); got != "luk-channel@1\ndrop.example.com:8443\n/drop" {
		t.Fatalf("%q", got)
	}
	if name := "Noise_" + noise.HandshakeNX.Name + "_" + string(suite.Name()); name != "Noise_NX_25519_ChaChaPoly_SHA256" {
		t.Fatalf("suite %s", name)
	}
}
