package channel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

// testPair is a client and a server session that share keys, without a
// handshake.
func testPair(t *testing.T) (c, s *Session) {
	t.Helper()
	var a, b [32]byte
	rand.Read(a[:])
	rand.Read(b[:])
	h := make([]byte, 32)
	rand.Read(h)
	return newSession(a, b, h), newSession(b, a, h)
}

func sealRequest(t *testing.T, c *Session, n Nonce, body []byte) []byte {
	t.Helper()
	var wire bytes.Buffer
	if err := c.SealRequest(&wire, n, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

func openRequest(t *testing.T, s *Session, wire []byte, n *Nonce) ([]byte, error) {
	t.Helper()
	r := bytes.NewReader(wire)
	_, got, hdr, err := ParseRequestHeader(r)
	if err != nil {
		t.Fatal(err)
	}
	if n != nil {
		got = *n
	}
	return io.ReadAll(s.OpenRequest(r, hdr, got))
}

func TestFramesExactMultiple(t *testing.T) {
	c, s := testPair(t)
	for _, size := range []int{0, 1, FrameSize - 1, FrameSize, FrameSize + 1, 3 * FrameSize} {
		body := bytes.Repeat([]byte{7}, size)
		var wire bytes.Buffer
		n := Nonce{Kind: KindPart, Number: 3, Attempt: 1}
		if err := c.SealRequest(&wire, n, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		frames := size/FrameSize + 1
		if want := 25 + size + 16*frames; wire.Len() != want {
			t.Fatalf("%d: wire %d, want %d", size, wire.Len(), want)
		}
		id, got, hdr, err := ParseRequestHeader(&wire)
		if err != nil || id != c.ID() || got.Kind != KindPart || got.Number != 3 || got.Attempt != 1 {
			t.Fatalf("%d: header %v", size, err)
		}
		out, err := io.ReadAll(s.OpenRequest(&wire, hdr, got))
		if err != nil || !bytes.Equal(out, body) {
			t.Fatalf("%d: %v len %d", size, err, len(out))
		}
	}
}

func TestRequestHeader(t *testing.T) {
	c, _ := testPair(t)
	wire := sealRequest(t, c, Nonce{Kind: KindOp, Frame: 9, Last: true}, nil)
	if wire[0] != 0x02 || binary.BigEndian.Uint64(wire[17:25]) != (Nonce{Kind: KindOp}).Uint64() {
		t.Fatalf("header %x", wire[:25])
	}
	for _, bad := range [][]byte{
		{0x01},
		append([]byte{0x01}, wire[1:25]...),
		append(append([]byte{0x02}, wire[1:17]...), 0x50, 0, 0, 0, 0, 0, 0, 0),
		append(append([]byte{0x02}, wire[1:17]...), 0x10, 0, 0, 0, 0, 0, 0, 1),
	} {
		if _, _, _, err := ParseRequestHeader(bytes.NewReader(bad)); err == nil {
			t.Fatalf("%x accepted", bad)
		}
	}
}

func TestFrameTruncated(t *testing.T) {
	c, s := testPair(t)
	body := bytes.Repeat([]byte{1}, 2*FrameSize+10)
	wire := sealRequest(t, c, Nonce{Kind: KindPart, Number: 1}, body)
	// Drop the final frame: the stream ends after a frame with last=0.
	cut := wire[:25+2*(FrameSize+16)]
	out, err := openRequest(t, s, cut, nil)
	if err == nil || err == io.EOF {
		t.Fatalf("truncated stream: %v", err)
	}
	if len(out) != 2*FrameSize {
		t.Fatalf("read %d before the error", len(out))
	}
	// No frame at all.
	if _, err := openRequest(t, s, wire[:25], nil); err == nil {
		t.Fatal("empty stream accepted")
	}
	// The final frame cut short.
	if _, err := openRequest(t, s, wire[:len(wire)-1], nil); err == nil {
		t.Fatal("short final frame accepted")
	}
}

func TestFrameTampered(t *testing.T) {
	c, s := testPair(t)
	body := bytes.Repeat([]byte{2}, 3*FrameSize)
	wire := sealRequest(t, c, Nonce{Kind: KindPart, Number: 1}, body)
	wire[25+(FrameSize+16)+100] ^= 1
	out, err := openRequest(t, s, wire, nil)
	if err == nil {
		t.Fatal("tampered frame accepted")
	}
	if len(out) != FrameSize {
		t.Fatalf("read %d before the error, want frame 1 only", len(out))
	}
	// Swapped frames fail too: each frame has its own nonce.
	wire = sealRequest(t, c, Nonce{Kind: KindPart, Number: 1}, bytes.Repeat([]byte{3}, 2*FrameSize))
	f0 := bytes.Clone(wire[25 : 25+FrameSize+16])
	copy(wire[25:], wire[25+FrameSize+16:25+2*(FrameSize+16)])
	copy(wire[25+FrameSize+16:], f0)
	if _, err := openRequest(t, s, wire, nil); err == nil {
		t.Fatal("swapped frames accepted")
	}
}

func TestFrameWrongAttempt(t *testing.T) {
	c, s := testPair(t)
	wire := sealRequest(t, c, Nonce{Kind: KindPart, Number: 1, Attempt: 1}, []byte("data"))
	other := Nonce{Kind: KindPart, Number: 1, Attempt: 2}
	r := bytes.NewReader(wire)
	_, _, hdr, err := ParseRequestHeader(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenRequest(r, hdr, other).Read(make([]byte, 10)); err == nil {
		t.Fatal("wrong attempt opened")
	}
	// A header of another session does not open either.
	c2, _ := testPair(t)
	wire = sealRequest(t, c2, Nonce{Kind: KindOp}, []byte("data"))
	if _, err := openRequest(t, s, wire, nil); err == nil {
		t.Fatal("frame of another session opened")
	}
}

func sealResponse(t *testing.T, s *Session, req Nonce, body []byte, chunk int) []byte {
	t.Helper()
	var wire bytes.Buffer
	w, err := s.SealResponse(&wire, req)
	if err != nil {
		t.Fatal(err)
	}
	for len(body) > 0 {
		n := min(chunk, len(body))
		if _, err := w.Write(body[:n]); err != nil {
			t.Fatal(err)
		}
		body = body[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

func TestResponseRoundTrip(t *testing.T) {
	c, s := testPair(t)
	req := Nonce{Kind: KindOp}
	for _, size := range []int{0, 5, FrameSize, 2*FrameSize + 3} {
		for _, chunk := range []int{1000, FrameSize + 7} {
			body := make([]byte, size)
			rand.Read(body)
			wire := sealResponse(t, s, req, body, chunk)
			if want := 9 + size + 16*(size/FrameSize+1); len(wire) != want {
				t.Fatalf("%d/%d: wire %d, want %d", size, chunk, len(wire), want)
			}
			rc, err := c.OpenResponse(bytes.NewReader(wire), req)
			if err != nil {
				t.Fatal(err)
			}
			out, err := io.ReadAll(rc)
			if err != nil || !bytes.Equal(out, body) {
				t.Fatalf("%d/%d: %v len %d", size, chunk, err, len(out))
			}
			rc.Close()
		}
	}
}

func TestResponseBoundToRequest(t *testing.T) {
	c, s := testPair(t)
	a := Nonce{Kind: KindPart, Number: 1}
	b := Nonce{Kind: KindPart, Number: 2}
	wire := sealResponse(t, s, a, []byte("ok"), 100)
	rc, err := c.OpenResponse(bytes.NewReader(wire), b)
	if err == nil {
		_, err = io.ReadAll(rc)
	}
	if err == nil {
		t.Fatal("response for A opened as B")
	}
	// Truncated and tampered responses fail on Read.
	wire = sealResponse(t, s, a, bytes.Repeat([]byte{1}, FrameSize+1), 100)
	for _, bad := range [][]byte{wire[:9+FrameSize+16], wire[:len(wire)-1]} {
		rc, err := c.OpenResponse(bytes.NewReader(bad), a)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(rc); err == nil {
			t.Fatal("truncated response accepted")
		}
	}
	bad := bytes.Clone(wire)
	bad[20] ^= 1
	rc, _ = c.OpenResponse(bytes.NewReader(bad), a)
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("tampered response accepted")
	}
	// A different counter in the clear header does not open.
	bad = bytes.Clone(wire)
	bad[8] ^= 3
	if rc, err := c.OpenResponse(bytes.NewReader(bad), a); err == nil {
		if _, err := io.ReadAll(rc); err == nil {
			t.Fatal("response with another counter accepted")
		}
	}
}

func TestResponseCountersUnique(t *testing.T) {
	_, s := testPair(t)
	for want := uint64(1); want <= 2; want++ {
		wire := sealResponse(t, s, Nonce{Kind: KindOp}, nil, 1)
		if wire[0] != 0x02 || binary.BigEndian.Uint64(wire[1:9]) != want {
			t.Fatalf("counter %x, want %d", wire[:9], want)
		}
	}
	s.counter.Store(1<<32 - 1)
	if _, err := s.SealResponse(io.Discard, Nonce{Kind: KindOp}); err == nil {
		t.Fatal("counter wrapped")
	}
}
