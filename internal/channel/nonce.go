package channel

import "fmt"

// Kind is the operation of a request, the top four bits of its nonce.
type Kind uint8

const (
	KindOp       Kind = 1
	KindPart     Kind = 2
	KindComplete Kind = 3
	KindAbort    Kind = 4
	// KindKeepalive keeps the session of an upload active while the
	// client waits on a slow source; 5 is reserved for a later FETCH.
	KindKeepalive Kind = 6
)

const (
	maxAttempt = 1<<12 - 1
	maxFrame   = 1<<15 - 1
)

// Nonce of a request frame. Every request frame has a nonce of its own, so
// the AEAD binds each frame to its operation, number, attempt and position:
// a frame replayed into another request, attempt or position fails to open.
type Nonce struct {
	Kind    Kind
	Number  uint32
	Attempt uint16
	Frame   uint16
	Last    bool
}

// Uint64 lays the nonce out as kind(4) number(32) attempt(12) frame(15)
// last(1). Out-of-range fields are a programming error: silently masking
// them would reuse a nonce of another frame.
func (n Nonce) Uint64() uint64 {
	if n.Attempt > maxAttempt || n.Frame > maxFrame || n.Kind > 15 {
		panic(fmt.Sprintf("channel: nonce out of range: %+v", n))
	}
	v := uint64(n.Kind)<<60 | uint64(n.Number)<<28 | uint64(n.Attempt)<<16 | uint64(n.Frame)<<1
	if n.Last {
		v |= 1
	}
	return v
}

// ParseNonce is the inverse of Uint64. Only the kinds this version speaks
// are accepted; 5 is reserved for a later FETCH.
func ParseNonce(v uint64) (Nonce, error) {
	k := Kind(v >> 60)
	if (k < KindOp || k > KindAbort) && k != KindKeepalive {
		return Nonce{}, fmt.Errorf("channel: unknown request kind %d", k)
	}
	return Nonce{
		Kind:    k,
		Number:  uint32(v >> 28),
		Attempt: uint16(v>>16) & maxAttempt,
		Frame:   uint16(v>>1) & maxFrame,
		Last:    v&1 == 1,
	}, nil
}

// base is the nonce of the request as a whole, as it travels in the clear
// header and in the AD of the response frames.
func (n Nonce) base() Nonce {
	n.Frame, n.Last = 0, false
	return n
}

// ResponseNonce is the nonce of a response frame. Counters are never reused
// within a session, so response frames never share a nonce.
func ResponseNonce(counter uint32, frame uint32, last bool) uint64 {
	if frame >= 1<<31 {
		panic(fmt.Sprintf("channel: response frame %d out of range", frame))
	}
	v := uint64(counter)<<32 | uint64(frame)<<1
	if last {
		v |= 1
	}
	return v
}
