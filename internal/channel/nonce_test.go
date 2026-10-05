package channel

import "testing"

func TestNonceRoundTrip(t *testing.T) {
	for _, n := range []Nonce{
		{Kind: KindOp},
		{Kind: KindPart, Number: 1<<32 - 1, Attempt: 4095, Frame: 32767, Last: true},
		{Kind: KindComplete, Number: 7, Attempt: 1, Frame: 3},
	} {
		got, err := ParseNonce(n.Uint64())
		if err != nil || got != n {
			t.Fatalf("%+v: %+v %v", n, got, err)
		}
	}
	if _, err := ParseNonce(0); err == nil {
		t.Fatal("kind 0 accepted")
	}
	if v := (Nonce{Kind: KindPart, Number: 1}).Uint64(); v != 2<<60|1<<28 {
		t.Fatalf("layout %x", v)
	}
}
