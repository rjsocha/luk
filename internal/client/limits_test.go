package client

import (
	"context"
	"testing"

	"luk/internal/channel"
	"luk/internal/channel/chantest"
)

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
