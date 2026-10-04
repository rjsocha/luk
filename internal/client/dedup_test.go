package client

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

func TestUploadDeduplicated(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint("h2=", h2), func(t *testing.T) {
			s := newSigner(t)
			ts, pin := newTestServer(t, h2, testHandler(t, s.PublicKey()))
			body := strings.Repeat("x", 1<<20)
			o := fileOpts(t, ts.URL+"/drop", s, []byte(body))
			o.Pin = pin
			first, err := Upload(context.Background(), o)
			if err != nil || first.Receipt.Deduplicated {
				t.Fatalf("first %+v %v", first, err)
			}
			var read atomic.Int64
			var progress bytes.Buffer
			o.Body = countingReader{n: &read, r: strings.NewReader(body)}
			o.Progress = &progress
			second, err := Upload(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			if !second.Receipt.Deduplicated || second.Receipt.URL == first.Receipt.URL || second.Receipt.SHA256 != o.Meta.SHA256 {
				t.Fatalf("second %+v", second.Receipt)
			}
			if read.Load() != 0 {
				t.Fatalf("read %d body bytes", read.Load())
			}
			if progress.String() != "" {
				t.Fatalf("progress %q", progress.String())
			}
		})
	}
}
