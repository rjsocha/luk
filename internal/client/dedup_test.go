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
	for _, tlsOn := range []bool{false, true} {
		t.Run(fmt.Sprint("tls=", tlsOn), func(t *testing.T) {
			s := newSigner(t)
			base, pins := lukdChannel(t, s.PublicKey(), tlsOn)
			body := strings.Repeat("x", 1<<20)
			o := fileOpts(t, base+"/drop", pins, s, []byte(body))
			first, err := Upload(context.Background(), o)
			if err != nil || first.Receipt.Deduplicated {
				t.Fatalf("first %+v %v", first, err)
			}
			var read atomic.Int64
			var progress bytes.Buffer
			o.Source = countingReaderAt{n: &read, r: strings.NewReader(body)}
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
