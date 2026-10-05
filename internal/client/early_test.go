package client

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// An upload refused at its OP reads nothing of its content.
func TestRejectedBeforeBody(t *testing.T) {
	base, pins := lukdChannel(t, newSigner(t).PublicKey(), false)
	var read atomic.Int64
	body := strings.Repeat("x", 1<<20)
	o := fileOpts(t, base+"/backup", pins, newSigner(t), []byte(body)) // stranger key
	o.Source = countingReaderAt{n: &read, r: bytes.NewReader([]byte(body))}
	_, err := Upload(context.Background(), o)
	var re *RejectedError
	if !errors.As(err, &re) || re.Status != 401 {
		t.Fatalf("%v", err)
	}
	if read.Load() != 0 {
		t.Fatalf("client read %d body bytes before the rejection", read.Load())
	}
}

// newTestServer serves h over HTTP/1, or over HTTP/2 with TLS whose
// certificate the requests outside the channel trust.
func newTestServer(t *testing.T, h2 bool, h http.Handler) *httptest.Server {
	t.Helper()
	if !h2 {
		ts := httptest.NewServer(h)
		t.Cleanup(ts.Close)
		return ts
	}
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	testRoots = x509.NewCertPool()
	testRoots.AddCert(ts.Certificate())
	t.Cleanup(func() { testRoots = nil })
	return ts
}

var protocols = []struct {
	name string
	h2   bool
}{{"http1", false}, {"http2", true}}
