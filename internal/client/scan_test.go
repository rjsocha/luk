package client

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"luk/internal/tlsself"
)

func TestScanTLSVerified(t *testing.T) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	c, err := ScanTLS(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	if c.Verified || c.Pin != tlsself.Pin(ts.Certificate()) {
		t.Fatalf("untrusted: %+v", c)
	}
	testRoots = x509.NewCertPool()
	testRoots.AddCert(ts.Certificate())
	t.Cleanup(func() { testRoots = nil })
	if c, err = ScanTLS(context.Background(), u); err != nil || !c.Verified {
		t.Fatalf("trusted: %+v %v", c, err)
	}
}
