package client

import (
	"context"
	"crypto/x509"
	"errors"
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
	// Verified by the chain, the listing needs no pin; the server answers
	// 404 as a lukd without the listing does.
	_, err = ListEndpoints(context.Background(), GetOptions{URL: u, Signer: newSigner(t)})
	var nl *NoListingError
	var re *RejectedError
	if !errors.As(err, &nl) || !errors.As(err, &re) || re.Status != http.StatusNotFound {
		t.Fatalf("%v", err)
	}
}
