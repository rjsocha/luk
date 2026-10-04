package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"luk/internal/tlsself"
	"luk/internal/wire"
)

// testRoots replaces the system CAs in tests.
var testRoots *x509.CertPool

// Certificate is the leaf certificate a TLS server presents: its pin, its
// subject and validity, and whether its chain verifies against the system
// CAs for the host.
type Certificate struct {
	Pin       string
	Subject   string
	NotBefore time.Time
	NotAfter  time.Time
	Verified  bool
}

// ScanTLS connects to the host and port of the https URL u without
// verifying the chain (trust on first use) and returns the certificate
// the server presents.
func ScanTLS(ctx context.Context, u *url.URL) (*Certificate, error) {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname()}}
	conn, err := d.DialContext(dctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return nil, transferError(ctx, err, u.Host, 0, -1, false)
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("server sent no certificate")
	}
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: u.Hostname(), Intermediates: inter, Roots: testRoots})
	return &Certificate{
		Pin: tlsself.Pin(leaf), Subject: leaf.Subject.String(),
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Verified: verr == nil,
	}, nil
}

// NoListingError is a server that answers 404 to the endpoint listing: a
// lukd older than the listing, or no lukd.
type NoListingError struct{ Err error }

func (e *NoListingError) Error() string { return "the server does not offer an endpoint listing" }
func (e *NoListingError) Unwrap() error { return e.Err }

// ListEndpoints asks the server of o.URL (only its scheme and host count)
// for the endpoints the signer may use on that listener (luk-list@v1).
func ListEndpoints(ctx context.Context, o GetOptions) (*wire.EndpointList, error) {
	u := &url.URL{Scheme: o.URL.Scheme, Host: o.URL.Host, Path: wire.EndpointsPath}
	o.URL = u
	resp, err := signedGet(ctx, o, http.MethodGet, wire.ListNamespace)
	if err != nil {
		var re *RejectedError
		if errors.As(err, &re) && re.Status == http.StatusNotFound {
			return nil, &NoListingError{err}
		}
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxListAnswer))
	if err != nil {
		return nil, transferError(ctx, err, u.Host, 0, -1, true)
	}
	l := &wire.EndpointList{}
	if err := json.Unmarshal(data, l); err != nil {
		return nil, fmt.Errorf("bad answer (200): %w", err)
	}
	return l, nil
}
