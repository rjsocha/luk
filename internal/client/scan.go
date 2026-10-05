package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/tlsself"
	"luk/internal/wire"
)

// testRoots replaces the system CAs in tests.
var testRoots *x509.CertPool

// Certificate is the leaf certificate a TLS server presents: its SPKI pin,
// the pin of downloads, and whether its chain verifies against the system
// CAs for the host.
type Certificate struct {
	Pin      string
	Verified bool
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
	return &Certificate{Pin: tlsself.Pin(leaf), Verified: verr == nil}, nil
}

// listingURL is the endpoint listing of the server of u: its scheme and
// host count.
func listingURL(u *url.URL) *url.URL {
	return &url.URL{Scheme: u.Scheme, Host: u.Host, Path: wire.EndpointsPath}
}

// Scan runs a handshake with the lukd of u (only its scheme and host
// count) on the endpoint listing, the one path every listener takes, and
// returns the key lukd presents. Nothing authenticates that key: it is
// what luk scan shows to be pinned.
func Scan(ctx context.Context, u *url.URL) ([]byte, error) {
	c, err := Dial(ctx, DialOptions{URL: listingURL(u), Discover: true})
	if err != nil {
		return nil, err
	}
	c.Close()
	return c.PeerKey(), nil
}

// ListEndpoints asks the lukd of u (only its scheme and host count),
// through the channel with the lukd keys pins accepted, for the endpoints
// signer may use on that listener (luk-list@v2).
func ListEndpoints(ctx context.Context, u *url.URL, pins []channel.Pin, signer ssh.Signer) (*wire.EndpointList, error) {
	lu := listingURL(u)
	c, err := Dial(ctx, DialOptions{URL: lu, Pins: pins})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	req, err := signedOp(Options{URL: lu.String(), Signer: signer}, c, http.MethodGet, "", nil, func(host, path, ts, nonce string) (string, []byte) {
		return wire.ListNamespaceV2, wire.ListCanonicalTextV2(http.MethodGet, host, path, ts, nonce, c.H())
	})
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	if resp.Status >= 400 {
		return nil, rejection(resp)
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("unexpected answer %d %s to an endpoint listing", resp.Status, http.StatusText(resp.Status))
	}
	l := &wire.EndpointList{}
	if err := json.Unmarshal(resp.Body, l); err != nil {
		return nil, fmt.Errorf("bad answer (%d): %w", resp.Status, err)
	}
	return l, nil
}
