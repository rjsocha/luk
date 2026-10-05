package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"luk/internal/channel"
	"luk/internal/wire"
)

const (
	// defaultHandshakeTimeout bounds the handshake of Dial.
	defaultHandshakeTimeout = 10 * time.Second
	// maxInnerResponse bounds an inner response: it is read whole before
	// it is trusted, and endpoint answers are small JSON.
	maxInnerResponse = 64 << 20
	// maxClearAnswer bounds the body read of an answer in the clear.
	maxClearAnswer = 64 << 10
	// maxAttempt is the largest attempt a nonce carries (12 bits).
	maxAttempt = 1<<12 - 1
)

// ErrNoPin is a Dial without a pin outside discovery: luk never trusts an
// endpoint it has no key for.
var ErrNoPin = errors.New("no pin for this endpoint: run luk scan URL")

// The resolver and the dialer of Dial; tests replace them.
var (
	lookupNetIP = net.DefaultResolver.LookupNetIP
	dialContext = (&net.Dialer{}).DialContext
)

// PinMismatchError is a handshake with a lukd whose key matches none of
// the pins. Got is that key.
type PinMismatchError struct{ Got []byte }

func (e *PinMismatchError) Error() string {
	return fmt.Sprintf("the lukd key %s matches no pin of this endpoint", channel.Words(e.Got))
}

// TransportError is an answer outside the channel: to a handshake, one
// that is not the channel's, so the server is not lukd; to a message, a
// refusal in the clear. Nothing authenticates it, so it is a hint, never
// the result of an operation.
type TransportError struct {
	Status    int
	Message   string
	Handshake bool
}

func (e *TransportError) Error() string {
	s := fmt.Sprintf("channel request refused: HTTP %d", e.Status)
	if e.Handshake {
		s = fmt.Sprintf("not answered by lukd: HTTP %d", e.Status)
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// InnerResponse is an answer inside the channel, read whole and
// authenticated. Date is the Date of the outer response and At the local
// time it came: nothing authenticates Date, so it serves a clock offset
// hint only.
type InnerResponse struct {
	Status int
	Header http.Header
	Body   []byte
	Date   string
	At     time.Time
}

// sourceError is a read error of the content a message carries: it is
// the caller's own failure, never one of the network or the server.
type sourceError struct{ err error }

func (e *sourceError) Error() string { return e.err.Error() }
func (e *sourceError) Unwrap() error { return e.err }

// sourceReader keeps the first read error of r other than EOF.
type sourceReader struct {
	r   io.Reader
	err error
}

func (s *sourceReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && err != io.EOF && s.err == nil {
		s.err = err
	}
	return n, err
}

// DialOptions are the options of Dial.
type DialOptions struct {
	// URL is the endpoint (or listing) URL, http or https; its fragment
	// is ignored.
	URL *url.URL
	// Pins are the lukd keys accepted; none is ErrNoPin unless Discover.
	Pins []channel.Pin
	// Discover accepts any key, for luk scan to report it.
	Discover bool
	// Timeout bounds the handshake; zero is 10s.
	Timeout time.Duration
}

// Channel is a session of the channel with one lukd. Every request goes
// to the one address the host resolved to when it was dialed, so all the
// messages of a session reach the lukd that holds it. A Channel sends one
// OP and never two messages under one nonce.
type Channel struct {
	client *http.Client
	sess   *channel.Session
	peer   []byte
	target string // the URL the messages go to
	host   string

	mu   sync.Mutex
	op   bool
	sent map[channel.Nonce]bool
}

// Dial resolves the host of o.URL once, runs the handshake and checks the
// key of lukd against o.Pins before it returns. TLS is only transport
// here: the channel authenticates lukd, so certificates are not checked.
func Dial(ctx context.Context, o DialOptions) (*Channel, error) {
	u := o.URL
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid endpoint URL %v", u)
	}
	if len(o.Pins) == 0 && !o.Discover {
		return nil, ErrNoPin
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	host := strings.ToLower(u.Host)
	addr, err := resolveOnce(hctx, u)
	if err != nil {
		return nil, transferError(ctx, err, u.Host, 0, -1, false)
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, ServerName: strings.ToLower(u.Hostname())},
		TLSHandshakeTimeout: timeout,
		IdleConnTimeout:     90 * time.Second,
	}
	ok := false
	defer func() {
		if !ok {
			tr.CloseIdleConnections()
		}
	}()
	path := u.Path
	if path == "" {
		path = "/"
	}
	target := (&url.URL{Scheme: u.Scheme, Host: host, Path: path, RawPath: u.RawPath}).String()
	c := &Channel{
		client: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		target: target,
		host:   host,
		sent:   map[channel.Nonce]bool{},
	}
	hs, msg, err := channel.NewClientHandshake(host, path)
	if err != nil {
		return nil, err
	}
	resp, err := c.post(hctx, bytes.NewReader(msg))
	if err != nil {
		return nil, transferError(ctx, err, u.Host, 0, -1, false)
	}
	defer resp.Body.Close()
	if !isChannelAnswer(resp) {
		te := clearAnswer(resp)
		te.Handshake = true
		return nil, te
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxClearAnswer))
	if err != nil {
		return nil, transferError(ctx, err, u.Host, 0, -1, true)
	}
	sess, peer, err := hs.Finish(body)
	if err != nil {
		return nil, err
	}
	if !o.Discover && !matchesAny(o.Pins, peer) {
		return nil, &PinMismatchError{Got: peer}
	}
	c.sess, c.peer, ok = sess, peer, true
	return c, nil
}

// resolveOnce is the address of u: its IP literal, else the first address
// the host resolves to, with the port of u.
func resolveOnce(ctx context.Context, u *url.URL) (string, error) {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	name := strings.ToLower(u.Hostname())
	ip, err := netip.ParseAddr(name)
	if err != nil {
		ips, lerr := lookupNetIP(ctx, "ip", name)
		if lerr != nil {
			return "", lerr
		}
		if len(ips) == 0 {
			return "", &net.DNSError{Err: "no address", Name: name}
		}
		ip = ips[0]
	}
	return net.JoinHostPort(ip.Unmap().String(), port), nil
}

func matchesAny(pins []channel.Pin, key []byte) bool {
	for _, p := range pins {
		if p.Matches(key) {
			return true
		}
	}
	return false
}

// PeerKey is the static key of lukd.
func (c *Channel) PeerKey() []byte { return c.peer }

// H is the handshake hash that signed texts inside the channel carry.
func (c *Channel) H() []byte { return c.sess.H() }

// Close closes the idle connections of the channel; a request still
// running goes on.
func (c *Channel) Close() {
	if tr, ok := c.client.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// Do sends the OP of the session (kind OP, attempt 0) and returns the
// inner response; body may be nil. A session takes one OP.
func (c *Channel) Do(ctx context.Context, req channel.Request, body io.Reader) (*InnerResponse, error) {
	var head bytes.Buffer
	if err := channel.WriteHead(&head, req); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.op {
		c.mu.Unlock()
		return nil, errors.New("the channel has sent its operation")
	}
	c.op = true
	c.mu.Unlock()
	plain := io.Reader(&head)
	if body != nil {
		plain = io.MultiReader(&head, body)
	}
	return c.message(ctx, channel.Nonce{Kind: channel.KindOp}, plain)
}

// Send sends one PART, COMPLETE or ABORT message under n; body may be nil.
// The caller picks the attempt: a nonce already sent in this Channel is
// refused, as a second encryption under it would reuse the AEAD nonce.
func (c *Channel) Send(ctx context.Context, n channel.Nonce, body io.Reader) (*InnerResponse, error) {
	if n.Kind != channel.KindPart && n.Kind != channel.KindComplete && n.Kind != channel.KindAbort {
		return nil, fmt.Errorf("channel: Send takes PART, COMPLETE or ABORT, not kind %d", n.Kind)
	}
	if n.Attempt > maxAttempt {
		return nil, fmt.Errorf("channel: attempt %d over %d", n.Attempt, maxAttempt)
	}
	n.Frame, n.Last = 0, false
	c.mu.Lock()
	if c.sent[n] {
		c.mu.Unlock()
		return nil, fmt.Errorf("channel: nonce %+v already sent", n)
	}
	c.sent[n] = true
	c.mu.Unlock()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	return c.message(ctx, n, body)
}

// message seals plain under n, posts it and reads the inner response
// whole: its body is trusted only once the stream ended where the sender
// ended it.
//
// A read error of plain is returned as such. plain is no longer read once
// message returns, so the caller may reuse what it reads from.
func (c *Channel) message(ctx context.Context, n channel.Nonce, plain io.Reader) (*InnerResponse, error) {
	src := &sourceReader{r: plain}
	pr, pw := io.Pipe()
	sealed := make(chan struct{})
	go func() {
		defer close(sealed)
		pw.CloseWithError(c.sess.SealRequest(pw, n, src))
	}()
	resp, err := c.post(ctx, pr)
	at := time.Now()
	pr.Close()
	<-sealed
	if src.err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, &sourceError{src.err}
	}
	if err != nil {
		return nil, transferError(ctx, err, c.host, 0, -1, false)
	}
	defer resp.Body.Close()
	if !isChannelAnswer(resp) {
		return nil, clearAnswer(resp)
	}
	rc, err := c.sess.OpenResponse(resp.Body, n)
	if err != nil {
		return nil, err
	}
	plainResp, err := io.ReadAll(io.LimitReader(rc, maxInnerResponse+1))
	if err != nil {
		return nil, transferError(ctx, err, c.host, 0, -1, true)
	}
	if len(plainResp) > maxInnerResponse {
		return nil, fmt.Errorf("channel: response over %d bytes", maxInnerResponse)
	}
	r := bytes.NewReader(plainResp)
	var head channel.Response
	if err := channel.ReadHead(r, &head); err != nil {
		return nil, err
	}
	return &InnerResponse{Status: head.Status, Header: head.Header, Body: plainResp[len(plainResp)-r.Len():], Date: resp.Header.Get("Date"), At: at}, nil
}

// post sends a channel request body to the target of c.
func (c *Channel) post(ctx context.Context, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", channel.ContentType)
	return c.client.Do(req)
}

// isChannelAnswer reports whether resp is an answer of the channel: 200
// with the channel content type.
func isChannelAnswer(resp *http.Response) bool {
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return resp.StatusCode == http.StatusOK && err == nil && mt == channel.ContentType
}

// clearAnswer is the TransportError of an answer outside the channel, with
// the error text lukd sends in the clear when the body has one.
func clearAnswer(resp *http.Response) *TransportError {
	te := &TransportError{Status: resp.StatusCode}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxClearAnswer))
	var e wire.ErrorResponse
	if json.Unmarshal(b, &e) == nil {
		te.Message = Printable(e.Error)
	}
	return te
}
