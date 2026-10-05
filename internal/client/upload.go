package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/sshsig"
	"luk/internal/wire"
)

// Options is an upload to the endpoint URL through the channel, with the
// lukd keys Pins accepted. The content is a file (Source, Size bytes,
// Mtime as its hash pass saw it, checked before the upload completes) or
// a stream (Body, Size -1).
type Options struct {
	URL    string
	Pins   []channel.Pin
	Signer ssh.Signer
	Meta   wire.Meta
	Source io.ReaderAt
	Mtime  time.Time
	Body   io.Reader
	Size   int64
	// Parallel is the number of parts in flight at once, at most what
	// lukd offers; 0 is 1.
	Parallel int
	// Progress receives the transfer progress; nil turns it off.
	Progress io.Writer
	// BWLimit caps the body rate in bytes per second; 0 is unlimited.
	BWLimit int64
	// NoBody marks a content that cannot be sent (a stream already
	// read): an upload lukd wants the content of ends with ErrBodyWanted.
	NoBody bool
}

type RejectedError struct {
	Status  int
	Message string
	// ClockOffset is how far the local clock is from the Date of the
	// answer, set for a timestamp the server refused as out of its window.
	ClockOffset *time.Duration
	// RetryAfter is the Retry-After of an upload over its quota; zero
	// without one.
	RetryAfter time.Duration
}

func (e *RejectedError) Error() string {
	switch {
	case e.Status == http.StatusTooManyRequests && e.Message == wire.ErrQuotaExceeded:
		if e.RetryAfter <= 0 {
			return e.Message + ", try again later"
		}
		return e.Message + ", try again in " + waitText(e.RetryAfter)
	case e.Status == http.StatusRequestEntityTooLarge && e.Message == wire.ErrQuotaTooLarge:
		return e.Message
	}
	return fmt.Sprintf("rejected (%d %s): %s", e.Status, http.StatusText(e.Status), e.Message)
}

// waitText is a wait rounded up to whole seconds under a minute, whole
// minutes under an hour, whole hours above ("3h", "2d").
func waitText(d time.Duration) string {
	u := time.Hour
	switch {
	case d < time.Minute:
		u = time.Second
	case d < time.Hour:
		u = time.Minute
	}
	return wire.FormatDuration((d + u - 1) / u * u)
}

// ErrBodyWanted ends an upload with Options.NoBody whose content the
// server asked for.
var ErrBodyWanted = errors.New("the server asked for the content")

type HashMismatchError struct{ Local, Remote string }

func (e *HashMismatchError) Error() string {
	return fmt.Sprintf("sha256 mismatch: sent %s, expected %s (the file may have changed after hashing)", e.Local, message(e.Remote))
}

// Answer is a successful answer: Receipt for a stored upload (201 with the
// URL, 202 without), Debug for a dry run (200).
type Answer struct {
	Status  int
	Receipt *wire.Receipt
	Debug   *wire.Response
}

// Quiet is the line luk send --quiet prints: the URL of the answer (for a
// dry run the would-be URL), or empty when the endpoint answers without one
// (respond accept); the upload id is in the JSON answer.
func (a *Answer) Quiet() string {
	if a.Debug != nil {
		return a.Debug.Respond.URL
	}
	return a.Receipt.URL
}

// Body is the decoded answer.
func (a *Answer) Body() any {
	if a.Debug != nil {
		return a.Debug
	}
	return a.Receipt
}

// Upload sends o through the channel and returns the answer of lukd: a
// dry run, a deduplicated upload or a refusal answer the OP; otherwise the
// content goes in parts and the COMPLETE answers.
func Upload(ctx context.Context, o Options) (*Answer, error) {
	if err := o.Meta.Normalize(); err != nil {
		return nil, err
	}
	metaS, err := wire.EncodeMeta(o.Meta)
	if err != nil {
		return nil, err
	}
	res, err := uploadParts(ctx, o, func(c *Channel) (channel.Request, error) {
		return signedOp(o, c, http.MethodPut, metaS, nil, func(host, path, ts, nonce string) (string, []byte) {
			return wire.Namespace, wire.CanonicalText(host, path, ts, nonce, metaS, c.H())
		})
	})
	if err != nil {
		return nil, err
	}
	resp := res.resp
	if resp.Status >= 400 {
		if he := changedSource(o, res, resp.Status); he != nil {
			return nil, he
		}
		return nil, rejection(resp)
	}
	a, err := decodeAnswer(resp.Status, resp.Body, o.Meta.DryRun)
	if err != nil {
		return nil, err
	}
	if a.Debug != nil {
		return a, nil
	}
	if a.Receipt.Deduplicated || (!res.parts && o.Size != 0) {
		// Answered without the content: the server took the content it
		// holds for the signer, by the signed size and sha256.
		a.Receipt.Deduplicated = true
		if o.Meta.Size == nil || a.Receipt.Size != *o.Meta.Size || a.Receipt.SHA256 != o.Meta.SHA256 {
			return a, &HashMismatchError{Local: o.Meta.SHA256, Remote: a.Receipt.SHA256}
		}
		return a, nil
	}
	if local := sentSum(o, res); a.Receipt.SHA256 != local {
		return a, &HashMismatchError{Local: local, Remote: a.Receipt.SHA256}
	}
	return a, nil
}

// sentSum is the sha256 of the content sent: the signed one of a file,
// whose parts lukd checks against it, else that of the stream as read.
func sentSum(o Options, res *partsResult) string {
	if o.Source != nil && o.Meta.SHA256 != "" {
		return o.Meta.SHA256
	}
	return res.sum
}

// changedSource tells a file whose content no longer has its signed
// sha256 when lukd refused the content sent (422): the file changed
// after its hash pass.
func changedSource(o Options, res *partsResult, status int) *HashMismatchError {
	if status != http.StatusUnprocessableEntity || !res.parts || o.Source == nil || o.Meta.SHA256 == "" || o.Size < 0 {
		return nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(o.Source, 0, o.Size)); err != nil {
		return nil
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != o.Meta.SHA256 {
		return &HashMismatchError{Local: sum, Remote: o.Meta.SHA256}
	}
	return nil
}

// signedOp is the OP of a signed request inside the channel c: the Luk-*
// signature headers over what sign returns (the namespace and the
// canonical text) for the Host, the path, the timestamp and the nonce,
// plus header and the meta when there is one.
func signedOp(o Options, c *Channel, method, metaS string, header map[string]string, sign func(host, path, ts, nonce string) (string, []byte)) (channel.Request, error) {
	u, err := url.Parse(o.URL)
	if err != nil {
		return channel.Request{}, err
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := wire.NewNonce()
	ns, text := sign(strings.ToLower(u.Host), path, ts, nonce)
	sig, err := sshsig.Sign(o.Signer, ns, text)
	if err != nil {
		return channel.Request{}, err
	}
	h := http.Header{}
	for k, v := range header {
		h.Set(k, v)
	}
	if metaS != "" {
		h.Set(wire.HeaderMeta, metaS)
	}
	h.Set(wire.HeaderTimestamp, ts)
	h.Set(wire.HeaderNonce, nonce)
	h.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
	target := (&url.URL{Path: path, RawPath: u.RawPath}).RequestURI()
	return channel.Request{Method: method, Target: target, Header: h}, nil
}

// rejected is the RejectedError of an answer of status with body data:
// a timestamp refused as out of the window carries the offset of the
// local clock from date (got at at), and retry is its Retry-After.
func rejected(status int, data []byte, date string, at time.Time, retry string) *RejectedError {
	msg := errorText(data)
	re := &RejectedError{Status: status, Message: message(msg)}
	if status == http.StatusUnauthorized && msg == wire.ErrTimestampWindow {
		if d, err := http.ParseTime(date); err == nil {
			off := at.Sub(d).Round(time.Second)
			re.ClockOffset = &off
		}
	}
	if n, err := strconv.ParseInt(retry, 10, 64); err == nil && n > 0 {
		re.RetryAfter = time.Duration(n) * time.Second
	}
	return re
}

func decodeAnswer(status int, data []byte, dryRun bool) (*Answer, error) {
	a := &Answer{Status: status}
	switch {
	case status == http.StatusOK && dryRun:
		a.Debug = &wire.Response{}
		if err := json.Unmarshal(data, a.Debug); err != nil {
			return nil, fmt.Errorf("bad answer (%d): %w", status, err)
		}
		return a, nil
	case (status == http.StatusCreated || status == http.StatusAccepted) && !dryRun:
		a.Receipt = &wire.Receipt{}
		if err := json.Unmarshal(data, a.Receipt); err != nil {
			return nil, fmt.Errorf("bad answer (%d): %w", status, err)
		}
		if status == http.StatusCreated && a.Receipt.URL == "" {
			return nil, errors.New("bad answer (201): no url")
		}
		return a, nil
	}
	what := "an upload"
	if dryRun {
		what = "a dry run"
	}
	return nil, fmt.Errorf("unexpected answer %d %s to %s", status, http.StatusText(status), what)
}

func transport(u *url.URL, pin string) (*http.Transport, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if pin == "" {
		if testRoots != nil {
			t.TLSClientConfig = &tls.Config{RootCAs: testRoots}
		}
		return t, nil
	}
	if u.Scheme != "https" {
		return nil, errors.New("a pin needs an https endpoint")
	}
	t.TLSClientConfig = &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: true, // trust is the SPKI pin, not a chain
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			got := "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
			if got != pin {
				return fmt.Errorf("server certificate pin mismatch (got %s, want %s)", got, pin)
			}
			return nil
		},
	}
	return t, nil
}
