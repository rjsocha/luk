package client

import (
	"cmp"
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
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/sshsig"
	"luk/internal/wire"
)

type Options struct {
	URL    string
	Pin    string
	Signer ssh.Signer
	Meta   wire.Meta
	Body   io.Reader
	Size   int64 // -1: unknown, sent chunked
	// DecisionTimeout bounds the wait for 100 Continue or a final answer
	// before any body byte goes out; 0 means 60s.
	DecisionTimeout time.Duration
	// IdleTimeout bounds each wait for the server once decided: for it to
	// take the next body bytes, for the answer after the body and between
	// the bytes of the answer; 0 means 2m.
	IdleTimeout time.Duration
	// Progress receives the transfer progress; nil turns it off.
	Progress io.Writer
	// BWLimit caps the body rate in bytes per second; 0 is unlimited.
	BWLimit int64
	// NoBody marks a body that cannot be sent (a stream already read): the
	// request goes with Size, and a 100 Continue ends it with
	// ErrBodyWanted.
	NoBody bool

	// maxAnswer caps the answer body read; 0 means 1 MiB.
	maxAnswer int64
}

var expectContinueTimeout = 10 * time.Second

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

// ErrBodyWanted ends an upload with Options.NoBody whose body the server
// asked for (100 Continue).
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

type countWriter struct{ n atomic.Int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n.Add(int64(len(p)))
	return len(p), nil
}

// errReader fails every read with err.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// gateReader yields no bytes until the server has answered 100 Continue.
type gateReader struct {
	r    io.Reader
	open <-chan struct{}
	done <-chan struct{}
}

func (g *gateReader) Read(p []byte) (int, error) {
	select {
	case <-g.open:
	case <-g.done:
		return 0, errors.New("request ended before 100 Continue")
	}
	return g.r.Read(p)
}

func Upload(ctx context.Context, o Options) (*Answer, error) {
	if err := o.Meta.Normalize(); err != nil {
		return nil, err
	}
	metaS, err := wire.EncodeMeta(o.Meta)
	if err != nil {
		return nil, err
	}
	res, err := send(ctx, o, http.MethodPut, metaS, nil, func(host, path, ts, nonce string) (string, []byte) {
		return wire.Namespace, wire.CanonicalText(host, path, ts, nonce, metaS)
	})
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		if res.status == http.StatusUnprocessableEntity && o.Meta.SHA256 != "" && o.Meta.Size != nil && res.sent == *o.Meta.Size {
			if res.sum != o.Meta.SHA256 {
				return nil, &HashMismatchError{Local: res.sum, Remote: o.Meta.SHA256}
			}
		}
		return nil, res.rejected()
	}
	a, err := decodeAnswer(res.status, res.data, o.Meta.DryRun)
	if err != nil {
		return nil, err
	}
	if a.Debug != nil {
		return a, nil
	}
	if a.Receipt.Deduplicated || (!res.continued && o.Size != 0 && (o.Body != nil || o.NoBody)) {
		// Answered without the body: the server took the content it holds
		// for the signer, by the signed size and sha256.
		a.Receipt.Deduplicated = true
		if o.Meta.Size == nil || a.Receipt.Size != *o.Meta.Size || a.Receipt.SHA256 != o.Meta.SHA256 {
			return a, &HashMismatchError{Local: o.Meta.SHA256, Remote: a.Receipt.SHA256}
		}
		return a, nil
	}
	if a.Receipt.SHA256 != res.sum {
		return a, &HashMismatchError{Local: res.sum, Remote: a.Receipt.SHA256}
	}
	return a, nil
}

// result is the answer to a signed request: the status, the body (at most
// 1 MiB), the bytes of the request body sent with their sha256, and
// whether the server asked for the body (100 Continue).
type result struct {
	status    int
	data      []byte
	sent      int64
	sum       string
	continued bool
	// date is the Date header of the answer, at the local time it came.
	date string
	at   time.Time
	// retry is the Retry-After header (seconds).
	retry string
}

// rejected is the error of an answer of 400 or above.
func (r *result) rejected() error {
	var e wire.ErrorResponse
	msg := strings.TrimSpace(string(r.data))
	if json.Unmarshal(r.data, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	re := &RejectedError{Status: r.status, Message: message(msg)}
	if r.status == http.StatusUnauthorized && msg == wire.ErrTimestampWindow {
		if d, err := http.ParseTime(r.date); err == nil {
			off := r.at.Sub(d).Round(time.Second)
			re.ClockOffset = &off
		}
	}
	if n, err := strconv.ParseInt(r.retry, 10, 64); err == nil && n > 0 {
		re.RetryAfter = time.Duration(n) * time.Second
	}
	return re
}

// send makes one signed request to o.URL: the Luk-* signature headers over
// what sign returns (the namespace and the canonical text) for the Host,
// the path, the timestamp and the nonce, plus header. A PUT goes with
// Expect: 100-continue and its body (o.Body, o.Size) only after 100
// Continue.
func send(ctx context.Context, o Options, method, metaS string, header map[string]string, sign func(host, path, ts, nonce string) (string, []byte)) (*result, error) {
	u, err := url.Parse(o.URL)
	if err != nil {
		return nil, err
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := wire.NewNonce()
	ns, text := sign(u.Host, path, ts, nonce)
	sig, err := sshsig.Sign(o.Signer, ns, text)
	if err != nil {
		return nil, err
	}

	wait, err := orDefault(o.DecisionTimeout, defaultDecision, "decision timeout")
	if err != nil {
		return nil, err
	}
	idle, err := orDefault(o.IdleTimeout, defaultIdle, "idle timeout")
	if err != nil {
		return nil, err
	}
	caller := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The decision is 100 Continue or the complete headers of a final
	// answer, whichever comes first; another 1xx is none. The decision
	// timer never covers the body upload; the idle watchdogs do, the
	// wait for the answer after it, and the reading of the answer.
	dec := newDecider(wait, cancel)
	defer dec.stop()
	sendWD, answerWD := newWatchdog(idle, cancel), newWatchdog(idle, cancel)
	defer sendWD.stop()
	defer answerWD.stop()
	proceed := make(chan struct{})
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		Got100Continue: sync.OnceFunc(func() {
			if dec.decide() {
				close(proceed)
			}
		}),
	})

	h := sha256.New()
	counter := &countWriter{}
	var body io.Reader
	if o.Size != 0 && o.NoBody {
		body = &sendIdle{&gateReader{r: errReader{ErrBodyWanted}, open: proceed, done: ctx.Done()}, sendWD}
	} else if o.Size != 0 && o.Body != nil {
		src := o.Body
		if o.BWLimit > 0 {
			src = newLimitReader(ctx, src, o.BWLimit)
		}
		// A dry run sends no body: nothing to report.
		if o.Progress != nil && !o.Meta.DryRun {
			pr := newProgress(src, o.Progress, o.Size, time.Now)
			defer pr.Finish()
			src = pr
		}
		body = &sendIdle{&gateReader{r: io.TeeReader(src, io.MultiWriter(h, counter)), open: proceed, done: ctx.Done()}, sendWD}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil && o.Size > 0 {
		req.ContentLength = o.Size
	} else if body != nil && o.Size < 0 {
		req.ContentLength = -1
	}
	if method == http.MethodPut {
		req.Header.Set("Expect", "100-continue")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set(wire.HeaderMeta, metaS)
	req.Header.Set(wire.HeaderTimestamp, ts)
	req.Header.Set(wire.HeaderNonce, nonce)
	req.Header.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))

	tr, err := transport(u, o.Pin)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	at := time.Now()
	stalled := sendWD.stop()
	if !dec.decide() {
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil {
			err = context.Canceled
		}
		return nil, &TransferError{Reason: NoDecision, Host: u.Host, Total: o.Size, Wait: wait, Err: err}
	}
	if o.NoBody && body != nil {
		select {
		case <-proceed:
			if resp != nil {
				resp.Body.Close()
			}
			return nil, ErrBodyWanted
		default:
		}
	}
	if err != nil {
		if stalled {
			err = &stalledError{idle}
		}
		return nil, transferError(caller, err, u.Host, counter.n.Load(), o.Size, stalled)
	}
	defer resp.Body.Close()
	// Cancel first: an HTTP/2 body Close waits for the gated body writer.
	defer cancel()
	answer := &readIdle{r: resp.Body, w: answerWD}
	data, err := io.ReadAll(io.LimitReader(answer, cmp.Or(o.maxAnswer, 1<<20)))
	if err != nil {
		return nil, transferError(caller, err, u.Host, counter.n.Load(), o.Size, true)
	}
	continued := false
	select {
	case <-proceed:
		continued = true
	default:
	}
	return &result{status: resp.StatusCode, data: data, sent: counter.n.Load(), sum: hex.EncodeToString(h.Sum(nil)), continued: continued,
		date: resp.Header.Get("Date"), at: at, retry: resp.Header.Get("Retry-After")}, nil
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
	t.ExpectContinueTimeout = expectContinueTimeout
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
