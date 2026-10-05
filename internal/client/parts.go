package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"luk/internal/channel"
	"luk/internal/wire"
)

// The pace of the parts of an upload; tests shorten them.
var (
	// partIdle bounds a part attempt without progress, in the sending or
	// in the answer.
	partIdle = 30 * time.Second
	// partBackoff is the wait before the second, third... attempt of a
	// part, give or take 20%.
	partBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	// abortTimeout bounds the ABORT of an upload that failed.
	abortTimeout = 5 * time.Second
)

const (
	// partAttempts is the number of failed attempts that fail a part.
	partAttempts = 5
	// completeRounds is the number of times the parts a COMPLETE lists as
	// missing are sent again.
	completeRounds = 3
)

var (
	// ErrResultUnknown is an upload whose session lukd lost when its
	// COMPLETE went out: whether it was stored is not known, so it is
	// not sent again.
	ErrResultUnknown = errors.New("result unknown: the server lost the upload session at its end; check whether it arrived before sending it again")
	errStreamLost    = errors.New("server lost the upload; the stream cannot be sent again")
	errFileChanged   = errors.New("file changed while sending: send it again")
	// errSessionGone is an answer of lukd that no longer has the session:
	// it restarted or dropped it.
	errSessionGone = errors.New("the server lost the upload session")
)

// partsResult is the answer that ended an upload: to its OP when the OP
// needed no parts (a dry run, a deduplicated upload, a refusal), else to
// its COMPLETE. sum is the sha256 of the stream sent.
type partsResult struct {
	resp  *InnerResponse
	parts bool
	sum   string
}

// opFunc is the signed OP of an upload for the channel c: its signature
// covers the handshake hash of c.
type opFunc func(c *Channel) (channel.Request, error)

// uploadParts sends the upload o through the channel: the OP that op
// signs, then, when lukd offers it, the content in parts. A file whose
// session lukd lost is sent once more from the start in a new session.
func uploadParts(ctx context.Context, o Options, op opFunc) (*partsResult, error) {
	u, err := url.Parse(o.URL)
	if err != nil {
		return nil, err
	}
	meter := newPartsMeter(o.Progress, o.Size, time.Now)
	if o.Meta.DryRun {
		meter = nil
	}
	defer meter.finish()
	for again := o.Source != nil; ; again = false {
		res, err := uploadOnce(ctx, o, u, op, meter)
		switch {
		case !errors.Is(err, errSessionGone):
			return res, err
		case o.Source == nil:
			return nil, errStreamLost
		case !again:
			return nil, err
		}
	}
}

// uploadOnce is one session of an upload.
func uploadOnce(ctx context.Context, o Options, u *url.URL, op opFunc, meter *partsMeter) (*partsResult, error) {
	c, err := Dial(ctx, DialOptions{URL: u, Pins: o.Pins})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	req, err := op(c)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK || o.Meta.DryRun {
		return &partsResult{resp: resp}, nil
	}
	var offer wire.PartsOffer
	if err := json.Unmarshal(resp.Body, &offer); err != nil || offer.Parts.Size <= 0 || offer.Parts.Parallel <= 0 {
		return nil, fmt.Errorf("bad parts offer: %s", Printable(string(resp.Body)))
	}
	r := &partsRun{c: c, o: &o, host: u.Host, partSize: offer.Parts.Size, meter: meter, pace: newPacer(o.BWLimit),
		attempts: map[channel.Nonce]uint16{}}
	r.limit = min(max(o.Parallel, 1), offer.Parts.Parallel)
	if o.NoBody || (o.Source == nil && o.Body == nil) {
		r.abort()
		return nil, ErrBodyWanted
	}
	return r.run(ctx)
}

// partJob is one part to send: n, and a reader of its bytes for each
// attempt. done gives a buffered part back once lukd verified it.
type partJob struct {
	n    uint32
	size int64
	open func() io.Reader
	done func()
}

// partsRun is the content of an upload going in parts through c.
type partsRun struct {
	c        *Channel
	o        *Options
	host     string
	partSize int64
	meter    *partsMeter
	pace     *pacer

	mu sync.Mutex
	// limit is the number of workers that send; a timeout of lukd
	// lowers it.
	limit int
	// attempts is the next attempt per base nonce: a Channel never
	// sends a nonce twice.
	attempts map[channel.Nonce]uint16
	// verified is the bytes of the parts lukd verified.
	verified int64
	// sum is the hash of a stream as it is read.
	sum hash.Hash
}

// nonce is n with its next attempt.
func (r *partsRun) nonce(n channel.Nonce) (channel.Nonce, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.attempts[n]
	if a > maxAttempt {
		return n, fmt.Errorf("part %d: out of attempts", n.Number)
	}
	r.attempts[n] = a + 1
	n.Attempt = a
	return n, nil
}

func (r *partsRun) workers() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.limit
}

// slower takes one worker away, keeping one.
func (r *partsRun) slower() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limit = max(r.limit-1, 1)
}

func (r *partsRun) run(ctx context.Context) (*partsResult, error) {
	err := r.send(ctx, r.feed)
	for round := 0; err == nil; round++ {
		if err = r.unchanged(); err != nil {
			break
		}
		var resp *InnerResponse
		resp, err = r.complete(ctx, uint32(round))
		if err != nil {
			break
		}
		if resp.Status != http.StatusConflict {
			res := &partsResult{resp: resp, parts: true}
			if r.sum != nil {
				res.sum = hex.EncodeToString(r.sum.Sum(nil))
			}
			return res, nil
		}
		var m wire.PartsMissing
		switch {
		case json.Unmarshal(resp.Body, &m) != nil || len(m.Missing) == 0:
			err = rejection(resp)
		case round == completeRounds:
			err = fmt.Errorf("the server still misses %d parts after %d rounds", len(m.Missing), completeRounds)
		case r.o.Source == nil:
			err = fmt.Errorf("the server misses part %d of the stream, already sent", m.Missing[0])
		default:
			err = r.send(ctx, func(ctx context.Context, jobs chan<- partJob) error {
				for _, n := range m.Missing {
					if err := r.offer(ctx, jobs, r.filePart(n)); err != nil {
						return err
					}
				}
				return nil
			})
		}
	}
	return nil, r.fail(ctx, err)
}

// fail ends the upload with err: lukd drops it (ABORT) unless it lost it
// already. A file that changed is reported as such whatever failed before
// the COMPLETE, and a transfer error carries the bytes lukd verified.
func (r *partsRun) fail(ctx context.Context, err error) error {
	if errors.Is(err, ErrResultUnknown) {
		return err
	}
	if !errors.Is(err, errSessionGone) {
		r.abort()
	}
	if errors.Is(r.unchanged(), errFileChanged) {
		return errFileChanged
	}
	if ctx.Err() != nil {
		err = &TransferError{Reason: Interrupted, Host: r.host}
	}
	var te *TransferError
	if errors.As(err, &te) {
		c := *te
		r.mu.Lock()
		c.Done, c.Total = r.verified, r.o.Size
		r.mu.Unlock()
		return &c
	}
	return err
}

// abort asks lukd to drop the upload, within abortTimeout and whatever
// the caller's context.
func (r *partsRun) abort() {
	ctx, cancel := context.WithTimeout(context.Background(), abortTimeout)
	defer cancel()
	if n, err := r.nonce(channel.Nonce{Kind: channel.KindAbort}); err == nil {
		_, _ = r.c.Send(ctx, n, nil)
	}
}

// unchanged checks a file against its hash pass: the same size and
// modification time, else errFileChanged.
func (r *partsRun) unchanged() error {
	st, ok := r.o.Source.(interface{ Stat() (os.FileInfo, error) })
	if !ok {
		return nil
	}
	fi, err := st.Stat()
	if err != nil {
		return err
	}
	if fi.Size() != r.o.Size || (!r.o.Mtime.IsZero() && !fi.ModTime().Equal(r.o.Mtime)) {
		return errFileChanged
	}
	return nil
}

// feed hands out every part of the content.
func (r *partsRun) feed(ctx context.Context, jobs chan<- partJob) error {
	if r.o.Source != nil {
		for n := int64(0); n*r.partSize < r.o.Size; n++ {
			if err := r.offer(ctx, jobs, r.filePart(uint32(n))); err != nil {
				return err
			}
		}
		return nil
	}
	return r.feedStream(ctx, jobs)
}

func (r *partsRun) offer(ctx context.Context, jobs chan<- partJob, j partJob) error {
	select {
	case jobs <- j:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// filePart is part n of the file, read anew for every attempt.
func (r *partsRun) filePart(n uint32) partJob {
	off := int64(n) * r.partSize
	size := min(r.partSize, r.o.Size-off)
	return partJob{n: n, size: size, open: func() io.Reader {
		return io.NewSectionReader(r.o.Source, off, size)
	}, done: func() {}}
}

// feedStream reads the stream part by part into one buffer per worker; a
// buffer goes back once its part is verified. The short (or empty) part
// that ends the stream is its last.
func (r *partsRun) feedStream(ctx context.Context, jobs chan<- partJob) error {
	r.sum = sha256.New()
	free := make(chan []byte, r.workers())
	for range cap(free) {
		free <- make([]byte, r.partSize)
	}
	for n := uint32(0); ; n++ {
		var buf []byte
		select {
		case buf = <-free:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
		k, err := io.ReadFull(r.o.Body, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return &sourceError{err}
		}
		r.sum.Write(buf[:k])
		data := buf[:k]
		j := partJob{n: n, size: int64(k), open: func() io.Reader { return bytes.NewReader(data) }, done: func() { free <- buf }}
		if err := r.offer(ctx, jobs, j); err != nil {
			return err
		}
		if k < len(buf) {
			return nil
		}
	}
}

// send runs feed to its end and sends what it hands out with the
// workers; the first error ends both.
func (r *partsRun) send(parent context.Context, feed func(context.Context, chan<- partJob) error) error {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	jobs := make(chan partJob)
	var wg sync.WaitGroup
	fail := func(err error) {
		if err != nil {
			cancel(err)
		}
	}
	for i := range r.workers() {
		wg.Go(func() {
			for i < r.workers() {
				var j partJob
				var ok bool
				select {
				case j, ok = <-jobs:
				case <-ctx.Done():
					return
				}
				if !ok {
					return
				}
				if err := r.sendPart(ctx, j); err != nil {
					fail(err)
					return
				}
				j.done()
			}
			// A worker that leaves lets the others take its parts.
		})
	}
	ferr := make(chan error, 1)
	go func() {
		err := feed(ctx, jobs)
		if err != nil {
			cancel(err)
		} else {
			close(jobs)
		}
		ferr <- err
	}()
	wg.Wait()
	cause := context.Cause(ctx)
	cancel(nil)
	switch {
	case parent.Err() != nil:
		return parent.Err()
	case cause != nil:
		return cause
	}
	// Without a failure the workers left as the feed closed the parts:
	// it returned nil. A stream feed is never waited for otherwise, as
	// it may block in a read of its source.
	return <-ferr
}

// sendPart sends part j until lukd verified it. A part refused as past the
// window waits and goes again without counting an attempt; a timeout of
// lukd also takes a worker away; any other refusal ends the upload.
func (r *partsRun) sendPart(ctx context.Context, j partJob) error {
	var last error
	for failed := 0; ; {
		n, err := r.nonce(channel.Nonce{Kind: channel.KindPart, Number: j.n})
		if err != nil {
			return err
		}
		resp, err := r.attempt(ctx, j, n)
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		var se *sourceError
		var te *TransportError
		switch {
		case errors.As(err, &se):
			return err
		case errors.As(err, &te) && te.Status == http.StatusNotFound:
			return errSessionGone
		case err != nil:
			last = err
		case resp.Status == http.StatusOK:
			r.mu.Lock()
			r.verified += j.size
			r.mu.Unlock()
			return nil
		case resp.Status == http.StatusTooManyRequests && message(errorText(resp.Body)) != wire.ErrQuotaExceeded:
			if err := sleep(ctx, retryAfter(resp)); err != nil {
				return err
			}
			continue
		case resp.Status == http.StatusRequestTimeout:
			r.slower()
			last = rejection(resp)
		default:
			return rejection(resp)
		}
		if failed++; failed == partAttempts {
			return last
		}
		if err := sleep(ctx, jitter(partBackoff[min(failed, len(partBackoff))-1])); err != nil {
			return err
		}
	}
}

// attempt sends part j once under n. The watchdog cuts an attempt that
// waits for lukd longer than partIdle, while it takes the bytes or
// before it answers; its bytes count as progress until it fails.
func (r *partsRun) attempt(ctx context.Context, j partJob, n channel.Nonce) (*InnerResponse, error) {
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	wd := newWatchdog(partIdle, cancel)
	cr := &meterReader{r: r.pace.reader(actx, j.open()), m: r.meter}
	wd.arm()
	resp, err := r.c.Send(actx, n, &sendIdle{cr, wd})
	stalled := wd.stop()
	if err != nil || resp.Status != http.StatusOK {
		r.meter.add(-cr.n)
	}
	var te *TransferError
	switch {
	case err != nil && stalled && ctx.Err() == nil:
		err = &TransferError{Reason: Stalled, Host: r.host, Wait: partIdle, Err: err}
	case errors.As(err, &te) && te.Reason == Unreachable && cr.n > 0:
		// The connection broke once bytes of the part went out.
		c := *te
		c.Reason = Closed
		err = &c
	}
	return resp, err
}

// complete sends the COMPLETE of round seq, again when its answer is
// lost. A session lukd lost by then leaves the result unknown.
func (r *partsRun) complete(ctx context.Context, seq uint32) (*InnerResponse, error) {
	for failed := 0; ; {
		n, err := r.nonce(channel.Nonce{Kind: channel.KindComplete, Number: seq})
		if err != nil {
			return nil, err
		}
		resp, err := r.c.Send(ctx, n, nil)
		var te *TransportError
		switch {
		case err == nil:
			return resp, nil
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case errors.As(err, &te) && te.Status == http.StatusNotFound:
			return nil, ErrResultUnknown
		}
		if failed++; failed == partAttempts {
			return nil, err
		}
		if err := sleep(ctx, jitter(partBackoff[min(failed, len(partBackoff))-1])); err != nil {
			return nil, err
		}
	}
}

// meterReader counts the bytes read into m and into n.
type meterReader struct {
	r io.Reader
	m *partsMeter
	n int64
}

func (mr *meterReader) Read(p []byte) (int, error) {
	k, err := mr.r.Read(p)
	mr.n += int64(k)
	mr.m.add(int64(k))
	return k, err
}

// sleep waits d or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// jitter is d give or take 20%.
func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// retryAfter is the Retry-After of an answer, 1s without one.
func retryAfter(resp *InnerResponse) time.Duration {
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	return time.Second
}

// errorText is the error of a JSON error answer, else the body.
func errorText(data []byte) string {
	var e wire.ErrorResponse
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		return e.Error
	}
	return string(bytes.TrimSpace(data))
}

// rejection is the RejectedError of an answer inside the channel.
func rejection(resp *InnerResponse) *RejectedError {
	return rejected(resp.Status, resp.Body, resp.Date, resp.At, resp.Header.Get("Retry-After"))
}
