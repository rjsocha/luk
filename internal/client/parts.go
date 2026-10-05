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
	"sync/atomic"
	"time"

	"golang.org/x/term"

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
	// completeWait bounds each attempt of a COMPLETE: lukd answers one
	// sent again from the answer it kept, or once the first one is done.
	completeWait = 2 * time.Minute
	// signNotice is how long a signature may take before luk says it
	// waits for it, signLimit how long before it is too late to send.
	signNotice = time.Second
	signLimit  = 55 * time.Second
	// signNoticeOut is where the notice goes: stderr when a terminal,
	// else nowhere.
	signNoticeOut = func() io.Writer {
		if term.IsTerminal(int(os.Stderr.Fd())) {
			return os.Stderr
		}
		return nil
	}
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

// msgUnknownSession is the error lukd answers in the clear (404) to a
// message of a session it does not have.
const msgUnknownSession = "unknown session"

// sessionGone reports whether err is lukd's 404 unknown session. Only its
// message tells it from any other 404 in the clear, such as one of a
// proxy on the way, which says nothing about the session.
func sessionGone(err error) bool {
	var te *TransportError
	return errors.As(err, &te) && te.Status == http.StatusNotFound && te.Message == msgUnknownSession
}

// noAnswerError is an upload whose COMPLETE got no answer after its
// attempts: lukd may have stored it, so the result is unknown
// (ErrResultUnknown). committed is set when the ABORT that followed was
// refused as the upload committed: stored, but its URL was lost.
type noAnswerError struct {
	cause     error
	committed bool
}

func (e *noAnswerError) Error() string {
	if e.committed {
		return fmt.Sprintf("result unknown: %v at the end of the upload; lukd reports the upload as committed, but its answer with the URL was lost", e.cause)
	}
	return fmt.Sprintf("result unknown: %v at the end of the upload; check whether it arrived before sending it again", e.cause)
}

func (e *noAnswerError) Is(target error) bool { return target == ErrResultUnknown }

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
		meter.restart()
	}
}

// opSession dials u and sends the OP that op signs for the channel. A
// 404 unknown session to the OP is a session lukd dropped before its OP
// came (under a burst of handshakes the oldest pending ones go): it is
// dialed once more, with a new handshake and a new signature.
func opSession(ctx context.Context, u *url.URL, pins []channel.Pin, op opFunc) (*Channel, *InnerResponse, error) {
	for again := true; ; again = false {
		c, err := Dial(ctx, DialOptions{URL: u, Pins: pins})
		if err != nil {
			return nil, nil, err
		}
		req, err := signOp(c, op)
		if err != nil {
			c.Close()
			return nil, nil, err
		}
		resp, err := c.Do(ctx, req, nil)
		if err == nil {
			return c, resp, nil
		}
		c.Close()
		if !again || !sessionGone(err) {
			return nil, nil, err
		}
	}
}

// signOp is the OP that op signs for c, which just finished its
// handshake. A signature still pending after signNotice (a hardware key
// waiting for a touch) is announced once on a terminal. One that took
// longer than signLimit is not sent: lukd drops a session without its OP
// after limits.channel.auth (60s), and the OP would come too late.
func signOp(c *Channel, op opFunc) (channel.Request, error) {
	start := time.Now()
	if w := signNoticeOut(); w != nil {
		t := time.AfterFunc(signNotice, func() { fmt.Fprintln(w, "waiting for the signature (touch the key)") })
		defer t.Stop()
	}
	req, err := op(c)
	if err == nil && time.Since(start) > signLimit {
		err = fmt.Errorf("the signature took longer than %s; lukd drops a session that waits longer than 60s (limits.channel.auth): run it again", signLimit)
	}
	return req, err
}

// uploadOnce is one session of an upload.
func uploadOnce(ctx context.Context, o Options, u *url.URL, op opFunc, meter *partsMeter) (*partsResult, error) {
	c, resp, err := opSession(ctx, u, o.Pins, op)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if resp.Status != http.StatusOK || o.Meta.DryRun {
		return &partsResult{resp: resp}, nil
	}
	var offer wire.PartsOffer
	if err := json.Unmarshal(resp.Body, &offer); err != nil || offer.Parts.Size <= 0 || offer.Parts.Parallel <= 0 {
		return nil, fmt.Errorf("bad parts offer: %s", Printable(string(resp.Body)))
	}
	r := &partsRun{c: c, o: &o, host: u.Host, partSize: offer.Parts.Size, meter: meter, pace: newPacer(o.BWLimit),
		idle: time.Duration(offer.Parts.Idle) * time.Second, attempts: map[channel.Nonce]uint16{}, done: map[uint32]bool{}}
	r.limit = partsWorkers(o.Parallel, offer.Parts.Parallel, o.BWLimit, offer.Parts.Rate)
	if o.NoBody || (o.Source == nil && o.Body == nil) {
		r.abort()
		return nil, ErrBodyWanted
	}
	// Every part must arrive at the rate of the offer: below it lukd
	// refuses each part (408) whatever luk does.
	if rate := offer.Parts.Rate; o.BWLimit > 0 && rate > 0 && o.BWLimit < rate {
		r.abort()
		return nil, fmt.Errorf("--bwlimit %s/s is below the minimum rate of this endpoint (%s/s)", HumanBytes(o.BWLimit), HumanBytes(rate))
	}
	return r.run(ctx)
}

// partsWorkers is the number of workers of an upload: --parallel (at
// least one) within the offer, and under --bwlimit so few that each part
// still gets the rate lukd asks of it.
func partsWorkers(parallel, offer int, bwlimit, rate int64) int {
	n := min(max(parallel, 1), offer)
	if bwlimit > 0 && rate > 0 {
		n = int(min(int64(n), max(bwlimit/rate, 1)))
	}
	return n
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
	// idle is the time lukd keeps the upload open without activity (0:
	// not offered).
	idle time.Duration

	mu sync.Mutex
	// limit is the number of workers that send; a timeout of lukd
	// lowers it.
	limit int
	// attempts is the next attempt per base nonce: a Channel never
	// sends a nonce twice.
	attempts map[channel.Nonce]uint16
	// verified is the bytes of the parts lukd verified, done those parts:
	// a part sent again counts once.
	verified int64
	done     map[uint32]bool
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
		case !r.inRange(m.Missing):
			err = fmt.Errorf("bad answer (409): missing parts %v beyond the upload", m.Missing)
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

// inRange reports whether every part of ns is one of a file, or one of a
// stream read so far.
func (r *partsRun) inRange(ns []uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range ns {
		if r.o.Source != nil && int64(n)*r.partSize >= r.o.Size {
			return false
		}
		if r.o.Source == nil && !r.done[n] {
			return false
		}
	}
	return true
}

// fail ends the upload with err: lukd drops it (ABORT) unless it lost it
// already. A file that changed is reported as such whatever failed before
// the COMPLETE, and a transfer error carries the bytes lukd verified.
func (r *partsRun) fail(ctx context.Context, err error) error {
	var na *noAnswerError
	if errors.As(err, &na) {
		// The session may still hold the upload: the ABORT drops it, or
		// tells it was committed meanwhile.
		resp := r.abort()
		na.committed = resp != nil && resp.Status == http.StatusConflict && errorText(resp.Body) == "upload committed"
		return err
	}
	if errors.Is(err, ErrResultUnknown) {
		return err
	}
	if !errors.Is(err, errSessionGone) {
		r.abort()
	}
	switch {
	case ctx.Err() != nil:
		err = &TransferError{Reason: Interrupted, Host: r.host}
	case errors.Is(r.unchanged(), errFileChanged):
		return errFileChanged
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
// the caller's context; its answer, nil without one.
func (r *partsRun) abort() *InnerResponse {
	ctx, cancel := context.WithTimeout(context.Background(), abortTimeout)
	defer cancel()
	n, err := r.nonce(channel.Nonce{Kind: channel.KindAbort})
	if err != nil {
		return nil
	}
	resp, err := r.c.Send(ctx, n, nil)
	if err != nil {
		return nil
	}
	return resp
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

// feedStream reads the stream part by part into two buffers per worker,
// so the next part is read while the last one goes; a buffer goes back
// once its part is verified. The short (or empty) part that ends the
// stream is its last.
func (r *partsRun) feedStream(ctx context.Context, jobs chan<- partJob) error {
	r.sum = sha256.New()
	free := make(chan []byte, 2*r.workers())
	for range cap(free) {
		free <- make([]byte, r.partSize)
	}
	var waiting atomic.Bool
	kctx, stop := context.WithCancel(ctx)
	var kwg sync.WaitGroup
	kwg.Go(func() { r.keepalive(kctx, &waiting) })
	defer func() {
		stop()
		kwg.Wait()
	}()
	for n := uint32(0); ; n++ {
		var buf []byte
		select {
		case buf = <-free:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
		waiting.Store(true)
		k, err := io.ReadFull(r.o.Body, buf)
		waiting.Store(false)
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

// keepalive sends a KEEPALIVE every idle/3 while waiting is set (the
// feed waits on its source), so lukd keeps the upload of a slow source
// open; parts and their answers keep it open otherwise. Its failures are
// left to the parts that follow.
func (r *partsRun) keepalive(ctx context.Context, waiting *atomic.Bool) {
	if r.idle <= 0 {
		return
	}
	every := r.idle / 3
	t := time.NewTicker(every)
	defer t.Stop()
	for seq := uint32(0); ; {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !waiting.Load() {
			continue
		}
		n, err := r.nonce(channel.Nonce{Kind: channel.KindKeepalive, Number: seq})
		seq++
		if err != nil {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, every)
		_, _ = r.c.Send(sctx, n, nil)
		cancel()
	}
}

// send runs feed to its end and sends what it hands out with the
// workers. The first error ends both, except a lost session: the parts in
// flight then finish, as one of them may end the upload with a more
// telling answer (a refusal that ended it) that must win, so a file is
// not sent again for nothing.
func (r *partsRun) send(parent context.Context, feed func(context.Context, chan<- partJob) error) error {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	// fctx ends the feed and the taking of parts: on any error.
	fctx, halt := context.WithCancelCause(ctx)
	defer halt(nil)
	jobs := make(chan partJob)
	var wg sync.WaitGroup
	var emu sync.Mutex
	var first error
	fail := func(err error) {
		emu.Lock()
		if first == nil || (errors.Is(first, errSessionGone) && !errors.Is(err, errSessionGone) && !errors.Is(err, context.Canceled)) {
			first = err
		}
		emu.Unlock()
		halt(err)
		if !errors.Is(err, errSessionGone) {
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
				case <-fctx.Done():
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
		err := feed(fctx, jobs)
		if err != nil {
			fail(err)
		} else {
			close(jobs)
		}
		ferr <- err
	}()
	wg.Wait()
	cancel(nil)
	emu.Lock()
	err := first
	emu.Unlock()
	switch {
	case parent.Err() != nil:
		return parent.Err()
	case err != nil:
		return err
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
		resp, sent, err := r.attempt(ctx, j, n)
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		var se *sourceError
		var te *TransportError
		switch {
		case errors.As(err, &se):
			return err
		case sessionGone(err):
			return errSessionGone
		case errors.As(err, &te) && te.Status == http.StatusRequestEntityTooLarge:
			// lukd answers a part too large inside the channel: a 413 in
			// the clear is a proxy on the way, and every attempt gets it.
			return fmt.Errorf("the part size (%s) exceeds what a proxy on the way accepts: HTTP 413", HumanBytes(r.partSize))
		case err != nil:
			last = err
		case resp.Status == http.StatusOK:
			r.mu.Lock()
			again := r.done[j.n]
			if !again {
				r.done[j.n] = true
				r.verified += j.size
			}
			r.mu.Unlock()
			if again {
				r.meter.add(-sent)
			}
			return nil
		case resp.Status == http.StatusConflict && errorText(resp.Body) == "older attempt":
			// lukd has a newer attempt of the part than this one: the next
			// attempt is newer than every one sent, so it counts no failure,
			// but waits as one would.
			if err := sleep(ctx, jitter(partBackoff[min(failed, len(partBackoff)-1)])); err != nil {
				return err
			}
			continue
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
// before it answers; its bytes (sent) count as progress until it fails.
func (r *partsRun) attempt(ctx context.Context, j partJob, n channel.Nonce) (resp *InnerResponse, sent int64, err error) {
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	wd := newWatchdog(partIdle, cancel)
	cr := &meterReader{r: r.pace.reader(actx, j.open()), m: r.meter}
	wd.arm()
	resp, err = r.c.Send(actx, n, &sendIdle{cr, wd})
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
	return resp, cr.n, err
}

// complete sends the COMPLETE of round seq, again when its answer is
// lost or does not come within completeWait: lukd answers the attempt
// that follows from the answer it kept, or once the first one is done. A
// session lukd lost by then, or no answer after every attempt, leaves the
// result unknown; a 404 in the clear that is not lukd's is a transfer
// error.
func (r *partsRun) complete(ctx context.Context, seq uint32) (*InnerResponse, error) {
	for failed := 0; ; {
		n, err := r.nonce(channel.Nonce{Kind: channel.KindComplete, Number: seq})
		if err != nil {
			return nil, err
		}
		actx, cancel := context.WithTimeout(ctx, completeWait)
		resp, err := r.c.Send(actx, n, nil)
		cancel()
		var te *TransportError
		switch {
		case err == nil:
			return resp, nil
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case sessionGone(err):
			return nil, ErrResultUnknown
		case errors.Is(actx.Err(), context.DeadlineExceeded):
			err = &TransferError{Reason: NoAnswer, Host: r.host, Total: -1, Wait: completeWait, Err: context.DeadlineExceeded}
		}
		if failed++; failed == partAttempts {
			if errors.As(err, &te) && te.Status == http.StatusNotFound {
				return nil, err
			}
			return nil, &noAnswerError{cause: err}
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
