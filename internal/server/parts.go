package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"luk/internal/auth"
	"luk/internal/channel"
	"luk/internal/config"
	"luk/internal/queue"
	"luk/internal/quota"
	"luk/internal/wire"
)

// partState is the state of one part of an upload.
type partState uint8

const (
	partAbsent partState = iota
	partReceiving
	partVerified
)

// The states of an upload in parts.
const (
	upOpen       = "open"
	upFinalizing = "finalizing"
	upCommitted  = "committed"
	upAborted    = "aborted"
	upExpired    = "expired"
)

// maxMissing caps the part numbers a complete answer lists: the client
// sends what is listed and completes again.
const maxMissing = 1024

// partWriter is the request writing a part; a newer attempt replaces it.
type partWriter struct{ n channel.Nonce }

// answer is an inner response: a status and its JSON body.
type answer struct {
	code  int
	body  any
	retry time.Duration
}

// partsUpload is an upload admitted inside the channel whose content
// arrives in parts into its stage. It lives in its session: the session
// ends when the upload has ended and its answer was kept long enough.
type partsUpload struct {
	u     *upload
	stage *queue.Stage
	// size is the signed size, -1 for a stream; max the limit of a
	// stream (0: none).
	size, max int64
	partSize  int64
	parallel  int
	idle      time.Duration
	// release gives back the place of the upload under limits.uploads.
	release func()

	// finish orders complete, abort and expiry: one ends the upload.
	finish sync.Mutex

	mu      sync.Mutex
	states  []partState
	writers map[uint32]*partWriter
	// prefix is the number of verified parts from part 0 on.
	prefix uint32
	// end is the number of parts of a stream once its short part is
	// verified, -1 before; lastLen is the length of that part.
	end, lastLen int64
	state        string
	// ended is when the upload was committed, aborted or expired; the
	// session keeps it 3 x idle from then on.
	ended time.Time
	// tomb is the answer of the complete that ended the upload, given
	// again to a repeated complete.
	tomb *answer
}

// openUpload admits the upload u of the session cs: everything before the
// body has passed (dedup and dry run answered already), so the content
// goes in parts. The acceptance order is taken here, so uploads are
// accepted in the order they were admitted.
func (s *Server) openUpload(cs *chanSession, r *http.Request, u *upload, max int64) (int, any, error) {
	if r.ContentLength != 0 {
		return 0, nil, fail(http.StatusBadRequest, "an upload inside the channel sends its content in parts")
	}
	size := int64(-1)
	if u.meta.Size != nil {
		size = *u.meta.Size
	}
	ep := u.ep
	partSize := int64(ep.Parts.Size)
	if size >= 0 && (size+partSize-1)/partSize > 1<<32-1 {
		return 0, nil, u.tooLarge(size)
	}
	release, err := s.uploads.acquire(auth.OwnerKey(u.id), u.sn.cfg.Limits.Uploads)
	if err != nil {
		return 0, nil, err
	}
	ok := false
	var res *queue.Reservation
	defer func() {
		if !ok {
			res.Release()
			if u.charge != nil {
				u.charge.Cancel()
			}
			release()
		}
	}()
	if lim, has := quota.Resolve(ep.Quota, u.id); has {
		u.charge = s.quota.Begin(ep.Name, auth.OwnerKey(u.id), lim)
		if size >= 0 {
			if err := u.charge.Take(size); err != nil {
				return 0, nil, quotaFail(err)
			}
		}
	}
	if size >= 0 {
		if res, err = s.queue.Reserve(u.queueDir(), size); errors.Is(err, queue.ErrNoSpace) {
			return 0, nil, fail(http.StatusInsufficientStorage, "not enough space")
		} else if err != nil {
			return 0, nil, fmt.Errorf("queue %s: %w", u.queueDir(), err)
		}
	}
	acc := s.accepted.Next()
	u.accepted = &acc
	st, err := s.queue.Stage(u.queueDir(), u.vars.Id, size, res)
	if errors.Is(err, queue.ErrNoSpace) {
		return 0, nil, fail(http.StatusInsufficientStorage, "not enough space")
	} else if err != nil {
		return 0, nil, fmt.Errorf("queue %s: %w", u.queueDir(), err)
	}
	pu := &partsUpload{
		u: u, stage: st, size: size, max: max, partSize: partSize, parallel: ep.Parts.Parallel,
		idle: time.Duration(ep.Limits.Body.Idle), release: release,
		writers: map[uint32]*partWriter{}, end: -1, state: upOpen,
	}
	if size >= 0 {
		pu.states = make([]partState, (size+partSize-1)/partSize)
	}
	if !cs.setUpload(pu) {
		st.Abort()
		return 0, nil, fail(http.StatusConflict, "the session has an upload")
	}
	ok = true
	s.log.Debug("upload opened", "id", u.vars.Id, "sender", u.id.Name, "endpoint", ep.Name, "size", size, "part", partSize)
	var offer wire.PartsOffer
	offer.Parts.Size, offer.Parts.Parallel = partSize, pu.parallel
	return http.StatusOK, &offer, nil
}

// uploadSlots counts the open uploads in parts, in all and per identity
// (limits.uploads).
type uploadSlots struct {
	mu    sync.Mutex
	total int
	by    map[string]int
}

// acquire takes a place for an upload of owner; the release it returns
// gives it back once.
func (us *uploadSlots) acquire(owner string, lim config.UploadLimits) (func(), error) {
	us.mu.Lock()
	defer us.mu.Unlock()
	if us.total >= lim.Total || us.by[owner] >= lim.Identity {
		return nil, &httpError{code: http.StatusTooManyRequests, msg: "too many open uploads", retry: time.Second}
	}
	if us.by == nil {
		us.by = map[string]int{}
	}
	us.total++
	us.by[owner]++
	var once sync.Once
	return func() {
		once.Do(func() {
			us.mu.Lock()
			defer us.mu.Unlock()
			us.total--
			if us.by[owner]--; us.by[owner] == 0 {
				delete(us.by, owner)
			}
		})
	}, nil
}

// answerOf is the inner response of a handler result, as serveEndpoint
// writes it.
func (s *Server) answerOf(r *http.Request, code int, v any, err error) answer {
	if err == nil {
		return answer{code: code, body: v}
	}
	var he *httpError
	if !errors.As(err, &he) {
		s.log.Error("upload failed", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path, "error", err)
		he = &httpError{code: http.StatusInternalServerError, msg: "internal error"}
	}
	return answer{code: he.code, body: wire.ErrorResponse{Error: he.msg}, retry: he.retry}
}

// seal sends a as the answer to the message of nonce n. A body left
// unread ends the connection.
func (s *Server) seal(w http.ResponseWriter, r *http.Request, cs *chanSession, n channel.Nonce, a answer, unread bool) {
	if unread {
		w.Header().Set("Connection", "close")
	}
	cw, err := newChanWriter(w, cs.sess, n)
	if err != nil {
		chanFail(w, http.StatusConflict, err.Error())
		return
	}
	if a.retry > 0 {
		cw.Header().Set("Retry-After", strconv.FormatInt(int64(a.retry/time.Second), 10))
	}
	writeJSON(cw, a.code, a.body)
	if err := cw.Close(); err != nil {
		s.log.Debug("channel response not sent", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path, "error", err)
	}
}

func refused(code int, format string, a ...any) *answer {
	return &answer{code: code, body: wire.ErrorResponse{Error: fmt.Sprintf(format, a...)}}
}

var verified = &answer{code: http.StatusOK, body: struct{}{}}

// admitLocked checks part n from the clear nonce alone: its number
// against the size and the window, and whether it is still to come. A
// non-nil answer ends the request. pu.mu held.
func (pu *partsUpload) admitLocked(n uint32) *answer {
	switch {
	case pu.size >= 0 && int(n) >= len(pu.states):
		return refused(http.StatusBadRequest, "part %d beyond the %d parts of the upload", n, len(pu.states))
	case pu.size < 0 && pu.end >= 0 && int64(n) >= pu.end:
		return refused(http.StatusBadRequest, "part %d beyond the last part %d", n, pu.end-1)
	case pu.size < 0 && pu.max > 0 && int64(n) > pu.max/pu.partSize:
		return refused(http.StatusBadRequest, "part %d beyond the size limit", n)
	case int(n) < len(pu.states) && pu.states[n] == partVerified:
		return verified
	case pu.state == upAborted || pu.state == upExpired:
		return refused(http.StatusGone, "upload %s", pu.state)
	case pu.state != upOpen:
		return refused(http.StatusConflict, "upload %s", pu.state)
	case int64(n) >= int64(pu.prefix)+2*int64(pu.parallel):
		return refused(http.StatusTooManyRequests, "part %d ahead of the window", n)
	}
	return nil
}

// limitsLocked is what part n may carry: at most max bytes (the part
// size, or less at the size limit of a stream), exactly that many when
// exact. pu.mu held.
func (pu *partsUpload) limitsLocked(n uint32) (max int64, exact bool) {
	off := int64(n) * pu.partSize
	switch {
	case pu.size >= 0:
		return min(pu.partSize, pu.size-off), true
	case pu.end >= 0 && int64(n) < pu.end-1:
		return pu.partSize, true
	case pu.max > 0:
		return min(pu.partSize, pu.max-off), false
	}
	return pu.partSize, false
}

// take makes w the writer of part n once its first frame opened: it
// replaces an older writer, whose writes stop at their next frame.
func (pu *partsUpload) take(n uint32, w *partWriter) *answer {
	pu.mu.Lock()
	defer pu.mu.Unlock()
	if a := pu.admitLocked(n); a != nil {
		return a
	}
	for int(n) >= len(pu.states) {
		pu.states = append(pu.states, partAbsent)
	}
	pu.states[n] = partReceiving
	pu.writers[n] = w
	return nil
}

var (
	errSuperseded = errors.New("part taken over by a newer attempt")
	errEnded      = errors.New("upload ended")
)

// write puts p at off within part n while w is its writer.
func (pu *partsUpload) write(n uint32, w *partWriter, p []byte, off int64) error {
	pu.mu.Lock()
	defer pu.mu.Unlock()
	if pu.state != upOpen {
		return errEnded
	}
	if pu.writers[n] != w {
		return errSuperseded
	}
	return pu.stage.WriteAt(p, int64(n)*pu.partSize+off)
}

// drop gives part n back to a new attempt after w failed.
func (pu *partsUpload) drop(n uint32, w *partWriter) {
	pu.mu.Lock()
	defer pu.mu.Unlock()
	if pu.writers[n] == w {
		delete(pu.writers, n)
		pu.states[n] = partAbsent
	}
}

// verify marks part n of length l, received whole by w, as verified and
// hashes what became contiguous.
func (pu *partsUpload) verify(n uint32, w *partWriter, l int64, exact bool, max int64, now time.Time) *answer {
	pu.mu.Lock()
	defer pu.mu.Unlock()
	if pu.state != upOpen {
		return refused(http.StatusGone, "upload %s", pu.state)
	}
	if pu.writers[n] != w {
		return refused(http.StatusConflict, "%v", errSuperseded)
	}
	short := l < pu.partSize
	var bad *answer
	switch {
	case exact && l != max:
		bad = refused(http.StatusBadRequest, "part %d of %d bytes, want %d", n, l, max)
	case pu.size < 0 && short && pu.laterLocked(n):
		bad = refused(http.StatusBadRequest, "part %d of %d bytes is short but not the last part", n, l)
	}
	if bad != nil {
		delete(pu.writers, n)
		pu.states[n] = partAbsent
		return bad
	}
	// A stream is charged as its parts arrive. A refusal gives back what
	// the upload took, so the upload ends with it.
	if pu.size < 0 && pu.u.charge != nil {
		if err := pu.u.charge.Take(l); err != nil {
			pu.endLocked(upAborted, now)
			a := answer{code: http.StatusTooManyRequests, body: wire.ErrorResponse{Error: wire.ErrQuotaExceeded}}
			var he *httpError
			if errors.As(quotaFail(err), &he) {
				a = answer{code: he.code, body: wire.ErrorResponse{Error: he.msg}, retry: he.retry}
			}
			return &a
		}
	}
	if err := pu.stage.Advance(int64(n)*pu.partSize, l); err != nil {
		delete(pu.writers, n)
		pu.states[n] = partAbsent
		return refused(http.StatusInternalServerError, "internal error")
	}
	delete(pu.writers, n)
	pu.states[n] = partVerified
	if pu.size < 0 && short {
		pu.end, pu.lastLen = int64(n)+1, l
	}
	for int(pu.prefix) < len(pu.states) && pu.states[pu.prefix] == partVerified {
		pu.prefix++
	}
	return verified
}

// laterLocked reports whether a part after n of a stream is verified or
// arriving: n then cannot be the last one.
func (pu *partsUpload) laterLocked(n uint32) bool {
	for _, st := range pu.states[n+1:] {
		if st != partAbsent {
			return true
		}
	}
	return false
}

// servePart receives one part of the upload of cs. Its number is checked
// from the clear nonce before the body is read; nothing changes before
// its first frame opened, and the part is verified only once the whole
// message opened and its length is right. Bytes land in the stage as
// their frames open.
func (s *Server) servePart(w http.ResponseWriter, r *http.Request, rc *http.ResponseController, cs *chanSession, n channel.Nonce, hdr []byte, body io.Reader) {
	pu := cs.uploadOf()
	if pu == nil {
		chanFail(w, http.StatusNotFound, "no upload in the session")
		return
	}
	pu.mu.Lock()
	a := pu.admitLocked(n.Number)
	maxLen, exact := pu.limitsLocked(n.Number)
	pu.mu.Unlock()
	if a != nil {
		s.seal(w, r, cs, n, *a, true)
		return
	}
	bl := pu.u.ep.Limits.Body
	ir := &idleReader{r: body, rc: rc, d: time.Duration(bl.Idle)}
	if rate := bl.BytesPerSecond(); rate > 0 {
		ir.total = time.Duration(pu.partSize) * time.Second / time.Duration(rate)
		ir.end = time.Now().Add(ir.total)
	}
	fr := cs.sess.OpenRequest(ir, hdr, n)
	buf := make([]byte, channel.FrameSize)
	k, err := fr.Read(buf)
	if err != nil && err != io.EOF {
		chanFail(w, readStatus(err), "bad channel message")
		return
	}
	// The first frame opened: the message is the client's.
	if !cs.claimNonce(n, s.now()) {
		chanFail(w, http.StatusConflict, "repeated nonce")
		return
	}
	me := &partWriter{n: n}
	if a := pu.take(n.Number, me); a != nil {
		s.seal(w, r, cs, n, *a, true)
		return
	}
	got := int64(0)
	fail := func(a answer, unread bool) {
		pu.drop(n.Number, me)
		s.seal(w, r, cs, n, a, unread)
	}
	for {
		if k > 0 {
			if got+int64(k) > maxLen {
				if pu.size >= 0 || got+int64(k) > pu.partSize {
					fail(*refused(http.StatusBadRequest, "part %d over %d bytes", n.Number, min(maxLen, pu.partSize)), true)
				} else {
					fail(s.answerOf(r, 0, nil, pu.u.tooLarge(pu.max)), true)
				}
				return
			}
			if werr := pu.write(n.Number, me, buf[:k], got); werr != nil {
				switch {
				case errors.Is(werr, errSuperseded):
					fail(*refused(http.StatusConflict, "%v", werr), true)
				case errors.Is(werr, errEnded):
					fail(*refused(http.StatusGone, "%v", werr), true)
				case errors.Is(werr, queue.ErrNoSpace):
					fail(answer{code: http.StatusInsufficientStorage, body: wire.ErrorResponse{Error: "not enough space"}}, true)
				default:
					fail(s.answerOf(r, 0, nil, fmt.Errorf("queue %s: %w", pu.stage.Entry.Dir, werr)), true)
				}
				return
			}
			got += int64(k)
			cs.touch(s.now())
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			if ir.err != nil && errors.Is(err, ir.err) {
				fail(s.answerOf(r, 0, nil, ir.fail(err)), true)
			} else {
				fail(*refused(http.StatusBadRequest, "bad channel message"), true)
			}
			return
		}
		k, err = fr.Read(buf)
	}
	s.seal(w, r, cs, n, *pu.verify(n.Number, me, got, exact, maxLen, s.now()), false)
}

// missingLocked lists the parts a complete still needs, at most
// maxMissing of them: for a stream whose end is not known yet the one
// after the last part it has, which has to be the short one. pu.mu held.
func (pu *partsUpload) missingLocked() []uint32 {
	var out []uint32
	for i, st := range pu.states {
		if st != partVerified && len(out) < maxMissing {
			out = append(out, uint32(i))
		}
	}
	if pu.size < 0 && pu.end < 0 && len(out) < maxMissing {
		out = append(out, uint32(len(pu.states)))
	}
	return out
}

// serveControl answers a COMPLETE or an ABORT of the upload of cs. Its
// message is empty and must open before anything acts on it.
func (s *Server) serveControl(w http.ResponseWriter, r *http.Request, cs *chanSession, n channel.Nonce, hdr []byte, body io.Reader) {
	pu := cs.uploadOf()
	if pu == nil {
		chanFail(w, http.StatusNotFound, "no upload in the session")
		return
	}
	plain, err := io.ReadAll(io.LimitReader(cs.sess.OpenRequest(body, hdr, n), 1))
	if err != nil {
		chanFail(w, readStatus(err), "bad channel message")
		return
	}
	if !cs.claimNonce(n, s.now()) {
		chanFail(w, http.StatusConflict, "repeated nonce")
		return
	}
	if len(plain) > 0 {
		s.seal(w, r, cs, n, *refused(http.StatusBadRequest, "a control message carries nothing"), true)
		return
	}
	var a answer
	if n.Kind == channel.KindComplete {
		a = s.complete(r, pu)
	} else {
		a = s.abort(pu)
	}
	s.seal(w, r, cs, n, a, false)
}

// complete commits the upload once every part is verified and answers as
// an upload outside the channel does; the answer is kept for a repeated
// complete.
func (s *Server) complete(r *http.Request, pu *partsUpload) answer {
	pu.finish.Lock()
	defer pu.finish.Unlock()
	pu.mu.Lock()
	switch {
	case pu.tomb != nil:
		pu.mu.Unlock()
		return *pu.tomb
	case pu.state != upOpen:
		pu.mu.Unlock()
		return *refused(http.StatusGone, "upload %s", pu.state)
	}
	whole := int(pu.prefix) == len(pu.states) && (pu.size >= 0 || pu.end >= 0)
	if !whole {
		m := pu.missingLocked()
		pu.mu.Unlock()
		return answer{code: http.StatusConflict, body: &wire.PartsMissing{Missing: m}}
	}
	pu.state = upFinalizing
	size, sha := pu.size, pu.u.meta.SHA256
	if size < 0 {
		size, sha = (pu.end-1)*pu.partSize+pu.lastLen, ""
	}
	pu.mu.Unlock()

	u := pu.u
	n, sum, err := pu.stage.Finish(size, sha)
	var a answer
	switch {
	case errors.Is(err, queue.ErrMismatch):
		// The answer and its log line keep nothing derived from a secret.
		msg := fmt.Sprintf("content differs from the signed %d bytes sha256 %s", size, sha)
		if u.secret != "" {
			msg = fmt.Sprintf("content differs from the signed %d bytes", size)
		}
		a = s.answerOf(r, 0, nil, fail(http.StatusUnprocessableEntity, "%s", msg))
	case errors.Is(err, queue.ErrNoSpace):
		a = s.answerOf(r, 0, nil, fail(http.StatusInsufficientStorage, "not enough space"))
	case err != nil:
		a = s.answerOf(r, 0, nil, fmt.Errorf("queue %s: %w", pu.stage.Entry.Dir, err))
	default:
		code, v, err := s.accept(u, pu.stage.Entry, n, sum, false)
		a = s.answerOf(r, code, v, err)
	}
	pu.mu.Lock()
	defer pu.mu.Unlock()
	pu.state = upCommitted
	if a.code >= 300 {
		pu.state = upAborted
		pu.stage.Abort()
		if u.charge != nil {
			u.charge.Cancel()
		}
		s.log.Info("upload rejected", "id", u.vars.Id, "sender", u.id.Name, "endpoint", u.ep.Name, "status", a.code)
	}
	pu.release()
	pu.ended, pu.tomb = s.now(), &a
	return a
}

// abort ends an open upload at the client's request: the stage goes at
// once, and what the upload holds goes back.
func (s *Server) abort(pu *partsUpload) answer {
	pu.finish.Lock()
	defer pu.finish.Unlock()
	pu.mu.Lock()
	defer pu.mu.Unlock()
	switch pu.state {
	case upOpen:
		pu.endLocked(upAborted, s.now())
		s.log.Info("upload aborted", "id", pu.u.vars.Id, "sender", pu.u.id.Name, "endpoint", pu.u.ep.Name)
	case upCommitted:
		return *refused(http.StatusConflict, "upload committed")
	}
	return answer{code: http.StatusOK, body: struct{}{}}
}

// endLocked ends an open upload without a commit: its writers stop, the
// stage, the charge and the place go back. pu.mu held.
func (pu *partsUpload) endLocked(state string, now time.Time) {
	pu.state, pu.ended = state, now
	clear(pu.writers)
	pu.stage.Abort()
	if pu.u.charge != nil {
		pu.u.charge.Cancel()
	}
	pu.release()
}

// expire ends the upload when it is open and its session had no
// activity for its idle time; it reports whether it did. A complete in
// progress is left to finish.
func (pu *partsUpload) expire(now, last time.Time) bool {
	if !pu.finish.TryLock() {
		return false
	}
	defer pu.finish.Unlock()
	pu.mu.Lock()
	defer pu.mu.Unlock()
	if pu.state != upOpen || now.Sub(last) <= pu.idle {
		return false
	}
	pu.endLocked(upExpired, now)
	return true
}

// gone reports whether the upload ended long enough ago for its session
// to go: 3 x its idle time.
func (pu *partsUpload) gone(now time.Time) bool {
	pu.mu.Lock()
	defer pu.mu.Unlock()
	return !pu.ended.IsZero() && now.Sub(pu.ended) > 3*pu.idle
}

func (pu *partsUpload) partState(n uint32) partState {
	pu.mu.Lock()
	defer pu.mu.Unlock()
	if int(n) >= len(pu.states) {
		return partAbsent
	}
	return pu.states[n]
}

func (pu *partsUpload) stateOf() string {
	pu.mu.Lock()
	defer pu.mu.Unlock()
	return pu.state
}

// sweepChannels drops the sessions past their time and expires the
// uploads idle past theirs.
func (s *Server) sweepChannels() {
	now := s.now()
	for _, cs := range s.chans.sweep(now) {
		pu := cs.uploadOf()
		if pu.expire(now, cs.lastActive()) {
			s.log.Info("upload expired", "id", pu.u.vars.Id, "sender", pu.u.id.Name, "endpoint", pu.u.ep.Name)
		}
		if pu.gone(now) {
			s.chans.drop(cs)
		}
	}
}
