package server

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"luk/internal/channel"
	"luk/internal/config"
	"luk/internal/wire"
)

const (
	// The first byte of a channel request body: a handshake or a
	// transport request (see the channel package).
	chanTypeHandshake = 0x01
	chanTypeTransport = 0x02
	// maxHandshake bounds the body of a handshake request (33 bytes).
	maxHandshake = 64
	// maxOp bounds the plaintext of an OP: endpoint operations carry
	// headers and small JSON only.
	maxOp = 1 << 20
)

// chanSession is a session of the channel: opened by a handshake on a
// path of a listener, it carries one operation (OP) to that path.
type chanSession struct {
	sess     *channel.Session
	host     string
	path     string
	listener string
	created  time.Time
	mu       sync.Mutex
	op       bool           // the OP has been received (authenticated or public)
	id       *wire.Identity // set by a signed OP that verified
	last     time.Time      // last activity
	// seen holds the base nonces of the messages taken, so that a message
	// is acted on once whatever is replayed.
	seen map[channel.Nonce]bool
	// elem is the place of the session in the pending list of its table;
	// nil once it has its OP or is dropped. The table lock guards it.
	elem *list.Element
	// upload is the upload in parts the OP opened; the session lives on
	// for its parts.
	upload *partsUpload
}

// setUpload makes pu the upload of the session; false when it has one.
func (cs *chanSession) setUpload(pu *partsUpload) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.upload != nil {
		return false
	}
	cs.upload = pu
	return true
}

func (cs *chanSession) uploadOf() *partsUpload {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.upload
}

// claimNonce takes the message of base nonce n once it opened; false
// when a message of that nonce was taken.
func (cs *chanSession) claimNonce(n channel.Nonce, now time.Time) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.seen[n] {
		return false
	}
	cs.seen[n], cs.last = true, now
	return true
}

// touch records activity of the session: bytes of a part that opened.
func (cs *chanSession) touch(now time.Time) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.last = now
}

func (cs *chanSession) lastActive() time.Time {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.last
}

// hasOp reports whether the session has taken its OP.
func (cs *chanSession) hasOp() bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.op
}

// claimOp takes the authenticated OP of nonce n; false when the session
// already has one.
func (cs *chanSession) claimOp(n channel.Nonce, now time.Time) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.op {
		return false
	}
	cs.op, cs.seen[n], cs.last = true, true, now
	return true
}

// seenNonce reports whether a message of base nonce n was taken.
func (cs *chanSession) seenNonce(n channel.Nonce) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.seen[n]
}

// chanTable holds the sessions by channel id. The sessions without an OP
// are also kept in the order of their handshakes, so that a burst of
// handshakes drops the oldest of them, never a session in use.
type chanTable struct {
	mu      sync.Mutex
	m       map[[16]byte]*chanSession
	pending *list.List
	limits  func() config.ChannelLimits
}

func newChanTable(limits func() config.ChannelLimits) *chanTable {
	return &chanTable{m: map[[16]byte]*chanSession{}, pending: list.New(), limits: limits}
}

// add registers a session without an OP; it evicts the oldest pending
// sessions beyond limits.channel.pending.
func (t *chanTable) add(cs *chanSession, now time.Time) {
	max := t.limits().Pending
	t.mu.Lock()
	defer t.mu.Unlock()
	for t.pending.Len() > 0 && t.pending.Len() >= max {
		t.dropLocked(t.pending.Front().Value.(*chanSession))
	}
	cs.last = now
	t.m[cs.sess.ID()] = cs
	cs.elem = t.pending.PushBack(cs)
}

func (t *chanTable) get(id [16]byte) *chanSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[id]
}

// claim takes the authenticated OP of nonce n for cs while cs is in the
// table; gone when it left it (evicted or swept while the OP was read).
func (t *chanTable) claim(cs *chanSession, n channel.Nonce, now time.Time) (ok, gone bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m[cs.sess.ID()] != cs {
		return false, true
	}
	return cs.claimOp(n, now), false
}

// attach makes pu the upload of cs while cs is in the table, so that the
// sweep and the drop of cs always reach it.
func (t *chanTable) attach(cs *chanSession, pu *partsUpload) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m[cs.sess.ID()] != cs {
		return fail(http.StatusNotFound, "unknown session")
	}
	if !cs.setUpload(pu) {
		return fail(http.StatusConflict, "the session has an upload")
	}
	return nil
}

// opened takes cs off the pending list once it has its OP.
func (t *chanTable) opened(cs *chanSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cs.elem != nil {
		t.pending.Remove(cs.elem)
		cs.elem = nil
	}
}

func (t *chanTable) drop(cs *chanSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropLocked(cs)
}

// dropLocked removes cs; an upload it still has open ends with it, so
// nothing of it is left behind.
func (t *chanTable) dropLocked(cs *chanSession) {
	if pu := cs.uploadOf(); pu != nil {
		pu.discard(time.Now())
	}
	if id := cs.sess.ID(); t.m[id] == cs {
		delete(t.m, id)
	}
	if cs.elem != nil {
		t.pending.Remove(cs.elem)
		cs.elem = nil
	}
}

// sweep drops the sessions past their time: without an OP after
// limits.channel.auth from the handshake, with one after
// limits.channel.idle without a request. The sessions of uploads follow
// the time of their upload: they are returned for that.
func (t *chanTable) sweep(now time.Time) []*chanSession {
	lim := t.limits()
	t.mu.Lock()
	defer t.mu.Unlock()
	var uploads []*chanSession
	for _, cs := range t.m {
		cs.mu.Lock()
		op, last, up := cs.op, cs.last, cs.upload != nil
		cs.mu.Unlock()
		switch {
		case up:
			uploads = append(uploads, cs)
		case (!op && now.Sub(cs.created) > time.Duration(lim.Auth)) || (op && now.Sub(last) > time.Duration(lim.Idle)):
			t.dropLocked(cs)
		}
	}
	return uploads
}

type ctxKey struct{}

// sessionOf is the session an operation came through; nil outside the
// channel.
func sessionOf(ctx context.Context) *chanSession {
	cs, _ := ctx.Value(ctxKey{}).(*chanSession)
	return cs
}

// isChannel reports whether r is a channel request: a POST of the channel
// content type.
func isChannel(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == channel.ContentType
}

// chanFail answers a channel request that reached no session or did not
// open: in the clear, as any refused request.
func chanFail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Connection", "close")
	writeJSON(w, code, wire.ErrorResponse{Error: msg})
}

// endpointOf is the endpoint of l at path, a trailing slash ignored.
func endpointOf(l *listener, path string) (*config.Endpoint, bool) {
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	ep, ok := l.byPath[path]
	return ep, ok
}

// serveChannel answers a channel request: a handshake opens a session, a
// transport request carries a message of one.
// The server has no read timeout of its own: the body, up to the clear
// header of a transport request, must arrive within
// limits.header.timeout, so a stalled one does not hold the connection.
func (s *Server) serveChannel(w http.ResponseWriter, r *http.Request, sn *snapshot, l *listener) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(time.Duration(sn.cfg.Limits.Header.Timeout)))
	defer func() { _ = rc.SetReadDeadline(time.Time{}) }()
	body := bufio.NewReader(r.Body)
	first, err := body.Peek(1)
	switch {
	case err != nil:
		chanFail(w, readStatus(err), "empty channel request")
	case first[0] == chanTypeHandshake:
		s.chanHandshake(w, r, l, body)
	case first[0] == chanTypeTransport:
		s.chanTransport(w, r, sn, l, rc, body)
	default:
		chanFail(w, http.StatusBadRequest, "unknown channel request")
	}
}

// readStatus is the status of a channel body that could not be read: 408
// when it did not arrive in time.
func readStatus(err error) int {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return http.StatusRequestTimeout
	}
	return http.StatusBadRequest
}

// chanHandshake answers a handshake on an endpoint path of l or the
// endpoint listing; any other path is refused before any key exchange
// state exists. The Host is one l serves: Handler picked l by it.
func (s *Server) chanHandshake(w http.ResponseWriter, r *http.Request, l *listener, body io.Reader) {
	reject := func(code int, msg string, err error) {
		s.log.Debug("channel handshake refused", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path, "status", code, "error", errText(msg, err))
		chanFail(w, code, msg)
	}
	if _, ok := endpointOf(l, r.URL.Path); !ok && r.URL.Path != wire.EndpointsPath {
		reject(http.StatusNotFound, "no endpoint "+r.URL.Path, nil)
		return
	}
	k := s.key.Load()
	if k == nil {
		reject(http.StatusNotFound, "no channel", nil)
		return
	}
	b, err := io.ReadAll(io.LimitReader(body, maxHandshake+1))
	if err != nil {
		reject(readStatus(err), "bad handshake", err)
		return
	}
	if len(b) > maxHandshake {
		reject(http.StatusBadRequest, "bad handshake", nil)
		return
	}
	host := strings.ToLower(r.Host)
	sess, msg, err := channel.ServerHandshake(*k, host, r.URL.Path, b)
	if err != nil {
		reject(http.StatusBadRequest, "bad handshake", err)
		return
	}
	now := s.now()
	s.chans.add(&chanSession{sess: sess, host: host, path: r.URL.Path, listener: l.cfg.Name, created: now, seen: map[channel.Nonce]bool{}}, now)
	w.Header().Set("Content-Type", channel.ContentType)
	w.Header().Set("Content-Length", fmt.Sprint(len(msg)))
	_, _ = w.Write(msg)
}

// errText is err as text, else msg.
func errText(msg string, err error) string {
	if err != nil {
		return err.Error()
	}
	return msg
}

// chanTransport answers a transport request. A session is found only on
// the Host, path and listener of its handshake, so a message relayed to
// another URL is unknown there.
func (s *Server) chanTransport(w http.ResponseWriter, r *http.Request, sn *snapshot, l *listener, rc *http.ResponseController, body io.Reader) {
	id, n, hdr, err := channel.ParseRequestHeader(body)
	if err != nil {
		chanFail(w, readStatus(err), "bad channel request")
		return
	}
	cs := s.chans.get(id)
	if cs == nil || cs.host != strings.ToLower(r.Host) || cs.path != r.URL.Path || cs.listener != l.cfg.Name {
		chanFail(w, http.StatusNotFound, "unknown session")
		return
	}
	// Activity counts once a message opens: a forged one with a known id
	// does not keep a session alive.
	if n.Kind == channel.KindOp {
		_ = rc.SetReadDeadline(time.Now().Add(time.Duration(sn.cfg.Limits.Channel.Auth)))
		s.chanOp(w, r, sn, l, cs, n, hdr, body)
		return
	}
	if cs.seenNonce(n) {
		chanFail(w, http.StatusConflict, "repeated nonce")
		return
	}
	if n.Kind == channel.KindPart {
		s.servePart(w, r, rc, cs, n, hdr, body)
		return
	}
	s.serveControl(w, r, cs, n, hdr, body)
}

// chanOp runs the OP of a session: the whole message is read and
// authenticated before anything acts on it, then it runs through the
// endpoint handlers and its answer goes back sealed. A session takes one
// OP: another one is refused and leaves it alone, whether it opened or
// not, as anybody can name a session by the id in the clear and replay
// its messages. The session ends with the answer to its OP, unless the OP
// opened an upload in parts.
func (s *Server) chanOp(w http.ResponseWriter, r *http.Request, sn *snapshot, l *listener, cs *chanSession, n channel.Nonce, hdr []byte, body io.Reader) {
	if cs.hasOp() {
		chanFail(w, http.StatusConflict, "the session has had its operation")
		return
	}
	plain, err := io.ReadAll(io.LimitReader(cs.sess.OpenRequest(body, hdr, n), maxOp+1))
	if err != nil {
		chanFail(w, readStatus(err), "bad channel message")
		return
	}
	if len(plain) > maxOp {
		chanFail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("operation over %d bytes", maxOp))
		return
	}
	// A copy of the OP that got past the check above is refused alone:
	// the session may be opening an upload with the first one.
	ok, gone := s.chans.claim(cs, n, s.now())
	if gone {
		chanFail(w, http.StatusNotFound, "unknown session")
		return
	}
	if !ok {
		chanFail(w, http.StatusConflict, "the session has had its operation")
		return
	}
	s.chans.opened(cs)
	cw, err := newChanWriter(w, cs.sess, n)
	if err != nil {
		chanFail(w, http.StatusConflict, err.Error())
		return
	}
	if ir, he := innerRequest(r, cs, plain); he != nil {
		writeJSON(cw, he.code, wire.ErrorResponse{Error: he.msg})
	} else {
		s.serveInner(cw, ir, sn, l)
	}
	if err := cw.Close(); err != nil {
		s.log.Debug("channel response not sent", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path, "error", err)
	}
	if cs.uploadOf() == nil {
		s.chans.drop(cs)
	}
}

// innerRequest is the request an OP carries, to the Host of the session
// and bound to it by the context. Its path must be the session path.
func innerRequest(r *http.Request, cs *chanSession, plain []byte) (*http.Request, *httpError) {
	rd := bytes.NewReader(plain)
	var req channel.Request
	if err := channel.ReadHead(rd, &req); err != nil {
		return nil, &httpError{code: http.StatusBadRequest, msg: err.Error()}
	}
	if req.Method == "" {
		return nil, &httpError{code: http.StatusBadRequest, msg: "operation without a method"}
	}
	u, err := url.ParseRequestURI(req.Target)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Path != cs.path {
		return nil, &httpError{code: http.StatusNotFound, msg: "not found"}
	}
	h := http.Header{}
	for k, vs := range req.Header {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	ir := &http.Request{
		Method: req.Method, URL: u, RequestURI: req.Target, Host: cs.host, Header: h,
		Proto: r.Proto, ProtoMajor: r.ProtoMajor, ProtoMinor: r.ProtoMinor,
		Body: io.NopCloser(rd), ContentLength: int64(rd.Len()),
		RemoteAddr: r.RemoteAddr, TLS: r.TLS,
	}
	return ir.WithContext(context.WithValue(r.Context(), ctxKey{}, cs)), nil
}

// serveInner runs an operation of the channel: the endpoint listing or an
// endpoint of l, the only paths a session has. The expose is never
// reached from here.
func (s *Server) serveInner(w http.ResponseWriter, r *http.Request, sn *snapshot, l *listener) {
	if r.URL.Path == wire.EndpointsPath {
		s.serveEndpoints(w, r, sn, l)
		return
	}
	ep, ok := endpointOf(l, r.URL.Path)
	s.serveEndpoint(w, r, sn, l, ep, ok)
}
