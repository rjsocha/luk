// Package chantest runs a stand-in for lukd that speaks the channel, for
// the tests of clients whose answers a real lukd does not give: it answers
// the OP with a handler of the test, takes the parts of an upload it
// offered, and answers the COMPLETE with what the test makes of the
// content.
package chantest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"luk/internal/channel"
	"luk/internal/wire"
)

// Answer is an inner response: a status, its header and a JSON body
// (nil: none).
type Answer struct {
	Status int
	Body   any
	Header http.Header
}

// Server is the stand-in. Set its handlers before the first request.
type Server struct {
	*httptest.Server
	Key channel.Key
	// Op answers an OP; a nil answer offers the content in parts.
	Op func(req channel.Request, body []byte) *Answer
	// Complete answers the COMPLETE n with the parts received, joined in
	// the order of their numbers.
	Complete func(req channel.Request, n channel.Nonce, content []byte) Answer
	// PartAnswer, when set, answers a PART once it was read; nil keeps
	// the part and answers 200.
	PartAnswer func(n channel.Nonce, data []byte) *Answer
	// Abort, when set, answers an ABORT; nil answers 200.
	Abort func(n channel.Nonce) *Answer
	// Part, when set, runs when a PART arrives, before it is read; true
	// lets the PART go on.
	Part func(w http.ResponseWriter, r *http.Request, n channel.Nonce) bool
	// Message, when set, runs when any message arrives, before it is read
	// and before Part; true lets the message go on.
	Message func(w http.ResponseWriter, r *http.Request, n channel.Nonce) bool
	// Header is set on every outer response, Date for instance.
	Header http.Header
	// Fallback, when set, serves the requests that are not of the
	// channel.
	Fallback http.Handler
	// PartSize, Parallel and Idle (seconds) are the offer; zero is 64KiB,
	// 4 and 120. Rate (bytes per second) goes into the offer as it is.
	PartSize int64
	Parallel int
	Idle     int64
	Rate     int64

	mu    sync.Mutex
	sess  map[[16]byte]*session
	kinds map[channel.Kind]int
}

type session struct {
	s     *channel.Session
	req   channel.Request
	parts map[uint32][]byte
}

// New starts a Server over plain HTTP; it stops with the test.
func New(t testing.TB) *Server {
	t.Helper()
	k, err := channel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Key: k, sess: map[[16]byte]*session{}, kinds: map[channel.Kind]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Pin is the words pin of the key of s.
func (s *Server) Pin() string { return channel.Words(s.Key.Public) }

// Count is the number of messages of kind k that arrived.
func (s *Server) Count(k channel.Kind) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kinds[k]
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if s.Fallback != nil && (r.Method != http.MethodPost || r.Header.Get("Content-Type") != channel.ContentType) {
		s.Fallback.ServeHTTP(w, r)
		return
	}
	for k, v := range s.Header {
		w.Header()[k] = v
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if body[0] == 0x01 {
		sess, msg, err := channel.ServerHandshake(s.Key, strings.ToLower(r.Host), r.URL.Path, body)
		if err != nil {
			http.Error(w, `{"error":"bad handshake"}`, http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.sess[sess.ID()] = &session{s: sess, parts: map[uint32][]byte{}}
		s.mu.Unlock()
		w.Header().Set("Content-Type", channel.ContentType)
		w.Write(msg)
		return
	}
	rd := bytes.NewReader(body)
	id, n, hdr, err := channel.ParseRequestHeader(rd)
	s.mu.Lock()
	cs := s.sess[id]
	if err == nil {
		s.kinds[n.Kind]++
	}
	s.mu.Unlock()
	if err != nil || cs == nil {
		http.Error(w, `{"error":"unknown session"}`, http.StatusNotFound)
		return
	}
	if s.Message != nil && !s.Message(w, r, n) {
		return
	}
	if n.Kind == channel.KindPart && s.Part != nil && !s.Part(w, r, n) {
		return
	}
	plain, err := io.ReadAll(cs.s.OpenRequest(rd, hdr, n))
	if err != nil {
		http.Error(w, `{"error":"bad channel message"}`, http.StatusBadRequest)
		return
	}
	var a Answer
	switch n.Kind {
	case channel.KindOp:
		pr := bytes.NewReader(plain)
		if err := channel.ReadHead(pr, &cs.req); err != nil {
			a = Answer{Status: http.StatusBadRequest, Body: wire.ErrorResponse{Error: err.Error()}}
			break
		}
		rest, _ := io.ReadAll(pr)
		if op := s.Op(cs.req, rest); op != nil {
			a = *op
			break
		}
		var offer wire.PartsOffer
		offer.Parts.Size, offer.Parts.Parallel = s.PartSize, s.Parallel
		offer.Parts.Idle, offer.Parts.Rate = s.Idle, s.Rate
		if offer.Parts.Size == 0 {
			offer.Parts.Size = 64 << 10
		}
		if offer.Parts.Parallel == 0 {
			offer.Parts.Parallel = 4
		}
		if offer.Parts.Idle == 0 {
			offer.Parts.Idle = 120
		}
		a = Answer{Status: http.StatusOK, Body: offer}
	case channel.KindPart:
		if s.PartAnswer != nil {
			if pa := s.PartAnswer(n, plain); pa != nil {
				a = *pa
				break
			}
		}
		s.mu.Lock()
		cs.parts[n.Number] = plain
		s.mu.Unlock()
		a = Answer{Status: http.StatusOK, Body: struct{}{}}
	case channel.KindComplete:
		s.mu.Lock()
		nums := make([]uint32, 0, len(cs.parts))
		for k := range cs.parts {
			nums = append(nums, k)
		}
		sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
		var content []byte
		for _, k := range nums {
			content = append(content, cs.parts[k]...)
		}
		s.mu.Unlock()
		a = s.Complete(cs.req, n, content)
	case channel.KindAbort:
		a = Answer{Status: http.StatusOK, Body: struct{}{}}
		if s.Abort != nil {
			if aa := s.Abort(n); aa != nil {
				a = *aa
			}
		}
	default:
		a = Answer{Status: http.StatusOK, Body: struct{}{}}
	}
	w.Header().Set("Content-Type", channel.ContentType)
	fw, err := cs.s.SealResponse(w, n)
	if err != nil {
		return
	}
	h := a.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	var out []byte
	if a.Body != nil {
		h.Set("Content-Type", "application/json")
		out, _ = json.Marshal(a.Body)
	}
	channel.WriteHead(fw, channel.Response{Status: a.Status, Header: h})
	fw.Write(out)
	fw.Close()
}
