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

// Answer is an inner response: a status and a JSON body (nil: none).
type Answer struct {
	Status int
	Body   any
}

// Server is the stand-in. Set its handlers before the first request.
type Server struct {
	*httptest.Server
	Key channel.Key
	// Op answers an OP; a nil answer offers the content in parts.
	Op func(req channel.Request, body []byte) *Answer
	// Complete answers a COMPLETE with the parts received, joined in
	// the order of their numbers.
	Complete func(req channel.Request, content []byte) Answer
	// Part, when set, runs when a PART arrives, before it is read; true
	// lets the PART go on.
	Part func(w http.ResponseWriter, r *http.Request, n channel.Nonce) bool
	// Header is set on every outer response, Date for instance.
	Header http.Header
	// Fallback, when set, serves the requests that are not of the
	// channel.
	Fallback http.Handler
	// PartSize and Parallel are the offer; zero is 64KiB and 4.
	PartSize int64
	Parallel int

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
			a = Answer{http.StatusBadRequest, wire.ErrorResponse{Error: err.Error()}}
			break
		}
		rest, _ := io.ReadAll(pr)
		if op := s.Op(cs.req, rest); op != nil {
			a = *op
			break
		}
		var offer wire.PartsOffer
		offer.Parts.Size, offer.Parts.Parallel = s.PartSize, s.Parallel
		if offer.Parts.Size == 0 {
			offer.Parts.Size = 64 << 10
		}
		if offer.Parts.Parallel == 0 {
			offer.Parts.Parallel = 4
		}
		a = Answer{http.StatusOK, offer}
	case channel.KindPart:
		s.mu.Lock()
		cs.parts[n.Number] = plain
		s.mu.Unlock()
		a = Answer{http.StatusOK, struct{}{}}
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
		a = s.Complete(cs.req, content)
	default:
		a = Answer{http.StatusOK, struct{}{}}
	}
	w.Header().Set("Content-Type", channel.ContentType)
	fw, err := cs.s.SealResponse(w, n)
	if err != nil {
		return
	}
	h := http.Header{}
	var out []byte
	if a.Body != nil {
		h.Set("Content-Type", "application/json")
		out, _ = json.Marshal(a.Body)
	}
	channel.WriteHead(fw, channel.Response{Status: a.Status, Header: h})
	fw.Write(out)
	fw.Close()
}
