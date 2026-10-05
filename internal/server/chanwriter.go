package server

import (
	"io"
	"net/http"

	"luk/internal/channel"
)

// chanWriter is the http.ResponseWriter of an operation inside the
// channel: the status and the header become the head of the inner
// response, the body its frames. The outer response is a 200 from the
// first byte on, whatever the inner status.
type chanWriter struct {
	outer  http.ResponseWriter
	fw     io.WriteCloser
	header http.Header
	wrote  bool
	err    error
}

// newChanWriter starts the outer response to the request of nonce n. On
// an error nothing is written to w yet.
func newChanWriter(w http.ResponseWriter, sess *channel.Session, n channel.Nonce) (*chanWriter, error) {
	w.Header().Set("Content-Type", channel.ContentType)
	fw, err := sess.SealResponse(w, n)
	if err != nil {
		w.Header().Del("Content-Type")
		return nil, err
	}
	return &chanWriter{outer: w, fw: fw, header: http.Header{}}, nil
}

func (cw *chanWriter) Header() http.Header { return cw.header }

// WriteHeader writes the head of the inner response once; later calls
// are ignored as on any http.ResponseWriter.
func (cw *chanWriter) WriteHeader(code int) {
	if cw.wrote {
		return
	}
	cw.wrote = true
	cw.err = channel.WriteHead(cw.fw, channel.Response{Status: code, Header: cw.header.Clone()})
}

func (cw *chanWriter) Write(p []byte) (int, error) {
	if !cw.wrote {
		cw.WriteHeader(http.StatusOK)
	}
	if cw.err != nil {
		return 0, cw.err
	}
	n, err := cw.fw.Write(p)
	cw.err = err
	return n, err
}

// Flush sends the complete frames written so far; the open frame goes out
// when it is full or on Close.
func (cw *chanWriter) Flush() {
	if f, ok := cw.outer.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the connection, so the read
// and write deadlines of the handlers apply to the outer request.
func (cw *chanWriter) Unwrap() http.ResponseWriter { return cw.outer }

// Close ends the inner response: a handler that wrote nothing answers an
// empty 200.
func (cw *chanWriter) Close() error {
	if !cw.wrote {
		cw.WriteHeader(http.StatusOK)
	}
	if err := cw.fw.Close(); cw.err == nil {
		cw.err = err
	}
	return cw.err
}
