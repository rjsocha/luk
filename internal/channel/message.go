package channel

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// maxHead bounds the JSON part of an inner message, so that a peer cannot
// make the other side buffer an unbounded head.
const maxHead = 65536

// Request is the head of an OP request inside the channel.
type Request struct {
	Method string      `json:"method"`
	Target string      `json:"target"`
	Header http.Header `json:"header"`
}

// Response is the head of every response inside the channel.
type Response struct {
	Status int         `json:"status"`
	Header http.Header `json:"header"`
}

// WriteHead writes v as a uint32 big-endian length and its JSON.
func WriteHead(w io.Writer, v any) error {
	j, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(j) > maxHead {
		return fmt.Errorf("channel: message head of %d bytes over %d", len(j), maxHead)
	}
	_, err = w.Write(binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(j)), uint32(len(j))))
	if err == nil {
		_, err = w.Write(j)
	}
	return err
}

// ReadHead reads a head written by WriteHead into v. It reads exactly the
// head, leaving the body in r, and refuses unknown fields and trailing data
// so that both sides agree on what a head means.
func ReadHead(r io.Reader, v any) error {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return fmt.Errorf("channel: message head: %w", err)
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > maxHead {
		return fmt.Errorf("channel: message head of %d bytes over %d", n, maxHead)
	}
	j := make([]byte, n)
	if _, err := io.ReadFull(r, j); err != nil {
		return fmt.Errorf("channel: message head: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("channel: message head: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("channel: message head: data after the JSON value")
	}
	return nil
}
