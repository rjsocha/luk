// Package runproto is the protocol between lukd run and its clients (luk-job
// run, relay steps): one request line, then frames of the job's stdout,
// stderr and exit code.
package runproto

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"unicode/utf8"
)

const (
	// DefaultSocket is the socket of lukd-run.socket.
	DefaultSocket = "/run/luk/run.sock"
	// MaxRequest caps the request line, newline included. A client's
	// request (a job name, a work path, the metadata environment with
	// values of at most 1 KiB) fits it even when every byte is escaped.
	MaxRequest = 32 << 10
	// MaxEnv caps the entries of the environment of a request.
	MaxEnv = 16
	// MaxFrame caps the payload of one frame.
	MaxFrame = 1 << 20
	maxExit  = 16

	Stdout byte = 'o'
	Stderr byte = 'e'
	Exit   byte = 'x'
)

// Request asks for one job on a work directory. Env is the free-form
// metadata environment the client passes on; lukd run keeps only what
// runstep.CleanMeta allows of it.
type Request struct {
	Job  string            `json:"job"`
	Work string            `json:"work"`
	Env  map[string]string `json:"env"`
}

// Encode is the request line.
func (r Request) Encode() []byte {
	if r.Env == nil {
		r.Env = map[string]string{}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(r)
	return b.Bytes()
}

// ReadRequest reads one request line of at most MaxRequest bytes. br must
// have a buffer of at least MaxRequest bytes.
func ReadRequest(br *bufio.Reader) (Request, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > MaxRequest {
		return Request{}, fmt.Errorf("request larger than %d bytes", MaxRequest)
	}
	if err != nil {
		return Request{}, fmt.Errorf("read request: %w", err)
	}
	r, err := decodeRequest(line)
	if err != nil {
		return Request{}, fmt.Errorf("request: %w", err)
	}
	return r, nil
}

// decodeRequest decodes b, valid UTF-8 holding exactly one flat JSON
// object: "job" and "work" strings, an optional "env" object of strings,
// at most MaxEnv of them. An unknown or repeated key, any other value and
// data after the object are refused.
func decodeRequest(b []byte) (Request, error) {
	var r Request
	if !utf8.Valid(b) {
		return r, errors.New("not valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if err := delim(d, '{'); err != nil {
		return r, err
	}
	seen := map[string]bool{}
	for d.More() {
		k, err := str(d)
		if err != nil {
			return r, err
		}
		if seen[k] {
			return r, fmt.Errorf("key %q repeated", k)
		}
		seen[k] = true
		switch k {
		case "job":
			r.Job, err = str(d)
		case "work":
			r.Work, err = str(d)
		case "env":
			r.Env, err = strMap(d)
		default:
			return r, fmt.Errorf("unknown key %q", k)
		}
		if err != nil {
			return r, fmt.Errorf("%s: %w", k, err)
		}
	}
	if err := delim(d, '}'); err != nil {
		return r, err
	}
	if _, err := d.Token(); err != io.EOF {
		return r, errors.New("trailing data")
	}
	if !seen["job"] || !seen["work"] {
		return r, errors.New("job and work required")
	}
	return r, nil
}

// strMap reads an object of strings, without a repeated key, of at most
// MaxEnv entries.
func strMap(d *json.Decoder) (map[string]string, error) {
	if err := delim(d, '{'); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for d.More() {
		k, err := str(d)
		if err != nil {
			return nil, err
		}
		if _, ok := m[k]; ok {
			return nil, fmt.Errorf("key %q repeated", k)
		}
		if len(m) == MaxEnv {
			return nil, fmt.Errorf("more than %d entries", MaxEnv)
		}
		if m[k], err = str(d); err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
	}
	return m, delim(d, '}')
}

func str(d *json.Decoder) (string, error) {
	t, err := d.Token()
	if err != nil {
		return "", err
	}
	s, ok := t.(string)
	if !ok {
		return "", errors.New("not a string")
	}
	return s, nil
}

func delim(d *json.Decoder, want json.Delim) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	if t != want {
		return fmt.Errorf("want %v", want)
	}
	return nil
}

// WriteFrame writes one frame: type, 4 byte big-endian length, payload.
func WriteFrame(w io.Writer, typ byte, p []byte) error {
	if len(p) > MaxFrame {
		return fmt.Errorf("frame of %d bytes", len(p))
	}
	b := make([]byte, 5+len(p))
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:5], uint32(len(p)))
	copy(b[5:], p)
	_, err := w.Write(b)
	return err
}

// ReadFrame reads one frame. io.EOF means the stream ended between frames.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			err = errors.New("truncated frame")
		}
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	switch {
	case h[0] != Stdout && h[0] != Stderr && h[0] != Exit:
		return 0, nil, fmt.Errorf("unknown frame type %q", h[0])
	case n > MaxFrame, h[0] == Exit && n > maxExit:
		return 0, nil, fmt.Errorf("frame %q of %d bytes", h[0], n)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, errors.New("truncated frame")
	}
	return h[0], p, nil
}

// ExitCode parses the payload of an exit frame.
func ExitCode(p []byte) (int, error) {
	c, err := strconv.Atoi(string(p))
	if err != nil || c < 0 || c > 255 {
		return 0, fmt.Errorf("bad exit status %q", p)
	}
	return c, nil
}

// FrameWriter serializes the frames of several streams on one connection.
type FrameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func NewFrameWriter(w io.Writer) *FrameWriter { return &FrameWriter{w: w} }

func (f *FrameWriter) write(typ byte, p []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return WriteFrame(f.w, typ, p)
}

// Stream is a writer whose writes become frames of typ.
func (f *FrameWriter) Stream(typ byte) io.Writer { return stream{f, typ} }

// Exit writes the exit frame.
func (f *FrameWriter) Exit(code int) error {
	return f.write(Exit, []byte(strconv.Itoa(code)))
}

type stream struct {
	f   *FrameWriter
	typ byte
}

func (s stream) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		c := p[:min(len(p), MaxFrame)]
		if err := s.f.write(s.typ, c); err != nil {
			return n, err
		}
		n += len(c)
		p = p[len(c):]
	}
	return n, nil
}

// ExitError is the non-zero exit status of a job.
type ExitError int

func (e ExitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// Ask sends req to lukd run at socket and relays the job's stdout
// and stderr. A non-zero exit status is an ExitError. A cancelled ctx
// closes the connection, which makes lukd run stop the job.
func Ask(ctx context.Context, socket string, req Request, stdout, stderr io.Writer) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err := conn.Write(req.Encode()); err != nil {
		return err
	}
	for {
		typ, p, err := ReadFrame(conn)
		if ctx.Err() != nil {
			return errors.New("interrupted, job stopped")
		}
		if err == io.EOF {
			return errors.New("connection closed before the exit status")
		}
		if err != nil {
			return err
		}
		switch typ {
		case Stdout:
			_, err = stdout.Write(p)
		case Stderr:
			_, err = stderr.Write(p)
		case Exit:
			c, err := ExitCode(p)
			if err != nil {
				return err
			}
			if c != 0 {
				return ExitError(c)
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}
