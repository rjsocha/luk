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
)

const (
	// DefaultSocket is the socket of lukd-run.socket.
	DefaultSocket = "/run/luk/run.sock"
	// MaxRequest caps the request line, newline included.
	MaxRequest = 4 << 10
	// MaxFrame caps the payload of one frame.
	MaxFrame = 1 << 20
	maxExit  = 16

	Stdout byte = 'o'
	Stderr byte = 'e'
	Exit   byte = 'x'
)

// Request asks for one job on a work directory.
type Request struct {
	Job  string `json:"job"`
	Work string `json:"work"`
}

// Encode is the request line.
func (r Request) Encode() []byte {
	b, _ := json.Marshal(r)
	return append(b, '\n')
}

// ReadRequest reads one request line of at most MaxRequest bytes. br must
// have a buffer of at least MaxRequest bytes.
func ReadRequest(br *bufio.Reader) (Request, error) {
	var r Request
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > MaxRequest {
		return r, fmt.Errorf("request larger than %d bytes", MaxRequest)
	}
	if err != nil {
		return r, fmt.Errorf("read request: %w", err)
	}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, fmt.Errorf("request: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return r, errors.New("request: trailing data")
	}
	return r, nil
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

// Ask asks lukd run at socket for job on work and relays the job's stdout
// and stderr. A non-zero exit status is an ExitError. A cancelled ctx
// closes the connection, which makes lukd run stop the job.
func Ask(ctx context.Context, socket, job, work string, stdout, stderr io.Writer) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err := conn.Write(Request{Job: job, Work: work}.Encode()); err != nil {
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
