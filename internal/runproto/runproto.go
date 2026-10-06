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
	"os"
	"strconv"
	"sync"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// DefaultSocket is the socket of lukd-run.socket.
	DefaultSocket = "/run/luk/run.sock"
	// MaxRequest caps the request line, newline included. A step request
	// of lukd process (a pipeline name, a step, a queue id, a job name and
	// the metadata environment after runstep.CleanStepMeta: no control
	// character, free-form values of at most 1 KiB, LUK_FILE a bare file
	// name) fits it even when every quote and backslash is escaped.
	MaxRequest = 32 << 10
	// MaxEnv caps the entries of the environment of a request.
	MaxEnv = 16
	// MaxFrame caps the payload of one frame.
	MaxFrame = 1 << 20
	maxExit  = 16

	Stdout  byte = 'o'
	Stderr  byte = 'e'
	Exit    byte = 'x'
	Started byte = 's'
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

// StepRequest asks for the unit of a step, or of a nested job of that
// step, on the workspace whose channel goes with the request. Env is the
// free-form metadata environment lukd process passes on; lukd run keeps
// only what runstep.CleanStepMeta allows of it.
type StepRequest struct {
	Pipeline string            `json:"pipeline"`
	Step     int               `json:"step"`
	ID       string            `json:"id"`
	Job      string            `json:"job,omitempty"` // a nested job of the step; empty for the step itself
	Env      map[string]string `json:"env"`
}

// Encode is the request line.
func (r StepRequest) Encode() []byte {
	if r.Env == nil {
		r.Env = map[string]string{}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(r)
	return b.Bytes()
}

// maxRights is room for more descriptors than a request may carry, so
// that a second one is seen and closed rather than truncated away.
var maxRights = unix.CmsgSpace(4 * 4)

// ReadStepRequest reads the request line and its one descriptor, which
// must be an AF_UNIX socket; extra bytes after the line, in the read of
// the line or already waiting behind it, are malformed. Bytes the peer
// sends later belong to whoever reads the connection next. Every received
// descriptor is closed on a refusal.
func ReadStepRequest(c *net.UnixConn) (StepRequest, *os.File, error) {
	buf := make([]byte, MaxRequest+1)
	oob := make([]byte, maxRights)
	var fds []int
	closeAll := func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}
	fail := func(err error) (StepRequest, *os.File, error) {
		closeAll()
		return StepRequest{}, nil, err
	}
	n, end := 0, -1
	for end < 0 && n < len(buf) {
		m, oobn, flags, _, err := c.ReadMsgUnix(buf[n:], oob)
		got, perr := rights(oob[:oobn])
		fds = append(fds, got...)
		switch {
		case perr != nil:
			return fail(fmt.Errorf("request: %w", perr))
		case flags&unix.MSG_CTRUNC != 0:
			return fail(errors.New("request: more than one descriptor"))
		case err != nil && err != io.EOF:
			return fail(fmt.Errorf("read request: %w", err))
		case m == 0:
			return fail(fmt.Errorf("read request: %w", io.ErrUnexpectedEOF))
		}
		end = bytes.IndexByte(buf[n:n+m], '\n')
		if end >= 0 {
			end += n
		}
		n += m
	}
	switch {
	case end < 0 || end >= MaxRequest:
		return fail(fmt.Errorf("request larger than %d bytes", MaxRequest))
	case end+1 < n:
		return fail(errors.New("request: data after the request line"))
	}
	more, err := pending(c)
	switch {
	case err != nil:
		return fail(fmt.Errorf("read request: %w", err))
	case more:
		return fail(errors.New("request: data after the request line"))
	case len(fds) == 0:
		return fail(errors.New("request: without its descriptor"))
	case len(fds) > 1:
		return fail(errors.New("request: more than one descriptor"))
	}
	r, err := decodeStepRequest(buf[:n])
	if err != nil {
		return fail(fmt.Errorf("request: %w", err))
	}
	if d, err := unix.GetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_DOMAIN); err != nil || d != unix.AF_UNIX {
		return fail(errors.New("request: descriptor is not a unix socket"))
	}
	return r, os.NewFile(uintptr(fds[0]), "channel"), nil
}

// rights is the descriptors of the SCM_RIGHTS messages of oob. It walks
// the headers itself so that the descriptors before a malformed header
// are returned, with the error, to be closed.
func rights(oob []byte) ([]int, error) {
	var fds []int
	for len(oob) > 0 {
		if len(oob) < unix.SizeofCmsghdr {
			return fds, errors.New("truncated control message")
		}
		var h unix.Cmsghdr
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&h)), unix.SizeofCmsghdr), oob)
		hdr, l := unix.CmsgLen(0), int(h.Len)
		if l < hdr {
			return fds, errors.New("malformed control message")
		}
		data := oob[hdr:min(l, len(oob))]
		if h.Level == unix.SOL_SOCKET && h.Type == unix.SCM_RIGHTS {
			for ; len(data) >= 4; data = data[4:] {
				fds = append(fds, int(int32(binary.NativeEndian.Uint32(data))))
			}
		}
		if l > len(oob) {
			return fds, errors.New("truncated control message")
		}
		oob = oob[min(unix.CmsgSpace(l-hdr), len(oob)):]
	}
	return fds, nil
}

// pending reports whether c has bytes waiting to be read, without
// reading or waiting for them.
func pending(c *net.UnixConn) (bool, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return false, err
	}
	var n int
	var rerr error
	err = rc.Read(func(fd uintptr) bool {
		var b [1]byte
		n, _, rerr = unix.Recvfrom(int(fd), b[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		return true
	})
	switch {
	case err != nil:
		return false, err
	case rerr == unix.EAGAIN:
		return false, nil
	case rerr != nil:
		return false, rerr
	}
	return n > 0, nil
}

// decodeStepRequest decodes b, valid UTF-8 holding exactly one flat JSON
// object: "pipeline" and "id" strings and "step" a number from 1, an
// optional "job" string and an optional "env" object of strings, at most
// MaxEnv of them. An unknown or repeated key, any other value and data
// after the object are refused.
func decodeStepRequest(b []byte) (StepRequest, error) {
	var r StepRequest
	if !utf8.Valid(b) {
		return r, errors.New("not valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
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
		case "pipeline":
			r.Pipeline, err = str(d)
		case "step":
			r.Step, err = stepNumber(d)
		case "id":
			r.ID, err = str(d)
		case "job":
			r.Job, err = str(d)
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
	if !seen["pipeline"] || !seen["step"] || !seen["id"] {
		return r, errors.New("pipeline, step and id required")
	}
	return r, nil
}

// stepNumber reads a JSON number that is an integer from 1.
func stepNumber(d *json.Decoder) (int, error) {
	t, err := d.Token()
	if err != nil {
		return 0, err
	}
	n, ok := t.(json.Number)
	if !ok {
		return 0, errors.New("not a step number")
	}
	i, err := strconv.Atoi(string(n))
	if err != nil || i < 1 {
		return 0, errors.New("not a step number")
	}
	return i, nil
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
	case h[0] != Stdout && h[0] != Stderr && h[0] != Exit && h[0] != Started:
		return 0, nil, fmt.Errorf("unknown frame type %q", h[0])
	case n > MaxFrame, h[0] == Exit && n > maxExit, h[0] == Started && n != 0:
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

// Started writes the empty started frame.
func (f *FrameWriter) Started() error { return f.write(Started, nil) }

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
	return relay(ctx, conn, nil, stdout, stderr)
}

// AskStep connects to socket, sends req with ch attached and relays the
// frames: started is called once on 's'; stdout and stderr get 'o' and
// 'e'. A non-zero exit is an ExitError. A cancelled ctx closes the
// connection.
func AskStep(ctx context.Context, socket string, req StepRequest, ch *os.File, started func(), stdout, stderr io.Writer) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer c.Close()
	conn := c.(*net.UnixConn)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	line := req.Encode()
	// Control, not Fd: Fd would put ch in blocking mode and end its
	// deadlines.
	rc, err := ch.SyscallConn()
	if err != nil {
		return err
	}
	var n int
	cerr := rc.Control(func(fd uintptr) {
		n, _, err = conn.WriteMsgUnix(line, unix.UnixRights(int(fd)), nil)
	})
	if cerr != nil {
		return cerr
	}
	if err == nil && n < len(line) {
		_, err = conn.Write(line[n:])
	}
	if err != nil {
		if ctx.Err() != nil {
			return errors.New("interrupted, job stopped")
		}
		return err
	}
	return relay(ctx, conn, started, stdout, stderr)
}

// relay reads the frames of conn up to the exit frame. A started frame is
// refused when started is nil and when it comes twice.
func relay(ctx context.Context, conn net.Conn, started func(), stdout, stderr io.Writer) error {
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
		case Started:
			if started == nil {
				return fmt.Errorf("unexpected frame %q", typ)
			}
			started()
			started = nil
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
