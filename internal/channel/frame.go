package channel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/flynn/noise"
)

const (
	// ContentType is the media type of every channel request and response.
	ContentType = "application/vnd.luk.channel"
	// FrameSize is the plaintext size of every frame but the final one.
	FrameSize = 65536

	typeHandshake = 0x01
	typeTransport = 0x02
	tagSize       = 16
	sealedFrame   = FrameSize + tagSize
	idSize        = 16
	// requestHeaderSize is 0x02 || channel id || nonce.
	requestHeaderSize = 1 + idSize + 8
	// responseHeaderSize is 0x02 || counter.
	responseHeaderSize = 1 + 8
	maxResponseFrame   = 1<<31 - 1
)

var errTruncated = errors.New("channel: stream truncated")

// Session holds the keys and ids after the handshake. The ciphers are
// stateless AEADs used with explicit nonces only, so a session is safe for
// concurrent use.
type Session struct {
	send, recv noise.Cipher
	h          []byte
	id         [idSize]byte
	// counter is the last response counter taken on lukd.
	counter atomic.Uint32
}

func newSession(sendKey, recvKey [32]byte, h []byte) *Session {
	return sessionFrom(noise.CipherChaChaPoly.Cipher(sendKey), noise.CipherChaChaPoly.Cipher(recvKey), h)
}

func sessionFrom(send, recv noise.Cipher, h []byte) *Session {
	s := &Session{send: send, recv: recv, h: h}
	sum := sha256.Sum256(append([]byte("luk channel id"), h...))
	copy(s.id[:], sum[:idSize])
	return s
}

// H is the final handshake hash, which signed texts inside the channel
// carry to bind a signature to this session.
func (s *Session) H() []byte { return s.h }

// ID names the session in the clear header of every request.
func (s *Session) ID() [idSize]byte { return s.id }

// SealRequest writes a transport request: the clear header, then the body
// in frames. n.Frame and n.Last are set per frame.
func (s *Session) SealRequest(w io.Writer, n Nonce, body io.Reader) error {
	n = n.base()
	hdr := make([]byte, requestHeaderSize, requestHeaderSize+sealedFrame)
	hdr[0] = typeTransport
	copy(hdr[1:], s.id[:])
	binary.BigEndian.PutUint64(hdr[1+idSize:], n.Uint64())
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	pt := make([]byte, FrameSize)
	out := make([]byte, 0, sealedFrame)
	for frame := 0; ; frame++ {
		k, err := io.ReadFull(body, pt)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		if frame > maxFrame {
			return fmt.Errorf("channel: request body over %d frames", maxFrame+1)
		}
		// A full chunk is never final: the reader tells the final frame by
		// its short length, so data that is a multiple of FrameSize ends
		// with an empty frame.
		last := k < FrameSize
		fn := n
		fn.Frame, fn.Last = uint16(frame), last
		out = s.send.Encrypt(out[:0], fn.Uint64(), hdr, pt[:k])
		if _, err := w.Write(out); err != nil {
			return err
		}
		if last {
			return nil
		}
	}
}

// ParseRequestHeader reads the clear header of a transport request. The
// header carries the nonce of the request as a whole: frame and last bits
// set there are refused.
func ParseRequestHeader(r io.Reader) (id [idSize]byte, n Nonce, hdr []byte, err error) {
	hdr = make([]byte, requestHeaderSize)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return id, n, nil, fmt.Errorf("channel: request header: %w", err)
	}
	if hdr[0] != typeTransport {
		return id, n, nil, fmt.Errorf("channel: request type %#x, want %#x", hdr[0], typeTransport)
	}
	copy(id[:], hdr[1:])
	if n, err = ParseNonce(binary.BigEndian.Uint64(hdr[1+idSize:])); err != nil {
		return id, Nonce{}, nil, err
	}
	if n != n.base() {
		return id, Nonce{}, nil, errors.New("channel: request header nonce has frame bits")
	}
	return id, n, hdr, nil
}

// OpenRequest returns the decrypted body of a request whose clear header
// ParseRequestHeader has read. Nothing is read before the first Read.
func (s *Session) OpenRequest(r io.Reader, hdr []byte, n Nonce) io.Reader {
	n = n.base()
	return &frameReader{r: r, maxFrame: maxFrame, open: func(dst []byte, frame uint32, last bool, ct []byte) ([]byte, error) {
		fn := n
		fn.Frame, fn.Last = uint16(frame), last
		return s.recv.Decrypt(dst, fn.Uint64(), hdr, ct)
	}}
}

// takeCounter returns the next response counter. Counters are never
// reused, so a session that has used all of them answers no more.
func (s *Session) takeCounter() (uint32, error) {
	for {
		c := s.counter.Load()
		if c == 1<<32-1 {
			return 0, errors.New("channel: session response counters exhausted")
		}
		if s.counter.CompareAndSwap(c, c+1) {
			return c + 1, nil
		}
	}
}

// responseAD binds a response to its session, its request and its counter.
func (s *Session) responseAD(req Nonce, counter uint32) []byte {
	ad := make([]byte, 0, 1+idSize+8+8)
	ad = append(ad, typeTransport)
	ad = append(ad, s.id[:]...)
	ad = binary.BigEndian.AppendUint64(ad, req.base().Uint64())
	return binary.BigEndian.AppendUint64(ad, uint64(counter))
}

// SealResponse takes the next counter and writes the clear response
// header. Frames are written as the body is written, the final frame on
// Close; Close does not close w.
func (s *Session) SealResponse(w io.Writer, req Nonce) (io.WriteCloser, error) {
	counter, err := s.takeCounter()
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, responseHeaderSize)
	hdr[0] = typeTransport
	binary.BigEndian.PutUint64(hdr[1:], uint64(counter))
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return &frameWriter{
		w:       w,
		cipher:  s.send,
		ad:      s.responseAD(req, counter),
		counter: counter,
		buf:     make([]byte, 0, FrameSize),
		out:     make([]byte, 0, sealedFrame),
	}, nil
}

// OpenResponse reads the clear response header and returns the decrypted
// body. Truncation and tampering surface as errors on Read; Close closes r
// when it is an io.Closer.
func (s *Session) OpenResponse(r io.Reader, req Nonce) (io.ReadCloser, error) {
	hdr := make([]byte, responseHeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("channel: response header: %w", err)
	}
	if hdr[0] != typeTransport {
		return nil, fmt.Errorf("channel: response type %#x, want %#x", hdr[0], typeTransport)
	}
	c := binary.BigEndian.Uint64(hdr[1:])
	if c == 0 || c >= 1<<32 {
		return nil, fmt.Errorf("channel: response counter %d out of range", c)
	}
	counter := uint32(c)
	ad := s.responseAD(req, counter)
	fr := &frameReader{r: r, maxFrame: maxResponseFrame, open: func(dst []byte, frame uint32, last bool, ct []byte) ([]byte, error) {
		return s.recv.Decrypt(dst, ResponseNonce(counter, frame, last), ad, ct)
	}}
	return fr, nil
}

type frameWriter struct {
	w       io.Writer
	cipher  noise.Cipher
	ad      []byte
	counter uint32
	frame   uint32
	buf     []byte
	out     []byte
	closed  bool
	err     error
}

func (fw *frameWriter) Write(p []byte) (int, error) {
	if fw.closed {
		return 0, errors.New("channel: write after close")
	}
	if fw.err != nil {
		return 0, fw.err
	}
	written := 0
	for len(p) > 0 {
		k := copy(fw.buf[len(fw.buf):FrameSize], p)
		fw.buf = fw.buf[:len(fw.buf)+k]
		p, written = p[k:], written+k
		if len(fw.buf) == FrameSize {
			if err := fw.flush(false); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (fw *frameWriter) flush(last bool) error {
	if fw.frame > maxResponseFrame {
		fw.err = fmt.Errorf("channel: response body over %d frames", maxResponseFrame+1)
		return fw.err
	}
	fw.out = fw.cipher.Encrypt(fw.out[:0], ResponseNonce(fw.counter, fw.frame, last), fw.ad, fw.buf)
	fw.buf = fw.buf[:0]
	fw.frame++
	if _, err := fw.w.Write(fw.out); err != nil {
		fw.err = err
	}
	return fw.err
}

// Close writes the final frame, which carries what Write has buffered.
func (fw *frameWriter) Close() error {
	if fw.closed {
		return fw.err
	}
	fw.closed = true
	if fw.err != nil {
		return fw.err
	}
	return fw.flush(true)
}

// frameReader decrypts a stream of frames. A frame shorter than a sealed
// full frame is the final one; a stream that ends after a full frame is
// truncated. Errors are sticky.
type frameReader struct {
	r        io.Reader
	maxFrame uint32
	open     func(dst []byte, frame uint32, last bool, ct []byte) ([]byte, error)
	frame    uint32
	ct, pt   []byte
	pending  []byte
	done     bool
	err      error
}

func (fr *frameReader) Read(p []byte) (int, error) {
	for len(fr.pending) == 0 {
		if fr.err != nil {
			return 0, fr.err
		}
		if fr.done {
			return 0, io.EOF
		}
		fr.err = fr.next()
	}
	n := copy(p, fr.pending)
	fr.pending = fr.pending[n:]
	return n, nil
}

func (fr *frameReader) next() error {
	if fr.ct == nil {
		fr.ct = make([]byte, sealedFrame)
		fr.pt = make([]byte, 0, FrameSize)
	}
	k, err := io.ReadFull(fr.r, fr.ct)
	switch err {
	case nil, io.ErrUnexpectedEOF:
	case io.EOF:
		return errTruncated
	default:
		return err
	}
	if fr.frame > fr.maxFrame {
		return errors.New("channel: too many frames")
	}
	last := k < sealedFrame
	pt, err := fr.open(fr.pt[:0], fr.frame, last, fr.ct[:k])
	if err != nil {
		return fmt.Errorf("channel: frame %d: %w", fr.frame, err)
	}
	fr.frame++
	fr.pending, fr.done = pt, last
	return nil
}

// Close closes the underlying reader when it is an io.Closer.
func (fr *frameReader) Close() error {
	if c, ok := fr.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
