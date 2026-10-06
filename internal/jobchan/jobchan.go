// Package jobchan is the channel between lukd process and the wrapper of
// a unit of lukd run (and between luk-job run and that wrapper): a
// SOCK_SEQPACKET socket, one JSON line per packet of at most MaxPacket
// bytes, with at most one descriptor (SCM_RIGHTS), present exactly on the
// frames that carry a file (meta, in, out). See SPEC, Service, Channel of
// a unit.
package jobchan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	MaxPacket = 64 << 10
	MaxFiles  = 1024
	ResultGap = time.Minute
)

const (
	TMeta    = "meta"
	TIn      = "in"
	TGo      = "go"
	TStatus  = "status"
	TOut     = "out"
	TRefuse  = "refuse"
	TEnd     = "end"
	TJob     = "job"
	TStop    = "stop"
	TStdout  = "o"
	TStderr  = "e"
	TExit    = "exit"
	TRefused = "refused"
)

type Frame struct {
	T      string `json:"t"`
	Name   string `json:"name,omitempty"`
	Job    string `json:"job,omitempty"`
	Reason string `json:"reason,omitempty"`
	Fail   string `json:"fail,omitempty"`
	Status *int   `json:"status,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

// Status returns a pointer to n, for Frame.Status.
func Status(n int) *int { return &n }

var withFile = map[string]bool{TMeta: true, TIn: true, TOut: true}

func needName(f Frame) error {
	if f.Name == "" {
		return fmt.Errorf("frame %s: needs a name", f.T)
	}
	return nil
}

func needStatus(f Frame) error {
	if f.Status == nil {
		return fmt.Errorf("frame %s: needs a status", f.T)
	}
	return nil
}

func needJob(f Frame) error {
	if f.Job == "" {
		return fmt.Errorf("frame %s: needs a job", f.T)
	}
	return nil
}

func none(Frame) error { return nil }

// known holds the rules of each type: the fields it needs.
var known = map[string]func(Frame) error{
	TMeta: none, TIn: needName, TGo: none, TStatus: needStatus,
	TOut: needName, TRefuse: needName, TEnd: none, TJob: needJob,
	TStop: none, TStdout: none, TStderr: none, TExit: needStatus,
	TRefused: none,
}

func check(f Frame) error {
	rule, ok := known[f.T]
	if !ok {
		return fmt.Errorf("frame: unknown frame %q", f.T)
	}
	if f.Data != nil && f.T != TStdout && f.T != TStderr {
		return fmt.Errorf("frame %s: data only on o and e", f.T)
	}
	return rule(f)
}

// Decode parses one packet: a JSON object of known fields and a newline.
func Decode(b []byte) (Frame, error) {
	var f Frame
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return f, errors.New("frame: no newline at the end")
	}
	if !utf8.Valid(b) {
		return f, errors.New("frame: not valid UTF-8")
	}
	if t := bytes.TrimSpace(b); len(t) == 0 || t[0] != '{' {
		return f, errors.New("frame: not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("frame: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return f, errors.New("frame: trailing data")
	}
	return f, check(f)
}

// Encode renders f as one packet.
func Encode(f Frame) ([]byte, error) {
	if err := check(f); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	if b.Len() > MaxPacket {
		return nil, fmt.Errorf("frame %s: larger than %d bytes", f.T, MaxPacket)
	}
	return b.Bytes(), nil
}

// Conn is one end of a channel.
type Conn struct{ c *net.UnixConn }

// Pair creates a channel: the local end, and the remote end as a file to
// pass on (SCM_RIGHTS, stdin of a unit). The caller closes the file once
// passed.
func Pair() (*Conn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("channel: %w", err)
	}
	local := os.NewFile(uintptr(fds[0]), "channel")
	remote := os.NewFile(uintptr(fds[1]), "channel")
	c, err := FromFile(local)
	local.Close()
	if err != nil {
		remote.Close()
		return nil, nil, err
	}
	return c, remote, nil
}

// FromFile makes a Conn of a received or inherited end. The Conn holds
// its own descriptor: the caller still closes f.
func FromFile(f *os.File) (*Conn, error) {
	nc, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("channel: %w", err)
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok || uc.LocalAddr() == nil || uc.LocalAddr().Network() != "unixpacket" {
		nc.Close()
		return nil, errors.New("channel: not a SOCK_SEQPACKET socket")
	}
	return &Conn{c: uc}, nil
}

// inDir names name in the directory dir through /proc/self/fd, so the
// socket path stays short whatever the depth of dir.
func inDir(dir *os.File, name string) string {
	return filepath.Join("/proc/self/fd", strconv.FormatUint(uint64(dir.Fd()), 10), name)
}

// ListenIn listens on the socket name in the directory dir. Closing the
// listener removes the socket; dir has to stay open until then.
func ListenIn(dir *os.File, name string) (*net.UnixListener, error) {
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: inDir(dir, name), Net: "unixpacket"})
	runtime.KeepAlive(dir)
	if err != nil {
		return nil, fmt.Errorf("channel: %w", err)
	}
	l.SetUnlinkOnClose(true)
	return l, nil
}

// DialIn connects to the socket name in the directory dir.
func DialIn(dir *os.File, name string) (*Conn, error) {
	c, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: inDir(dir, name), Net: "unixpacket"})
	runtime.KeepAlive(dir)
	if err != nil {
		return nil, fmt.Errorf("channel: %w", err)
	}
	return &Conn{c: c}, nil
}

// Accept waits for the next peer of l.
func Accept(l *net.UnixListener) (*Conn, error) {
	c, err := l.AcceptUnix()
	if err != nil {
		return nil, err
	}
	return &Conn{c: c}, nil
}

// Send writes f as one packet, with file as its descriptor: present
// exactly on meta, in and out.
func (c *Conn) Send(f Frame, file *os.File) error {
	if withFile[f.T] != (file != nil) {
		if file == nil {
			return fmt.Errorf("frame %s: without its descriptor", f.T)
		}
		return fmt.Errorf("frame %s: takes no descriptor", f.T)
	}
	b, err := Encode(f)
	if err != nil {
		return err
	}
	if file == nil {
		_, _, err = c.c.WriteMsgUnix(b, nil, nil)
		return err
	}
	rc, err := file.SyscallConn()
	if err != nil {
		return err
	}
	if cerr := rc.Control(func(fd uintptr) {
		_, _, err = c.c.WriteMsgUnix(b, unix.UnixRights(int(fd)), nil)
	}); cerr != nil {
		return cerr
	}
	return err
}

// rights returns the descriptors of the control messages; on an error
// also those parsed until then, for the caller to close.
func rights(oob []byte) ([]int, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("frame: control message: %w", err)
	}
	var fds []int
	for i := range msgs {
		if msgs[i].Header.Level != unix.SOL_SOCKET || msgs[i].Header.Type != unix.SCM_RIGHTS {
			continue
		}
		got, err := unix.ParseUnixRights(&msgs[i])
		if err != nil {
			return fds, fmt.Errorf("frame: control message: %w", err)
		}
		fds = append(fds, got...)
	}
	return fds, nil
}

// Recv reads one packet. Every received descriptor has close-on-exec
// (Go reads with MSG_CMSG_CLOEXEC); a refused packet closes them all.
// Recv returns io.EOF when the peer closed.
func (c *Conn) Recv() (Frame, *os.File, error) {
	buf := make([]byte, MaxPacket+1)
	oob := make([]byte, unix.CmsgSpace(2*4))
	n, oobn, flags, _, err := c.c.ReadMsgUnix(buf, oob)
	if err != nil {
		return Frame{}, nil, err
	}
	fds, perr := rights(oob[:oobn])
	closeAll := func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}
	switch {
	case n == 0 && oobn == 0:
		return Frame{}, nil, io.EOF
	case perr != nil:
		closeAll()
		return Frame{}, nil, perr
	case n > MaxPacket || flags&unix.MSG_TRUNC != 0:
		closeAll()
		return Frame{}, nil, fmt.Errorf("frame: larger than %d bytes", MaxPacket)
	case flags&unix.MSG_CTRUNC != 0 || len(fds) > 1:
		closeAll()
		return Frame{}, nil, errors.New("frame: more than one descriptor")
	}
	f, err := Decode(buf[:n])
	if err != nil {
		closeAll()
		return Frame{}, nil, err
	}
	switch {
	case withFile[f.T] && len(fds) == 0:
		return Frame{}, nil, fmt.Errorf("frame %s: without its descriptor", f.T)
	case !withFile[f.T] && len(fds) == 1:
		closeAll()
		return Frame{}, nil, fmt.Errorf("frame %s: takes no descriptor", f.T)
	}
	var file *os.File
	if len(fds) == 1 {
		file = os.NewFile(uintptr(fds[0]), f.Name)
	}
	return f, file, nil
}

func (c *Conn) SetReadDeadline(t time.Time) error { return c.c.SetReadDeadline(t) }

func (c *Conn) Close() error { return c.c.Close() }
