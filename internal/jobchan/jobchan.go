// Package jobchan is the channel between lukd process and the wrapper of
// a unit of lukd run (and between luk-job run and that wrapper): a
// SOCK_SEQPACKET socket, one JSON line per packet of at most MaxPacket
// bytes, with at most one descriptor (SCM_RIGHTS), present exactly on the
// frames that carry a file (meta, in, out). See SPEC, Service, Channel of
// a unit.
package jobchan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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

// fields holds the fields each type may carry besides "t".
var fields = map[string][]string{
	TMeta: nil, TIn: {"name"}, TGo: nil, TStatus: {"status", "fail"},
	TOut: {"name"}, TRefuse: {"name", "reason"}, TEnd: nil, TJob: {"job"},
	TStop: nil, TStdout: {"data"}, TStderr: {"data"}, TExit: {"status"},
	TRefused: {"reason"},
}

// present names the fields of f that Encode writes.
func present(f Frame) map[string]bool {
	return map[string]bool{
		"name": f.Name != "", "job": f.Job != "", "reason": f.Reason != "",
		"fail": f.Fail != "", "status": f.Status != nil, "data": len(f.Data) > 0,
	}
}

// check applies the rules of the type of f: has names the fields set.
func check(f Frame, has map[string]bool) error {
	allowed, ok := fields[f.T]
	if !ok {
		return fmt.Errorf("frame: unknown frame %q", f.T)
	}
	for _, k := range []string{"name", "job", "reason", "fail", "status", "data"} {
		if has[k] && !slices.Contains(allowed, k) {
			if k == "data" {
				return fmt.Errorf("frame %s: data only on o and e", f.T)
			}
			return fmt.Errorf("frame %s: field %q does not belong to it", f.T, k)
		}
	}
	switch {
	case (f.T == TIn || f.T == TOut || f.T == TRefuse) && f.Name == "":
		return fmt.Errorf("frame %s: needs a name", f.T)
	case (f.T == TStatus || f.T == TExit) && f.Status == nil:
		return fmt.Errorf("frame %s: needs a status", f.T)
	case f.T == TJob && f.Job == "":
		return fmt.Errorf("frame %s: needs a job", f.T)
	}
	return nil
}

// Decode parses one packet: valid UTF-8 holding exactly one flat JSON
// object and a newline. A key not spelled exactly as a field, a repeated
// key, a value of the wrong kind (null included), a field the type does
// not carry and data after the object are refused.
func Decode(b []byte) (Frame, error) {
	f, err := decode(b)
	if err != nil {
		return Frame{}, fmt.Errorf("frame: %w", err)
	}
	if err := check(f.Frame, f.has); err != nil {
		return Frame{}, err
	}
	return f.Frame, nil
}

type decoded struct {
	Frame
	has map[string]bool
}

func decode(b []byte) (decoded, error) {
	f := decoded{has: map[string]bool{}}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return f, errors.New("no newline at the end")
	}
	if !utf8.Valid(b) {
		return f, errors.New("not valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return f, errors.New("not a JSON object")
	}
	for d.More() {
		k, err := str(d)
		if err != nil {
			return f, err
		}
		if f.has[k] {
			return f, fmt.Errorf("field %q repeated", k)
		}
		f.has[k] = true
		switch k {
		case "t":
			f.T, err = str(d)
		case "name":
			f.Name, err = str(d)
		case "job":
			f.Job, err = str(d)
		case "reason":
			f.Reason, err = str(d)
		case "fail":
			f.Fail, err = str(d)
		case "status":
			f.Status, err = num(d)
		case "data":
			var s string
			if s, err = str(d); err == nil {
				f.Data, err = base64.StdEncoding.DecodeString(s)
			}
		default:
			return f, fmt.Errorf("unknown field %q", k)
		}
		if err != nil {
			return f, fmt.Errorf("%s: %w", k, err)
		}
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return f, errors.New("not a flat JSON object")
	}
	if _, err := d.Token(); err != io.EOF {
		return f, errors.New("trailing data")
	}
	return f, nil
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

func num(d *json.Decoder) (*int, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	n, ok := t.(json.Number)
	if !ok {
		return nil, errors.New("not a number")
	}
	i, err := strconv.Atoi(string(n))
	if err != nil {
		return nil, errors.New("not an integer")
	}
	return &i, nil
}

// Encode renders f as one packet.
func Encode(f Frame) ([]byte, error) {
	if err := check(f, present(f)); err != nil {
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
