package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"
)

// Reason is why a request ended in transit.
type Reason int

const (
	// Interrupted: the caller's context ended (Ctrl-C).
	Interrupted Reason = iota + 1
	// Closed: the connection broke while the body moved.
	Closed
	// Unreachable: the connection broke before any body byte.
	Unreachable
	// NoAnswer: no answer headers to a GET or HEAD within the decision
	// timeout.
	NoAnswer
	// Stalled: the server made no progress for the idle timeout while the
	// body moved or while luk waited for the answer after the body.
	Stalled
)

// TransferError is a request that ended in transit. Done is the body bytes
// moved by then, Total the body size (-1: unknown), Wait the decision
// timeout of a NoAnswer or the idle timeout of a Stalled,
// and Err the cause, without the url.Error wrapper.
type TransferError struct {
	Reason Reason
	Host   string
	Done   int64
	Total  int64
	Wait   time.Duration
	Err    error
}

func (e *TransferError) Error() string {
	switch e.Reason {
	case Interrupted:
		if e.Done > 0 {
			return "interrupted after " + e.moved()
		}
		return "interrupted"
	case NoAnswer:
		return "the server gave no answer within " + seconds(e.Wait)
	case Stalled:
		if e.Done > 0 || e.Total > 0 {
			return "no progress for " + seconds(e.Wait) + " after " + e.moved()
		}
		return "no progress for " + seconds(e.Wait)
	case Closed:
		return fmt.Sprintf("connection closed after %s: %s", e.moved(), shortCause(e.Err))
	}
	return fmt.Sprintf("cannot reach %s: %s", e.Host, shortCause(e.Err))
}

func (e *TransferError) Unwrap() error { return e.Err }

// moved is "12.4 MiB of 2.1 GiB", or "12.4 MiB" for an unknown total.
func (e *TransferError) moved() string {
	if e.Total < 0 {
		return HumanBytes(e.Done)
	}
	return HumanBytes(e.Done) + " of " + HumanBytes(e.Total)
}

// seconds is d as "60s" when whole seconds, else as time.Duration prints it.
func seconds(d time.Duration) string {
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", d/time.Second)
	}
	return d.String()
}

// transferError classifies err of a request to host after done of total
// body bytes: Interrupted when ctx (the caller's) has ended, Stalled for a
// stalledError, Closed after a body byte or once started, else
// Unreachable.
func transferError(ctx context.Context, err error, host string, done, total int64, started bool) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	te := &TransferError{Reason: Unreachable, Host: host, Done: done, Total: total, Err: err}
	var se *stalledError
	switch {
	case ctx.Err() != nil:
		te.Reason = Interrupted
	case errors.As(err, &se):
		te.Reason, te.Wait = Stalled, se.idle
	case done > 0 || started:
		te.Reason = Closed
	}
	return te
}

// shortCause is err without the operation and address wrappers of the net
// package: "connection refused" rather than "dial tcp 127.0.0.1:1:
// connect: connection refused".
func shortCause(err error) string {
	for {
		var oe *net.OpError
		var se *os.SyscallError
		var de *net.DNSError
		switch {
		case err == nil:
			return "closed"
		case errors.As(err, &de):
			return de.Err
		case errors.As(err, &oe) && oe.Err != nil:
			err = oe.Err
		case errors.As(err, &se) && se.Err != nil:
			err = se.Err
		default:
			return err.Error()
		}
	}
}
