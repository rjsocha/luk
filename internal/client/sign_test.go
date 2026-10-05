package client

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/channel/chantest"
)

// slowSigner signs after a delay, as a key waiting for a touch.
type slowSigner struct {
	ssh.Signer
	delay time.Duration
}

func (s slowSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	time.Sleep(s.delay)
	return s.Signer.Sign(r, data)
}

// lockedBuf is a buffer written from a timer.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// signWaits makes the notice and the limit of the signature short and
// catches the notice in a buffer, as on a terminal.
func signWaits(t *testing.T, notice, limit time.Duration) *lockedBuf {
	t.Helper()
	oldNotice, oldLimit, oldOut := signNotice, signLimit, signNoticeOut
	buf := &lockedBuf{}
	signNotice, signLimit = notice, limit
	signNoticeOut = func() io.Writer { return buf }
	t.Cleanup(func() { signNotice, signLimit, signNoticeOut = oldNotice, oldLimit, oldOut })
	return buf
}

// A signature that takes longer than the notice delay tells, once, that
// luk waits for the key; a quick one says nothing.
func TestSignNotice(t *testing.T) {
	buf := signWaits(t, 50*time.Millisecond, 5*time.Second)
	srv := fakeParts(t, func(_ channel.Nonce, content []byte) chantest.Answer { return receipt(content) })
	o := fakeOpts(t, srv, patterned(3<<16))
	if _, err := Upload(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "" {
		t.Fatalf("quick signature: %q", buf.String())
	}
	o = fakeOpts(t, srv, patterned(3<<16+1))
	o.Signer = slowSigner{o.Signer, 300 * time.Millisecond}
	if _, err := Upload(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "waiting for the signature (touch the key)\n" {
		t.Fatalf("notice %q", got)
	}
}

// A signature that takes longer than the limit is not sent: lukd would
// have dropped the session by the time it arrives.
func TestSignTooLate(t *testing.T) {
	signWaits(t, time.Hour, 100*time.Millisecond)
	srv := fakeParts(t, func(_ channel.Nonce, content []byte) chantest.Answer { return receipt(content) })
	o := fakeOpts(t, srv, patterned(3<<16))
	o.Signer = slowSigner{o.Signer, 300 * time.Millisecond}
	_, err := Upload(context.Background(), o)
	if err == nil || err.Error() != "the signature took longer than 100ms; lukd drops a session that waits longer than 60s (limits.channel.auth): run it again" {
		t.Fatalf("%v", err)
	}
	if n := srv.Count(channel.KindOp); n != 0 {
		t.Fatalf("%d OPs sent", n)
	}
	if !strings.Contains(err.Error(), "limits.channel.auth") {
		t.Fatal(err)
	}
}

// With Quiet (luk send --quiet) a slow signature says nothing; one too
// late is still an error.
func TestSignQuiet(t *testing.T) {
	buf := signWaits(t, 50*time.Millisecond, 5*time.Second)
	srv := fakeParts(t, func(_ channel.Nonce, content []byte) chantest.Answer { return receipt(content) })
	o := fakeOpts(t, srv, patterned(3<<16))
	o.Signer, o.Quiet = slowSigner{o.Signer, 300 * time.Millisecond}, true
	if _, err := Upload(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "" {
		t.Fatalf("notice with quiet: %q", buf.String())
	}
	signLimit = 100 * time.Millisecond
	o = fakeOpts(t, srv, patterned(3<<16+1))
	o.Signer, o.Quiet = slowSigner{o.Signer, 300 * time.Millisecond}, true
	if _, err := Upload(context.Background(), o); err == nil || !strings.HasPrefix(err.Error(), "the signature took longer than 100ms") {
		t.Fatalf("%v", err)
	}
}
