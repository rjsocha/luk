package wrap

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"luk/internal/jobchan"
)

// nested serves the socket of luk-job run while the command runs: one
// nested job at a time, its frames relayed between the connection of
// luk-job and the channel of the unit. It owns Ch.Recv until stop.
type nested struct {
	ch     *jobchan.Conn
	l      *net.UnixListener
	mu     sync.Mutex
	closed bool
	active *relay
	wg     sync.WaitGroup // the accept loop, the relays and the refusals
	quitc  chan struct{}  // closed by stop
	read   chan struct{}  // closed when the reader of ch ended
}

func startNested(ch *jobchan.Conn, l *net.UnixListener) *nested {
	n := &nested{ch: ch, l: l, quitc: make(chan struct{}), read: make(chan struct{})}
	n.wg.Add(1)
	go n.accept()
	go n.reader()
	return n
}

// stop closes the listener (removing the socket), ends the refusals and
// the active relay (which drains a stopped job, see relay.drain) and the
// reader of ch.
func (n *nested) stop() {
	n.l.Close()
	n.mu.Lock()
	n.closed = true
	r := n.active
	n.mu.Unlock()
	close(n.quitc)
	if r != nil {
		r.quit()
	}
	n.wg.Wait()
	n.ch.SetReadDeadline(time.Now())
	<-n.read
	n.ch.SetReadDeadline(time.Time{})
}

func (n *nested) accept() {
	defer n.wg.Done()
	for {
		c, err := jobchan.Accept(n.l)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		n.mu.Lock()
		if n.closed || n.active != nil {
			n.wg.Add(1)
			n.mu.Unlock()
			go n.refuse(c)
			continue
		}
		r := &relay{n: n, c: c, in: make(chan item), done: make(chan struct{}), quitc: make(chan struct{})}
		n.active = r
		n.wg.Add(1)
		n.mu.Unlock()
		go r.run()
	}
}

// hangupGrace bounds the wait for luk-job to hang up after the answer.
const hangupGrace = 5 * time.Second

// refuse answers a second request while a nested job runs. It reads what
// the peer sent until it hangs up, briefly and not past stop, since
// closing a socket with unread frames would reset the connection before
// the peer reads the refusal.
func (n *nested) refuse(c *jobchan.Conn) {
	defer n.wg.Done()
	defer c.Close()
	ended := make(chan struct{})
	defer close(ended)
	go func() {
		select {
		case <-n.quitc:
			c.Close()
		case <-ended:
		}
	}()
	if c.Send(jobchan.Frame{T: jobchan.TRefused, Reason: "another job of this step is running"}, nil) != nil {
		return
	}
	c.SetReadDeadline(time.Now().Add(hangupGrace))
	for {
		_, fd, err := c.Recv()
		closeFile(fd)
		var ne net.Error
		if errors.Is(err, io.EOF) || errors.As(err, &ne) {
			return
		}
	}
}

type item struct {
	f  jobchan.Frame
	fd *os.File
}

// reader hands the frames of ch to the active relay and drops those that
// arrive without one. It ends when ch closes or its deadline passes.
func (n *nested) reader() {
	defer close(n.read)
	for {
		f, fd, err := n.ch.Recv()
		var ne net.Error
		switch {
		case errors.Is(err, io.EOF), errors.As(err, &ne):
			return
		case err != nil:
			continue
		}
		n.mu.Lock()
		r := n.active
		n.mu.Unlock()
		if r != nil {
			select {
			case r.in <- item{f, fd}:
				continue
			case <-r.done:
			}
		}
		closeFile(fd)
	}
}

// relay is one nested job: up forwards job, the in frames and go from
// luk-job to ch; run forwards the answers of lukd process back.
type relay struct {
	n        *nested
	c        *jobchan.Conn
	in       chan item
	done     chan struct{} // closed when the relay ended
	quitc    chan struct{} // closed when the command ended
	quitOnce sync.Once
	ended    atomic.Bool // exit or refused reached luk-job
}

func (r *relay) quit() {
	r.quitOnce.Do(func() {
		close(r.quitc)
		r.c.Close()
	})
}

// down are the frames of lukd process that go back to luk-job.
var down = map[string]bool{jobchan.TStdout: true, jobchan.TStderr: true, jobchan.TOut: true, jobchan.TExit: true, jobchan.TRefused: true}

func (r *relay) run() {
	gone := make(chan bool, 1)
	go func() { gone <- r.up() }()
	upDone, forwarded, stopped := false, false, false
	stopJob := func() {
		if forwarded && !stopped {
			r.n.ch.Send(jobchan.Frame{T: jobchan.TStop}, nil)
			stopped = true
		}
	}
	defer func() {
		if !upDone {
			if !r.ended.Load() {
				r.c.Close()
			}
			<-gone
		}
		r.c.Close()
		r.n.mu.Lock()
		r.n.active = nil
		r.n.mu.Unlock()
		close(r.done)
		r.n.wg.Done()
	}()
	for {
		select {
		case it := <-r.in:
			if !stopped && down[it.f.T] {
				r.c.Send(it.f, it.fd)
			}
			closeFile(it.fd)
			if it.f.T == jobchan.TExit || it.f.T == jobchan.TRefused {
				// Wait for luk-job to hang up: closing with its frames
				// unread would reset the connection before it reads these.
				r.ended.Store(true)
				r.c.SetReadDeadline(time.Now().Add(hangupGrace))
				return
			}
		case forwarded = <-gone:
			// luk-job left, or broke the protocol, before the end of its
			// job: stop the job and drain its frames until it ends.
			upDone = true
			if !forwarded {
				return
			}
			stopJob()
		case <-r.quitc:
			r.c.Close()
			if !upDone {
				forwarded, upDone = <-gone, true
			}
			stopJob()
			if stopped {
				r.drain()
			}
			return
		case <-r.n.read:
			return
		}
	}
}

// drainLimit bounds the wait for the end of a stopped job once the
// command ended.
var drainLimit = jobchan.ResultGap

// drain drops the frames of a stopped job until its exit or refused, so
// none is left unread on ch when the wrapper exits: closing a socket with
// unread frames would reset the connection before lukd process reads the
// results.
func (r *relay) drain() {
	t := time.NewTimer(drainLimit)
	defer t.Stop()
	for {
		select {
		case it := <-r.in:
			closeFile(it.fd)
			if it.f.T == jobchan.TExit || it.f.T == jobchan.TRefused {
				return
			}
		case <-t.C:
			return
		case <-r.n.read:
			return
		}
	}
}

// up forwards the request of luk-job to ch: job, the in frames with
// their descriptors, go. After go any frame or the end of the connection
// ends it; once the job ended it only reads until luk-job hangs up. It
// reports whether it forwarded anything.
func (r *relay) up() (forwarded bool) {
	started := false
	for {
		f, fd, err := r.c.Recv()
		switch {
		case err != nil:
			return forwarded
		case r.ended.Load():
			closeFile(fd)
			continue
		case started:
			closeFile(fd)
			return forwarded
		}
		ok := f.T == jobchan.TJob && !forwarded || (f.T == jobchan.TIn || f.T == jobchan.TGo) && forwarded
		if ok {
			err = r.n.ch.Send(f, fd)
		}
		closeFile(fd)
		if !ok || err != nil {
			return forwarded
		}
		forwarded = true
		started = f.T == jobchan.TGo
	}
}
