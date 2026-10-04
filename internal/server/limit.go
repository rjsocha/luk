package server

import (
	"net"
	"sync"
)

type limitListener struct {
	net.Listener
	sem chan struct{}
}

// LimitListener admits at most max open connections; a connection accepted
// over the limit is closed at once so the kernel backlog does not fill up.
func LimitListener(l net.Listener, max int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, max)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
		default:
			_ = c.Close()
		}
	}
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
