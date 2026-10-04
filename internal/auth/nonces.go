package auth

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"luk/internal/wire"
)

// NonceFile is the file of a persisted nonce cache in its directory (see
// NonceCache.Persist).
const NonceFile = "seen"

type NonceCache struct {
	mu        sync.Mutex
	ttl       time.Duration
	seen      map[string]time.Time
	lastSweep time.Time

	// path is the file the nonces are kept in, f its append handle; warn
	// gets the errors of writing it. All nil without Persist.
	path string
	f    *os.File
	warn func(error)
}

func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{ttl: ttl, seen: map[string]time.Time{}}
}

// Extend raises the TTL to ttl and returns the TTL before; a shorter ttl
// is ignored, so a nonce seen under a longer clock skew is still
// remembered as long as it could be replayed.
func (c *NonceCache) Extend(ttl time.Duration) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.ttl
	c.ttl = max(c.ttl, ttl)
	return old
}

// Check records a nonce; false means it was seen within the TTL. With
// Persist, a new nonce is appended to the file before it counts as seen,
// and the sweep of expired nonces rewrites the file.
func (c *NonceCache) Check(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.lastSweep) >= c.ttl/2 {
		for n, t := range c.seen {
			if now.Sub(t) > c.ttl {
				delete(c.seen, n)
			}
		}
		c.lastSweep = now
		if c.f != nil {
			c.report(c.compact())
		}
	}
	if t, ok := c.seen[nonce]; ok && now.Sub(t) <= c.ttl {
		return false
	}
	c.seen[nonce] = now
	if c.f != nil {
		_, err := c.f.WriteString(line(nonce, now.Add(c.ttl)))
		c.report(err)
	}
	return true
}

func (c *NonceCache) report(err error) {
	if err != nil && c.warn != nil {
		c.warn(fmt.Errorf("nonce cache %s: %w", c.path, err))
	}
}

// line is the record of a nonce in the file: the nonce and its expiry in
// Unix seconds, rounded up.
func line(nonce string, expires time.Time) string {
	sec := expires.Unix()
	if expires.Nanosecond() > 0 {
		sec++
	}
	return nonce + " " + strconv.FormatInt(sec, 10) + "\n"
}

// Persist keeps the nonces in the file NonceFile of dir as well, so a
// restart of the process still refuses the nonces seen before it: it
// loads the entries of the file not expired at now (a malformed or torn
// line, as a crash in the middle of an append leaves, is skipped),
// rewrites the file with them and from then on appends every new nonce
// with its expiry. A missing dir is fs.ErrNotExist and leaves the cache
// in memory only. warn gets the errors of later writes; they do not
// refuse a request.
func (c *NonceCache) Persist(dir string, now time.Time, warn func(error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory", dir)
	}
	p := filepath.Join(dir, NonceFile)
	b, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			break
		}
		nonce, exp, ok := strings.Cut(string(b[:i]), " ")
		b = b[i+1:]
		sec, err := strconv.ParseInt(exp, 10, 64)
		if !ok || err != nil || !wire.ValidNonce(nonce) {
			continue
		}
		if t := time.Unix(sec, 0); t.After(now) {
			// seen so that the current TTL ends at the recorded expiry.
			c.seen[nonce] = t.Add(-c.ttl)
		}
	}
	c.path, c.warn = p, warn
	if err := c.compact(); err != nil {
		c.path, c.warn = "", nil
		return err
	}
	c.lastSweep = now
	return nil
}

// compact rewrites the file with the nonces in memory, through a
// temporary file renamed over it, and reopens it for appending.
func (c *NonceCache) compact() error {
	dir := filepath.Dir(c.path)
	tmp, err := os.CreateTemp(dir, "."+NonceFile+".tmp-*")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(tmp)
	for n, t := range c.seen {
		w.WriteString(line(n, t.Add(c.ttl)))
	}
	err = w.Flush()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), c.path)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	f, err := os.OpenFile(c.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	if c.f != nil {
		c.f.Close()
	}
	c.f = f
	return nil
}
