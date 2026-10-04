// Package acmecert obtains and renews the certificates of a fixed list of
// names from one ACME directory with the HTTP-01 challenge
// (golang.org/x/crypto/acme). The account key and the certificates live
// in a cache directory, one file each.
package acmecert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"luk/internal/tlsself"
)

const (
	// accountFile is the account key in the cache directory; a
	// certificate is <name>.pem (its key, then the chain).
	accountFile = "account.key"
	// issueTimeout bounds one issuance: order, challenge, certificate.
	issueTimeout = 5 * time.Minute
	// retryAfter keeps handshakes from asking the CA again right after a
	// failure; the renewal loop tries again on its next check.
	retryAfter = time.Minute
	// checkEvery is how often the certificates are checked for renewal.
	checkEvery = time.Hour
	// requestPoll is how often renewal requests are looked for when the
	// cache directory cannot be watched.
	requestPoll = 10 * time.Second
)

// ChallengePrefix is the path of the HTTP-01 challenges.
const ChallengePrefix = "/.well-known/acme-challenge/"

type Options struct {
	Directory string
	CacheDir  string
	Email     string
	EAB       *acme.ExternalAccountBinding
	Hosts     []string
	Log       *slog.Logger
	// HTTPClient talks to the directory; nil is http.DefaultClient.
	HTTPClient *http.Client
}

// Manager holds the certificates of its names. Handshakes get them with
// GetCertificate, the CA reads the challenges through HTTPHandler and Run
// obtains missing ones at start and renews them.
type Manager struct {
	o      Options
	client *acme.Client
	now    func() time.Time

	acctMu     sync.Mutex
	registered bool

	mu      sync.Mutex
	certs   map[string]*tls.Certificate
	issuing map[string]*issue
	failed  map[string]failure
	tokens  map[string]string
	state   map[string]*HostStatus
	results map[string]*RequestResult
	// nextCheck is the next hourly check of Run.
	nextCheck time.Time

	// statusMu orders the writes of status.json.
	statusMu sync.Mutex
}

type issue struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

type failure struct {
	at  time.Time
	err error
}

func New(o Options) *Manager {
	return &Manager{
		o:       o,
		client:  &acme.Client{DirectoryURL: o.Directory, HTTPClient: o.HTTPClient, UserAgent: "lukd"},
		now:     time.Now,
		certs:   map[string]*tls.Certificate{},
		issuing: map[string]*issue{},
		failed:  map[string]failure{},
		tokens:  map[string]string{},
		state:   map[string]*HostStatus{},
		results: map[string]*RequestResult{},
	}
}

// Hosts returns the names of the manager.
func (m *Manager) Hosts() []string { return m.o.Hosts }

// GetCertificate serves the certificate of the server name, obtaining it
// first when there is none yet; a handshake for a name not in the list
// fails.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if !slices.Contains(m.o.Hosts, host) {
		return nil, fmt.Errorf("acme: no certificate for %q", hello.ServerName)
	}
	ctx := hello.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return m.cert(ctx, host, false)
}

// HTTPHandler answers the HTTP-01 challenges in flight; anything else is
// 404.
func (m *Manager) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		v, ok := m.tokens[r.URL.Path]
		m.mu.Unlock()
		if !ok || r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(v))
	})
}

// Run obtains the certificates that are missing and renews those due,
// at once and then every hour, until ctx is done. Each result is logged;
// a failure is retried on the next check. It also renews the names of
// the <name>.renew requests in the cache directory at once, watched with
// inotify (polled every 10s without) and looked for on every check, and
// keeps status.json there.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(checkEvery)
	defer t.Stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	wake, err := watchDir(ctx, m.o.CacheDir)
	var poll <-chan time.Time
	if err != nil {
		m.o.Log.Warn("acme renewal requests polled", "dir", m.o.CacheDir, "every", requestPoll, "error", err)
		pt := time.NewTicker(requestPoll)
		defer pt.Stop()
		poll = pt.C
	}
	for _, h := range m.o.Hosts {
		if _, err := m.cached(h); err != nil {
			m.o.Log.Error("acme cached certificate unreadable", "host", h, "error", err)
		}
	}
	m.setNextCheck(m.now().Add(checkEvery))
	m.writeStatus()
	checks := func(first bool) {
		for _, h := range m.o.Hosts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.check(ctx, h, first)
			}()
		}
	}
	checks(true)
	m.requests(ctx, &wg)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.setNextCheck(m.now().Add(checkEvery))
			checks(false)
			m.requests(ctx, &wg)
		case <-wake:
			m.requests(ctx, &wg)
		case <-poll:
			m.requests(ctx, &wg)
		}
	}
}

func (m *Manager) setNextCheck(t time.Time) {
	m.mu.Lock()
	m.nextCheck = t
	m.mu.Unlock()
}

// requests takes every renewal request of the cache directory (the file
// is removed) and renews its name in the background.
func (m *Manager) requests(ctx context.Context, wg *sync.WaitGroup) {
	ents, err := os.ReadDir(m.o.CacheDir)
	if err != nil {
		m.o.Log.Error("acme renewal requests", "dir", m.o.CacheDir, "error", err)
		return
	}
	for _, e := range ents {
		host, ok := strings.CutSuffix(e.Name(), RenewSuffix)
		if !ok || host == "" || strings.HasPrefix(host, ".") || !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(m.o.CacheDir, e.Name())
		data, err := os.ReadFile(p)
		if err == nil {
			err = os.Remove(p)
		}
		if err != nil {
			m.o.Log.Error("acme renewal request unreadable", "file", p, "error", err)
			continue
		}
		var req Request
		// A request without a nonce (touched by hand) renews all the same.
		_ = json.Unmarshal(data, &req)
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.renewRequest(ctx, host, req)
		}()
	}
}

// renewRequest renews host regardless of its expiry and records the
// result under the nonce of the request. The new certificate is served by
// the next handshake.
func (m *Manager) renewRequest(ctx context.Context, host string, req Request) {
	res := &RequestResult{Host: host, Requested: req.Requested}
	if !slices.Contains(m.o.Hosts, host) {
		res.Error = fmt.Sprintf("%s is not a name of %s", host, m.o.Directory)
		m.o.Log.Error("acme renewal requested for an unknown name", "host", host)
	} else {
		m.o.Log.Info("acme renewal requested", "host", host)
		c, err := m.cert(ctx, host, true)
		if err != nil {
			res.Error = err.Error()
			m.o.Log.Error("acme certificate not obtained", "host", host, "error", err)
		} else {
			res.Serial, res.NotAfter = Serial(c.Leaf), c.Leaf.NotAfter.UTC()
		}
	}
	res.Done = m.now().UTC()
	if req.Nonce != "" {
		m.mu.Lock()
		m.results[req.Nonce] = res
		for len(m.results) > keepResults {
			var oldest string
			for n, r := range m.results {
				if oldest == "" || r.Done.Before(m.results[oldest].Done) {
					oldest = n
				}
			}
			delete(m.results, oldest)
		}
		m.mu.Unlock()
	}
	m.writeStatus()
}

// writeStatus replaces status.json with the state of every name and the
// request results; a failure is logged only.
func (m *Manager) writeStatus() {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	st := Status{Directory: m.o.Directory, Written: m.now().UTC(), Hosts: map[string]*HostStatus{}, Requests: map[string]*RequestResult{}}
	m.mu.Lock()
	for _, h := range m.o.Hosts {
		hs := &HostStatus{}
		if s := m.state[h]; s != nil {
			*hs = *s
		}
		if c := m.certs[h]; c != nil {
			hs.Serial, hs.NotAfter = Serial(c.Leaf), c.Leaf.NotAfter.UTC()
		}
		st.Hosts[h] = hs
	}
	for n, r := range m.results {
		st.Requests[n] = r
	}
	m.mu.Unlock()
	data, err := json.MarshalIndent(st, "", "  ")
	if err == nil {
		err = writeFile(filepath.Join(m.o.CacheDir, StatusFile), append(data, '\n'))
	}
	if err != nil {
		m.o.Log.Warn("acme status not written", "dir", m.o.CacheDir, "error", err)
	}
}

// check renews the certificate of host when it is due; the first check
// also logs a certificate that is not.
func (m *Manager) check(ctx context.Context, host string, first bool) {
	c, _ := m.cached(host)
	if c != nil && !m.due(c.Leaf) {
		if first {
			m.o.Log.Info("acme certificate", "host", host, "pin", tlsself.Pin(c.Leaf), "expires", c.Leaf.NotAfter.UTC().Format(time.RFC3339))
		}
		return
	}
	if _, err := m.cert(ctx, host, true); err != nil && ctx.Err() == nil {
		m.o.Log.Error("acme certificate not obtained", "host", host, "error", err)
	}
}

// due reports whether a certificate is to be renewed (see RenewAt).
func (m *Manager) due(leaf *x509.Certificate) bool {
	return !m.now().Before(RenewAt(leaf))
}

// Leaf returns the current certificate of host (memory, else cache), nil
// when there is none.
func (m *Manager) Leaf(host string) (*x509.Certificate, error) {
	c, err := m.cached(host)
	if c == nil {
		return nil, err
	}
	return c.Leaf, nil
}

// cached is the certificate of host in memory or in the cache directory,
// expired ones included; nil when there is none.
func (m *Manager) cached(host string) (*tls.Certificate, error) {
	m.mu.Lock()
	c := m.certs[host]
	m.mu.Unlock()
	if c != nil {
		return c, nil
	}
	pair, err := loadPair(m.certFile(host))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.certs[host] = pair
	m.mu.Unlock()
	return pair, nil
}

// cert returns a valid certificate of host: the current one, or a new one
// when there is none, it expired or renew is set. One issuance per name
// runs at a time; callers wait for it or for their ctx. A handshake
// within retryAfter of a failure gets that failure.
func (m *Manager) cert(ctx context.Context, host string, renew bool) (*tls.Certificate, error) {
	c, err := m.cached(host)
	if err != nil {
		m.o.Log.Error("acme cached certificate unreadable", "host", host, "error", err)
	}
	if c != nil && m.now().Before(c.Leaf.NotAfter) && !renew {
		return c, nil
	}
	m.mu.Lock()
	is := m.issuing[host]
	if is == nil {
		if f, ok := m.failed[host]; ok && !renew && m.now().Sub(f.at) < retryAfter {
			m.mu.Unlock()
			return nil, f.err
		}
		is = &issue{done: make(chan struct{})}
		m.issuing[host] = is
		go m.issue(host, is)
	}
	m.mu.Unlock()
	select {
	case <-is.done:
		return is.cert, is.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// issue runs one issuance in its own context, so a handshake that gives
// up does not abort it.
func (m *Manager) issue(host string, is *issue) {
	ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
	defer cancel()
	m.mu.Lock()
	st := m.state[host]
	if st == nil {
		st = &HostStatus{}
		m.state[host] = st
	}
	st.LastAttempt = m.now().UTC()
	m.mu.Unlock()
	is.cert, is.err = m.obtain(ctx, host)
	m.mu.Lock()
	delete(m.issuing, host)
	if is.err != nil {
		m.failed[host] = failure{at: m.now(), err: is.err}
		st.LastError, st.NextRetry = is.err.Error(), m.nextCheck.UTC()
	} else {
		delete(m.failed, host)
		m.certs[host] = is.cert
		st.LastSuccess, st.LastError, st.NextRetry = m.now().UTC(), "", time.Time{}
	}
	m.mu.Unlock()
	if is.err == nil {
		leaf := is.cert.Leaf
		m.o.Log.Info("acme certificate obtained", "host", host, "pin", tlsself.Pin(leaf), "expires", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	m.writeStatus()
	close(is.done)
}

func (m *Manager) obtain(ctx context.Context, host string) (*tls.Certificate, error) {
	if err := m.account(ctx); err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}
	o, err := m.client.AuthorizeOrder(ctx, acme.DomainIDs(host))
	if err != nil {
		return nil, fmt.Errorf("order: %w", err)
	}
	for _, u := range o.AuthzURLs {
		if err := m.authorize(ctx, u); err != nil {
			return nil, err
		}
	}
	if o, err = m.client.WaitOrder(ctx, o.URI); err != nil {
		return nil, fmt.Errorf("order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
	}, key)
	if err != nil {
		return nil, err
	}
	der, _, err := m.client.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("finalize: %w", err)
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return nil, err
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return nil, err
	}
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("issued certificate does not match the key")
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	for _, b := range der {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	if err := writeFile(m.certFile(host), data); err != nil {
		// Served from memory until the next start, which obtains it again.
		m.o.Log.Error("acme certificate not cached", "host", host, "error", err)
	}
	return &tls.Certificate{Certificate: der, PrivateKey: key, Leaf: leaf}, nil
}

// authorize answers the http-01 challenge of a pending authorization and
// waits for the CA to validate it.
func (m *Manager) authorize(ctx context.Context, url string) error {
	z, err := m.client.GetAuthorization(ctx, url)
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if z.Status == acme.StatusValid {
		return nil
	}
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == "http-01" {
			chal = c
		}
	}
	if chal == nil {
		return fmt.Errorf("authorization %s: the CA offers no http-01 challenge", z.Identifier.Value)
	}
	resp, err := m.client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}
	p := m.client.HTTP01ChallengePath(chal.Token)
	m.mu.Lock()
	m.tokens[p] = resp
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.tokens, p)
		m.mu.Unlock()
	}()
	if _, err := m.client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	if _, err := m.client.WaitAuthorization(ctx, z.URI); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	return nil
}

// account loads or creates the account key and registers it once per
// process; a key the CA already knows is fine.
func (m *Manager) account(ctx context.Context) error {
	m.acctMu.Lock()
	defer m.acctMu.Unlock()
	if m.registered {
		return nil
	}
	if m.client.Key == nil {
		key, err := m.accountKey()
		if err != nil {
			return err
		}
		m.client.Key = key
	}
	a := &acme.Account{ExternalAccountBinding: m.o.EAB}
	if m.o.Email != "" {
		a.Contact = []string{"mailto:" + m.o.Email}
	}
	if _, err := m.client.Register(ctx, a, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return err
	}
	m.registered = true
	return nil
}

func (m *Manager) accountKey() (*ecdsa.PrivateKey, error) {
	p := filepath.Join(m.o.CacheDir, accountFile)
	k, err := loadAccountKey(p)
	if !errors.Is(err, os.ErrNotExist) {
		return k, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}

func (m *Manager) certFile(host string) string {
	return CertFile(m.o.CacheDir, host)
}

// writeFile replaces p atomically with a 0600 file.
func writeFile(p string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
