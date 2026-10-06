package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"luk/internal/channel"
	"luk/internal/config"
	"luk/internal/expose"
	"luk/internal/pipeline"
	"luk/internal/queue"
	"luk/internal/quota"
	"luk/internal/status"
	"luk/internal/tlsself"
)

const shutdownTimeout = 10 * time.Second

// ACMEHTTPClient talks to the ACME directories; nil is the default client.
// Tests point it at a local CA.
var ACMEHTTPClient *http.Client

// processPickup is how often the process role looks for committed queue
// entries besides the inotify wakeup on commit.
var processPickup = 5 * time.Second

// hangup receives SIGHUP from CatchHangup on; nil until then.
var (
	hangup     chan os.Signal
	hangupOnce sync.Once
)

// CatchHangup routes SIGHUP to the role started later in the process.
// Without a handler SIGHUP ends a Go program, so lukd installs it before
// loading the configuration: a reload sent right after the start (Type=
// simple units are started at once) reaches the role as soon as it runs.
func CatchHangup() {
	hangupOnce.Do(func() {
		hangup = make(chan os.Signal, 1)
		signal.Notify(hangup, syscall.SIGHUP)
	})
}

// hangupSignals is the SIGHUP channel of a role: the one CatchHangup
// installed, or its own while the role runs.
func hangupSignals() (<-chan os.Signal, func()) {
	if hangup != nil {
		return hangup, func() {}
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	return hup, func() { signal.Stop(hup) }
}

// Receive runs the receive role: listeners, verification, queue writes,
// expose, expiry, TLS reload. It never runs pipelines and does not write
// status.json: accepted uploads stay committed in the queue for the
// process role (see Process) sharing the root. It runs every listener
// until ctx is done or one of them fails, then stops them, bounded by the
// shutdown timeout.
func Receive(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	// The receive role holds the TLS and ACME keys in memory.
	if err := setNonDumpable(); err != nil {
		return fmt.Errorf("non-dumpable: %w", err)
	}
	if err := prepareDirs(cfg, "receive"); err != nil {
		return err
	}
	lock, err := lockRole(cfg.DataDir(), "receive")
	if err != nil {
		return err
	}
	defer lock.Close()
	hup, stopHup := hangupSignals()
	defer stopHup()
	ac := newACME(cfg, log, ACMEHTTPClient)
	certs, err := loadCerts(cfg, ac)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := New(cfg, log)
	s.acme = ac
	s.certs = certs
	if err := s.loadIdentity(); err != nil {
		return err
	}
	if err := s.persistNonces(cfg.Auth.Nonces); err != nil {
		return err
	}
	mark := queue.MarkPath(cfg.DataDir())
	if err := s.accepted.Persist(mark, func(err error) {
		s.log.Warn("acceptance mark not written", "file", mark, "error", err)
	}); err != nil {
		return fmt.Errorf("acceptance mark: %w", err)
	}
	aside, err := s.quota.Open(quota.Path(cfg.DataDir()))
	if err != nil {
		return fmt.Errorf("quota state: %w", err)
	}
	if aside != "" {
		log.Warn("quota state corrupt, moved aside, starting with full buckets", "file", quota.Path(cfg.DataDir()), "aside", aside)
	}
	var servers []*http.Server
	defer func() {
		shut, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		for _, srv := range servers {
			_ = srv.Shutdown(shut)
		}
	}()
	if err := pipeline.CleanupQueues(cfg); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("queue: %w", err)
	}
	beat, err := startAlive(cfg.DataDir(), "receive", log)
	if err != nil {
		return err
	}
	expose.StartJanitor(ctx, s.config, log, time.Minute, expose.Expire, nil, func(time.Time) { s.sweepChannels() }, beat)
	errc := make(chan error, 1)
	if servers, err = s.listen(cfg, certs, errc); err != nil {
		return err
	}
	saveRunning(cfg, "receive", log)
	// After the listeners: HTTP-01 needs the acme: true listener open.
	ac.run(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case err = <-errc:
			return err
		case <-hup:
			reloadCerts(certs, log)
			ac.logState()
			if next := s.reload(); next != nil {
				saveRunning(next, "receive", log)
			}
		}
	}
}

// persistNonces keeps the nonce cache in the directory dir, so a restart
// still refuses the nonces seen before it. A missing dir (no tmpfiles.d
// entry, a development host) leaves it in memory only, with a warning.
func (s *Server) persistNonces(dir string) error {
	err := s.nonces.Persist(dir, s.now(), func(err error) { s.log.Warn("nonce cache not written", "error", err) })
	if errors.Is(err, fs.ErrNotExist) {
		s.log.Warn("nonce cache in memory only: its directory is missing", "dir", dir)
		return nil
	}
	if err != nil {
		return fmt.Errorf("nonce cache: %w", err)
	}
	return nil
}

// Process runs the process role: no listener; it runs the pipelines of the
// committed queue entries, picked up on commit (inotify) and every
// processPickup, keeps the failure records and status.json and maintains
// the storages.
// On the way out it waits for the running pipelines, bounded by the
// shutdown timeout.
func Process(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if err := prepareDirs(cfg, "process"); err != nil {
		return err
	}
	lock, err := lockRole(cfg.DataDir(), "process")
	if err != nil {
		return err
	}
	defer lock.Close()
	hup, stopHup := hangupSignals()
	defer stopHup()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stPath := status.Path(cfg.DataDir())
	st, aside, err := status.Open(stPath)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if aside != "" {
		log.Warn("status file corrupt, moved aside, starting empty", "file", stPath, "aside", aside)
	}
	q := queue.New(int64(cfg.Limits.Queue.Reserve), nil)
	d := pipeline.NewDispatcher(cfg, q, log)
	d.SetStatus(st)
	d.RefreshFailed()
	defer stopDispatcher(d, log)
	if err := d.Resume(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("queue: %w", err)
	}
	var cur atomic.Pointer[config.Config]
	cur.Store(cfg)
	beat, err := startAlive(cfg.DataDir(), "process", log)
	if err != nil {
		return err
	}
	expose.StartJanitor(ctx, cur.Load, log, time.Minute, expose.Maintain, d.Maintain, func(now time.Time) { d.RefreshWatch(now); d.RefreshRuntime(now) }, beat)
	wake := make(chan struct{}, 1)
	watch := watchQueues(ctx, wake, log)
	watch(pipeline.QueueDirs(cfg))
	every := processPickup
	go pickup(ctx, d, wake, every)
	log.Info("process started", "pickup", every)
	saveRunning(cfg, "process", log)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-hup:
			next := reloadConfig(cur.Load(), "process", log, func(next *config.Config) {
				q.SetReserve(int64(next.Limits.Queue.Reserve))
				d.Reload(next)
				cur.Store(next)
			})
			if next != nil {
				saveRunning(next, "process", log)
				watch(pipeline.QueueDirs(next))
			}
		}
	}
}

// Version is the lukd version a role writes to its liveness file.
var Version = "dev"

// startAlive writes the liveness file of the role (see status.Alive) and
// returns the heartbeat for its janitor loop: the loop that does the
// role's periodic work (receive: expiry, process: queue maintenance,
// pickup, storage maintenance, watch evaluation) touches the file, so its
// mtime goes stale when that loop hangs.
func startAlive(data, role string, log *slog.Logger) (func(time.Time), error) {
	a, err := status.StartAlive(data, role, Version, time.Now())
	if err != nil {
		return nil, fmt.Errorf("liveness file: %w", err)
	}
	return func(now time.Time) {
		if err := a.Beat(now); err != nil {
			log.Warn("liveness file not touched", "file", a.Path(), "error", err)
		}
	}, nil
}

// stopDispatcher stops taking pipeline jobs and waits for the running ones,
// bounded by the shutdown timeout. Entries not finished stay in the queue
// for the next start.
func stopDispatcher(d *pipeline.Dispatcher, log *slog.Logger) {
	d.Close()
	done := make(chan struct{})
	go func() {
		d.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		log.Warn("shutdown", "error", "pipelines still running")
	}
}

// NewLogger is a text logger on w at log.level of cfg; a reload through
// it (reloadConfig) sets the level of the new configuration.
func NewLogger(w io.Writer, cfg *config.Config) *slog.Logger {
	lv := new(slog.LevelVar)
	lv.Set(cfg.LogLevel())
	return slog.New(&levelHandler{Handler: slog.NewTextHandler(w, &slog.HandlerOptions{Level: lv}), level: lv})
}

// levelHandler carries the level of a NewLogger logger.
type levelHandler struct {
	slog.Handler
	level *slog.LevelVar
}

// setLevel applies log.level of cfg to a NewLogger logger; any other
// logger is left alone.
func setLevel(log *slog.Logger, cfg *config.Config) {
	if h, ok := log.Handler().(*levelHandler); ok {
		h.level.Set(cfg.LogLevel())
	}
}

// reload reloads the configuration of the receive role (see reloadConfig)
// and re-reads the identity key; a key that does not load keeps the one in
// use.
func (s *Server) reload() *config.Config {
	next := reloadConfig(s.config(), "receive", s.log, s.apply)
	if err := s.loadIdentity(); err != nil {
		s.log.Error("reload: identity key not read, keeping the current one", "error", err)
	}
	return next
}

// loadIdentity loads the identity key of the current configuration, the
// static key of the channel handshakes. A configuration not read from a
// file has no key file and leaves the server without a channel.
func (s *Server) loadIdentity() error {
	p := s.config().IdentityPath
	if p == "" {
		return nil
	}
	k, err := channel.LoadKey(p)
	if err != nil {
		return fmt.Errorf("identity key: %w (run lukd key generate)", err)
	}
	s.key.Store(&k)
	return nil
}

// reloadConfig reads the configuration cur was loaded from again and hands
// it to apply. An invalid configuration, a change of a setting that needs
// a restart (see config.Restart.Changes) or a directory that cannot be
// prepared (for receive, the TLS files too) keeps the current one entirely.
// It returns the new configuration, nil when it kept the current one.
func reloadConfig(cur *config.Config, role string, log *slog.Logger, apply func(*config.Config)) *config.Config {
	if cur.Path == "" {
		log.Info("reload: configuration not read from a file, nothing to reload")
		return nil
	}
	next, err := config.Load(cur.Path)
	if err != nil {
		log.Error("reload failed, keeping the current configuration", "error", err)
		return nil
	}
	if changes := cur.Restart().Changes(next.Restart()); len(changes) > 0 {
		for _, what := range changes {
			log.Error("reload refused: " + what + " changed, restart required")
		}
		return nil
	}
	if err := prepareDirs(next, role); err != nil {
		log.Error("reload failed, keeping the current configuration", "error", err)
		return nil
	}
	apply(next)
	setLevel(log, next)
	log.Info("config reloaded", "keys", len(next.Auth.Keys), "ca", len(next.Auth.CA), "endpoints", len(next.Endpoint),
		"pipelines", len(next.Pipeline), "storages", len(next.Storage), "files", strings.Join(next.Files, ","))
	for _, w := range next.Warnings() {
		log.Warn("config: " + w)
	}
	return next
}

// watchQueues returns a function that watches queue directories not
// watched yet and signals a commit in any of them on wake.
func watchQueues(ctx context.Context, wake chan struct{}, log *slog.Logger) func([]string) {
	watched := map[string]bool{}
	return func(dirs []string) {
		var add []string
		for _, d := range dirs {
			if !watched[d] {
				add = append(add, d)
			}
		}
		if len(add) == 0 {
			return
		}
		w, err := queue.Watch(ctx, add)
		if err != nil {
			log.Warn("queue watch unavailable, polling only", "dirs", strings.Join(add, ","), "error", err)
			return
		}
		for _, d := range add {
			watched[d] = true
		}
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-w.Done():
					return
				case <-w.C:
					select {
					case wake <- struct{}{}:
					default:
					}
				}
			}
		}()
	}
}

// lockRole holds <root>/data/<name>.lock until the file is closed, so a
// role runs once per root: two process roles would run the pipelines
// twice, two receive roles would expire and claim the same files.
func lockRole(data, name string) (*os.File, error) {
	if err := os.MkdirAll(data, 0o750); err != nil {
		return nil, fmt.Errorf("%s: %v (%s)", data, err, dirHint)
	}
	p := filepath.Join(data, name+".lock")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	// lukd check holds the lock shared for an instant (see roleHeld).
	for deadline := time.Now().Add(200 * time.Millisecond); ; {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == syscall.EINTR {
			continue
		}
		if err != syscall.EWOULDBLOCK || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if errors.Is(err, syscall.EWOULDBLOCK) {
		f.Close()
		return nil, fmt.Errorf("another lukd runs the %s role on %s (%s is locked)", name, data, p)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return f, nil
}

// pickup submits the committed queue entries not in flight on every wake
// and every `every` until ctx is done.
func pickup(ctx context.Context, d *pipeline.Dispatcher, wake <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.Pickup()
		case <-wake:
			d.Pickup()
		}
	}
}

// MaxStreams is the most requests one HTTP/2 connection runs at once, so
// an address runs at most MaxStreams x limits.conn.max requests.
const MaxStreams = 16

// httpServer is the HTTP server of the address g.
func (s *Server) httpServer(cfg *config.Config, g config.AddrGroup) *http.Server {
	return &http.Server{
		Addr:              g.Addr,
		Handler:           s.Handler(g.Addr),
		ReadHeaderTimeout: time.Duration(cfg.Limits.Header.Timeout),
		IdleTimeout:       time.Duration(cfg.Limits.Conn.Idle),
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: MaxStreams},
		ErrorLog:          stdlog.New(httpErrors{s.log}, "", 0),
	}
}

// listen opens every address and serves it in the background; a serve
// failure goes to errc.
func (s *Server) listen(cfg *config.Config, certs map[string]*certSlot, errc chan<- error) ([]*http.Server, error) {
	var servers []*http.Server
	var lns []net.Listener
	for _, g := range cfg.Addrs() {
		srv := s.httpServer(cfg, g)
		tlsOn := g.Listen[0].TLS != nil
		if tlsOn {
			srv.TLSConfig = tlsConfig(g, certs)
		} else {
			// A plain listener also takes HTTP/2 with prior knowledge (h2c):
			// a proxy that ends TLS on a TCP route passes on the HTTP/2 the
			// client negotiated by ALPN.
			srv.Protocols = new(http.Protocols)
			srv.Protocols.SetHTTP1(true)
			srv.Protocols.SetUnencryptedHTTP2(true)
		}
		raw, err := net.Listen("tcp", g.Addr)
		if err != nil {
			closeAll(lns)
			return servers, fmt.Errorf("listen %s: %w", g.Addr, err)
		}
		ln := LimitListener(raw, cfg.Limits.Conn.Max)
		lns = append(lns, ln)
		servers = append(servers, srv)
		go func(srv *http.Server, ln net.Listener) {
			s.log.Info("listening", "addr", ln.Addr().String(), "tls", tlsOn, "listen", listenNames(g))
			var err error
			if tlsOn {
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				select {
				case errc <- fmt.Errorf("listen %s: %w", srv.Addr, err):
				default:
				}
			}
		}(srv, ln)
	}
	return servers, nil
}

// httpErrors is the ErrorLog of the listeners. Failed TLS handshakes and
// malformed requests come from anyone on the internet and are logged at
// DEBUG; a handler panic is logged at ERROR.
type httpErrors struct{ log *slog.Logger }

func (h httpErrors) Write(p []byte) (int, error) {
	msg := strings.TrimSuffix(string(p), "\n")
	level := slog.LevelDebug
	if strings.HasPrefix(msg, "http: panic serving") {
		level = slog.LevelError
	}
	h.log.Log(context.Background(), level, msg)
	return len(p), nil
}

func closeAll(lns []net.Listener) {
	for _, ln := range lns {
		_ = ln.Close()
	}
}

// tlsConfig picks the certificate of a listener of the address by SNI: the
// listener whose host list names the server name; without a match (no SNI,
// an IP, an unknown name) the first listener's certificate, by name order.
func tlsConfig(g config.AddrGroup, certs map[string]*certSlot) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(hello.ServerName)
			for _, l := range g.Listen {
				if name != "" && slices.Contains(l.Host, name) {
					return certs[l.Name].get(hello)
				}
			}
			return certs[g.Listen[0].Name].get(hello)
		},
	}
}

// certSlot holds the certificate a TLS listener serves; a reload replaces
// it. An acme listener has acme instead, which obtains and renews its own.
type certSlot struct {
	l    *config.Listen
	cur  atomic.Pointer[tls.Certificate]
	acme func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func (c *certSlot) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c.acme != nil {
		return c.acme(hello)
	}
	return c.cur.Load(), nil
}

func loadCerts(cfg *config.Config, ac *acmeCerts) (map[string]*certSlot, error) {
	certs := map[string]*certSlot{}
	for _, name := range cfg.ListenNames() {
		l := cfg.Listen[name]
		if l.TLS == nil {
			continue
		}
		if l.TLS.Mode == "acme" {
			certs[name] = &certSlot{l: l, acme: ac.getCertificate(l)}
			continue
		}
		c, err := loadCert(l)
		if err != nil {
			return nil, err
		}
		certs[name] = &certSlot{l: l}
		certs[name].cur.Store(c)
	}
	return certs, nil
}

func loadCert(l *config.Listen) (*tls.Certificate, error) {
	hint := "create it with: lukd tls generate"
	if l.TLS.Mode == "files" {
		hint = "tls mode files: the tool that manages the certificate provides it"
	}
	for _, p := range []string{l.TLS.Cert, l.TLS.Key} {
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("listen %s: %v (%s)", l.Name, err, hint)
		}
	}
	cert, err := tls.LoadX509KeyPair(l.TLS.Cert, l.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", l.Name, err)
	}
	return &cert, nil
}

// reloadCerts reads the certificate and key of every self and files
// listener again. A listener whose new pair does not load keeps serving
// its current one. Acme listeners keep theirs (see acmeCerts.logState).
func reloadCerts(certs map[string]*certSlot, log *slog.Logger) {
	if len(certs) == 0 {
		log.Info("reload: no tls listener")
	}
	for _, name := range sortedKeys(certs) {
		slot := certs[name]
		if slot.acme != nil {
			continue
		}
		c, err := loadCert(slot.l)
		if err != nil {
			log.Error("tls reload failed, keeping the current certificate", "listen", name, "error", err)
			continue
		}
		slot.cur.Store(c)
		log.Info("tls reloaded", "listen", name, "pin", tlsself.Pin(c.Leaf), "expires", c.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
}

func listenNames(g config.AddrGroup) string {
	names := make([]string, len(g.Listen))
	for i, l := range g.Listen {
		names[i] = l.Name
	}
	return strings.Join(names, ",")
}
