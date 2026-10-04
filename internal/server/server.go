// Package server runs the lukd roles. Its HTTP side (the receive role)
// authenticates, authorizes and routes an upload and receives the body
// into the endpoint queue, where the entry stays committed for the process
// role. A dry run only reads and hashes the body and answers a debug JSON.
package server

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"luk/internal/auth"
	"luk/internal/config"
	"luk/internal/expose"
	"luk/internal/pipeline"
	"luk/internal/queue"
	"luk/internal/quota"
	"luk/internal/sshsig"
	"luk/internal/store"
	"luk/internal/tlsself"
	"luk/internal/wire"
)

type Server struct {
	// snap is the current configuration with everything derived from it;
	// a request takes it once and uses it to the end (see reload).
	snap   atomic.Pointer[snapshot]
	nonces *auth.NonceCache
	now    func() time.Time
	start  time.Time
	// floor is the earliest timestamp accepted after a reload raised
	// auth.clock_skew past what the nonce cache remembers (Unix
	// nanoseconds, 0 for none; see apply).
	floor atomic.Int64
	log   *slog.Logger
	queue *queue.Queue
	// quota holds the buckets of the endpoint quotas; it survives a
	// reload, the limits come from the configuration of each upload.
	quota *quota.Book
	// acme answers the acme: true listeners; nil outside Receive.
	acme *acmeCerts
	// certs are the certificates of the TLS listeners, for the pin of a
	// luk:// URL; nil outside Receive, where the pin comes from the files.
	certs map[string]*certSlot
}

// snapshot is one configuration and what is built from it; it is never
// changed once in use.
type snapshot struct {
	cfg       *config.Config
	auth      *auth.Authenticator
	listeners map[string]*listener
}

// listener is the routing table of one named listener: PUT to its
// endpoints, GET, HEAD and POST to its exposes.
type listener struct {
	cfg    *config.Listen
	byPath map[string]*config.Endpoint
	// expose serves the requests outside the endpoints; nil answers 404.
	expose http.Handler
}

func New(cfg *config.Config, log *slog.Logger) *Server {
	s := &Server{
		nonces: auth.NewNonceCache(2 * time.Duration(cfg.Auth.ClockSkew)),
		now:    time.Now,
		start:  time.Now(),
		log:    log,
		queue:  queue.New(int64(cfg.Limits.Queue.Reserve), nil),
	}
	s.queue.SetDirReserves(cfg.SecretReserves())
	s.quota = quota.New(log, func() time.Time { return s.now() })
	s.snap.Store(s.newSnapshot(cfg))
	return s
}

func (s *Server) newSnapshot(cfg *config.Config) *snapshot {
	sn := &snapshot{cfg: cfg, auth: auth.New(cfg.Auth), listeners: map[string]*listener{}}
	for name, l := range cfg.Listen {
		ln := &listener{cfg: l, byPath: map[string]*config.Endpoint{}}
		for _, e := range cfg.Endpoint {
			if slices.Contains(e.Listen, name) {
				ln.byPath[e.Endpoint] = e
			}
		}
		ln.expose = expose.New(cfg, s.log, func() time.Time { return s.now() }, name,
			func(r *http.Request) (*wire.Identity, error) { return s.verifyGet(r, sn, ln) })
		sn.listeners[name] = ln
	}
	return sn
}

// cur is the current snapshot.
func (s *Server) cur() *snapshot { return s.snap.Load() }

// config is the current configuration.
func (s *Server) config() *config.Config { return s.cur().cfg }

// apply makes cfg current. The nonce cache, the queue reservations and
// everything in flight stay. A clock skew past half the TTL of the nonce
// cache widens the timestamp window back to requests whose nonces may be
// forgotten: an accepted request was seen at most TTL/2 before its
// timestamp and its nonce is kept TTL after that, so the timestamps from
// TTL/2 before the reload on are still covered, the older ones are
// refused.
func (s *Server) apply(cfg *config.Config) {
	s.queue.SetReserve(int64(cfg.Limits.Queue.Reserve))
	s.queue.SetDirReserves(cfg.SecretReserves())
	ttl := 2 * time.Duration(cfg.Auth.ClockSkew)
	if old := s.nonces.Extend(ttl); ttl > old {
		if f := s.now().Add(-old / 2).UnixNano(); f > s.floor.Load() {
			s.floor.Store(f)
		}
	}
	s.snap.Store(s.newSnapshot(cfg))
}

func (s *Server) SetClock(now func() time.Time) { s.now = now }

// Handler serves one address: it picks the listener of the address by the
// request Host (port ignored, case-insensitive) and answers 421 when none
// of them serves that host. A listener without a host list serves every
// host; validation allows that only when it is alone on its address.
// The listeners of an address never change while it is open; their routing
// comes from the snapshot current when the request arrives.
func (s *Server) Handler(addr string) http.Handler {
	var names []string
	for _, g := range s.config().Addrs() {
		if g.Addr == addr {
			for _, l := range g.Listen {
				names = append(names, l.Name)
			}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A download leaves its write deadline on the connection for the
		// final flush (see expose); the next request starts without one.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		host := hostname(r.Host)
		sn := s.cur()
		for _, n := range names {
			if l := sn.listeners[n]; l.cfg.Serves(host) {
				s.serveHTTP(w, r, sn, l)
				return
			}
		}
		s.log.Debug("request for an unknown host", "remote", r.RemoteAddr, "host", r.Host, "addr", addr)
		w.Header().Set("Connection", "close")
		writeJSON(w, http.StatusMisdirectedRequest, wire.ErrorResponse{Error: "no listener for host " + r.Host})
	})
}

// hostname is the lowercase host of a Host header, without the port.
func hostname(hostport string) string {
	h := hostport
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"))
}

// Match returns the sorted names of the pipelines of endpoint whose tags are
// all present in tags. A matching pipeline with claim is the only one, and
// skipped holds the other matching pipelines; two claims are an error.
func Match(cfg *config.Config, endpoint string, tags []string) (pipes, skipped []string, err error) {
	var out, claim []string
	for name, p := range cfg.Pipeline {
		if !slices.Contains(p.Endpoint, endpoint) {
			continue
		}
		all := true
		for _, t := range p.Tags {
			if !slices.Contains(tags, t) {
				all = false
				break
			}
		}
		if all {
			out = append(out, name)
			if p.Claim {
				claim = append(claim, name)
			}
		}
	}
	sort.Strings(out)
	sort.Strings(claim)
	switch {
	case len(claim) > 1:
		return nil, nil, fail(http.StatusUnprocessableEntity, "upload claimed by %s", strings.Join(claim, " and "))
	case len(claim) == 1:
		for _, n := range out {
			if n != claim[0] {
				skipped = append(skipped, n)
			}
		}
		return claim, skipped, nil
	}
	return out, nil, nil
}

type httpError struct {
	code int
	msg  string
	// allow is the Allow header of a 405; PUT when empty.
	allow string
	// retry is the Retry-After of a 429; none when zero.
	retry time.Duration
}

func (e *httpError) Error() string { return e.msg }

func fail(code int, format string, a ...any) error {
	return &httpError{code: code, msg: fmt.Sprintf(format, a...)}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request, sn *snapshot, l *listener) {
	if l.cfg.ACME {
		if s.acme == nil {
			http.NotFound(w, r)
			return
		}
		s.acme.serveHTTP(w, r)
		return
	}
	if r.URL.Path == wire.EndpointsPath {
		s.serveEndpoints(w, r, sn, l)
		return
	}
	p := r.URL.Path
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	ep, ok := l.byPath[p]
	// Without endpoints nothing is an upload: the expose answers every
	// request, 405 for what it does not take.
	if !ok && (len(l.byPath) == 0 || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodPost) {
		h := l.expose
		if h == nil {
			h = http.NotFoundHandler()
		}
		h.ServeHTTP(w, r)
		return
	}
	var (
		code int
		resp any
		err  error
	)
	if !ok {
		err = fail(http.StatusNotFound, "no endpoint %s", r.URL.Path)
	} else {
		code, resp, err = s.handle(w, r, sn, l, ep)
	}
	what := "upload rejected"
	if isLink(r) {
		what = "link rejected"
	}
	if err != nil {
		var he *httpError
		if !errors.As(err, &he) {
			s.log.Error("upload failed", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path, "error", err)
			he = &httpError{code: http.StatusInternalServerError, msg: "internal error"}
		} else {
			// Unsigned requests for other paths are scanners and stray
			// clients, not uploads.
			level := slog.LevelInfo
			if !ok && !signed(r) {
				level = slog.LevelDebug
			}
			s.log.Log(r.Context(), level, what, "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path, "status", he.code, "error", he.msg)
		}
		if he.code == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", cmp.Or(he.allow, http.MethodPut))
		}
		if he.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64(he.retry/time.Second), 10))
		}
		// The body may be unread; do not keep the connection.
		w.Header().Set("Connection", "close")
		writeJSON(w, he.code, wire.ErrorResponse{Error: he.msg})
		return
	}
	writeJSON(w, code, resp)
}

// signed reports whether r carries any of the signature headers.
func signed(r *http.Request) bool {
	for _, k := range []string{wire.HeaderMeta, wire.HeaderTimestamp, wire.HeaderNonce, wire.HeaderSignature, wire.HeaderLink, wire.HeaderLinkAction} {
		if r.Header.Get(k) != "" {
			return true
		}
	}
	return false
}

// upload is an authenticated, matched request before its body is read.
type upload struct {
	sn    *snapshot
	ep    *config.Endpoint
	id    *wire.Identity
	meta  wire.Meta
	pipes []string
	// skipped are the matching pipelines a claim of pipes[0] left out.
	skipped []string
	now     time.Time
	vars    store.Vars
	url     string
	// reveal marks a body capped at expose.MaxReveal.
	reveal bool
	// replace is the link whose content the body replaces; nil for an
	// upload.
	replace *pipeline.Replace
	link    string
	// secret is the storage of a secret upload (see config.Secret), whose
	// only pipeline is pipeline.SecretPipeline; empty otherwise.
	secret string
	// charge accounts the body against the quota of the endpoint; nil
	// without one.
	charge *quota.Charge
}

// storage is the respond storage of the upload: the secret storage of a
// secret upload, else the storage of the endpoint.
func (u *upload) storage() string {
	if u.secret != "" {
		return u.secret
	}
	return u.ep.Storage
}

// queueDir is the queue directory the upload is received into.
func (u *upload) queueDir() string {
	if u.secret != "" {
		return u.ep.Secret.Path
	}
	return u.ep.Path
}

func (u *upload) tooLarge(max int64) error {
	if u.reveal {
		return fail(http.StatusUnprocessableEntity, "body exceeds the reveal limit %d", max)
	}
	return fail(http.StatusRequestEntityTooLarge, "body exceeds the limit %d of %s", max, u.ep.Name)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request, sn *snapshot, l *listener, ep *config.Endpoint) (int, any, error) {
	if isLink(r) {
		return s.handleLink(w, r, sn, l, ep)
	}
	if r.Method != http.MethodPut {
		return 0, nil, fail(http.StatusMethodNotAllowed, "method %s not allowed, use PUT", r.Method)
	}
	now := s.now()
	var meta wire.Meta
	id, err := s.authenticate(r, sn, l, ep, now, wire.Namespace,
		func(ts, nonce, metaS string) []byte { return wire.CanonicalText(r.Host, r.URL.Path, ts, nonce, metaS) },
		func(metaS string) (err error) { meta, err = wire.DecodeMeta(metaS); return err })
	if err != nil {
		return 0, nil, err
	}
	// A secret upload goes to the secret storage alone, whatever the tags.
	secret := ""
	pipes := []string{pipeline.SecretPipeline}
	var skipped []string
	if ep.Secrets(meta.Portal) {
		// A signer secret.allow does not grant never has its secret
		// written to disk instead of RAM.
		if !auth.Allowed(id, ep.Secret.Allow) {
			return 0, nil, fail(http.StatusUnprocessableEntity, "endpoint %s does not keep secrets in RAM for this key", ep.Name)
		}
		secret = ep.Secret.Storage
	} else if pipes, skipped, err = Match(sn.cfg, ep.Name, meta.Tags); err != nil {
		return 0, nil, err
	}
	if len(pipes) == 0 {
		return 0, nil, fail(http.StatusUnprocessableEntity, "no pipeline for endpoint %s and tags [%s]", ep.Name, strings.Join(meta.Tags, ","))
	}
	max, reveal, err := bodyLimit(r, ep, meta, meta.Portal)
	if err != nil {
		return 0, nil, err
	}
	// A signer a capability is not granted to gets the answer of an
	// endpoint without it.
	if meta.PrettyURL && (ep.Pretty == nil || !auth.Allowed(id, ep.Pretty.Allow)) {
		return 0, nil, fail(http.StatusUnprocessableEntity, "endpoint %s does not offer pretty URLs", ep.Name)
	}
	if meta.Mutable && !auth.Allowed(id, ep.Link.Replace) {
		return 0, nil, fail(http.StatusUnprocessableEntity, "endpoint %s does not allow replacing links (link.replace); mutable refused", ep.Name)
	}
	if who, ok := ep.Private.Of(meta.Access); !ok || (meta.Access != "" && !auth.Allowed(id, who)) {
		mode := "owner"
		if meta.Access == wire.AccessAny {
			mode = "any"
		}
		return 0, nil, fail(http.StatusUnprocessableEntity, "endpoint %s does not accept private uploads of access %s (private.%s)", ep.Name, meta.Access, mode)
	}
	u := &upload{sn: sn, ep: ep, id: id, meta: meta, pipes: pipes, skipped: skipped, now: now, reveal: reveal, secret: secret}
	if err := s.prepare(u); err != nil {
		return 0, nil, err
	}
	if err := s.overLinks(u); err != nil {
		return 0, nil, err
	}
	if meta.DryRun {
		if err := s.quotaCheck(u); err != nil {
			return 0, nil, err
		}
		return s.dryRun(w, u)
	}
	if e, ok := s.dedup(u); ok {
		// The body is never read, so no 100 Continue is sent.
		w.Header().Set("Connection", "close")
		return s.accept(u, e, *meta.Size, meta.SHA256, true)
	}
	return s.receive(w, r, u, max)
}

// dedup makes the queue entry of an upload from the content the sender
// already has on the server, without its body: the signed meta carries
// size and sha256, the matched pipelines only store into local storages
// with hardlink, and in each of them the object of that content holds a
// name owned by the sender, or a committed queue entry of the endpoint
// from the sender still holds it (an upload not stored yet). Never across
// owners: a hash proves nothing, the content of another sender is never
// handed out for one. False keeps the upload as it is.
func (s *Server) dedup(u *upload) (queue.Entry, bool) {
	m := u.meta
	if m.Size == nil || m.SHA256 == "" || u.replace != nil {
		return queue.Entry{}, false
	}
	stores := storesOnly(u.sn.cfg, u.pipes, u.secret)
	if len(stores) == 0 {
		return queue.Entry{}, false
	}
	owner := auth.OwnerKey(u.id)
	src, fi, ok := held(stores, m.SHA256, *m.Size, owner)
	if !ok {
		src, fi, ok = queued(u.queueDir(), m.SHA256, *m.Size, owner)
	}
	if !ok {
		// The entry may have been stored and removed meanwhile.
		src, fi, ok = held(stores, m.SHA256, *m.Size, owner)
	}
	if !ok {
		return queue.Entry{}, false
	}
	e, err := s.queue.Link(u.queueDir(), u.vars.Id, src, fi)
	if err != nil {
		s.log.Debug("upload not deduplicated", "id", u.vars.Id, "sender", u.id.Name, "endpoint", u.ep.Name, "error", err)
		return queue.Entry{}, false
	}
	return e, true
}

// overLinks refuses, before the body, an upload with a signed size and
// sha256 whose sender already has links.max names of that content in a
// local storage with hardlink the pipelines store it into: the names of
// the objects index plus the committed entries of the sender with that
// content in the queue of the upload that store into it and are not
// stored there yet, so a burst cannot overshoot and no upload counts
// twice. The store step checks again.
func (s *Server) overLinks(u *upload) error {
	m := u.meta
	if m.Size == nil || m.SHA256 == "" || u.replace != nil {
		return nil
	}
	stores := directStores(u.sn.cfg, u.pipes, u.secret)
	if len(stores) == 0 {
		return nil
	}
	owner := auth.OwnerKey(u.id)
	// The queue is read before the indexes: an entry stored in between is
	// in the index and skipped, one removed in between was counted queued.
	queued := queuedFor(u.sn.cfg, u.queueDir(), m.SHA256, *m.Size, owner)
	for name, l := range stores {
		n, stored := l.OwnedIDs(m.SHA256, owner)
		for _, id := range queued[name] {
			if !stored[id] {
				n++
			}
		}
		if n >= l.MaxLinks {
			return fail(http.StatusTooManyRequests, "%v", &store.TooManyLinks{Max: l.MaxLinks})
		}
	}
	return nil
}

// directStores maps the local storages with hardlink and a links limit
// that the pipelines store the upload itself into (a store step before
// any run step other than tee and any encrypt step; a relay step passes
// the upload on) to their Local. secret is the storage of
// pipeline.SecretPipeline.
func directStores(cfg *config.Config, pipes []string, secret string) map[string]store.Local {
	out := map[string]store.Local{}
	for _, pn := range pipes {
		p, ok := pipeline.Lookup(cfg, pn, secret)
		if !ok {
			continue
		}
		for _, step := range p.Steps {
			if (step.Run != "" && !step.Tee) || step.Encrypt != nil {
				break
			}
			for _, sn := range step.Store {
				st := cfg.Storage[sn]
				if st == nil || st.Type != "local" {
					continue
				}
				if l := store.FromConfig(st); l.Hardlink && l.MaxLinks > 0 {
					out[sn] = l
				}
			}
		}
	}
	return out
}

// queuedFor lists per storage the upload ids of the committed entries of
// the queue directory dir uploaded by owner with the content that store it
// into.
func queuedFor(cfg *config.Config, dir, sum string, size int64, owner string) map[string][]string {
	out := map[string][]string{}
	pending, err := queue.Pending(dir)
	if err != nil {
		return out
	}
	for _, e := range pending {
		j, err := pipeline.LoadJob(e)
		if err != nil || j.Sidecar.SHA256 != sum || j.Sidecar.Size != size || j.Sidecar.OwnerKey != owner {
			continue
		}
		for sn := range directStores(cfg, j.Pipelines, j.Secret) {
			// A replace puts the content in place of its link.
			if j.Replace == nil || j.Replace.Storage != sn {
				out[sn] = append(out[sn], j.Sidecar.ID)
			}
		}
	}
	return out
}

// storesOnly lists the storages the pipelines store into when they have
// store steps only, into local storages with hardlink; nil otherwise.
// secret is the storage of pipeline.SecretPipeline.
func storesOnly(cfg *config.Config, pipes []string, secret string) []store.Local {
	seen := map[string]bool{}
	var out []store.Local
	for _, pn := range pipes {
		p, ok := pipeline.Lookup(cfg, pn, secret)
		if !ok {
			return nil
		}
		for _, step := range p.Steps {
			if step.Run != "" || step.Encrypt != nil || len(step.Store) == 0 {
				return nil
			}
			for _, sn := range step.Store {
				st := cfg.Storage[sn]
				if st == nil || st.Type != "local" || !store.FromConfig(st).Hardlink {
					return nil
				}
				if !seen[sn] {
					seen[sn] = true
					out = append(out, store.FromConfig(st))
				}
			}
		}
	}
	return out
}

// held finds the object of the content in every storage of ls, held by a
// name of owner; it returns the first.
func held(ls []store.Local, sum string, size int64, owner string) (string, os.FileInfo, bool) {
	var src string
	var fi os.FileInfo
	for _, l := range ls {
		p, f, ok := l.Object(sum, size, owner)
		if !ok {
			return "", nil, false
		}
		if src == "" {
			src, fi = p, f
		}
	}
	return src, fi, src != ""
}

// queued finds a committed entry of the queue directory dir uploaded by
// owner with the content: its payload.
func queued(dir, sum string, size int64, owner string) (string, os.FileInfo, bool) {
	pending, err := queue.Pending(dir)
	if err != nil {
		return "", nil, false
	}
	for _, e := range pending {
		j, err := pipeline.LoadJob(e)
		if err != nil || j.Sidecar.SHA256 != sum || j.Sidecar.Size != size || j.Sidecar.OwnerKey != owner {
			continue
		}
		p := filepath.Join(e.Dir, "payload")
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() && fi.Size() == size {
			return p, fi, true
		}
	}
	return "", nil, false
}

// bodyLimit checks the signed size against the limits of ep before the
// body and returns the limit of the body; the content of a reveal portal
// is capped at expose.MaxReveal (reveal).
func bodyLimit(r *http.Request, ep *config.Endpoint, meta wire.Meta, portal string) (int64, bool, error) {
	max := int64(ep.Limits.Body.Size)
	if meta.Size != nil {
		if max > 0 && *meta.Size > max {
			return 0, false, fail(http.StatusRequestEntityTooLarge, "size %d exceeds the limit %d of %s", *meta.Size, max, ep.Name)
		}
		if r.ContentLength >= 0 && r.ContentLength != *meta.Size {
			return 0, false, fail(http.StatusUnprocessableEntity, "Content-Length %d differs from the signed size %d", r.ContentLength, *meta.Size)
		}
		if portal == wire.PortalReveal && *meta.Size > expose.MaxReveal {
			return 0, false, fail(http.StatusUnprocessableEntity, "size %d exceeds the reveal limit %d", *meta.Size, expose.MaxReveal)
		}
	}
	if portal == wire.PortalReveal && (max == 0 || max > expose.MaxReveal) {
		return expose.MaxReveal, true, nil
	}
	return max, false, nil
}

// prepare draws the names of the upload and refuses, before the body,
// one that cannot be stored. A replace keeps the name of its link in the
// target storage.
func (s *Server) prepare(u *upload) error {
	sn, ep, meta, now := u.sn, u.ep, u.meta, u.now
	u.vars = store.Vars{
		Sender: u.id.Name, Endpoint: ep.Name, Time: now.UTC().Truncate(time.Second),
		Id: newID(now), Random: randomName(), File: meta.File, Tags: meta.Tags,
	}
	for n, st := range sn.cfg.Storage {
		if st.Random.Alphabet != "" {
			if u.vars.Randoms == nil {
				u.vars.Randoms = map[string]string{}
			}
			u.vars.Randoms[n] = store.RandomName(st.Random.Alphabet, st.Random.Length)
		}
	}
	if meta.PrettyURL {
		// One proquint for every storage, so the URL and the names agree.
		u.vars.Random, u.vars.Randoms = store.PrettyName(ep.Pretty.Bits), nil
	}
	if meta.Backup != nil {
		u.vars.Hostname = meta.Backup.Hostname
	}
	skip := ""
	switch {
	case u.replace != nil:
		u.url, skip = u.link, u.replace.Storage
	case ep.Respond == "url":
		var err error
		if u.url, err = s.downloadURL(sn.cfg, u.storage(), u.vars, meta.Access); err != nil {
			return fail(http.StatusUnprocessableEntity, "%v", err)
		}
	}
	return checkPaths(sn.cfg, u.pipes, u.secret, u.vars, skip)
}

// receive reads the body into the queue; Go sends 100 Continue on its
// first read. With a quota on the endpoint the signed size is charged
// before (refused before any body), a body without one while it streams;
// an upload not accepted gives back what it took.
func (s *Server) receive(w http.ResponseWriter, r *http.Request, u *upload, max int64) (int, any, error) {
	if lim, ok := quota.Resolve(u.ep.Quota, u.id); ok {
		u.charge = s.quota.Begin(u.ep.Name, auth.OwnerKey(u.id), lim)
		defer u.charge.Cancel()
		if u.meta.Size != nil {
			if err := u.charge.Take(*u.meta.Size); err != nil {
				return 0, nil, quotaFail(err)
			}
		}
	}
	bl := u.ep.Limits.Body
	rc := http.NewResponseController(w)
	defer func() { _ = rc.SetReadDeadline(time.Time{}) }()
	ir := &idleReader{r: r.Body, rc: rc, d: time.Duration(bl.Idle)}
	if bl.Timeout > 0 {
		ir.total = time.Duration(bl.Timeout)
		ir.end = time.Now().Add(ir.total)
	}
	return s.ingest(r.Context(), u, ir, max)
}

// quotaCheck is the quota check of a dry run: the signed size against the
// bucket of the sender, nothing charged.
func (s *Server) quotaCheck(u *upload) error {
	lim, ok := quota.Resolve(u.ep.Quota, u.id)
	if !ok || u.meta.Size == nil {
		return nil
	}
	c := s.quota.Begin(u.ep.Name, auth.OwnerKey(u.id), lim)
	defer c.Cancel()
	if err := c.Check(*u.meta.Size); err != nil {
		return quotaFail(err)
	}
	return nil
}

// quotaFail is the answer to a quota refusal: 429 with Retry-After for one
// that passes later, 413 for one larger than the bucket. Neither names the
// limits.
func quotaFail(err error) error {
	var qr *quota.Refusal
	if !errors.As(err, &qr) {
		return err
	}
	if qr.TooLarge {
		return &httpError{code: http.StatusRequestEntityTooLarge, msg: wire.ErrQuotaTooLarge}
	}
	return &httpError{code: http.StatusTooManyRequests, msg: wire.ErrQuotaExceeded, retry: qr.RetryAfter}
}

// downloadURL is the URL of the upload in its respond storage: on its
// expose, or for a private upload (access set) the luk:// URL on its
// protect expose.
func (s *Server) downloadURL(cfg *config.Config, storage string, v store.Vars, access string) (string, error) {
	st := cfg.Storage[storage]
	if st == nil {
		return "", fmt.Errorf("storage %s is not exposed", storage)
	}
	if st.Type != "local" || st.PathTemplate() == nil {
		return "", fmt.Errorf("storage %s is not a local storage", storage)
	}
	rel, err := store.FromConfig(st).Render(st.PathTemplate(), v.For(storage))
	if err != nil {
		return "", fmt.Errorf("storage %s: %w", storage, err)
	}
	if u, ok := s.fileURL(cfg, storage, rel, access); ok {
		return u, nil
	}
	if access != "" {
		return "", fmt.Errorf("storage %s has no protect expose", storage)
	}
	return "", fmt.Errorf("storage %s is not exposed", storage)
}

// fileURL is the URL of the stored name rel of storage: on its expose,
// or for a private file (access set) on its protect expose with the
// scheme luk and, when the first listener of that expose uses a
// certificate of mode self or files, its pin as the fragment.
func (s *Server) fileURL(cfg *config.Config, storage, rel, access string) (string, bool) {
	if access == "" {
		st := cfg.Storage[storage]
		if st == nil {
			return "", false
		}
		base, ok := cfg.ExposeURL(st.Expose)
		if !ok {
			return "", false
		}
		return expose.NameURL(base, rel), true
	}
	base, l, ok := cfg.ProtectURL(storage)
	if !ok {
		return "", false
	}
	u := expose.NameURL(base, rel)
	if pin := s.pin(l); pin != "" {
		u += "#" + pin
	}
	return u, true
}

// pin is the SPKI pin of the certificate the listener serves when it has
// tls mode self or files: the loaded certificate in the receive role,
// else the cert file; empty for any other listener or a certificate that
// cannot be read.
func (s *Server) pin(l *config.Listen) string {
	if l == nil || l.TLS == nil || (l.TLS.Mode != "self" && l.TLS.Mode != "files") {
		return ""
	}
	if slot := s.certs[l.Name]; slot != nil {
		if c := slot.cur.Load(); c != nil && c.Leaf != nil {
			return tlsself.Pin(c.Leaf)
		}
	}
	pin, err := tlsself.PinFile(l.TLS.Cert)
	if err != nil {
		s.log.Warn("pin of a luk:// URL", "listen", l.Name, "error", err)
		return ""
	}
	return pin
}

// checkPaths renders the path of every local storage the matched pipelines
// (secret: the storage of pipeline.SecretPipeline) store into but skip, so
// a name that cannot be stored is refused before the body.
func checkPaths(cfg *config.Config, pipes []string, secret string, v store.Vars, skip string) error {
	seen := map[string]bool{}
	for _, pn := range pipes {
		p, ok := pipeline.Lookup(cfg, pn, secret)
		if !ok {
			continue
		}
		for _, step := range p.Steps {
			for _, sn := range step.Store {
				st := cfg.Storage[sn]
				if seen[sn] || sn == skip || st == nil || st.Type != "local" || st.PathTemplate() == nil {
					continue
				}
				seen[sn] = true
				if _, err := store.FromConfig(st).Render(st.PathTemplate(), v.For(sn)); err != nil {
					return fail(http.StatusUnprocessableEntity, "storage %s: %v", sn, err)
				}
			}
		}
	}
	return nil
}

// dryRun answers once every check before the body passed; the body is
// never read, so no 100 Continue is sent.
func (s *Server) dryRun(w http.ResponseWriter, u *upload) (int, any, error) {
	respond := wire.Respond{Mode: "accept"}
	if u.ep.Respond == "url" {
		respond = wire.Respond{Mode: "url", URL: u.url}
	}
	w.Header().Set("Connection", "close")
	s.log.Info("dry run accepted", append([]any{"id", u.vars.Id, "sender", u.id.Name, "endpoint", u.ep.Name,
		"tags", strings.Join(u.meta.Tags, ","), "pipelines", strings.Join(u.pipes, ",")}, u.claimLog()...)...)
	var claimed *wire.Claimed
	if u.skipped != nil {
		claimed = &wire.Claimed{Pipeline: u.pipes[0], Skipped: u.skipped}
	}
	return http.StatusOK, &wire.Response{
		ID:        u.vars.Id,
		Identity:  *u.id,
		Endpoint:  u.ep.Name,
		Client:    u.meta,
		Server:    wire.ServerMeta{Received: u.now.UTC().Format(time.RFC3339)},
		Pipelines: u.pipes,
		Schedule:  schedule(u),
		Claimed:   claimed,
		Respond:   respond,
	}, nil
}

// claimLog is the log attributes of a claim: the claiming pipeline and the
// matching pipelines it left out; none without a claim.
func (u *upload) claimLog() []any {
	if u.skipped == nil {
		return nil
	}
	return []any{"claimed", u.pipes[0], "skipped", strings.Join(u.skipped, ",")}
}

// schedule is the dry run view of the matched pipelines of u: those
// without a group first, then the groups by name, each in ascending order.
func schedule(u *upload) []wire.Scheduled {
	out := []wire.Scheduled{}
	for _, pn := range u.pipes {
		sc := wire.Scheduled{Pipeline: pn}
		if p, ok := u.sn.cfg.Pipeline[pn]; ok {
			sc.Group, sc.Order = p.Queue.Group, p.Queue.Order
		}
		out = append(out, sc)
	}
	slices.SortFunc(out, func(a, b wire.Scheduled) int {
		return cmp.Or(strings.Compare(a.Group, b.Group), cmp.Compare(a.Order, b.Order), strings.Compare(a.Pipeline, b.Pipeline))
	})
	return out
}

func (s *Server) ingest(ctx context.Context, u *upload, ir *idleReader, max int64) (int, any, error) {
	var res *queue.Reservation
	if u.meta.Size != nil {
		var err error
		res, err = s.queue.Reserve(u.queueDir(), *u.meta.Size)
		if errors.Is(err, queue.ErrNoSpace) {
			return 0, nil, fail(http.StatusInsufficientStorage, "not enough space")
		}
		if err != nil {
			return 0, nil, fmt.Errorf("queue %s: %w", u.queueDir(), err)
		}
	}
	defer res.Release()
	var body io.Reader = ir
	if u.charge != nil && u.meta.Size == nil {
		body = u.charge.Reader(ir)
	}
	e, n, sum, err := s.queue.Receive(ctx, u.queueDir(), u.vars.Id, body, max, u.meta.Size, u.meta.SHA256, res)
	var qr *quota.Refusal
	switch {
	case err == nil:
	case errors.As(err, &qr):
		return 0, nil, quotaFail(err)
	case errors.Is(err, queue.ErrNoSpace):
		return 0, nil, fail(http.StatusInsufficientStorage, "not enough space")
	case errors.Is(err, queue.ErrTooLarge):
		return 0, nil, u.tooLarge(max)
	case errors.Is(err, queue.ErrMismatch):
		// The answer and its log line keep nothing derived from a secret.
		if u.secret != "" {
			return 0, nil, fail(http.StatusUnprocessableEntity, "body differs from the signed %d bytes", *u.meta.Size)
		}
		return 0, nil, fail(http.StatusUnprocessableEntity, "body differs from the signed %d bytes sha256 %s", *u.meta.Size, u.meta.SHA256)
	case ir.err != nil && errors.Is(err, ir.err):
		return 0, nil, ir.fail(err)
	case ctx.Err() != nil:
		return 0, nil, fail(http.StatusBadRequest, "reading body: %v", err)
	default:
		return 0, nil, fmt.Errorf("queue %s: %w", u.queueDir(), err)
	}
	return s.accept(u, e, n, sum, false)
}

// accept commits the entry e of the upload, its content of n bytes with
// sha256 sum, and answers per respond; dedup marks content taken from the
// server instead of the body.
func (s *Server) accept(u *upload, e queue.Entry, n int64, sum string, dedup bool) (int, any, error) {
	sc := store.Sidecar{
		ID: u.vars.Id, Sender: u.id.Name, Endpoint: u.ep.Name, Received: u.now.UTC().Format(time.RFC3339),
		Size: n, SHA256: sum, Client: u.meta,
	}
	if !u.meta.NoOwner {
		sc.Owner = u.sn.auth.Owner(u.id)
	}
	sc.OwnerKey = auth.OwnerKey(u.id)
	lts := lifetimes(u)
	exp := expires(u.now, lts)
	if u.ep.Respond == "url" && u.replace == nil {
		sc.Expires = exp[u.storage()]
	}
	job := pipeline.Job{Entry: e, Pipelines: u.pipes, Stages: pipeline.Stages(u.sn.cfg, u.pipes), Vars: u.vars, Sidecar: sc, Expires: exp, Replace: u.replace, Secret: u.secret}
	if err := s.queue.Commit(e, job.Meta()); errors.Is(err, queue.ErrNotSynced) {
		s.log.Warn("upload committed", "id", e.ID, "error", err)
	} else if err != nil {
		_ = s.queue.Remove(e)
		if errors.Is(err, queue.ErrNoSpace) {
			return 0, nil, fail(http.StatusInsufficientStorage, "not enough space")
		}
		return 0, nil, fmt.Errorf("queue %s: %w", e.Dir, err)
	}
	if u.charge != nil {
		u.charge.Done(n)
	}
	// The log keeps nothing derived from the content of a secret.
	logSum := sum
	if u.secret != "" {
		logSum = "-"
	}
	if u.replace != nil {
		s.log.Info("link replace accepted", "id", e.ID, "sender", u.id.Name, "endpoint", u.ep.Name,
			"storage", u.replace.Storage, "file", u.replace.Name, "pipelines", strings.Join(u.pipes, ","), "size", n, "sha256", logSum)
		return http.StatusAccepted, &wire.LinkAnswer{URL: u.link, ID: e.ID, Size: &n, SHA256: sum}, nil
	}
	what := "upload accepted"
	if dedup {
		what = "upload deduplicated"
	}
	s.log.Info(what, append([]any{"id", e.ID, "sender", u.id.Name, "endpoint", u.ep.Name,
		"tags", strings.Join(u.meta.Tags, ","), "pipelines", strings.Join(u.pipes, ","), "size", n, "sha256", logSum, "url", u.url}, u.claimLog()...)...)
	if u.ep.Respond == "url" {
		lt := lts[u.storage()]
		c := &wire.Created{ID: e.ID, URL: u.url, Expires: sc.Expires, Size: n, SHA256: sum, Deduplicated: dedup}
		c.TTL, c.TTLNote = lt.ttl()
		c.TTLMin, c.TTLMax = lt.bounds()
		return http.StatusCreated, c, nil
	}
	r := &wire.Receipt{ID: e.ID, Size: n, SHA256: sum, Deduplicated: dedup}
	if lt, ok := common(lts); ok {
		r.TTL, r.TTLNote = lt.ttl()
		r.TTLMin, r.TTLMax = lt.bounds()
	}
	return http.StatusAccepted, r, nil
}

// lifetime is the lifetime of the upload in one storage (0: never expires),
// what became of the client ttl there and the ttl.min and ttl.max of the
// storage (0: none).
type lifetime struct {
	d        time.Duration
	note     string
	min, max time.Duration
}

// lifetimeIn is the lifetime in st for the client ttl (empty: none).
func lifetimeIn(st *config.Storage, ttl string) lifetime {
	d, note := st.Lifetime(ttl)
	return lifetime{d, note, time.Duration(st.TTL.Min), time.Duration(st.TTL.Max)}
}

// lifetimes maps every local storage the upload is stored into (and the
// respond storage) to its lifetime under the storage ttl policy.
func lifetimes(u *upload) map[string]lifetime {
	names := map[string]bool{}
	if u.ep.Respond == "url" && u.replace == nil {
		names[u.storage()] = true
	}
	for _, pn := range u.pipes {
		if p, ok := pipeline.Lookup(u.sn.cfg, pn, u.secret); ok {
			for _, step := range p.Steps {
				for _, sn := range step.Store {
					names[sn] = true
				}
			}
		}
	}
	if u.replace != nil {
		// The link keeps its expiry.
		delete(names, u.replace.Storage)
	}
	out := make(map[string]lifetime, len(names))
	for n := range names {
		if st := u.sn.cfg.Storage[n]; st != nil && st.Type == "local" {
			out[n] = lifetimeIn(st, u.meta.TTL)
		}
	}
	return out
}

// expires maps each storage with a lifetime to its expiry.
func expires(now time.Time, lts map[string]lifetime) map[string]string {
	out := make(map[string]string, len(lts))
	for n, lt := range lts {
		if lt.d > 0 {
			out[n] = now.Add(lt.d).UTC().Format(time.RFC3339)
		}
	}
	return out
}

// ttl is what an answer states about the lifetime: the duration (empty
// when it never expires) and the note.
func (lt lifetime) ttl() (string, string) {
	if lt.d <= 0 {
		return "", lt.note
	}
	return wire.FormatDuration(lt.d), lt.note
}

// bounds is what an answer states about the ttl policy: ttl.min and
// ttl.max, each empty when unset.
func (lt lifetime) bounds() (string, string) {
	var lo, hi string
	if lt.min > 0 {
		lo = wire.FormatDuration(lt.min)
	}
	if lt.max > 0 {
		hi = wire.FormatDuration(lt.max)
	}
	return lo, hi
}

// common is the lifetime shared by every storage of the upload, for the
// 202 answer that names no storage; false when they differ or there are
// none.
func common(lts map[string]lifetime) (lifetime, bool) {
	var first lifetime
	n := 0
	for _, lt := range lts {
		if n > 0 && lt != first {
			return lifetime{}, false
		}
		first = lt
		n++
	}
	return first, n > 0
}

// authenticate verifies a signed request under namespace over the
// canonical text that text builds from the timestamp, the nonce and the
// meta header, after decode accepted the meta, and returns the identity
// allowed on ep.
func (s *Server) authenticate(r *http.Request, sn *snapshot, l *listener, ep *config.Endpoint, now time.Time,
	namespace string, text func(ts, nonce, meta string) []byte, decode func(string) error) (*wire.Identity, error) {
	metaS := r.Header.Get(wire.HeaderMeta)
	ts := r.Header.Get(wire.HeaderTimestamp)
	nonce := r.Header.Get(wire.HeaderNonce)
	sigS := r.Header.Get(wire.HeaderSignature)
	if metaS == "" || ts == "" || nonce == "" || sigS == "" {
		return nil, fail(http.StatusUnauthorized, "missing signature headers")
	}
	if len(metaS) > wire.MaxMetaHeader {
		return nil, fail(http.StatusUnauthorized, "meta header too large")
	}
	if err := decode(metaS); err != nil {
		return nil, fail(http.StatusUnauthorized, "bad meta: %v", err)
	}
	id, err := s.verify(r, sn, l, now, ts, nonce, sigS, namespace, text(ts, nonce, metaS))
	if err != nil {
		return nil, err
	}
	if !auth.Allowed(id, ep.Allow) {
		return nil, fail(http.StatusForbidden, "%s may not upload to %s", id.Name, ep.Name)
	}
	return id, nil
}

// verifyGet verifies a luk-get@v1 request to an expose with auth.ssh on l
// and returns the signer; expose.ErrUnsigned without any of the signature
// headers. Who may have which file is the expose's decision.
func (s *Server) verifyGet(r *http.Request, sn *snapshot, l *listener) (*wire.Identity, error) {
	ts := r.Header.Get(wire.HeaderTimestamp)
	nonce := r.Header.Get(wire.HeaderNonce)
	sigS := r.Header.Get(wire.HeaderSignature)
	if ts == "" && nonce == "" && sigS == "" {
		return nil, expose.ErrUnsigned
	}
	if ts == "" || nonce == "" || sigS == "" {
		return nil, errors.New("missing signature headers")
	}
	return s.verify(r, sn, l, s.now(), ts, nonce, sigS, wire.GetNamespace,
		wire.GetCanonicalText(r.Method, r.Host, r.URL.EscapedPath(), ts, nonce))
}

// verify checks the timestamp, the nonce and the signature of a signed
// request under namespace over text, and returns the identity of the
// signer on the configuration of sn.
func (s *Server) verify(r *http.Request, sn *snapshot, l *listener, now time.Time, ts, nonce, sigS, namespace string, text []byte) (*wire.Identity, error) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil, fail(http.StatusUnauthorized, "bad timestamp: %v", err)
	}
	if d := now.Sub(t).Abs(); d > time.Duration(sn.cfg.Auth.ClockSkew) {
		return nil, fail(http.StatusUnauthorized, "%s", wire.ErrTimestampWindow)
	}
	// Without a persisted nonce cache (see auth.nonces) this bounds replay
	// across a restart to the timestamps signed ahead of the server clock.
	if t.Before(s.start.Truncate(time.Second)) {
		return nil, fail(http.StatusUnauthorized, "timestamp before server start")
	}
	if f := s.floor.Load(); f != 0 && t.Before(time.Unix(0, f)) {
		return nil, fail(http.StatusUnauthorized, "timestamp before the clock skew was raised")
	}
	if !wire.ValidNonce(nonce) {
		return nil, fail(http.StatusUnauthorized, "bad nonce")
	}
	blob, err := base64.StdEncoding.DecodeString(sigS)
	if err != nil {
		return nil, fail(http.StatusUnauthorized, "bad signature encoding")
	}
	sig, err := sshsig.ParseBlob(blob)
	if err != nil {
		return nil, fail(http.StatusUnauthorized, "bad signature: %v", err)
	}
	if err := sig.Verify(namespace, text); err != nil {
		return nil, fail(http.StatusUnauthorized, "signature does not verify: %v", err)
	}
	// A request captured for another lukd trusting the same keys carries
	// that server's Host.
	if len(l.cfg.Host) > 0 && !slices.Contains(l.cfg.Host, hostname(r.Host)) {
		return nil, fail(http.StatusUnauthorized, "signed host %s is not served by listen %s", r.Host, l.cfg.Name)
	}
	id, err := sn.auth.Resolve(sig.Key, now)
	if err != nil {
		return nil, fail(http.StatusUnauthorized, "%v", err)
	}
	// After the identity: only known identities can fill the nonce cache.
	if !s.nonces.Check(nonce, now) {
		return nil, fail(http.StatusUnauthorized, "replayed nonce")
	}
	return id, nil
}

// randomName is the default .Random, the only protection of a plain blob:
// DefaultRandomLength characters of RandomAlphabet (about 184 bits).
func randomName() string {
	return store.RandomName(config.RandomAlphabet, config.DefaultRandomLength)
}

func newID(now time.Time) string { return queue.NewID(now) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// idleReader arms a read deadline before every Read, so only a stalled body
// times out, never a slow but progressing one. A non-zero end caps the whole
// body read.
// It keeps the last read error to tell a client failure from a disk one.
type idleReader struct {
	r     io.Reader
	rc    *http.ResponseController
	d     time.Duration
	end   time.Time
	total time.Duration
	err   error
}

func (i *idleReader) Read(p []byte) (int, error) {
	dl := time.Now().Add(i.d)
	if !i.end.IsZero() && i.end.Before(dl) {
		dl = i.end
	}
	_ = i.rc.SetReadDeadline(dl)
	n, err := i.r.Read(p)
	if err != nil && err != io.EOF {
		i.err = err
	}
	return n, err
}

// fail maps a body read error to its answer.
func (i *idleReader) fail(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		if !i.end.IsZero() && !time.Now().Before(i.end) {
			return fail(http.StatusRequestTimeout, "body not received within %s", i.total)
		}
		return fail(http.StatusRequestTimeout, "no body data for %s", i.d)
	}
	return fail(http.StatusBadRequest, "reading body: %v", err)
}
