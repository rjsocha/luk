// Package expose serves stored files of local storages over HTTP (GET and
// HEAD under the URL path of each expose) and runs the janitor that removes
// expired, aged and stale claimed files.
package expose

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"luk/internal/auth"
	"luk/internal/config"
	"luk/internal/store"
	"luk/internal/wire"
)

// MaxReveal is the largest content a reveal portal shows.
const MaxReveal = 64 << 10

// Test hooks: beforeClaim runs before a once file is claimed, claimHook
// after the claim and before the content is served; readReveal reads the
// reveal content.
var (
	beforeClaim = func() {}
	claimHook   = func() {}
	readReveal  = io.ReadAll
)

type route struct {
	name   string
	prefix string
	// public is the URL of the expose the 201 answer builds on (the public
	// of its first listener and its path); empty when there is none.
	public string
	st     store.Local
	users  map[string][]byte
	// dummy is compared for unknown users, so they cost as much as a wrong
	// password.
	dummy []byte
	// ssh marks an expose with auth.ssh: signed requests, judged by their
	// signature alone; allow is its allow list. As a protect it serves
	// private files only; as the expose of its storage (signed) it serves
	// the public files and the catalog to the identities of allow and
	// answers the signed listing. With users too, an unsigned request is judged by auth.basic
	// and served as on an expose without auth.ssh.
	ssh    bool
	signed bool
	allow  []string
	// index answers the directory URLs with a listing (expose index).
	index bool
}

// Verifier verifies a signed luk-get@v1 request and returns the identity
// of the signer; ErrUnsigned when the request carries none of the
// signature headers.
type Verifier func(r *http.Request) (*wire.Identity, error)

// ErrUnsigned is a request to an expose with auth.ssh without a signature;
// it is answered like a missing file.
var ErrUnsigned = errors.New("unsigned request")

type handler struct {
	routes []route
	log    *slog.Logger
	now    func() time.Time
	verify Verifier
	// idle is the longest a response waits for the client to take more of
	// it (limits.conn.idle).
	idle time.Duration
}

// bcryptSlots bounds the auth.basic checks running at once: each costs
// tens of milliseconds of CPU, and anyone may ask for one.
var bcryptSlots = make(chan struct{}, runtime.GOMAXPROCS(0))

// New returns the download handler of one listener: every expose on it
// backed by a local storage. verify checks the signed requests of exposes
// with auth.ssh; nil answers them all like missing files.
func New(cfg *config.Config, log *slog.Logger, now func() time.Time, listen string, verify Verifier) http.Handler {
	h := &handler{log: log, now: now, verify: verify, idle: cmp.Or(time.Duration(cfg.Limits.Conn.Idle), config.DefaultConnIdle)}
	for name, x := range cfg.Expose {
		_, st, ok := cfg.StorageServedBy(name)
		if !ok || st.Type != "local" || !slices.Contains(x.Listen, listen) {
			continue
		}
		if !strings.HasPrefix(x.Path, "/") || !strings.HasSuffix(x.Path, "/") {
			log.Error("expose: bad path", "expose", name)
			continue
		}
		rt := route{name: name, prefix: x.Path, st: store.FromConfig(st)}
		rt.public, _ = cfg.ExposeURL(name)
		if x.Auth.SSH != nil {
			rt.ssh, rt.allow = true, x.Auth.SSH.Allow
			rt.signed = st.Expose == name
		}
		rt.index = x.Index && (!rt.ssh || len(x.Auth.Basic) > 0)
		for _, b := range x.Auth.Basic {
			user, hash, _ := strings.Cut(b, ":")
			hash = config.BcryptHash(hash)
			if rt.users == nil {
				rt.users = map[string][]byte{}
				rt.dummy = []byte(hash)
			}
			rt.users[user] = []byte(hash)
		}
		h.routes = append(h.routes, rt)
	}
	sort.Slice(h.routes, func(i, j int) bool { return len(h.routes[i].prefix) > len(h.routes[j].prefix) })
	return h
}

// match finds the route of the longest expose path p starts with; the
// path of a nested expose without its slash goes to that expose too.
func (h *handler) match(p string) (*route, string) {
	for i := range h.routes {
		if rel, ok := strings.CutPrefix(p, h.routes[i].prefix); ok {
			return &h.routes[i], rel
		}
		if p+"/" == h.routes[i].prefix {
			return &h.routes[i], ""
		}
	}
	return nil, ""
}

// basic reports whether an unsigned request is judged by auth.basic (or
// served without auth) and served as on an expose without auth.ssh.
func (rt *route) basic() bool { return !rt.ssh || rt.users != nil }

func (rt *route) authorized(r *http.Request) bool {
	if rt.users == nil {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	hash, known := rt.users[user]
	if !known {
		hash = rt.dummy
	}
	select {
	case bcryptSlots <- struct{}{}:
	case <-r.Context().Done():
		return false
	}
	defer func() { <-bcryptSlots }()
	return bcrypt.CompareHashAndPassword(hash, []byte(pass)) == nil && known
}

// idleWriter arms a write deadline before the header and every write, so
// a client that stops reading a response is cut after d without progress,
// never a slow but reading one. The last deadline stays for the final
// flush; the server clears it when the next request starts.
type idleWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
	d  time.Duration
}

func (i *idleWriter) arm() { _ = i.rc.SetWriteDeadline(time.Now().Add(i.d)) }

func (i *idleWriter) WriteHeader(code int) {
	i.arm()
	i.ResponseWriter.WriteHeader(code)
}

func (i *idleWriter) Write(p []byte) (int, error) {
	i.arm()
	return i.ResponseWriter.Write(p)
}

func (i *idleWriter) Unwrap() http.ResponseWriter { return i.ResponseWriter }

// maxActionBody is the largest body a POST to a portal action may announce;
// the button sends none, and the body is never read.
const maxActionBody = 1024

func (h *handler) notFound(w http.ResponseWriter, r *http.Request) {
	h.log.Debug("not found", "remote", r.RemoteAddr, "host", r.Host, "method", r.Method, "path", r.URL.Path)
	w.Header().Del(wire.HeaderExpires)
	w.Header().Del(wire.HeaderOnce)
	http.Error(w, "not found", http.StatusNotFound)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w = &idleWriter{ResponseWriter: w, rc: http.NewResponseController(w), d: h.idle}
	rt, rel := h.match(r.URL.Path)
	// Only a portal action takes a POST. The method is checked by the path
	// alone, before the route and the file, so the answer tells nothing
	// about what exists.
	p := rel
	if rt == nil {
		p = r.URL.Path
	}
	// An expose with auth.ssh alone has no portal pages, so no actions.
	_, _, isAction := cutAction(p)
	isAction = isAction && (rt == nil || rt.basic())
	if r.Method != http.MethodGet && r.Method != http.MethodHead && (r.Method != http.MethodPost || !isAction) {
		h.log.Debug("method not allowed", "remote", r.RemoteAddr, "host", r.Host, "method", r.Method, "path", r.URL.Path)
		if isAction {
			methodNotAllowed(w, "GET, HEAD, POST")
		} else {
			methodNotAllowed(w, "GET, HEAD")
		}
		return
	}
	// Checked before anything else is done, the claim of a once upload
	// above all; an unknown length (chunked) counts as too large.
	if r.Method == http.MethodPost && (r.ContentLength > maxActionBody || r.ContentLength < 0) {
		h.log.Debug("portal action body too large", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path, "length", r.ContentLength)
		w.Header().Set("Connection", "close")
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if rt == nil {
		h.notFound(w, r)
		return
	}
	// The signature comes before anything about the file, so the answers
	// tell nothing about what exists. A signed request (id) is judged by
	// its signature alone, never by auth.basic.
	var id *wire.Identity
	if rt.ssh {
		var ok bool
		if id, ok = h.signed(w, r, rt); !ok {
			return
		}
	}
	if id == nil && !rt.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="luk"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// A signed request has no portal actions, so only GET and HEAD.
	if id != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	// A directory URL lists the directory; the expose path without its
	// slash goes to the slash form.
	if rt.index && id == nil && (rel == "" || strings.HasSuffix(rel, "/")) {
		if rel == "" && !strings.HasSuffix(r.URL.Path, "/") {
			toDir(w, r)
			return
		}
		h.index(w, r, rt, rel)
		return
	}
	// A directory URL of a signed expose answers the signed listing.
	if rt.signed && id != nil && strings.HasSuffix(r.URL.Path, "/") && (rel == "" || strings.HasSuffix(rel, "/")) {
		h.signedList(w, r, rt, rel, id)
		return
	}
	// A name under a nested expose is never this storage's, also on a
	// listener without that expose.
	if _, nests := rt.st.Nests(rel); rel == "" || nests {
		h.notFound(w, r)
		return
	}
	if rel == store.CatalogName && rt.st.Catalog && (!rt.ssh || rt.signed) {
		if id != nil && !auth.Allowed(id, rt.allow) {
			h.notFound(w, r)
			return
		}
		h.serveCatalog(w, r, rt)
		return
	}
	action := ""
	f, sc, err := rt.st.Open(rel)
	if err != nil {
		name, act, ok := cutAction(rel)
		if !ok || id != nil {
			h.missing(w, r, rt, rel, id, err)
			return
		}
		if f, sc, err = rt.st.Open(name); err != nil {
			h.missing(w, r, rt, rel, id, err)
			return
		}
		if !portalAction(act, sc.Client.Portal) {
			f.Close()
			h.notFound(w, r)
			return
		}
		rel, action = name, act
	}
	if !h.serves(rt, id, sc) {
		f.Close()
		h.notFound(w, r)
		return
	}
	defer f.Close()
	// reveal and download are POST only, so link previews and prefetchers
	// never reach the content. get also answers GET and HEAD for scripts
	// and terminals: the URL handed out is the landing page, so a GET on
	// its /get is a deliberate request. A cross-origin POST (a hidden form
	// or a no-cors fetch riding on cached basic auth) would consume a once
	// upload, so browsers must show a same-origin request; clients sending
	// neither Sec-Fetch-Site nor Origin pass. GET and HEAD always pass the
	// check.
	if action != "" {
		if r.Method != http.MethodPost && action != actionGet {
			methodNotAllowed(w, "POST")
			return
		}
		if err := http.NewCrossOriginProtection().Check(r); err != nil {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
	}
	if id != nil {
		msg := "private download"
		if rt.signed {
			msg = "signed download"
		}
		h.log.Info(msg, "remote", r.RemoteAddr, "method", r.Method, "auth", "ssh", "sender", id.Name, "expose", rt.name, "id", sc.ID, "file", rel)
		privateHeaders(w.Header(), sc)
		// No portal page: the content itself, as a direct download.
		h.serveFile(w, r, rt, rel, f, sc)
		return
	}
	// The unsigned requests to an expose with auth.ssh that send the
	// content are logged as its signed downloads are, once the content
	// goes out (200 or 206): not for a 304, a 416 or a once file claimed
	// meanwhile.
	logged := func() {
		if rt.ssh && r.Method != http.MethodHead {
			user, _, _ := r.BasicAuth()
			w = &sendLog{ResponseWriter: w, log: func() {
				h.log.Info("basic download", "remote", r.RemoteAddr, "method", r.Method, "auth", "basic", "user", user, "expose", rt.name, "id", sc.ID, "file", rel, "action", action)
			}}
		}
	}
	switch {
	case action == wire.PortalReveal:
		logged()
		// The page script asks for the raw text, the form for the page.
		w.Header().Set("Vary", "Accept")
		if prefersText(r) {
			h.raw(w, r, rt, rel, f, sc)
		} else {
			h.reveal(w, r, rt, rel, f, sc)
		}
	case action == actionGet && sc.Client.Portal == wire.PortalReveal:
		logged()
		h.raw(w, r, rt, rel, f, sc)
	case action == wire.PortalDownload || action == actionGet:
		logged()
		h.serveFile(w, r, rt, rel, f, sc)
	case r.Method == http.MethodPost:
		methodNotAllowed(w, "GET, HEAD")
	case sc.Client.Portal == wire.PortalReveal || sc.Client.Portal == wire.PortalDownload:
		h.landing(w, rel, sc)
	default:
		logged()
		h.serveFile(w, r, rt, rel, f, sc)
	}
}

// sendLog calls log once when the answer starts with 200 or 206.
type sendLog struct {
	http.ResponseWriter
	log  func()
	done bool
}

func (s *sendLog) WriteHeader(code int) {
	if !s.done {
		s.done = true
		if code == http.StatusOK || code == http.StatusPartialContent {
			s.log()
		}
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *sendLog) Write(p []byte) (int, error) {
	if !s.done {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(p)
}

// ReadFrom keeps the ReaderFrom (sendfile) of the writer for io.Copy.
func (s *sendLog) ReadFrom(r io.Reader) (int64, error) {
	if !s.done {
		s.WriteHeader(http.StatusOK)
	}
	return io.Copy(s.ResponseWriter, r)
}

func (s *sendLog) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// signed verifies the signature of a request to an expose with auth.ssh;
// an unsigned one is left to auth.basic (nil, true) when the expose has
// it. On failure it has answered (404 unsigned, 401 otherwise) and
// returns false.
func (h *handler) signed(w http.ResponseWriter, r *http.Request, rt *route) (*wire.Identity, bool) {
	var err error = ErrUnsigned
	var id *wire.Identity
	if h.verify != nil {
		id, err = h.verify(r)
	}
	switch {
	case errors.Is(err, ErrUnsigned) && rt.users != nil:
		return nil, true
	case errors.Is(err, ErrUnsigned):
		h.notFound(w, r)
		return nil, false
	case err != nil:
		h.log.Info("get rejected", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path, "expose", rt.name, "status", http.StatusUnauthorized, "error", err)
		w.Header().Set("Connection", "close")
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return nil, false
	}
	return id, true
}

// permits reports whether the expose serves the file of sc to id: an
// unsigned request (id nil) only public files, and only on an expose
// without auth.ssh or the expose of its storage with auth.basic too; one
// with auth.ssh that is the expose of its storage only public files, to
// every identity of its allow list; one with auth.ssh that is a protect
// only private files: those of wire.AccessPrivate to their owner, those of
// wire.AccessAny to every identity of its allow list.
func (rt *route) permits(id *wire.Identity, sc store.Sidecar) bool {
	if id == nil {
		return (!rt.ssh || rt.signed && rt.users != nil) && sc.Client.Access == ""
	}
	if rt.signed {
		return sc.Client.Access == "" && auth.Allowed(id, rt.allow)
	}
	switch sc.Client.Access {
	case wire.AccessPrivate:
		return sc.OwnerKey != "" && sc.OwnerKey == auth.OwnerKey(id)
	case wire.AccessAny:
		return auth.Allowed(id, rt.allow)
	}
	return false
}

// serves reports whether the expose serves the file of sc to id: one it
// permits that has not expired. A listing (index) shows the names it
// serves anonymously.
func (h *handler) serves(rt *route, id *wire.Identity, sc store.Sidecar) bool {
	return rt.permits(id, sc) && !expired(sc, h.now())
}

// serveCatalog answers the storage catalog, never cached. Every expose of
// the storage but a protect serves it: one with auth.ssh to the identities
// of its allow list and, with auth.basic too, to the unsigned requests
// auth.basic admits.
func (h *handler) serveCatalog(w http.ResponseWriter, r *http.Request, rt *route) {
	if r.Method == http.MethodPost {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	f, err := rt.st.OpenCatalog()
	if err != nil {
		h.openFailed(w, r, rt, err)
		return
	}
	defer f.Close()
	hd := w.Header()
	hd.Set("Content-Type", "application/json")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, "", time.Time{}, f)
}

// NameURL is the URL of the stored name rel under the URL base of its
// expose (config.Config.ExposeURL), each path element escaped.
func NameURL(base, rel string) string {
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return base + strings.Join(parts, "/")
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// actionGet answers the raw content of a reveal or download upload.
const actionGet = "get"

// cutAction splits "<name>/reveal", "<name>/download" or "<name>/get".
func cutAction(rel string) (string, string, bool) {
	i := strings.LastIndexByte(rel, '/')
	if i <= 0 {
		return "", "", false
	}
	switch act := rel[i+1:]; act {
	case wire.PortalReveal, wire.PortalDownload, actionGet:
		return rel[:i], act, true
	}
	return "", "", false
}

// portalAction reports whether act is an action of the portal: its own
// action, or get on either portal.
func portalAction(act, portal string) bool {
	if portal != wire.PortalReveal && portal != wire.PortalDownload {
		return false
	}
	return act == portal || act == actionGet
}

// prefersText reports whether the Accept header of r ranks text/plain
// above text/html, each by its most specific matching range.
func prefersText(r *http.Request) bool {
	return acceptQ(r, "text", "plain") > acceptQ(r, "text", "html")
}

// acceptQ is the quality the Accept header gives the media type typ/sub:
// that of the most specific range matching it, 0 when none does.
func acceptQ(r *http.Request, typ, sub string) float64 {
	q, best := 0.0, -1
	for _, v := range r.Header.Values("Accept") {
		for _, part := range strings.Split(v, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			t, s, _ := strings.Cut(mt, "/")
			spec := -1
			switch {
			case t == typ && s == sub:
				spec = 2
			case t == typ && s == "*":
				spec = 1
			case t == "*" && s == "*":
				spec = 0
			}
			if spec <= best {
				continue
			}
			best, q = spec, 1
			if qv, ok := params["q"]; ok {
				if f, err := strconv.ParseFloat(qv, 64); err == nil {
					q = f
				} else {
					q = 0
				}
			}
		}
	}
	return q
}

// claim takes a once file out of the served tree; on failure it has
// answered and returns false.
func (h *handler) claim(w http.ResponseWriter, r *http.Request, rt *route, rel string, sc store.Sidecar, fi os.FileInfo) (string, bool) {
	beforeClaim()
	claimed, err := rt.st.Claim(rel, sc.ID, fi)
	if claimed == "" {
		if errors.Is(err, fs.ErrNotExist) {
			h.notFound(w, r)
			return "", false
		}
		h.log.Error("expose: claim", "expose", rt.name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return "", false
	}
	if err != nil {
		h.log.Warn("expose: claim", "expose", rt.name, "id", sc.ID, "err", err)
	}
	claimHook()
	return claimed, true
}

// serveFile answers the content with the download headers; a once file is
// claimed unless the request is HEAD.
func (h *handler) serveFile(w http.ResponseWriter, r *http.Request, rt *route, rel string, f *os.File, sc store.Sidecar) {
	fi, err := f.Stat()
	if err != nil {
		h.log.Error("expose: stat", "expose", rt.name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !sc.Client.Once {
		setHeaders(w.Header(), rel, sc)
		http.ServeContent(w, r, "", time.Time{}, f)
		return
	}
	if r.Method != http.MethodHead {
		claimed, ok := h.claim(w, r, rt, rel, sc, fi)
		if !ok {
			return
		}
		defer h.removeClaimed(rt, claimed)
	}
	setHeaders(w.Header(), rel, sc)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, f); err != nil {
		h.log.Info("expose: once download interrupted", "expose", rt.name, "id", sc.ID, "err", err)
	}
}

// missing answers a name that does not open: on an expose with index a
// directory with a listing redirects an unsigned request (id nil) to its
// slash form, anything else is 404.
func (h *handler) missing(w http.ResponseWriter, r *http.Request, rt *route, rel string, id *wire.Identity, err error) {
	if rt.index && id == nil && r.Method != http.MethodPost && rt.st.HasEntries(rel+"/", h.listed(rt)) {
		toDir(w, r)
		return
	}
	h.openFailed(w, r, rt, err)
}

func (h *handler) openFailed(w http.ResponseWriter, r *http.Request, rt *route, err error) {
	if !errors.Is(err, store.ErrInvalid) && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
		h.log.Warn("expose: open", "expose", rt.name, "err", err)
	}
	h.notFound(w, r)
}

func expired(sc store.Sidecar, now time.Time) bool {
	if sc.Expires == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, sc.Expires)
	return err != nil || t.Before(now)
}

func (h *handler) removeClaimed(rt *route, claimed string) {
	root, err := os.OpenRoot(rt.st.Base)
	if err == nil {
		err = root.Remove(claimed)
		root.Close()
	}
	if err != nil {
		h.log.Warn("expose: removing claimed file", "expose", rt.name, "err", err)
	}
}

func setHeaders(hd http.Header, rel string, sc store.Sidecar) {
	hd.Set("Content-Type", contentType(rel, sc))
	hd.Set("Content-Disposition", disposition(fileName(rel, sc)))
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Security-Policy", "sandbox")
	if sc.SHA256 != "" {
		hd.Set("ETag", `"`+sc.SHA256+`"`)
	}
}

// privateHeaders announces the expiry (UTC) and the once flag of a
// private file, each only when set.
func privateHeaders(hd http.Header, sc store.Sidecar) {
	if t, err := time.Parse(time.RFC3339, sc.Expires); err == nil {
		hd.Set(wire.HeaderExpires, t.UTC().Format(time.RFC3339))
	}
	if sc.Client.Once {
		hd.Set(wire.HeaderOnce, "true")
	}
}

// fileName is the name a download is saved as: the name a run step gave
// the file, else the client file, else the stored name (of the target, for
// an alias).
func fileName(rel string, sc store.Sidecar) string {
	if sc.Produced != "" {
		return sc.Produced
	}
	if sc.Client.File != "" {
		return sc.Client.File
	}
	if sc.AliasOf != "" {
		return path.Base(sc.AliasOf)
	}
	return path.Base(rel)
}

// contentType is the client type (for the uploaded payload only), else by
// the extension of the file name, else application/octet-stream. The
// content is never sniffed.
func contentType(rel string, sc store.Sidecar) string {
	name := fileName(rel, sc)
	ctype := ""
	if sc.Produced == "" {
		ctype = sc.Client.Type
	}
	if ctype == "" {
		ctype = mime.TypeByExtension(path.Ext(name))
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	return ctype
}

// disposition builds an RFC 6266 attachment header: an ASCII filename and,
// for anything else, filename* in UTF-8.
func disposition(name string) string {
	var ascii strings.Builder
	plain := true
	for _, c := range name {
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			plain = false
			ascii.WriteByte('_')
			continue
		}
		ascii.WriteRune(c)
	}
	s := `attachment; filename="` + ascii.String() + `"`
	if plain {
		return s
	}
	var enc strings.Builder
	for _, c := range []byte(strings.ToValidUTF8(name, "_")) {
		if c < 0x80 && (c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte("!#$&+-.^_`|~", c) >= 0) {
			enc.WriteByte(c)
		} else {
			fmt.Fprintf(&enc, "%%%02X", c)
		}
	}
	return s + "; filename*=UTF-8''" + enc.String()
}
