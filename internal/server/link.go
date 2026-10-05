package server

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"luk/internal/auth"
	"luk/internal/config"
	"luk/internal/pipeline"
	"luk/internal/queue"
	"luk/internal/store"
	"luk/internal/wire"
)

// isLink reports whether r is a link request rather than an upload: it
// carries Luk-Link or Luk-Link-Action.
func isLink(r *http.Request) bool {
	return r.Header.Get(wire.HeaderLink) != "" || r.Header.Get(wire.HeaderLinkAction) != ""
}

// noLink is the one answer for a link that is not there, expired, of
// another endpoint or of another owner, so nothing tells them apart.
func noLink() error { return fail(http.StatusNotFound, "link not found") }

// linkTarget is the stored file a link URL points to.
type linkTarget struct {
	storage string
	st      *config.Storage
	local   store.Local
	rel     string
}

// handleLink serves a link request on an endpoint path: remove (DELETE),
// ttl (PATCH), replace (PUT with the new content) or list (GET, without a
// link).
func (s *Server) handleLink(w http.ResponseWriter, r *http.Request, sn *snapshot, l *listener, ep *config.Endpoint) (int, any, error) {
	link, action := r.Header.Get(wire.HeaderLink), r.Header.Get(wire.HeaderLinkAction)
	method, known := wire.LinkMethod(action)
	switch {
	case action == "" || (link == "" && action != wire.LinkList):
		return 0, nil, fail(http.StatusBadRequest, "%s and %s go together", wire.HeaderLink, wire.HeaderLinkAction)
	case !known:
		return 0, nil, fail(http.StatusBadRequest, "unknown link action %q (remove, ttl, replace, list)", action)
	case action == wire.LinkList && link != "":
		return 0, nil, fail(http.StatusBadRequest, "link list takes an empty %s", wire.HeaderLink)
	case r.Method != method:
		return 0, nil, &httpError{code: http.StatusMethodNotAllowed, msg: fmt.Sprintf("link %s needs method %s", action, method), allow: method}
	}
	now := s.now()
	var meta wire.Meta
	var lm wire.LinkMeta
	id, err := s.authenticate(r, sn, l, ep, now, wire.LinkNamespace,
		func(ts, nonce, metaS string) []byte {
			return wire.LinkCanonicalText(r.Method, r.Host, r.URL.Path, link, action, ts, nonce, metaS)
		},
		func(metaS string) (err error) {
			if action == wire.LinkReplace {
				meta, err = wire.DecodeMeta(metaS)
			} else {
				lm, err = wire.DecodeLinkMeta(metaS)
			}
			return err
		})
	if err != nil {
		return 0, nil, err
	}
	// The endpoint configuration is no secret to an allowed sender.
	if !auth.Allowed(id, ep.Link.Of(action)) {
		return 0, nil, fail(http.StatusForbidden, "endpoint %s does not allow link %s (link.%s)", ep.Name, action, action)
	}
	if action == wire.LinkList {
		if lm.TTL != "" {
			return 0, nil, fail(http.StatusUnprocessableEntity, "list takes no ttl")
		}
		return s.linkList(sn.cfg, ep, id, now)
	}
	t, err := resolveLink(sn.cfg, link)
	if err != nil {
		return 0, nil, err
	}
	// Checks of the request and the storage come before the file lookup,
	// so their answers tell nothing about the file.
	switch action {
	case wire.LinkRemove:
		if lm.TTL != "" {
			return 0, nil, fail(http.StatusUnprocessableEntity, "remove takes no ttl")
		}
	case wire.LinkTTL:
		if lm.TTL == "" {
			return 0, nil, fail(http.StatusUnprocessableEntity, "ttl needs a ttl in the meta")
		}
		if !t.st.TTL.User {
			return 0, nil, fail(http.StatusUnprocessableEntity, "storage ttl policy does not take client ttl")
		}
	case wire.LinkReplace:
		if err := meta.ValidateReplace(); err != nil {
			return 0, nil, fail(http.StatusUnprocessableEntity, "%v", err)
		}
	}
	sc, err := s.lookup(t, ep, id, now)
	if err != nil {
		return 0, nil, err
	}
	switch action {
	case wire.LinkRemove:
		return s.linkRemove(t, sc, id, ep, link)
	case wire.LinkTTL:
		return s.linkTTL(t, sc, id, ep, link, lm.TTL, now)
	}
	return s.linkReplace(w, r, sn, t, sc, id, ep, link, meta, now)
}

// resolveLink finds the stored file of a link URL: its host and path
// against the exposes of local storages, by the host lists (and public
// URLs) of their listeners and the expose path; the longest path wins. The
// scheme, port, query and fragment are ignored. A URL without a host is
// 422; one that matches no expose is 404.
func resolveLink(cfg *config.Config, raw string) (*linkTarget, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || !strings.HasPrefix(u.Path, "/") {
		return nil, fail(http.StatusUnprocessableEntity, "bad link URL %q", raw)
	}
	host := hostname(u.Host)
	var best *linkTarget
	bestLen := 0
	for _, xn := range sortedKeys(cfg.Expose) {
		x := cfg.Expose[xn]
		name, st, ok := cfg.StorageServedBy(xn)
		if !ok || st.Type != "local" || len(x.Path) <= bestLen || !strings.HasPrefix(u.Path, x.Path) {
			continue
		}
		if !slices.ContainsFunc(x.Listen, func(ln string) bool { return linkHost(cfg.Listen[ln], host) }) {
			continue
		}
		best = &linkTarget{storage: name, st: st, local: store.FromConfig(st), rel: strings.TrimPrefix(u.Path, x.Path)}
		bestLen = len(x.Path)
	}
	if best == nil || best.rel == "" {
		return nil, noLink()
	}
	return best, nil
}

// linkHost reports whether the listener l answers for host: by its host
// list (any host without one), or the host of its public URL.
func linkHost(l *config.Listen, host string) bool {
	if l == nil {
		return false
	}
	if l.Serves(host) {
		return true
	}
	p, err := url.Parse(l.Public)
	return err == nil && l.Public != "" && strings.EqualFold(p.Hostname(), host)
}

// lookup reads the sidecar of the link and checks that id may manage it on
// ep: an upload of that endpoint, owned by id, not expired. Anything else
// is noLink.
func (s *Server) lookup(t *linkTarget, ep *config.Endpoint, id *wire.Identity, now time.Time) (store.Sidecar, error) {
	f, sc, err := t.local.Open(t.rel)
	if err != nil {
		if !errors.Is(err, store.ErrInvalid) && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
			s.log.Warn("link: open", "storage", t.storage, "file", t.rel, "error", err)
		}
		return sc, noLink()
	}
	f.Close()
	if sc.AliasOf != "" || sc.Endpoint != ep.Name || sc.OwnerKey == "" || sc.OwnerKey != auth.OwnerKey(id) || expiredAt(sc.Expires, now) {
		return sc, noLink()
	}
	return sc, nil
}

// expiredAt reports whether an expiry (RFC 3339; empty: never) is past; an
// unreadable one counts as expired.
func expiredAt(exp string, now time.Time) bool {
	if exp == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, exp)
	return err != nil || !t.After(now)
}

// linkErr maps a store error of a link action to its answer.
func linkErr(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return noLink()
	case errors.Is(err, store.ErrAliased):
		return fail(http.StatusConflict, "link declares an alias")
	}
	return err
}

func (s *Server) linkRemove(t *linkTarget, sc store.Sidecar, id *wire.Identity, ep *config.Endpoint, link string) (int, any, error) {
	if err := t.local.RemoveIf(t.rel, sc.ID); err != nil {
		return 0, nil, linkErr(err)
	}
	s.log.Info("link removed", "id", sc.ID, "sender", id.Name, "endpoint", ep.Name, "storage", t.storage, "file", t.rel)
	return http.StatusOK, &wire.LinkAnswer{URL: link, Removed: true}, nil
}

// linkTTL sets a new expiry: now plus the requested ttl under the ttl
// policy of the storage, as for an upload; none (wire.TTLMax without
// ttl.max) clears it.
func (s *Server) linkTTL(t *linkTarget, sc store.Sidecar, id *wire.Identity, ep *config.Endpoint, link, ttl string, now time.Time) (int, any, error) {
	lt := lifetimeIn(t.st, ttl)
	exp := ""
	if lt.d > 0 {
		exp = now.Add(lt.d).UTC().Format(time.RFC3339)
	}
	_, err := t.local.Update(t.rel, sc.ID, func(c *store.Sidecar) error {
		if expiredAt(c.Expires, now) {
			return fs.ErrNotExist
		}
		c.Expires = exp
		return nil
	})
	if err != nil {
		return 0, nil, linkErr(err)
	}
	s.log.Info("link ttl set", "id", sc.ID, "sender", id.Name, "endpoint", ep.Name, "storage", t.storage, "file", t.rel, "expires", exp)
	a := &wire.LinkAnswer{URL: link, Expires: exp}
	a.TTL, a.TTLNote = lt.ttl()
	a.TTLMin, a.TTLMax = lt.bounds()
	return http.StatusOK, a, nil
}

// linkReplace receives the new content of a mutable link into the queue,
// like an upload with the tags of the stored one; the store step of the
// link storage puts it in place.
func (s *Server) linkReplace(w http.ResponseWriter, r *http.Request, sn *snapshot, t *linkTarget, sc store.Sidecar, id *wire.Identity, ep *config.Endpoint, link string, meta wire.Meta, now time.Time) (int, any, error) {
	if !sc.Client.Mutable {
		return 0, nil, fail(http.StatusConflict, "link is not mutable")
	}
	// The new content keeps the tags and the access of the link, also in
	// the other storages the pipelines store into.
	meta.Tags, meta.Access = sc.Client.Tags, sc.Client.Access
	// A link of the secret storage is replaced as a secret upload.
	secret := ""
	pipes := []string{pipeline.SecretPipeline}
	if ep.Secret != nil && ep.Secret.Storage == t.storage {
		secret = t.storage
	} else {
		var err error
		if pipes, _, err = Match(sn.cfg, ep.Name, meta.Tags); err != nil {
			return 0, nil, err
		}
	}
	if !storesInto(sn.cfg, pipes, secret, t.storage) {
		return 0, nil, fail(http.StatusUnprocessableEntity, "no pipeline of endpoint %s stores into storage %s", ep.Name, t.storage)
	}
	// The link keeps its portal, so a reveal link keeps its limit.
	max, reveal, err := bodyLimit(r, ep, meta, sc.Client.Portal)
	if err != nil {
		return 0, nil, err
	}
	u := &upload{sn: sn, ep: ep, id: id, meta: meta, pipes: pipes, now: now, reveal: reveal, link: link, secret: secret,
		replace: &pipeline.Replace{Storage: t.storage, Name: t.rel, ID: sc.ID, Updated: now.UTC().Format(time.RFC3339)}}
	if err := s.prepare(u); err != nil {
		return 0, nil, err
	}
	return s.receive(w, r, u, max)
}

// maxLinkList caps a list answer; tests lower it.
var maxLinkList = wire.MaxLinkList

// linkList answers the links of id on ep: the files of the respond
// storage of ep, and of its secret storage, uploaded through ep by id, not
// expired; claimed once files are out of the data tree. Newest first, at
// most maxLinkList.
func (s *Server) linkList(cfg *config.Config, ep *config.Endpoint, id *wire.Identity, now time.Time) (int, any, error) {
	storages := []string{ep.Storage}
	if ep.Secret != nil {
		storages = append(storages, ep.Secret.Storage)
	}
	key := auth.OwnerKey(id)
	type item struct {
		order queue.Acceptance
		id    string
		e     wire.LinkEntry
	}
	var items []item
	for _, sn := range storages {
		st := cfg.Storage[sn]
		if st == nil || st.Type != "local" || st.Expose == "" {
			return 0, nil, fail(http.StatusUnprocessableEntity, "storage %s of endpoint %s is not an exposed local storage", sn, ep.Name)
		}
		l := store.FromConfig(st)
		// The current version of each permanent name, by <path>/<name>:
		// only that version of a name is listed as one.
		current := map[string]store.PermanentInfo{}
		if ep.Permanent != nil && sn == ep.Storage {
			names, err := l.PermanentList()
			if err != nil {
				s.log.Warn("link list: permanent names", "storage", sn, "error", err)
			}
			for _, pi := range names {
				if pi.Current != "" {
					current[pi.Key] = pi
				}
			}
		}
		err := l.Walk(func(rel string, sc store.Sidecar) error {
			if sc.AliasOf != "" || sc.Endpoint != ep.Name || sc.OwnerKey == "" || sc.OwnerKey != key || expiredAt(sc.Expires, now) {
				return nil
			}
			u, ok := s.fileURL(cfg, sn, rel, sc.Client.Access)
			if !ok {
				return nil
			}
			e := wire.LinkEntry{
				URL: u, File: sc.Client.File, Size: sc.Size, Received: sc.Received, Expires: sc.Expires,
				Once: sc.Client.Once, Mutable: sc.Client.Mutable, Portal: sc.Client.Portal, Access: sc.Client.Access, Updated: sc.Updated,
			}
			if p := ep.Permanent; p != nil && sn == ep.Storage && sc.Client.Permanent != "" && sc.PermanentPath == p.Path {
				cur := current[p.Path+"/"+sc.Client.Permanent]
				if _, _, ok := p.Entry(sc.Client.Permanent); ok && cur.Current == rel && cur.ID == sc.ID {
					e.Permanent = sc.Client.Permanent
					e.PermanentURL, _ = s.fileURL(cfg, sn, p.Path+"/"+sc.Client.Permanent, "")
				}
			}
			items = append(items, item{sc.Order(), sc.ID, e})
			return nil
		})
		if err != nil {
			// Unreadable entries are left out; the rest is still the answer.
			s.log.Warn("link list: walk", "storage", sn, "error", err)
		}
	}
	slices.SortFunc(items, func(a, b item) int {
		return cmp.Or(b.order.Compare(a.order), strings.Compare(b.id, a.id), strings.Compare(a.e.URL, b.e.URL))
	})
	a := &wire.LinkListAnswer{Links: []wire.LinkEntry{}}
	for i, it := range items {
		if i == maxLinkList {
			a.Truncated = true
			break
		}
		a.Links = append(a.Links, it.e)
	}
	s.log.Info("link list", "sender", id.Name, "endpoint", ep.Name, "storage", strings.Join(storages, ","), "links", len(a.Links))
	return http.StatusOK, a, nil
}

// storesInto reports whether a step of the pipelines (secret: the storage
// of pipeline.SecretPipeline) stores into storage.
func storesInto(cfg *config.Config, pipes []string, secret, storage string) bool {
	for _, pn := range pipes {
		if p, ok := pipeline.Lookup(cfg, pn, secret); ok {
			for _, st := range p.Steps {
				if slices.Contains(st.Store, storage) {
					return true
				}
			}
		}
	}
	return false
}
