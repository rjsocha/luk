package server

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"luk/internal/auth"
	"luk/internal/config"
	"luk/internal/quota"
	"luk/internal/wire"
)

// serveEndpoints answers the endpoint listing (wire.EndpointsPath), an
// operation of the channel: a signed GET (luk-list@v2) gets the endpoints
// of l whose allow admits the signer; anything unsigned or not verified
// is 401 as for any signed request.
func (s *Server) serveEndpoints(w http.ResponseWriter, r *http.Request, sn *snapshot, l *listener) {
	reject := func(level slog.Level, he *httpError) {
		s.log.Log(r.Context(), level, "endpoint list rejected", "remote", r.RemoteAddr, "host", r.Host, "listen", l.cfg.Name, "status", he.code, "error", he.msg)
		if he.code == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", http.MethodGet)
		}
		writeJSON(w, he.code, wire.ErrorResponse{Error: he.msg})
	}
	if r.Method != http.MethodGet {
		reject(slog.LevelDebug, &httpError{code: http.StatusMethodNotAllowed, msg: "method " + r.Method + " not allowed, use GET"})
		return
	}
	ts := r.Header.Get(wire.HeaderTimestamp)
	nonce := r.Header.Get(wire.HeaderNonce)
	sigS := r.Header.Get(wire.HeaderSignature)
	if ts == "" || nonce == "" || sigS == "" {
		level := slog.LevelInfo
		if !signed(r) {
			level = slog.LevelDebug
		}
		reject(level, &httpError{code: http.StatusUnauthorized, msg: "missing signature headers"})
		return
	}
	text := wire.ListCanonicalText(r.Method, r.Host, r.URL.Path, ts, nonce, sessionOf(r.Context()).sess.H())
	id, err := s.verify(r, sn, l, s.now(), ts, nonce, sigS, wire.ListNamespace, text)
	if err != nil {
		var he *httpError
		if !errors.As(err, &he) {
			he = &httpError{code: http.StatusUnauthorized, msg: err.Error()}
		}
		reject(slog.LevelInfo, he)
		return
	}
	list := endpointList(sn.cfg, l, r.Host, id, s.quota)
	s.log.Info("endpoint list", "remote", r.RemoteAddr, "host", r.Host, "listen", l.cfg.Name, "sender", id.Name, "endpoints", len(list.Endpoints))
	writeJSON(w, http.StatusOK, list)
}

// endpointList is the listing of the endpoints of l that admit id, by
// name, their URLs on host, the capabilities granted to id and the quota
// of id on each from book.
func endpointList(cfg *config.Config, l *listener, host string, id *wire.Identity, book *quota.Book) *wire.EndpointList {
	scheme := "http"
	if l.cfg.TLS != nil {
		scheme = "https"
	}
	if u, err := url.Parse(l.cfg.Public); err == nil && u.Scheme != "" {
		scheme = u.Scheme
	}
	out := &wire.EndpointList{Endpoints: []wire.EndpointInfo{}}
	for _, ep := range l.byPath {
		if !auth.Allowed(id, ep.Allow) {
			continue
		}
		info := wire.EndpointInfo{
			Name: ep.Name, Path: ep.Endpoint, URL: scheme + "://" + host + ep.Endpoint,
			Respond:   ep.Respond,
			Secret:    ep.Secret != nil && auth.Allowed(id, ep.Secret.Allow),
			Pretty:    ep.Pretty != nil && auth.Allowed(id, ep.Pretty.Allow),
			Permanent: permanentOffered(id, ep),
			Private:   wire.PrivateModes{Owner: auth.Allowed(id, ep.Private.Owner), Any: auth.Allowed(id, ep.Private.Any)},
			Link: wire.LinkActions{Remove: auth.Allowed(id, ep.Link.Remove), TTL: auth.Allowed(id, ep.Link.TTL),
				Replace: auth.Allowed(id, ep.Link.Replace), List: auth.Allowed(id, ep.Link.List)},
		}
		if ep.Respond == "url" {
			info.TTL = ttlPolicy(cfg.Storage[ep.Storage])
			if info.Secret {
				if st := ttlPolicy(cfg.Storage[ep.Secret.Storage]); st != nil && (info.TTL == nil || *st != *info.TTL) {
					info.SecretTTL = st
				}
			}
		}
		if ep.Backup.Hostname != nil {
			info.BackupHostname = backupHostMode(id, ep.Backup.Hostname)
		}
		if lim, ok := quota.Resolve(ep.Quota, id); ok {
			info.Quota = &wire.QuotaInfo{Mode: lim.Mode, Rate: lim.Rate.String(), Burst: lim.Burst,
				Tokens: book.Tokens(ep.Name, auth.OwnerKey(id), lim)}
		}
		out.Endpoints = append(out.Endpoints, info)
	}
	slices.SortFunc(out.Endpoints, func(a, b wire.EndpointInfo) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// backupHostMode is which backup.hostname id may send under h: any when
// it matches h.Any (also when in both lists), principal when it matches
// h.Principal, else none.
func backupHostMode(id *wire.Identity, h *config.BackupHostname) string {
	switch {
	case auth.Allowed(id, h.Any):
		return wire.BackupHostAny
	case auth.Allowed(id, h.Principal):
		return wire.BackupHostPrincipal
	}
	return wire.BackupHostNone
}

// permanentOffered reports whether an entry of permanent.names of ep
// grants id.
func permanentOffered(id *wire.Identity, ep *config.Endpoint) bool {
	if ep.Permanent == nil || ep.Respond != "url" {
		return false
	}
	for _, e := range ep.Permanent.Names {
		if e != nil && auth.Allowed(id, e.Allow) {
			return true
		}
	}
	return false
}

// backupHostAllowed reports whether id may send the backup hostname to
// ep: always without a backup.hostname block, else by backupHostMode,
// where principal takes only a principal of the certificate of id.
func backupHostAllowed(id *wire.Identity, ep *config.Endpoint, hostname string) bool {
	h := ep.Backup.Hostname
	if h == nil {
		return true
	}
	switch backupHostMode(id, h) {
	case wire.BackupHostAny:
		return true
	case wire.BackupHostPrincipal:
		return id.Type == "certificate" && slices.ContainsFunc(id.Principals, func(p string) bool { return strings.EqualFold(p, hostname) })
	}
	return false
}

// ttlPolicy is the ttl policy of a local storage; nil for any other.
func ttlPolicy(st *config.Storage) *wire.TTLPolicy {
	if st == nil || st.Type != "local" {
		return nil
	}
	p := &wire.TTLPolicy{User: st.TTL.User}
	for _, v := range []struct {
		to *string
		d  time.Duration
	}{{&p.Min, time.Duration(st.TTL.Min)}, {&p.Max, time.Duration(st.TTL.Max)}} {
		if v.d > 0 {
			*v.to = wire.FormatDuration(v.d)
		}
	}
	if d, _ := st.Lifetime("", nil); d > 0 {
		p.Default = wire.FormatDuration(d)
	}
	return p
}
