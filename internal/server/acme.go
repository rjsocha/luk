package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"luk/internal/acmecert"
	"luk/internal/config"
	"luk/internal/tlsself"
	"luk/internal/wire"
)

// acmeCerts holds the certificates of the tls mode acme listeners: one
// manager per ACME directory, which shares its account and cache
// directory among the listeners using it.
type acmeCerts struct {
	managers []*acmecert.Manager
	hosts    map[string]*acmeHost
	listen   map[string]certSource
	log      *slog.Logger
}

// certSource serves the certificates of a listener.
type certSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// acmeHost is one certificate name: the listener it belongs to (the first
// by name when several list it) and the manager of its directory.
type acmeHost struct {
	l *config.Listen
	m *acmecert.Manager
}

// newACME builds the managers of cfg; httpClient talks to the directories
// (nil: the default client).
func newACME(cfg *config.Config, log *slog.Logger, httpClient *http.Client) *acmeCerts {
	a := &acmeCerts{hosts: map[string]*acmeHost{}, listen: map[string]certSource{}, log: log}
	type dir struct {
		o     acmecert.Options
		names []string
		ls    []*config.Listen
	}
	var dirs []*dir
	byURL := map[string]*dir{}
	for _, n := range cfg.ListenNames() {
		l := cfg.Listen[n]
		if l.TLS == nil || l.TLS.Mode != "acme" {
			continue
		}
		t := l.TLS
		d := byURL[t.Directory]
		if d == nil {
			d = &dir{o: acmecert.Options{
				Directory: t.Directory, CacheDir: cfg.ACMECacheDir(t.Directory), Email: t.Email,
				Log: log, HTTPClient: httpClient,
			}}
			if t.EAB.Set() {
				// Validated by config.
				mac, _ := t.EAB.MAC()
				d.o.EAB = &acme.ExternalAccountBinding{KID: t.EAB.KID, Key: mac}
			}
			byURL[t.Directory] = d
			dirs = append(dirs, d)
		}
		d.ls = append(d.ls, l)
		for _, h := range l.Host {
			if !slices.Contains(d.names, h) {
				d.names = append(d.names, h)
			}
		}
	}
	for _, d := range dirs {
		d.o.Hosts = d.names
		m := acmecert.New(d.o)
		a.managers = append(a.managers, m)
		for _, l := range d.ls {
			a.listen[l.Name] = m
			for _, h := range l.Host {
				if _, ok := a.hosts[h]; !ok {
					a.hosts[h] = &acmeHost{l: l, m: m}
				}
			}
		}
	}
	return a
}

// getCertificate serves the certificate of listener l: the one of the
// server name, or of the first host of l without SNI or for an unknown
// name, as the first listener of an address does for other modes.
func (a *acmeCerts) getCertificate(l *config.Listen) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	src := a.listen[l.Name]
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if !slices.Contains(l.Host, strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))) {
			h := *hello
			h.ServerName = l.Host[0]
			hello = &h
		}
		return src.GetCertificate(hello)
	}
}

// serveHTTP answers a plain acme: true listener: HTTP-01 challenges of the
// acme names, a 308 to https for any other request to them, 421 for names
// of no acme listener.
func (a *acmeCerts) serveHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostname(r.Host)
	h, ok := a.hosts[host]
	if !ok {
		a.log.Debug("request for an unknown host", "remote", r.RemoteAddr, "host", r.Host, "acme", true)
		w.Header().Set("Connection", "close")
		writeJSON(w, http.StatusMisdirectedRequest, wire.ErrorResponse{Error: "no listener for host " + r.Host})
		return
	}
	if strings.HasPrefix(r.URL.Path, acmecert.ChallengePrefix) {
		h.m.HTTPHandler().ServeHTTP(w, r)
		return
	}
	target := "https://" + host
	if u, err := url.Parse(h.l.Public); err == nil && u.Port() != "" {
		target += ":" + u.Port()
	}
	http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusPermanentRedirect)
}

// run obtains the missing certificates and renews them until ctx is done
// (see acmecert.Manager.Run).
func (a *acmeCerts) run(ctx context.Context) {
	for _, m := range a.managers {
		go m.Run(ctx)
	}
}

// logState logs the certificate of every name with its expiry; on SIGHUP,
// where self and files listeners re-read theirs.
func (a *acmeCerts) logState() {
	for _, host := range sortedKeys(a.hosts) {
		h := a.hosts[host]
		leaf, err := h.m.Leaf(host)
		switch {
		case err != nil:
			a.log.Error("tls acme: certificate unreadable", "listen", h.l.Name, "host", host, "error", err)
		case leaf == nil:
			a.log.Warn("tls acme: no certificate yet", "listen", h.l.Name, "host", host)
		default:
			a.log.Info("tls acme", "listen", h.l.Name, "host", host, "pin", tlsself.Pin(leaf), "expires", leaf.NotAfter.UTC().Format(time.RFC3339))
		}
	}
}

// prepareACMEDir creates an ACME cache directory and its parent, both
// 0700: the account key and the certificate keys live there.
func prepareACMEDir(dir string) error {
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("%s: %v (%s)", d, err, dirHint)
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return fmt.Errorf("%s: %v (%s)", d, err, dirHint)
		}
	}
	return prepareWritable(dir)
}
