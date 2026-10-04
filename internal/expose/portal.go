package expose

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"luk/internal/store"
	"luk/internal/wire"
)

//go:embed templates/portal.html
var templateFS embed.FS

var portalTmpl = template.Must(template.ParseFS(templateFS, "templates/portal.html"))

type page struct {
	Nonce     string
	Name      string
	Size      string
	Type      string
	SHA256    string
	Published stamp
	Expires   stamp
	Once      bool
	Action    string
	Target    string
	Content   string
	Limit     string
	// Updated is when the content was last replaced through the link;
	// empty Text: never.
	Updated stamp
	// Owner is the sender of the upload, empty with no_owner.
	Owner string
	// SaveName is the file name the landing page script saves binary
	// revealed content as.
	SaveName string
	// Binary is set on the reveal page when Content is the base64 of
	// content that is not text.
	Binary bool
	// Dir is the URL path of the listed directory (index); Parent adds
	// the ../ link; Entries are its entries.
	Dir     string
	Parent  bool
	Entries []indexEntry
}

// indexEntry is a line of a directory listing: Href is relative to the
// directory, Size and Stored are empty for a directory.
type indexEntry struct {
	Name   string
	Href   string
	Dir    bool
	Size   string
	Stored stamp
}

// stamp is a time on the page: Text is humanTime, ISO the RFC 3339 form the
// page script turns into the viewer's local time (empty: shown as Text).
type stamp struct {
	Text string
	ISO  string
}

func newStamp(s string, now time.Time) stamp {
	st := stamp{Text: humanTime(s, now)}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		st.ISO = t.UTC().Format(time.RFC3339)
	}
	return st
}

// mediaType is a content type without its parameters, for the page:
// text/plain for "text/plain; charset=utf-8".
func mediaType(ctype string) string {
	t, _, _ := strings.Cut(ctype, ";")
	return strings.TrimSpace(t)
}

func newPage(rel string, sc store.Sidecar, now time.Time) page {
	exp := stamp{Text: "never"}
	if sc.Expires != "" {
		exp = newStamp(sc.Expires, now)
	}
	var updated stamp
	if sc.Updated != "" {
		updated = newStamp(sc.Updated, now)
	}
	typ, sum := mediaType(contentType(rel, sc)), sc.SHA256
	if sc.Client.Portal == wire.PortalReveal {
		// A secret shows no media type and no sha256: a short secret
		// could be found from its hash by anyone who sees this page.
		typ, sum = "secret", ""
	}
	save := fileName(rel, sc)
	if sc.Produced == "" && sc.Client.File == "" {
		save = path.Base(rel) + ".bin"
	}
	return page{
		Name:      fileName(rel, sc),
		SaveName:  save,
		Size:      humanSize(sc.Size),
		Type:      typ,
		SHA256:    sum,
		Owner:     sc.Owner,
		Published: newStamp(sc.Received, now),
		Expires:   exp,
		Updated:   updated,
		Once:      sc.Client.Once,
	}
}

// humanTime shows an RFC 3339 time in UTC to the minute with the distance
// from now, "2026-10-02 17:40 UTC (12 min ago)"; anything unparsable is
// shown as it is.
func humanTime(s string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	rel := ""
	switch d := t.Sub(now); {
	case d <= -time.Minute:
		rel = humanDuration(-d) + " ago"
	case d <= 0:
		rel = "just now"
	case d < time.Minute:
		rel = "in under a minute"
	default:
		rel = "in " + humanDuration(d)
	}
	return t.UTC().Format("2006-01-02 15:04 UTC") + " (" + rel + ")"
}

// humanDuration shows the two largest units of d (at least a minute),
// truncated: "12 min", "23h 48m", "2d 5h".
func humanDuration(d time.Duration) string {
	m := int64(d / time.Minute)
	switch {
	case m < 60:
		return fmt.Sprintf("%d min", m)
	case m < 24*60:
		if m%60 == 0 {
			return fmt.Sprintf("%dh", m/60)
		}
		return fmt.Sprintf("%dh %dm", m/60, m%60)
	}
	if h := m / 60 % 24; h != 0 {
		return fmt.Sprintf("%dd %dh", m/(24*60), h)
	}
	return fmt.Sprintf("%dd", m/(24*60))
}

func humanSize(n int64) string {
	if n < 1024 {
		return shortSize(n)
	}
	return fmt.Sprintf("%s (%d bytes)", shortSize(n), n)
}

// shortSize is humanSize without the exact count: "512 bytes", "1.5 MiB".
func shortSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d bytes", n)
	}
	v, unit := float64(n)/1024, "KiB"
	for _, u := range []string{"MiB", "GiB", "TiB"} {
		if v < 1024 {
			break
		}
		v, unit = v/1024, u
	}
	return fmt.Sprintf("%.1f %s", v, unit)
}

// render writes a portal page with a fresh CSP nonce. The landing page
// saves binary revealed content through an <a download> of a blob: URL;
// that is a download, not a fetch, so the CSP needs nothing for it.
func (h *handler) render(w http.ResponseWriter, code int, name string, p page) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	p.Nonce = base64.RawURLEncoding.EncodeToString(b)
	var buf bytes.Buffer
	if err := portalTmpl.ExecuteTemplate(&buf, name, p); err != nil {
		h.log.Error("expose: portal template", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Content-Security-Policy", "default-src 'none'; img-src data:; connect-src 'self'; style-src 'nonce-"+p.Nonce+"'; script-src 'nonce-"+p.Nonce+
		"'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	hd.Set("X-Robots-Tag", "noindex")
	hd.Set("Cache-Control", "no-store")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

// landing shows the metadata and the action button, never the content.
func (h *handler) landing(w http.ResponseWriter, rel string, sc store.Sidecar) {
	p := newPage(rel, sc, h.now())
	p.Action = sc.Client.Portal
	// "./" keeps a name with a colon from reading as a URL scheme.
	p.Target = "./" + url.PathEscape(path.Base(rel)) + "/" + p.Action
	h.render(w, http.StatusOK, "landing", p)
}

// revealed reads the content of a reveal upload, at most MaxReveal bytes;
// a once file is claimed first when claim is set. On failure it has
// answered (an oversized content through tooLarge) and returns false.
func (h *handler) revealed(w http.ResponseWriter, r *http.Request, rt *route, rel string, f *os.File, sc store.Sidecar, claim bool, tooLarge func()) ([]byte, string, bool) {
	fi, err := f.Stat()
	if err != nil {
		h.log.Error("expose: stat", "expose", rt.name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, "", false
	}
	if fi.Size() > MaxReveal {
		tooLarge()
		return nil, "", false
	}
	claimed := ""
	if claim && sc.Client.Once {
		var ok bool
		if claimed, ok = h.claim(w, r, rt, rel, sc, fi); !ok {
			return nil, "", false
		}
	}
	b, err := readReveal(io.LimitReader(f, MaxReveal))
	if err != nil {
		// A claimed file stays under ClaimedDir for recovery.
		h.log.Error("expose: reading reveal content", "expose", rt.name, "id", sc.ID, "claimed", claimed, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, "", false
	}
	return b, claimed, true
}

// reveal shows at most MaxReveal bytes of the content; a once file is
// claimed first.
func (h *handler) reveal(w http.ResponseWriter, r *http.Request, rt *route, rel string, f *os.File, sc store.Sidecar) {
	p := newPage(rel, sc, h.now())
	p.Limit = humanSize(MaxReveal)
	b, claimed, ok := h.revealed(w, r, rt, rel, f, sc, true, func() { h.render(w, http.StatusRequestEntityTooLarge, "toolarge", p) })
	if !ok {
		return
	}
	if claimed != "" {
		defer h.removeClaimed(rt, claimed)
	}
	if isText(b) {
		p.Content = string(b)
	} else {
		p.Binary, p.Size = true, humanSize(int64(len(b)))
		p.Content = base64.StdEncoding.EncodeToString(b)
	}
	h.render(w, http.StatusOK, "reveal", p)
}

// isText reports whether b is shown as text: valid UTF-8 without control
// characters other than tab, newline and carriage return. The landing page
// script decides the same way.
func isText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

// raw answers the raw content of a reveal upload, exactly the stored
// bytes, for the page script, scripts and terminals; a once file is
// claimed unless the request is HEAD.
func (h *handler) raw(w http.ResponseWriter, r *http.Request, rt *route, rel string, f *os.File, sc store.Sidecar) {
	head := r.Method == http.MethodHead
	b, claimed, ok := h.revealed(w, r, rt, rel, f, sc, !head, func() {
		http.Error(w, "content larger than "+humanSize(MaxReveal), http.StatusRequestEntityTooLarge)
	})
	if !ok {
		return
	}
	if claimed != "" {
		defer h.removeClaimed(rt, claimed)
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("Content-Length", strconv.Itoa(len(b)))
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Security-Policy", "sandbox")
	hd.Set("Cache-Control", "no-store")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusOK)
	if head {
		return
	}
	if _, err := w.Write(b); err != nil {
		h.log.Info("expose: raw content interrupted", "expose", rt.name, "id", sc.ID, "err", err)
	}
}

// listed is the predicate of a listing: the files the expose serves
// anonymously that are not once, portal or private uploads, as the
// catalog lists them.
func (h *handler) listed(rt *route) func(string, store.Sidecar) bool {
	return func(_ string, sc store.Sidecar) bool {
		return !sc.Private() && h.serves(rt, nil, sc)
	}
}

// index lists the directory dir ("" or ending with a slash) of the
// expose, read from the disk; a directory other than the top without
// entries is 404, as if it did not exist.
func (h *handler) index(w http.ResponseWriter, r *http.Request, rt *route, dir string) {
	ents, err := rt.st.List(dir, h.listed(rt))
	if err != nil && !errors.Is(err, store.ErrInvalid) {
		h.log.Warn("expose: listing", "expose", rt.name, "dir", dir, "err", err)
	}
	if dir != "" && len(ents) == 0 {
		h.notFound(w, r)
		return
	}
	p := page{Dir: rt.prefix + dir, Parent: dir != "", Entries: make([]indexEntry, 0, len(ents))}
	for _, e := range ents {
		// "./" keeps a name with a colon from reading as a URL scheme.
		ie := indexEntry{Name: e.Name, Href: "./" + url.PathEscape(e.Name), Dir: e.Dir}
		if e.Dir {
			ie.Name += "/"
			ie.Href += "/"
		} else {
			ie.Size = shortSize(e.Sidecar.Size)
			ie.Stored = listStamp(e.Sidecar.Received)
		}
		p.Entries = append(p.Entries, ie)
	}
	h.render(w, http.StatusOK, "index", p)
}

// listStamp is a stamp of a listing: the time in UTC to the minute,
// without the distance from now.
func listStamp(s string) stamp {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return stamp{Text: s}
	}
	return stamp{Text: t.UTC().Format("2006-01-02 15:04 UTC"), ISO: t.UTC().Format(time.RFC3339)}
}

// toDir redirects a directory URL without its slash to the slash form,
// relative, so it holds behind a proxy that maps the path.
func toDir(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", "./"+url.PathEscape(path.Base(r.URL.Path))+"/")
	w.WriteHeader(http.StatusMovedPermanently)
}
