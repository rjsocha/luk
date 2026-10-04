package expose

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"luk/internal/auth"
	"luk/internal/store"
	"luk/internal/wire"
)

// signedList answers the signed listing of the directory dir ("" or
// ending with a slash) of a signed expose to id: one level, or with the
// query recursive=1 every file below it named relative to dir. The files
// are those of the HTML index (listed) that the expose serves to id; a
// directory other than the top without entries is 404, as is every
// listing for an identity the expose does not allow and every listing of
// a sharded storage (its names are flat, its files in hash directories).
func (h *handler) signedList(w http.ResponseWriter, r *http.Request, rt *route, dir string, id *wire.Identity) {
	recursive := false
	switch r.URL.RawQuery {
	case "":
	case wire.QueryRecursive:
		recursive = true
	default:
		http.Error(w, "unknown query, want none or "+wire.QueryRecursive, http.StatusBadRequest)
		return
	}
	if rt.st.Shard > 0 || !auth.Allowed(id, rt.allow) {
		h.notFound(w, r)
		return
	}
	show := func(_ string, sc store.Sidecar) bool {
		return !sc.Private() && h.serves(rt, id, sc)
	}
	list := rt.st.List
	if recursive {
		list = rt.st.ListAll
	}
	ents, err := list(dir, show)
	if err != nil && !errors.Is(err, store.ErrInvalid) {
		h.log.Warn("expose: listing", "expose", rt.name, "dir", dir, "err", err)
	}
	if dir != "" && len(ents) == 0 {
		h.notFound(w, r)
		return
	}
	out := make([]wire.ListEntry, 0, len(ents))
	for _, e := range ents {
		if e.Dir {
			out = append(out, wire.ListEntry{Name: e.Name + "/", Dir: true})
			continue
		}
		size := e.Sidecar.Size
		out = append(out, wire.ListEntry{Name: e.Name, Size: &size, Received: utc(e.Sidecar.Received), SHA256: e.Sidecar.SHA256})
	}
	b, err := json.Marshal(out)
	if err != nil {
		h.log.Error("expose: listing", "expose", rt.name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	b = append(b, '\n')
	h.log.Info("signed listing", "remote", r.RemoteAddr, "method", r.Method, "sender", id.Name, "expose", rt.name, "dir", dir, "recursive", recursive, "entries", len(out))
	hd := w.Header()
	hd.Set("Content-Type", "application/json")
	hd.Set("Content-Length", strconv.Itoa(len(b)))
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(b)
	}
}

// utc is the RFC 3339 time s in UTC; s itself when it does not parse.
func utc(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}
