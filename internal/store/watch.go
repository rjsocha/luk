package store

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Copy is one stored file of a series as the watch rules see it.
type Copy struct {
	Name     string
	Received time.Time
	Size     int64
	SHA256   string
}

// SeriesCopies is a series and its copies, newest first (by received,
// then by name); Unreadable counts its files whose received time cannot
// be read, which are not among the copies.
type SeriesCopies struct {
	Series
	Copies     []Copy
	Unreadable int
}

// seriesFresh caches per base the series of the last complete walk and the
// generation it saw.
var seriesFresh sync.Map

type seriesState struct {
	gen    int64
	series []SeriesCopies
}

// SeriesCopies groups the stored files of l (aliases left out) by series,
// in series order. The result of a walk that read every sidecar is kept
// for the generation of the base and returned while it holds; callers
// must not change it. Unreadable sidecars are returned as the error, after
// the series of the readable ones.
func (l Local) SeriesCopies() ([]SeriesCopies, error) {
	r, err := os.OpenRoot(l.Base)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	gen := generation(r)
	if v, ok := seriesFresh.Load(l.key()); ok && gen > 0 && gen%2 == 0 && v.(seriesState).gen == gen {
		return v.(seriesState).series, nil
	}
	groups := map[Series]*SeriesCopies{}
	err = l.walk(r, func(rel string, sc Sidecar) error {
		if sc.AliasOf != "" {
			return nil
		}
		s := SeriesOf(sc)
		g := groups[s]
		if g == nil {
			g = &SeriesCopies{Series: s}
			groups[s] = g
		}
		at, perr := time.Parse(time.RFC3339, sc.Received)
		if perr != nil {
			g.Unreadable++
			return nil
		}
		g.Copies = append(g.Copies, Copy{Name: rel, Received: at, Size: sc.Size, SHA256: sc.SHA256})
		return nil
	})
	out := make([]SeriesCopies, 0, len(groups))
	for _, g := range groups {
		slices.SortFunc(g.Copies, func(a, b Copy) int {
			return cmp.Or(b.Received.Compare(a.Received), strings.Compare(a.Name, b.Name))
		})
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b SeriesCopies) int {
		return cmp.Or(strings.Compare(a.Pipeline, b.Pipeline), strings.Compare(a.Origin, b.Origin), strings.Compare(a.File, b.File))
	})
	if err == nil && gen > 0 && gen%2 == 0 && generation(r) == gen {
		seriesFresh.Store(l.key(), seriesState{gen, out})
	}
	return out, err
}
