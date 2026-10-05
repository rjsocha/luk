package store

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"luk/internal/config"
	"luk/internal/queue"
)

// Series is the retention series of a stored file: the pipeline that
// stored it, the origin of its upload and its file name.
type Series struct {
	Pipeline string `json:"pipeline"`
	Origin   string `json:"origin"`
	File     string `json:"file"`
}

// SeriesOf is the series of sc. A sidecar without origin (stored before
// the field) takes the backup hostname of its client meta, else the
// sender; one without pipeline has an empty one. The file is the name a
// run step produced, else the client file name.
func SeriesOf(sc Sidecar) Series {
	origin := sc.Origin
	if origin == "" && sc.Client.Backup != nil {
		origin = sc.Client.Backup.Hostname
	}
	return Series{Pipeline: sc.Pipeline, Origin: cmp.Or(origin, sc.Sender), File: cmp.Or(sc.Produced, sc.Client.File)}
}

// Reasons a file is kept besides the counts of its rule.
const (
	KeptNoRule     = "no rule"
	KeptUnreadable = "received unreadable"
)

// RetainedFile is one file of a series in a retention plan: kept with the
// reasons (last, within, daily 2026-10-04, weekly 2026-W40, monthly
// 2026-10, yearly 2026, KeptNoRule, KeptUnreadable), or pruned.
type RetainedFile struct {
	Name     string   `json:"name"`
	ID       string   `json:"id"`
	Received string   `json:"received"`
	Keep     bool     `json:"keep"`
	Reasons  []string `json:"reasons,omitempty"`
}

// SeriesPlan is the retention plan of one series: the rule that applies
// (1-based, 0 for none) and its files, newest first.
type SeriesPlan struct {
	Series
	Rule  int            `json:"rule,omitempty"`
	Keep  *config.Keep   `json:"keep,omitempty"`
	Files []RetainedFile `json:"files"`
}

// SelectRetained returns for each time of at (newest file first) the reasons
// k keeps it, nil when it is pruned: the k.Last newest, every time at
// most k.Within before now, and for each of days, ISO weeks, months and
// years (UTC) the newest time of each distinct bucket until that many
// buckets are kept.
func SelectRetained(at []time.Time, k config.Keep, now time.Time) [][]string {
	out := make([][]string, len(at))
	for i := 0; i < len(at) && i < k.Last; i++ {
		out[i] = append(out[i], "last")
	}
	if k.Within > 0 {
		for i, t := range at {
			if now.Sub(t) <= time.Duration(k.Within) {
				out[i] = append(out[i], "within")
			}
		}
	}
	for _, b := range []struct {
		n    int
		kind string
		key  func(time.Time) string
	}{
		{k.Daily, "daily", func(t time.Time) string { return t.Format("2006-01-02") }},
		{k.Weekly, "weekly", func(t time.Time) string { y, w := t.ISOWeek(); return fmt.Sprintf("%04d-W%02d", y, w) }},
		{k.Monthly, "monthly", func(t time.Time) string { return t.Format("2006-01") }},
		{k.Yearly, "yearly", func(t time.Time) string { return t.Format("2006") }},
	} {
		n, seen := b.n, map[string]bool{}
		for i := 0; i < len(at) && n > 0; i++ {
			// Newest first: the first time of a bucket is its newest. A
			// bucket may come back (the files are in acceptance order,
			// their received times need not be), it is kept once.
			if key := b.key(at[i].UTC()); !seen[key] {
				seen[key] = true
				out[i] = append(out[i], b.kind+" "+key)
				n--
			}
		}
	}
	return out
}

// RetentionPlan groups the stored files of l (aliases left out) by series,
// in series order, and decides per series by the first rule of st whose
// origin globs match its origin; a series no rule matches is kept whole.
// now is the end of the within windows. Files whose received time cannot
// be read are kept and take no place in the counts. Unreadable sidecars
// are returned as the error, after the plan of the readable ones.
func (l Local) RetentionPlan(st *config.Storage, now time.Time) ([]SeriesPlan, error) {
	type file struct {
		RetainedFile
		at    time.Time
		order queue.Acceptance
		ok    bool
	}
	groups := map[Series][]file{}
	err := l.Walk(func(rel string, sc Sidecar) error {
		if sc.AliasOf != "" {
			return nil
		}
		at, perr := time.Parse(time.RFC3339, sc.Received)
		s := SeriesOf(sc)
		groups[s] = append(groups[s], file{RetainedFile{Name: rel, ID: sc.ID, Received: sc.Received}, at, sc.Order(), perr == nil})
		return nil
	})
	plans := make([]SeriesPlan, 0, len(groups))
	for s, files := range groups {
		slices.SortFunc(files, func(a, b file) int {
			if a.ok != b.ok {
				if a.ok {
					return -1
				}
				return 1
			}
			return cmp.Or(b.order.Compare(a.order), strings.Compare(b.ID, a.ID), strings.Compare(a.Name, b.Name))
		})
		p := SeriesPlan{Series: s, Files: make([]RetainedFile, len(files))}
		rule := st.RetentionRule(s.Origin)
		var reasons [][]string
		if rule >= 0 {
			k := st.Retention[rule].Keep
			p.Rule, p.Keep = rule+1, &k
			var at []time.Time
			for _, f := range files {
				if f.ok {
					at = append(at, f.at)
				}
			}
			reasons = SelectRetained(at, k, now)
		}
		for i, f := range files {
			p.Files[i] = f.RetainedFile
			switch {
			case rule < 0:
				p.Files[i].Reasons = []string{KeptNoRule}
			case !f.ok:
				p.Files[i].Reasons = []string{KeptUnreadable}
			default:
				p.Files[i].Reasons = reasons[i]
			}
			p.Files[i].Keep = p.Files[i].Reasons != nil
		}
		plans = append(plans, p)
	}
	slices.SortFunc(plans, func(a, b SeriesPlan) int {
		return cmp.Or(strings.Compare(a.Pipeline, b.Pipeline), strings.Compare(a.Origin, b.Origin), strings.Compare(a.File, b.File))
	})
	return plans, err
}

// retentionFresh caches per base the generation and the rules of the last
// complete retention pass, and until when its plan holds: the plan
// depends on the stored files, the rules and, through keep.within, on the
// time. A file kept for within changes the plan when it leaves its window,
// so the earliest such moment ends the plan; without one the plan holds
// until the base or the rules change.
var retentionFresh sync.Map

type retentionState struct {
	gen   int64
	rules string
	until time.Time
}

// fresh reports whether a pass with state s is still current at now.
func (s retentionState) fresh(next retentionState, now time.Time) bool {
	return s.gen == next.gen && s.rules == next.rules && (s.until.IsZero() || now.Before(s.until))
}

// planUntil is the earliest moment a file the plans keep for within leaves
// its window, zero when none does.
func planUntil(plans []SeriesPlan) time.Time {
	var until time.Time
	for _, p := range plans {
		if p.Keep == nil || p.Keep.Within <= 0 {
			continue
		}
		for _, f := range p.Files {
			if !slices.Contains(f.Reasons, "within") {
				continue
			}
			at, err := time.Parse(time.RFC3339, f.Received)
			if err != nil {
				continue
			}
			if end := at.Add(time.Duration(p.Keep.Within)); until.IsZero() || end.Before(until) {
				until = end
			}
		}
	}
	return until
}

// Retain removes the files the retention plan of st prunes, each as
// RemoveIf does (base lock, sidecar, aliases, content objects; the catalog
// as l rebuilds it), calling removed after each removal. A file replaced
// or removed meanwhile is skipped. It does nothing while the base and the
// rules are as at its last pass in this process that removed every file
// it pruned, and no file that pass kept for within has left its window
// by now.
func (l Local) Retain(st *config.Storage, now time.Time, removed func(SeriesPlan, RetainedFile)) error {
	if len(st.Retention) == 0 {
		return nil
	}
	r, err := os.OpenRoot(l.Base)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer r.Close()
	state := retentionState{gen: generation(r), rules: fmt.Sprint(st.Retention)}
	if v, ok := retentionFresh.Load(l.key()); ok && v.(retentionState).fresh(state, now) {
		return nil
	}
	plans, err := l.RetentionPlan(st, now)
	errs := []error{err}
	for _, p := range plans {
		for _, f := range p.Files {
			if f.Keep {
				continue
			}
			err := l.RemoveIf(f.Name, f.ID)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				errs = append(errs, err)
				continue
			}
			removed(p, f)
		}
	}
	// Unreadable sidecars are reported once: they do not keep the pass due.
	if len(errs) == 1 {
		if state.gen = generation(r); state.gen%2 == 0 {
			state.until = planUntil(plans)
			retentionFresh.Store(l.key(), state)
		}
	}
	return errors.Join(errs...)
}
