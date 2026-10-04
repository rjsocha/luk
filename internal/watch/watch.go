// Package watch evaluates the watch rules of the local storages: per
// series (pipeline, origin, file name, as in retention) the age and size
// of the newest copy, the step to the copy before it and the number of
// newest copies with one content, against the thresholds of the first
// rule that matches the series. The thresholds are the configured values
// only; the observed values (Suggest) are hints for setting them.
package watch

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"luk/internal/config"
	"luk/internal/status"
	"luk/internal/store"
	"luk/internal/wire"
)

// States of an evaluation, in order of severity.
const (
	OK   = "OK"
	WARN = "WARN"
	CRIT = "CRIT"
)

// NoSeries is the message of a rule no series matches.
const NoSeries = "no series matches"

// Check evaluates rule on copies (newest first) at now and returns the
// state and the failed checks: the size of the newest copy below
// size.min or above size.max and its age above every are CRIT; a
// difference to the copy before it above size.step and `same` newest
// copies with one sha256 are WARN. A series without a copy of readable
// received time is CRIT.
func Check(rule config.Watch, copies []store.Copy, now time.Time) (string, []string) {
	if len(copies) == 0 {
		return CRIT, []string{"no copy with a readable received time"}
	}
	newest := copies[0]
	var crit, warn []string
	if z := rule.Size.Min; z != nil && newest.Size < int64(*z) {
		crit = append(crit, fmt.Sprintf("%s below min %s", wire.HumanSize(newest.Size), wire.HumanSize(int64(*z))))
	}
	if z := rule.Size.Max; z != nil && newest.Size > int64(*z) {
		crit = append(crit, fmt.Sprintf("%s above max %s", wire.HumanSize(newest.Size), wire.HumanSize(int64(*z))))
	}
	if e := rule.Every; e != nil {
		if age := now.Sub(newest.Received); age > time.Duration(*e) {
			crit = append(crit, fmt.Sprintf("last copy %s ago (every %s)", Age(age), wire.FormatDuration(time.Duration(*e))))
		}
	}
	if z := rule.Size.Step; z != nil && len(copies) > 1 {
		d := newest.Size - copies[1].Size
		switch {
		case d > int64(*z):
			warn = append(warn, fmt.Sprintf("grew by %s to %s (step %s)", wire.HumanSize(d), wire.HumanSize(newest.Size), wire.HumanSize(int64(*z))))
		case -d > int64(*z):
			warn = append(warn, fmt.Sprintf("shrank by %s to %s (step %s)", wire.HumanSize(-d), wire.HumanSize(newest.Size), wire.HumanSize(int64(*z))))
		}
	}
	if n := rule.Same; n != nil && len(copies) >= *n && sameContent(copies[:*n]) {
		warn = append(warn, fmt.Sprintf("last %d copies identical (sha256 %s)", *n, short(newest.SHA256)))
	}
	switch {
	case len(crit) > 0:
		return CRIT, append(crit, warn...)
	case len(warn) > 0:
		return WARN, warn
	}
	return OK, nil
}

// sameContent reports whether every copy has the known sha256 of the first.
func sameContent(copies []store.Copy) bool {
	for _, c := range copies {
		if c.SHA256 == "" || c.SHA256 != copies[0].SHA256 {
			return false
		}
	}
	return true
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// Age is d for a message: "45s", "12m", "31h", "31h12m", "4d", "4d2h".
func Age(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 72*time.Hour:
		h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	days, h := int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour)
	if h == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd%dh", days, h)
}

// Evaluate evaluates the watch rules of the storage named storage on its
// series at now: one record per series a rule applies to (the first rule
// whose origin and file globs match), in series order, then one WARN
// record per rule no series matches (see Unmatched). Series no rule
// matches are left out.
func Evaluate(storage string, st *config.Storage, series []store.SeriesCopies, now time.Time) []status.Watch {
	out := []status.Watch{}
	for _, s := range series {
		if i := st.WatchRule(s.Origin, s.File); i >= 0 {
			out = append(out, Record(storage, i+1, st.Watch[i], s, now))
		}
	}
	return append(out, Unmatched(storage, st, series, now)...)
}

// Unmatched is one WARN record per watch rule of st that applies to none
// of series.
func Unmatched(storage string, st *config.Storage, series []store.SeriesCopies, now time.Time) []status.Watch {
	used := make([]bool, len(st.Watch))
	for _, s := range series {
		if i := st.WatchRule(s.Origin, s.File); i >= 0 {
			used[i] = true
		}
	}
	var out []status.Watch
	for i, u := range used {
		if !u {
			out = append(out, status.Watch{Storage: storage, Rule: i + 1, State: WARN,
				Message: fmt.Sprintf("rule %d (%s): %s", i+1, RuleText(st.Watch[i]), NoSeries), Evaluated: now.UTC().Format(time.RFC3339)})
		}
	}
	return out
}

// Record evaluates the watch rule w (number rule, 1-based) of the storage
// named storage on the series s at now.
func Record(storage string, rule int, w config.Watch, s store.SeriesCopies, now time.Time) status.Watch {
	r := status.Watch{Storage: storage, Rule: rule, Pipeline: s.Pipeline, Origin: s.Origin, File: s.File,
		Copies: len(s.Copies), Evaluated: now.UTC().Format(time.RFC3339)}
	state, failed := Check(w, s.Copies, now)
	r.State = state
	label := s.Origin + "/" + s.File
	if len(s.Copies) > 0 {
		r.NewestReceived = s.Copies[0].Received.UTC().Format(time.RFC3339)
		r.Size = s.Copies[0].Size
	}
	if state == OK {
		r.Message = fmt.Sprintf("%s: last copy %s ago, %s", label, Age(now.Sub(s.Copies[0].Received)), wire.HumanSize(r.Size))
	} else {
		r.Message = label + ": " + strings.Join(failed, "; ")
	}
	return r
}

// RuleText names the globs of w: "origin db1-prod; file db.sql*", "any
// series".
func RuleText(w config.Watch) string {
	var parts []string
	if len(w.Origin) > 0 {
		parts = append(parts, "origin "+strings.Join(w.Origin, ","))
	}
	if len(w.File) > 0 {
		parts = append(parts, "file "+strings.Join(w.File, ","))
	}
	if parts == nil {
		return "any series"
	}
	return strings.Join(parts, "; ")
}

// ChecksText names the checks of w: "every 26h, size.min 2G, same 3".
func ChecksText(w config.Watch) string {
	var out []string
	if w.Every != nil {
		out = append(out, "every "+wire.FormatDuration(time.Duration(*w.Every)))
	}
	for _, z := range []struct {
		key string
		v   *config.Size
	}{{"size.min", w.Size.Min}, {"size.max", w.Size.Max}, {"size.step", w.Size.Step}} {
		if z.v != nil {
			out = append(out, z.key+" "+wire.FormatSize(int64(*z.v)))
		}
	}
	if w.Same != nil {
		out = append(out, fmt.Sprintf("same %d", *w.Same))
	}
	return strings.Join(out, ", ")
}

// All evaluates the watch rules of every local storage of cfg that has
// any, in storage order. A storage whose sidecars cannot all be read is
// evaluated on the readable ones and its error returned.
func All(cfg *config.Config, now time.Time) ([]status.Watch, error) {
	out := []status.Watch{}
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(cfg.Storage)) {
		st := cfg.Storage[name]
		if st.Type != "local" || len(st.Watch) == 0 {
			continue
		}
		series, err := store.FromConfig(st).SeriesCopies()
		if err != nil {
			errs = append(errs, fmt.Errorf("storage %s: %w", name, err))
		}
		out = append(out, Evaluate(name, st, series, now)...)
	}
	return out, errors.Join(errs...)
}

// Watched reports whether any of the storages names has watch rules.
func Watched(cfg *config.Config, names []string) bool {
	for _, n := range names {
		if st := cfg.Storage[n]; st != nil && st.Type == "local" && len(st.Watch) > 0 {
			return true
		}
	}
	return false
}

// SuggestCopies is the number of newest copies Suggest looks at.
const SuggestCopies = 30

// Hints are values observed on the newest copies of a series, for setting
// the thresholds of a rule; they are never used as thresholds.
type Hints struct {
	Copies      int    `json:"copies"`
	NewestSize  int64  `json:"newest_size"`
	MinSize     int64  `json:"min_size"`
	MaxSize     int64  `json:"max_size"`
	MaxStep     int64  `json:"max_step"`
	Interval    string `json:"interval,omitempty"`
	MinInterval string `json:"min_interval,omitempty"`
	MaxInterval string `json:"max_interval,omitempty"`
	Same        int    `json:"same"`
}

// Suggest observes the newest SuggestCopies copies (newest first): the
// size of the newest, the smallest and largest size, the largest step
// between neighbours, the median, shortest and longest interval between
// them, and how many newest copies share the content of the newest.
func Suggest(copies []store.Copy) Hints {
	if len(copies) > SuggestCopies {
		copies = copies[:SuggestCopies]
	}
	h := Hints{Copies: len(copies)}
	if len(copies) == 0 {
		return h
	}
	h.NewestSize, h.MinSize, h.MaxSize = copies[0].Size, copies[0].Size, copies[0].Size
	var gaps []time.Duration
	for i, c := range copies {
		h.MinSize, h.MaxSize = min(h.MinSize, c.Size), max(h.MaxSize, c.Size)
		if i > 0 {
			step := copies[i-1].Size - c.Size
			h.MaxStep = max(h.MaxStep, step, -step)
			gaps = append(gaps, copies[i-1].Received.Sub(c.Received))
		}
	}
	for _, c := range copies {
		if c.SHA256 == "" || c.SHA256 != copies[0].SHA256 {
			break
		}
		h.Same++
	}
	if len(gaps) > 0 {
		sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
		h.Interval = Age(gaps[len(gaps)/2])
		h.MinInterval, h.MaxInterval = Age(gaps[0]), Age(gaps[len(gaps)-1])
	}
	return h
}
