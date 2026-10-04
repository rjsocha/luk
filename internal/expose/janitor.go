package expose

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"luk/internal/config"
	"luk/internal/pipeline"
	"luk/internal/store"
)

const (
	claimedAge = time.Hour
	sweepAge   = time.Hour
	workAge    = 7 * 24 * time.Hour
)

var beforeRemove = func() {}

// Janitor selects the parts of a janitor pass.
type Janitor int

const (
	// Expire removes expired files, files past cleanup.age (those without
	// an expiry) and stale claimed files of every local storage.
	Expire Janitor = 1 << iota
	// Maintain removes the files the retention rules prune (see
	// store.Local.Retain), repairs aliases and the catalog (see
	// store.Local.Reconcile),
	// reconciles the content objects (see store.Local.MaintainObjects)
	// and removes store crash leftovers and empty directories of every
	// local storage, and work directories older than 7 days whose id has
	// no queue entry (a failed entry keeps them).
	Maintain
)

// StartJanitor runs one pass of the given parts at once and then every
// `every` until ctx is done. Data files without a sidecar are logged, never
// deleted. before, when set, runs first in every pass. An interval <= 0
// means one minute. Every pass works on the configuration cfg returns then.
func StartJanitor(ctx context.Context, cfg func() *config.Config, log *slog.Logger, every time.Duration, parts Janitor, before func(time.Time)) {
	if every <= 0 {
		every = time.Minute
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			now := time.Now()
			if before != nil {
				before(now)
			}
			c := cfg()
			if parts&Expire != 0 {
				expire(c, log, now)
			}
			if parts&Maintain != 0 {
				maintain(c, log, now)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func expire(cfg *config.Config, log *slog.Logger, now time.Time) {
	for name, s := range cfg.Storage {
		if s.Type != "local" {
			continue
		}
		// Removals only mark the catalog stale; it is rebuilt once after
		// the pass.
		st := store.FromConfig(s).Batch()
		age := time.Duration(s.Cleanup.Age)
		removed := 0
		err := st.Walk(func(rel string, sc store.Sidecar) error {
			// An alias follows its target: removing the target moves or
			// removes it, and Reconcile repairs it.
			if sc.AliasOf != "" {
				return nil
			}
			why := ""
			if sc.Expires != "" {
				exp, err := time.Parse(time.RFC3339, sc.Expires)
				if err != nil {
					log.Warn("storage: unreadable expires, file kept", "storage", name, "file", rel, "id", sc.ID, "expires", sc.Expires)
					return nil
				}
				if exp.Before(now) {
					why = "expired"
				}
			} else if age > 0 && received(sc, now).Add(age).Before(now) {
				why = "cleanup.age"
			}
			if why == "" {
				return nil
			}
			beforeRemove()
			err := st.RemoveExpired(rel, sc.ID, sc.Expires)
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			removed++
			log.Info("storage: removed", "storage", name, "file", rel, "id", sc.ID, "reason", why)
			return nil
		})
		if err != nil {
			log.Warn("storage: janitor", "storage", name, "err", err)
		}
		if removed > 0 {
			if err := store.FromConfig(s).RebuildCatalog(); err != nil {
				log.Warn("storage: catalog", "storage", name, "err", err)
			}
		}
		removeClaimed(st.Base, now, log, name)
	}
}

func maintain(cfg *config.Config, log *slog.Logger, now time.Time) {
	for name, s := range cfg.Storage {
		if s.Type != "local" {
			continue
		}
		st := store.FromConfig(s)
		// Retention removals only mark the catalog stale; Reconcile
		// rebuilds it once.
		err := st.Batch().Retain(s, now, func(p store.SeriesPlan, f store.RetainedFile) {
			log.Info("retention removed", "storage", name, "name", f.Name, "id", f.ID,
				"pipeline", p.Pipeline, "origin", p.Origin, "file", p.File, "rule", p.Rule)
		})
		if err != nil {
			log.Warn("storage: retention", "storage", name, "err", err)
		}
		if err := st.Reconcile(); err != nil {
			log.Warn("storage: aliases and catalog", "storage", name, "err", err)
		}
		objs, err := st.MaintainObjects()
		if err != nil {
			log.Warn("storage: objects", "storage", name, "err", err)
		}
		if objs.Adopted > 0 || objs.Removed > 0 {
			log.Info("storage: objects", "storage", name, "adopted", objs.Adopted, "removed", objs.Removed)
		}
		sw, err := st.Sweep(sweepAge, now)
		if err != nil {
			log.Warn("storage: sweep", "storage", name, "err", err)
		}
		for _, p := range sw.Orphans {
			log.Warn("storage: data file without sidecar", "storage", name, "file", p)
		}
	}
	removeWork(cfg.WorkDir(), pipeline.EntryIDs(cfg), now, log)
}

// removeWork deletes <work>/<id>/<pipeline> directories not modified for
// workAge, and an <id> directory left empty, unless keep holds the id.
func removeWork(work string, keep map[string]bool, now time.Time, log *slog.Logger) {
	if work == "" {
		return
	}
	ids, err := os.ReadDir(work)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warn("work: janitor", "err", err)
		}
		return
	}
	for _, id := range ids {
		if !id.IsDir() || keep[id.Name()] {
			continue
		}
		dir := filepath.Join(work, id.Name())
		pipes, err := os.ReadDir(dir)
		if err != nil {
			log.Warn("work: janitor", "err", err)
			continue
		}
		left := 0
		for _, p := range pipes {
			fi, err := p.Info()
			if err != nil || !p.IsDir() || now.Sub(fi.ModTime()) <= workAge {
				left++
				continue
			}
			if err := os.RemoveAll(filepath.Join(dir, p.Name())); err != nil {
				log.Warn("work: removing", "dir", filepath.Join(dir, p.Name()), "err", err)
				left++
				continue
			}
			log.Info("work: removed", "id", id.Name(), "pipeline", p.Name())
		}
		if left > 0 {
			continue
		}
		if fi, err := id.Info(); len(pipes) > 0 || (err == nil && now.Sub(fi.ModTime()) > workAge) {
			os.Remove(dir)
		}
	}
}

// received is the upload time; an unreadable one counts as now, so the
// file is kept.
func received(sc store.Sidecar, now time.Time) time.Time {
	t, err := time.Parse(time.RFC3339, sc.Received)
	if err != nil {
		return now
	}
	return t
}

func removeClaimed(base string, now time.Time, log *slog.Logger, name string) {
	root, err := os.OpenRoot(base)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warn("storage: janitor", "storage", name, "err", err)
		}
		return
	}
	defer root.Close()
	ents, err := fs.ReadDir(root.FS(), store.ClaimedDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warn("storage: janitor", "storage", name, "err", err)
		}
		return
	}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil || now.Sub(fi.ModTime()) <= claimedAge {
			continue
		}
		if err := root.Remove(store.ClaimedDir + "/" + e.Name()); err != nil {
			log.Warn("storage: removing claimed file", "storage", name, "err", err)
		}
	}
}
