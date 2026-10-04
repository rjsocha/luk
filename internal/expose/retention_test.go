package expose

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"luk/internal/config"
	"luk/internal/store"
	"luk/internal/wire"
)

func TestMaintainRetention(t *testing.T) {
	base := t.TempDir()
	st := &config.Storage{Type: "local", Base: base, Conflict: "version", Catalog: true, Retention: []config.Retention{
		{Origin: config.StringList{"*-prod"}, Keep: config.Keep{Last: 1, Daily: 2}},
	}}
	cfg := &config.Config{Storage: map[string]*config.Storage{"archive": st}}
	e := &env{cfg: cfg, base: base, st: store.FromConfig(st), now: t0, logs: &bytes.Buffer{}}
	for _, f := range []struct{ rel, origin, at string }{
		{"db1-prod/4b", "db1-prod", "2026-10-04T18:00:00Z"},
		{"db1-prod/4a", "db1-prod", "2026-10-04T06:00:00Z"},
		{"db1-prod/3", "db1-prod", "2026-10-03T06:00:00Z"},
		{"db1-prod/2", "db1-prod", "2026-10-02T06:00:00Z"},
		{"db1-stage/1", "db1-stage", "2026-09-01T06:00:00Z"},
		{"db1-stage/2", "db1-stage", "2026-09-02T06:00:00Z"},
	} {
		e.put(t, f.rel, f.rel, store.Sidecar{Received: f.at, Pipeline: "nightly", Origin: f.origin, Client: wire.Meta{File: "db.sql", Portal: wire.PortalDirect}})
	}
	var logs bytes.Buffer
	maintain(cfg, slog.New(slog.NewTextHandler(&logs, nil)), t0)
	for rel, want := range map[string]bool{"db1-prod/4b": true, "db1-prod/4a": false, "db1-prod/3": true, "db1-prod/2": false,
		"db1-stage/1": true, "db1-stage/2": true} {
		if exists(filepath.Join(base, store.DataDir, rel)) != want || exists(e.st.SidecarPath(rel)) != want {
			t.Errorf("%s: present %v, want %v", rel, !want, want)
		}
	}
	for _, rel := range []string{"db1-prod/4a", "db1-prod/2"} {
		want := `msg="retention removed" storage=archive name=` + rel + ` id=id-` + rel + ` pipeline=nightly origin=db1-prod file=db.sql rule=1`
		if !strings.Contains(logs.String(), want) {
			t.Errorf("no %s in\n%s", want, logs.String())
		}
	}
	f, err := store.FromConfig(st).OpenCatalog()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var cat struct {
		Files []struct {
			Name string `json:"name"`
		} `json:"files"`
	}
	if err := json.NewDecoder(f).Decode(&cat); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range cat.Files {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "db1-prod/3,db1-prod/4b,db1-stage/1,db1-stage/2" {
		t.Errorf("catalog %v", names)
	}
}
