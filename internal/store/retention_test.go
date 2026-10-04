package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/wire"
)

func times(t *testing.T, s ...string) []time.Time {
	t.Helper()
	var out []time.Time
	for _, v := range s {
		at, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, at)
	}
	return out
}

func TestSelectRetained(t *testing.T) {
	for _, c := range []struct {
		name string
		at   []string
		keep config.Keep
		want []string // reasons per time joined with "; ", "-" for pruned
	}{
		{"no files", nil, config.Keep{Last: 3, Daily: 7}, nil},
		{"last", []string{"2026-10-04T10:00:00Z", "2026-10-03T10:00:00Z", "2026-10-02T10:00:00Z"}, config.Keep{Last: 2},
			[]string{"last", "last", "-"}},
		{"several per day, gaps",
			[]string{"2026-10-04T18:00:00Z", "2026-10-04T06:00:00Z", "2026-10-03T12:00:00Z", "2026-10-01T09:00:00Z", "2026-09-30T09:00:00Z"},
			config.Keep{Daily: 3},
			[]string{"daily 2026-10-04", "-", "daily 2026-10-03", "daily 2026-10-01", "-"}},
		{"last and daily overlap",
			[]string{"2026-10-04T18:00:00Z", "2026-10-04T06:00:00Z", "2026-10-03T12:00:00Z", "2026-10-02T12:00:00Z"},
			config.Keep{Last: 1, Daily: 2},
			[]string{"last; daily 2026-10-04", "-", "daily 2026-10-03", "-"}},
		{"iso week across the year",
			[]string{"2027-01-04T01:00:00Z", "2027-01-02T01:00:00Z", "2026-12-30T01:00:00Z", "2026-12-27T01:00:00Z", "2026-12-20T01:00:00Z"},
			config.Keep{Weekly: 3},
			[]string{"weekly 2027-W01", "weekly 2026-W53", "-", "weekly 2026-W52", "-"}},
		{"monthly and yearly",
			[]string{"2026-10-04T10:00:00Z", "2026-09-15T10:00:00Z", "2026-09-01T10:00:00Z", "2025-12-31T10:00:00Z", "2024-06-01T10:00:00Z"},
			config.Keep{Monthly: 2, Yearly: 2},
			[]string{"monthly 2026-10; yearly 2026", "monthly 2026-09", "-", "yearly 2025", "-"}},
		{"more buckets asked than present", []string{"2026-10-04T10:00:00Z", "2026-10-03T10:00:00Z"}, config.Keep{Last: 5, Daily: 30},
			[]string{"last; daily 2026-10-04", "last; daily 2026-10-03"}},
		{"buckets in UTC", []string{"2026-10-05T01:00:00+02:00", "2026-10-04T12:00:00Z"}, config.Keep{Daily: 2},
			[]string{"daily 2026-10-04", "-"}},
		{"zero counts keep nothing", []string{"2026-10-04T10:00:00Z"}, config.Keep{}, []string{"-"}},
	} {
		got := SelectRetained(times(t, c.at...), c.keep)
		var s []string
		for _, r := range got {
			if r == nil {
				s = append(s, "-")
			} else {
				s = append(s, strings.Join(r, "; "))
			}
		}
		if !slices.Equal(s, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, s, c.want)
		}
	}
}

func TestSeriesOf(t *testing.T) {
	for _, c := range []struct {
		sc   Sidecar
		want Series
	}{
		{Sidecar{Pipeline: "nightly", Origin: "db1-prod", Sender: "robert.socha", Client: wire.Meta{File: "db.sql"}}, Series{"nightly", "db1-prod", "db.sql"}},
		{Sidecar{Sender: "robert.socha", Client: wire.Meta{File: "db.sql", Backup: &wire.Backup{Hostname: "db1-stage"}}}, Series{"", "db1-stage", "db.sql"}},
		{Sidecar{Sender: "robert.socha", Client: wire.Meta{File: "db.sql"}}, Series{"", "robert.socha", "db.sql"}},
		{Sidecar{Pipeline: "p", Origin: "o", Produced: "db.sql.gpg", Client: wire.Meta{File: "db.sql"}}, Series{"p", "o", "db.sql.gpg"}},
	} {
		if got := SeriesOf(c.sc); got != c.want {
			t.Errorf("%+v: %+v, want %+v", c.sc, got, c.want)
		}
	}
}

// putSeries stores content at rel as a file of the series s received at.
func putSeries(t *testing.T, l Local, rel string, s Series, at string, alias string) {
	t.Helper()
	src := srcFile(t, t.TempDir(), rel)
	sc := Sidecar{ID: "id-" + rel, Sender: "robert.socha", Endpoint: "up", Received: at, Size: int64(len(rel)), SHA256: shaOf(rel),
		Pipeline: s.Pipeline, Origin: s.Origin, Client: wire.Meta{File: s.File, Portal: wire.PortalDirect}}
	if alias != "" {
		sc.Meta = json.RawMessage(fmt.Sprintf(`{"alias":%q}`, alias))
	}
	if _, err := l.Put(src, rel, sc); err != nil {
		t.Fatal(err)
	}
}

func retentionStorage() *config.Storage {
	return &config.Storage{Retention: []config.Retention{
		{Origin: config.StringList{"db1-prod", "*-prod"}, Keep: config.Keep{Last: 1, Daily: 2}},
		{Origin: config.StringList{"*-stage"}, Keep: config.Keep{Last: 1}},
	}}
}

func TestRetentionPlanAndRetain(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "version", Catalog: true, Hardlink: true}
	prod := Series{"nightly", "db1-prod", "db.sql"}
	stage := Series{"nightly", "db1-stage", "db.sql"}
	other := Series{"nightly", "web1", "site.tar"}
	putSeries(t, l, "prod/4b", prod, "2026-10-04T18:00:00Z", "prod/latest")
	putSeries(t, l, "prod/4a", prod, "2026-10-04T06:00:00Z", "prod/latest")
	putSeries(t, l, "prod/3", prod, "2026-10-03T06:00:00Z", "prod/latest")
	putSeries(t, l, "prod/1", prod, "2026-10-01T06:00:00Z", "prod/latest")
	putSeries(t, l, "stage/2", stage, "2026-10-02T06:00:00Z", "")
	putSeries(t, l, "stage/1", stage, "2026-10-01T06:00:00Z", "")
	putSeries(t, l, "stage/bad", stage, "yesterday", "")
	putSeries(t, l, "web/1", other, "2026-09-01T06:00:00Z", "")
	putSeries(t, l, "web/bad", other, "yesterday", "")
	checkAlias(t, l, "prod/latest", "prod/4b", "prod/4b")

	st := retentionStorage()
	plans, err := l.RetentionPlan(st)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		series Series
		rule   int
		files  string
	}
	var got []row
	for _, p := range plans {
		var fs []string
		for _, f := range p.Files {
			fs = append(fs, fmt.Sprintf("%s:%v:%s", f.Name, f.Keep, strings.Join(f.Reasons, ",")))
		}
		got = append(got, row{p.Series, p.Rule, strings.Join(fs, " ")})
	}
	want := []row{
		{prod, 1, "prod/4b:true:last,daily 2026-10-04 prod/4a:false: prod/3:true:daily 2026-10-03 prod/1:false:"},
		{stage, 2, "stage/2:true:last stage/1:false: stage/bad:true:received unreadable"},
		{other, 0, "web/1:true:no rule web/bad:true:no rule"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan:\n got %+v\nwant %+v", got, want)
	}

	var removed []string
	rec := func(p SeriesPlan, f RetainedFile) { removed = append(removed, fmt.Sprintf("%s@%d", f.Name, p.Rule)) }
	if err := l.Retain(st, rec); err != nil {
		t.Fatal(err)
	}
	slices.Sort(removed)
	if !slices.Equal(removed, []string{"prod/1@1", "prod/4a@1", "stage/1@2"}) {
		t.Fatalf("removed %v", removed)
	}
	for _, rel := range []string{"prod/1", "prod/4a", "stage/1"} {
		mustNotExist(t, filepath.Join(l.Base, DataDir, rel))
		mustNotExist(t, l.SidecarPath(rel))
	}
	for _, rel := range []string{"prod/4b", "prod/3", "stage/2", "stage/bad", "web/1", "web/bad"} {
		mustExist(t, filepath.Join(l.Base, DataDir, rel))
		mustExist(t, l.SidecarPath(rel))
	}
	checkAlias(t, l, "prod/latest", "prod/4b", "prod/4b")
	names := catalogNames(readCatalog(t, l))
	slices.Sort(names)
	if !slices.Equal(names, []string{"prod/3", "prod/4b", "stage/2", "stage/bad", "web/1", "web/bad"}) {
		t.Fatalf("catalog %v", names)
	}
	if _, err := os.Stat(objectPath(l, "prod/4a")); err == nil {
		if n := indexNames(t, l, "prod/4a"); len(n) != 0 {
			t.Fatalf("index of a removed name: %v", n)
		}
	}

	// An unchanged base and unchanged rules need no pass; new rules do.
	removed = nil
	if err := l.Retain(st, rec); err != nil || removed != nil {
		t.Fatalf("second pass: %v %v", removed, err)
	}
	st.Retention[0].Keep = config.Keep{Last: 1}
	if err := l.Retain(st, rec); err != nil || !slices.Equal(removed, []string{"prod/3@1"}) {
		t.Fatalf("new rules: %v %v", removed, err)
	}
	checkAlias(t, l, "prod/latest", "prod/4b", "prod/4b")
}

func TestRetainWithoutRules(t *testing.T) {
	l := Local{Base: t.TempDir()}
	putSeries(t, l, "a", Series{"p", "o", "f"}, "2026-10-01T06:00:00Z", "")
	putSeries(t, l, "b", Series{"p", "o", "f"}, "2026-10-02T06:00:00Z", "")
	if err := l.Retain(&config.Storage{}, func(SeriesPlan, RetainedFile) { t.Error("removed") }); err != nil {
		t.Fatal(err)
	}
	mustExist(t, filepath.Join(l.Base, DataDir, "a"))
}
