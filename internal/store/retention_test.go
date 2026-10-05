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
		{"within keeps every file of the window",
			[]string{"2026-10-04T18:00:00Z", "2026-10-04T06:00:00Z", "2026-10-03T00:00:00Z", "2026-10-02T23:59:59Z", "2026-09-01T00:00:00Z"},
			config.Keep{Within: config.Duration(48 * time.Hour)},
			[]string{"within", "within", "within", "-", "-"}},
		{"within next to counts",
			[]string{"2026-10-04T18:00:00Z", "2026-10-04T06:00:00Z", "2026-09-30T06:00:00Z", "2026-09-29T06:00:00Z"},
			config.Keep{Last: 1, Daily: 2, Within: config.Duration(24 * time.Hour)},
			[]string{"last; within; daily 2026-10-04", "within", "daily 2026-09-30", "-"}},
		{"within of a file from the future", []string{"2026-10-06T00:00:00Z"}, config.Keep{Within: config.Duration(time.Hour)},
			[]string{"within"}},
	} {
		got := SelectRetained(times(t, c.at...), c.keep, time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC))
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
	plans, err := l.RetentionPlan(st, time.Now())
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
	if err := l.Retain(st, time.Now(), rec); err != nil {
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
	if err := l.Retain(st, time.Now(), rec); err != nil || removed != nil {
		t.Fatalf("second pass: %v %v", removed, err)
	}
	st.Retention[0].Keep = config.Keep{Last: 1}
	if err := l.Retain(st, time.Now(), rec); err != nil || !slices.Equal(removed, []string{"prod/3@1"}) {
		t.Fatalf("new rules: %v %v", removed, err)
	}
	checkAlias(t, l, "prod/latest", "prod/4b", "prod/4b")
}

func TestRetainWithoutRules(t *testing.T) {
	l := Local{Base: t.TempDir()}
	putSeries(t, l, "a", Series{"p", "o", "f"}, "2026-10-01T06:00:00Z", "")
	putSeries(t, l, "b", Series{"p", "o", "f"}, "2026-10-02T06:00:00Z", "")
	if err := l.Retain(&config.Storage{}, time.Now(), func(SeriesPlan, RetainedFile) { t.Error("removed") }); err != nil {
		t.Fatal(err)
	}
	mustExist(t, filepath.Join(l.Base, DataDir, "a"))
}

func TestRetainWithin(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "version"}
	s := Series{"nightly", "db1-prod", "db.sql"}
	putSeries(t, l, "c", s, "2026-10-04T12:00:00Z", "")
	putSeries(t, l, "b", s, "2026-10-04T06:00:00Z", "")
	putSeries(t, l, "a", s, "2026-10-03T06:00:00Z", "")
	st := &config.Storage{Retention: []config.Retention{{Keep: config.Keep{Last: 1, Within: config.Duration(24 * time.Hour)}}}}
	var removed []string
	rec := func(_ SeriesPlan, f RetainedFile) { removed = append(removed, f.Name) }
	at := func(s string) time.Time { return times(t, s)[0] }
	// a is out of the window; b leaves it at 2026-10-05T06:00:00Z.
	if err := l.Retain(st, at("2026-10-04T12:00:00Z"), rec); err != nil || !slices.Equal(removed, []string{"a"}) {
		t.Fatalf("first pass: %v %v", removed, err)
	}
	// The base is unchanged and b is still in its window: no pass.
	removed = nil
	if err := l.Retain(st, at("2026-10-05T05:59:59Z"), rec); err != nil || removed != nil {
		t.Fatalf("within the window: %v %v", removed, err)
	}
	// b has left its window: the plan is due again although nothing
	// changed.
	if err := l.Retain(st, at("2026-10-05T06:00:01Z"), rec); err != nil || !slices.Equal(removed, []string{"b"}) {
		t.Fatalf("after the window: %v %v", removed, err)
	}
	mustExist(t, filepath.Join(l.Base, DataDir, "c"))
}

// TestAcceptanceOrdersFiles: the acceptance order, not the received
// time, decides which file of a series is the newest: for retention, the
// watch copies and aliases. A file stored before the acceptance order
// counts by its received time.
func TestAcceptanceOrdersFiles(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "version", Hardlink: true}
	s := Series{"nightly", "db1-prod", "db.sql"}
	t0 := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	put := func(rel string, received time.Time, ns int64, seq int) {
		t.Helper()
		sc := Sidecar{ID: "id-" + rel, Sender: "robert.socha", Endpoint: "up", Received: received.Format(time.RFC3339), Accepted: ns, AcceptedSeq: seq,
			Size: int64(len(rel)), SHA256: shaOf(rel), Pipeline: s.Pipeline, Origin: s.Origin,
			Client: wire.Meta{File: s.File, Portal: wire.PortalDirect}, Meta: json.RawMessage(`{"alias":"latest"}`)}
		if _, err := l.Put(srcFile(t, t.TempDir(), rel), rel, sc); err != nil {
			t.Fatal(err)
		}
	}
	base := t0.Add(10 * time.Second).UnixNano()
	// "started" began first (received earlier) and was committed last.
	put("started", t0, base+500, 0)
	put("tie-1", t0.Add(5*time.Second), base, 1)
	put("tie-0", t0.Add(5*time.Second), base, 0)
	// Stored before the acceptance order: received a second before t0.
	put("old", t0.Add(-time.Second), 0, 0)
	want := []string{"started", "tie-1", "tie-0", "old"}
	series, err := l.SeriesCopies()
	if err != nil || len(series) != 1 {
		t.Fatalf("series %+v %v", series, err)
	}
	var got []string
	for _, c := range series[0].Copies {
		got = append(got, c.Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("copies %v, want %v", got, want)
	}
	plans, err := l.RetentionPlan(&config.Storage{Retention: []config.Retention{{Keep: config.Keep{Last: 1}}}}, t0)
	if err != nil || len(plans) != 1 {
		t.Fatalf("plans %+v %v", plans, err)
	}
	got = nil
	for _, f := range plans[0].Files {
		got = append(got, f.Name)
	}
	if !slices.Equal(got, want) || !plans[0].Files[0].Keep || plans[0].Files[1].Keep {
		t.Fatalf("retention %+v, want %v first and kept", plans[0].Files, want)
	}
	checkAlias(t, l, "latest", "started", "started")
}
