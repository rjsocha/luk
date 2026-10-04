package watch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/status"
	"luk/internal/store"
	"luk/internal/wire"
)

var now = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

const (
	K = int64(1) << 10
	M = K << 10
	G = M << 10
)

func dur(d time.Duration) *config.Duration { v := config.Duration(d); return &v }
func size(n int64) *config.Size            { v := config.Size(n); return &v }
func count(n int) *int                     { return &n }

// copies builds copies newest first from (hours ago, size, content) triples.
func copies(spec ...any) []store.Copy {
	var out []store.Copy
	for i := 0; i < len(spec); i += 3 {
		out = append(out, store.Copy{Name: "c", Received: now.Add(-time.Duration(spec[i].(int)) * time.Hour),
			Size: spec[i+1].(int64), SHA256: spec[i+2].(string)})
	}
	return out
}

func TestCheck(t *testing.T) {
	full := config.Watch{Every: dur(26 * time.Hour), Size: config.WatchSize{Min: size(2 * G), Max: size(20 * G), Step: size(500 * M)}, Same: count(3)}
	for _, c := range []struct {
		name   string
		rule   config.Watch
		copies []store.Copy
		state  string
		failed string
	}{
		{"all fine", full, copies(3, 4*G, "c", 27, 4*G+100*M, "b", 51, 4*G, "a"), OK, ""},
		{"no copy", full, nil, CRIT, "no copy with a readable received time"},
		{"every exceeded", config.Watch{Every: dur(26 * time.Hour)}, copies(31, 4*G, "a"), CRIT, "last copy 31h ago (every 26h)"},
		{"every exactly reached is fine", config.Watch{Every: dur(26 * time.Hour)}, copies(26, 4*G, "a"), OK, ""},
		{"every in days", config.Watch{Every: dur(48 * time.Hour)}, copies(100, 4*G, "a"), CRIT, "last copy 4d4h ago (every 2d)"},
		{"below min", config.Watch{Size: config.WatchSize{Min: size(2 * G)}}, copies(1, 980*M, "a"), CRIT, "980M below min 2G"},
		{"min exactly is fine", config.Watch{Size: config.WatchSize{Min: size(2 * G)}}, copies(1, 2*G, "a"), OK, ""},
		{"above max", config.Watch{Size: config.WatchSize{Max: size(20 * G)}}, copies(1, 25*G+512*M, "a"), CRIT, "25.5G above max 20G"},
		{"grew", config.Watch{Size: config.WatchSize{Step: size(500 * M)}}, copies(1, 5*G, "b", 25, 4*G, "a"), WARN, "grew by 1G to 5G (step 500M)"},
		{"shrank", config.Watch{Size: config.WatchSize{Step: size(500 * M)}}, copies(1, 3*G, "b", 25, 4*G, "a"), WARN, "shrank by 1G to 3G (step 500M)"},
		{"step exactly is fine", config.Watch{Size: config.WatchSize{Step: size(500 * M)}}, copies(1, 4*G+500*M, "b", 25, 4*G, "a"), OK, ""},
		{"step with one copy", config.Watch{Size: config.WatchSize{Step: size(1)}}, copies(1, 4*G, "a"), OK, ""},
		{"same", config.Watch{Same: count(3)}, copies(1, G, "abcdef0123456789", 25, G, "abcdef0123456789", 49, G, "abcdef0123456789"), WARN,
			"last 3 copies identical (sha256 abcdef012345)"},
		{"same, older copy differs", config.Watch{Same: count(3)}, copies(1, G, "a", 25, G, "a", 49, G, "b", 73, G, "a"), OK, ""},
		{"same, fewer copies", config.Watch{Same: count(3)}, copies(1, G, "a", 25, G, "a"), OK, ""},
		{"same, unknown sha256", config.Watch{Same: count(2)}, copies(1, G, "", 25, G, ""), OK, ""},
		{"combined: crit first, then warn", full, copies(31, 980*M, "a", 55, 1900*M, "a", 79, 980*M, "a"), CRIT,
			"980M below min 2G; last copy 31h ago (every 26h); shrank by 920M to 980M (step 500M); last 3 copies identical (sha256 a)"},
		{"warn only", full, copies(1, 3*G, "a", 25, 3*G, "a", 49, 3*G, "a"), WARN, "last 3 copies identical (sha256 a)"},
	} {
		state, failed := Check(c.rule, c.copies, now)
		if state != c.state || strings.Join(failed, "; ") != c.failed {
			t.Errorf("%s: %s %q, want %s %q", c.name, state, strings.Join(failed, "; "), c.state, c.failed)
		}
	}
}

func TestAge(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Second: "0s", 45 * time.Second: "45s", 12*time.Minute + 30*time.Second: "12m", 31 * time.Hour: "31h",
		31*time.Hour + 12*time.Minute: "31h12m", 71*time.Hour + 59*time.Minute: "71h59m", 96 * time.Hour: "4d", 98*time.Hour + 30*time.Minute: "4d2h",
	} {
		if got := Age(d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}

func storage(rules ...config.Watch) *config.Storage {
	return &config.Storage{Type: "local", Watch: rules}
}

func TestEvaluate(t *testing.T) {
	st := storage(
		config.Watch{Origin: config.StringList{"db1-prod"}, File: config.StringList{"db.sql*"}, Every: dur(26 * time.Hour), Size: config.WatchSize{Min: size(2 * G)}},
		config.Watch{Origin: config.StringList{"*-stage"}, Every: dur(50 * time.Hour)},
		config.Watch{Origin: config.StringList{"*-dev"}, Every: dur(time.Hour)},
		config.Watch{Origin: config.StringList{"db1-prod"}, Same: count(2)},
	)
	series := []store.SeriesCopies{
		{Series: store.Series{Pipeline: "nightly", Origin: "db1-prod", File: "db.sql"}, Copies: copies(31, 980*M, "a")},
		{Series: store.Series{Pipeline: "nightly", Origin: "db1-prod", File: "site.tar"}, Copies: copies(2, G, "b", 26, G, "c")},
		{Series: store.Series{Pipeline: "nightly", Origin: "db1-stage", File: "db.sql"}, Copies: copies(3, 300*M, "d")},
		{Series: store.Series{Pipeline: "nightly", Origin: "web1", File: "site.tar"}, Copies: copies(3, M, "e")},
		{Series: store.Series{Pipeline: "nightly", Origin: "db2-stage", File: "db.sql"}, Unreadable: 2},
	}
	got := Evaluate("archive", st, series, now)
	ev := "2026-10-04T12:00:00Z"
	want := []status.Watch{
		{Storage: "archive", Rule: 1, Pipeline: "nightly", Origin: "db1-prod", File: "db.sql", State: CRIT,
			Message: "db1-prod/db.sql: 980M below min 2G; last copy 31h ago (every 26h)", NewestReceived: "2026-10-03T05:00:00Z", Size: 980 * M, Copies: 1, Evaluated: ev},
		{Storage: "archive", Rule: 4, Pipeline: "nightly", Origin: "db1-prod", File: "site.tar", State: OK,
			Message: "db1-prod/site.tar: last copy 2h ago, 1G", NewestReceived: "2026-10-04T10:00:00Z", Size: G, Copies: 2, Evaluated: ev},
		{Storage: "archive", Rule: 2, Pipeline: "nightly", Origin: "db1-stage", File: "db.sql", State: OK,
			Message: "db1-stage/db.sql: last copy 3h ago, 300M", NewestReceived: "2026-10-04T09:00:00Z", Size: 300 * M, Copies: 1, Evaluated: ev},
		{Storage: "archive", Rule: 2, Pipeline: "nightly", Origin: "db2-stage", File: "db.sql", State: CRIT,
			Message: "db2-stage/db.sql: no copy with a readable received time", Evaluated: ev},
		{Storage: "archive", Rule: 3, State: WARN, Message: "rule 3 (origin *-dev): no series matches", Evaluated: ev},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("record %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
	if got := Evaluate("archive", storage(), series, now); len(got) != 0 {
		t.Errorf("no rules: %+v", got)
	}
	if got := Evaluate("archive", st, nil, now); len(got) != 4 || got[0].Message != "rule 1 (origin db1-prod; file db.sql*): no series matches" {
		t.Errorf("no series: %+v", got)
	}
}

func TestTexts(t *testing.T) {
	w := config.Watch{Origin: config.StringList{"a", "b*"}, File: config.StringList{"db.sql*"}, Every: dur(26 * time.Hour),
		Size: config.WatchSize{Min: size(2 * G), Max: size(20 * G), Step: size(500 * M)}, Same: count(3)}
	if got := RuleText(w); got != "origin a,b*; file db.sql*" {
		t.Errorf("rule %q", got)
	}
	if got := RuleText(config.Watch{}); got != "any series" {
		t.Errorf("rule %q", got)
	}
	if got := ChecksText(w); got != "every 26h, size.min 2G, size.max 20G, size.step 500M, same 3" {
		t.Errorf("checks %q", got)
	}
}

func TestSuggest(t *testing.T) {
	if h := Suggest(nil); h != (Hints{}) {
		t.Errorf("no copies: %+v", h)
	}
	h := Suggest(copies(2, 4*G, "x", 26, 4*G, "x", 50, 3*G, "y", 76, 3*G+100*M, "z"))
	want := Hints{Copies: 4, NewestSize: 4 * G, MinSize: 3 * G, MaxSize: 4 * G, MaxStep: G, Interval: "24h", MinInterval: "24h",
		MaxInterval: "26h", Same: 2}
	if h != want {
		t.Errorf("hints:\n got %+v\nwant %+v", h, want)
	}
	var many []any
	for i := range SuggestCopies + 10 {
		many = append(many, i*24, int64(i), "s")
	}
	if h := Suggest(copies(many...)); h.Copies != SuggestCopies || h.MaxSize != SuggestCopies-1 || h.Same != SuggestCopies {
		t.Errorf("capped: %+v", h)
	}
}

func TestAll(t *testing.T) {
	base := t.TempDir()
	cfg := &config.Config{Storage: map[string]*config.Storage{
		"archive": {Type: "local", Base: base, Conflict: "version", Watch: []config.Watch{{Origin: config.StringList{"db1-prod"}, Every: dur(26 * time.Hour)}}},
		"plain":   {Type: "local", Base: t.TempDir()},
		"cloud":   {Type: "s3", Watch: []config.Watch{{Every: dur(time.Hour)}}},
	}}
	l := store.FromConfig(cfg.Storage["archive"])
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc := store.Sidecar{ID: "id1", Sender: "robert.socha", Received: now.Add(-30 * time.Hour).Format(time.RFC3339), Size: 4, SHA256: "s",
		Pipeline: "nightly", Origin: "db1-prod", Client: wire.Meta{File: "db.sql", Portal: wire.PortalDirect}}
	if _, err := l.Put(src, "db1-prod/db.sql", sc); err != nil {
		t.Fatal(err)
	}
	got, err := All(cfg, now)
	if err != nil || len(got) != 1 || got[0].Storage != "archive" || got[0].State != CRIT ||
		got[0].Message != "db1-prod/db.sql: last copy 30h ago (every 26h)" {
		t.Fatalf("%+v %v", got, err)
	}
	if !Watched(cfg, []string{"plain", "archive"}) || Watched(cfg, []string{"plain", "cloud", "none"}) {
		t.Error("Watched")
	}
}
