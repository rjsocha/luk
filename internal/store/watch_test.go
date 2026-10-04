package store

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"luk/internal/wire"
)

func TestSeriesCopies(t *testing.T) {
	l := Local{Base: t.TempDir(), Conflict: "version"}
	if got, err := l.SeriesCopies(); err != nil || len(got) != 0 {
		t.Fatalf("empty base: %v %v", got, err)
	}
	prod := Series{"nightly", "db1-prod", "db.sql"}
	stage := Series{"nightly", "db1-stage", "db.sql"}
	putSeries(t, l, "prod/2", prod, "2026-10-04T06:00:00Z", "prod/latest")
	putSeries(t, l, "prod/1", prod, "2026-10-03T06:00:00Z", "prod/latest")
	putSeries(t, l, "prod/3", prod, "2026-10-05T06:00:00Z", "prod/latest")
	putSeries(t, l, "prod/bad", prod, "yesterday", "")
	putSeries(t, l, "stage/1", stage, "2026-10-04T07:00:00Z", "")
	show := func() string {
		t.Helper()
		got, err := l.SeriesCopies()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range got {
			var cs []string
			for _, c := range s.Copies {
				cs = append(cs, fmt.Sprintf("%s@%s:%d:%s", c.Name, c.Received.Format("02T15"), c.Size, c.SHA256[:4]))
			}
			out = append(out, fmt.Sprintf("%s/%s/%s %s unreadable=%d", s.Pipeline, s.Origin, s.File, strings.Join(cs, ","), s.Unreadable))
		}
		return strings.Join(out, "\n")
	}
	want := fmt.Sprintf("nightly/db1-prod/db.sql prod/3@05T06:6:%s,prod/2@04T06:6:%s,prod/1@03T06:6:%s unreadable=1\n"+
		"nightly/db1-stage/db.sql stage/1@04T07:7:%s unreadable=0", shaOf("prod/3")[:4], shaOf("prod/2")[:4], shaOf("prod/1")[:4], shaOf("stage/1")[:4])
	if got := show(); got != want {
		t.Fatalf("series:\n%s\nwant:\n%s", got, want)
	}
	// The cached walk holds while the base is unchanged; a store ends it.
	if got := show(); got != want {
		t.Fatalf("cached:\n%s", got)
	}
	putSeries(t, l, "stage/2", stage, "2026-10-05T07:00:00Z", "")
	if got := show(); !strings.Contains(got, "stage/2@05T07") {
		t.Fatalf("after a store:\n%s", got)
	}
}

func TestSeriesCopiesOfSidecarsWithoutFields(t *testing.T) {
	l := Local{Base: t.TempDir()}
	src := srcFile(t, t.TempDir(), "x")
	sc := Sidecar{ID: "a", Sender: "alice", Received: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC).Format(time.RFC3339), Size: 1, SHA256: shaOf("x"),
		Client: wire.Meta{File: "db.sql", Portal: wire.PortalDirect, Backup: &wire.Backup{Hostname: "db1-prod"}}}
	if _, err := l.Put(src, "a", sc); err != nil {
		t.Fatal(err)
	}
	got, err := l.SeriesCopies()
	if err != nil || len(got) != 1 || got[0].Series != (Series{"", "db1-prod", "db.sql"}) {
		t.Fatalf("%+v %v", got, err)
	}
}
