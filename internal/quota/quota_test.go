package quota

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/wire"
)

func parseQuota(t *testing.T, text string) *config.Quota {
	t.Helper()
	cfg, err := config.Parse([]byte(`
listen: {main: {addr: "127.0.0.1:0"}}
auth:
  keys: [{name: robert.socha, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGl5ZNGdDDrFOD9hUIo3uI0OBOutD7fZ0J9wlhQ0vvB0"}]
  ca: [{name: hosts, type: host, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBWNH4m3n1bMpJ6GU0yDxWVd5ixzwSJqGqv0MNEOh0Yo"}]
endpoint:
  backup: {listen: main, endpoint: /backup, path: q, allow: ["*"], quota: ` + text + `}
pipeline:
  p: {endpoint: [backup], steps: [{store: s}]}
storage:
  s: {type: local, base: s, path: "{{ .Id }}"}
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Endpoint["backup"].Quota
}

func host(keyID string, principals ...string) *wire.Identity {
	return &wire.Identity{Name: "hosts:" + keyID, Type: "certificate", CA: "hosts", KeyID: keyID, Principals: principals}
}

var robert = &wire.Identity{Name: "robert.socha", Type: "key"}

func TestResolve(t *testing.T) {
	q := parseQuota(t, `{class: [
    {name: large, members: ["hosts#db*"], rate: 50G/1d, burst: 100G},
    {name: medium, members: ["hosts:*.example.org", robert.socha], rate: 20G/1d},
    {name: tie, members: ["hosts#db9"], rate: 20G/1d, burst: 10G},
    {name: others, rate: 5G/1d}]}`)
	for _, c := range []struct {
		id      *wire.Identity
		class   string
		matched string
	}{
		{host("db1"), "large", ""},
		// The lowest of several wins: the rate, then the burst.
		{host("db1", "db1.example.org"), "medium", "large,medium"},
		{host("db9", "db9.example.org"), "tie", "large,medium,tie"},
		{host("web1"), "others", ""},
		{robert, "medium", ""},
	} {
		l, ok := Resolve(q, c.id)
		if !ok || l.Class != c.class || strings.Join(l.Matched, ",") != c.matched || l.Mode != "enforce" {
			t.Errorf("%s: %+v %v", c.id.Name, l, ok)
		}
	}
	l, _ := Resolve(q, robert)
	if l.Rate.String() != "20G/1d" || l.Burst != 20<<30 {
		t.Errorf("%+v", l)
	}
	// Without a catch-all an identity in no class has no limit.
	q = parseQuota(t, `{class: [{name: large, members: ["hosts#db*"], rate: 50G/1d}]}`)
	if _, ok := Resolve(q, robert); ok {
		t.Error("robert has a limit")
	}
	// The top-level rate is the catch-all.
	q = parseQuota(t, `{mode: passive, rate: 10G/1d, burst: 50G, class: [{name: large, members: ["hosts#db*"], rate: 50G/1d}]}`)
	if l, ok := Resolve(q, robert); !ok || l.Class != "" || l.Burst != 50<<30 || l.Mode != "passive" {
		t.Errorf("%+v %v", l, ok)
	}
	// Equal rate and burst: the first.
	q = parseQuota(t, `{class: [{name: a, members: ["hosts#x*"], rate: 1G/1d}, {name: b, members: ["hosts:*"], rate: 1G/1d}]}`)
	if l, _ := Resolve(q, host("x")); l.Class != "a" {
		t.Errorf("%+v", l)
	}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newBook(t *testing.T) (*Book, *clock, *bytes.Buffer) {
	var log bytes.Buffer
	c := &clock{time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	return New(slog.New(slog.NewTextHandler(&log, nil)), c.now), c, &log
}

func limit(rate string, burst int64) Limit {
	size, per, _ := wire.ParseRate(rate)
	return Limit{Mode: config.QuotaEnforce, Class: "c", Rate: config.Rate{Size: size, Per: per}, Burst: burst}
}

func refusal(t *testing.T, err error) *Refusal {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("not a refusal: %v", err)
	}
	return r
}

func TestBucket(t *testing.T) {
	b, c, log := newBook(t)
	l := limit("100/1h", 300)
	ch := b.Begin("e", "key:a", l)
	if err := ch.Take(250); err != nil {
		t.Fatal(err)
	}
	ch.Done(250)
	if n := b.Tokens("e", "key:a", l); n != 50 {
		t.Fatal(n)
	}
	// Refill, never above the burst.
	c.t = c.t.Add(30 * time.Minute)
	if n := b.Tokens("e", "key:a", l); n != 100 {
		t.Fatal(n)
	}
	c.t = c.t.Add(10 * time.Hour)
	if n := b.Tokens("e", "key:a", l); n != 300 {
		t.Fatal(n)
	}
	// A stream charged as it reads, cut at the limit and given back.
	ch = b.Begin("e", "key:a", l)
	_, err := io.Copy(io.Discard, ch.Reader(io.MultiReader(bytes.NewReader(make([]byte, 200)), bytes.NewReader(make([]byte, 200)))))
	if r := refusal(t, err); !r.TooLarge {
		t.Fatalf("%+v", r)
	}
	ch.Cancel()
	if n := b.Tokens("e", "key:a", l); n != 300 {
		t.Fatal(n)
	}
	ch = b.Begin("e", "key:a", l)
	_ = ch.Take(250)
	ch.Done(250)
	ch = b.Begin("e", "key:a", l)
	if r := refusal(t, ch.Take(100)); r.TooLarge || r.RetryAfter != 30*time.Minute {
		t.Fatalf("%+v", r)
	}
	ch.Cancel()
	if !strings.Contains(log.String(), `msg="quota: refused" endpoint=e sender=a class=c size=100 tokens=50 retry=30m0s`) {
		t.Fatal(log.String())
	}
	// A new burst clamps the bucket.
	c.t = c.t.Add(10 * time.Hour)
	if n := b.Tokens("e", "key:a", limit("100/1h", 120)); n != 120 {
		t.Fatal(n)
	}
}

func TestPassive(t *testing.T) {
	b, _, log := newBook(t)
	l := limit("100/1h", 300)
	l.Mode = config.QuotaPassive
	ch := b.Begin("e", "key:a", l)
	_ = ch.Take(250)
	ch.Done(250)
	ch = b.Begin("e", "key:a", l)
	// Past the limit nothing more is charged.
	if err := ch.Take(100); err != nil {
		t.Fatal(err)
	}
	if err := ch.Take(100); err != nil {
		t.Fatal(err)
	}
	ch.Done(200)
	if n := b.Tokens("e", "key:a", l); n != 50 {
		t.Fatal(n)
	}
	if strings.Count(log.String(), `msg="quota: would refuse"`) != 1 {
		t.Fatal(log.String())
	}
}

func TestWarnOnce(t *testing.T) {
	b, _, log := newBook(t)
	l := limit("1G/1d", 1<<30)
	l.Class, l.Matched = "small", []string{"large", "small"}
	b.Begin("e", "cert:hosts:db1", l).Cancel()
	b.Begin("e", "cert:hosts:db1", l).Cancel()
	if n := strings.Count(log.String(), `level=WARN msg="quota: hosts#db1 matches large, small; using small" endpoint=e`); n != 1 {
		t.Fatalf("%d: %s", n, log.String())
	}
}

func TestStateFile(t *testing.T) {
	b, c, _ := newBook(t)
	p := filepath.Join(t.TempDir(), "quota.json")
	if aside, err := b.Open(p); err != nil || aside != "" {
		t.Fatal(aside, err)
	}
	l := limit("100/1h", 300)
	for _, owner := range []string{"key:a", "cert:hosts:db1"} {
		ch := b.Begin("e", owner, l)
		_ = ch.Take(200)
		ch.Done(200)
	}
	ch := b.Begin("e", "key:a", l)
	_ = ch.Take(200)
	ch.Cancel()

	b2, _, _ := newBook(t)
	b2.now = c.now
	if _, err := b2.Open(p); err != nil {
		t.Fatal(err)
	}
	if n := b2.Tokens("e", "key:a", l); n != 100 {
		t.Fatal(n)
	}
	rows, err := Report(p, c.t.Add(25*time.Hour))
	if err != nil || len(rows) != 2 {
		t.Fatalf("%+v %v", rows, err)
	}
	if r := rows[1]; r.Identity != "hosts#db1" || r.Rate != "100/1h" || r.Tokens != 300 || r.Bytes24h != 0 || r.Bytes7d != 200 || r.Uploads7d != 1 || *r.Low != 100 || r.Refused != 0 || rows[0].Refused != 1 {
		t.Fatalf("%+v", r)
	}
	// After a week without uploads a full bucket is dropped.
	c.t = c.t.Add(8 * 24 * time.Hour)
	ch = b.Begin("e", "key:a", l)
	_ = ch.Take(1)
	ch.Done(1)
	if rows, _ = Report(p, c.t); len(rows) != 1 || rows[0].Identity != "a" {
		t.Fatalf("%+v", rows)
	}
	// A corrupt file is moved aside.
	if err := os.WriteFile(p, []byte("{"), 0o640); err != nil {
		t.Fatal(err)
	}
	b3, _, _ := newBook(t)
	if aside, err := b3.Open(p); err != nil || !strings.HasPrefix(aside, p+".corrupt-") {
		t.Fatal(aside, err)
	}
}

// An upload in flight is written to the state file as not charged: when
// another upload persists the state and the process then dies, the new
// process finds the bucket of the unfinished upload untouched.
func TestStateFileInFlight(t *testing.T) {
	b, c, _ := newBook(t)
	p := filepath.Join(t.TempDir(), "quota.json")
	if _, err := b.Open(p); err != nil {
		t.Fatal(err)
	}
	l := limit("1000/24h", 1000)
	a := b.Begin("backup", "key:alice", l)
	if err := a.Take(900); err != nil {
		t.Fatal(err)
	}
	o := b.Begin("backup", "key:bob", l)
	if err := o.Take(10); err != nil {
		t.Fatal(err)
	}
	o.Done(10)
	if n := b.Tokens("backup", "key:alice", l); n != 100 {
		t.Fatalf("in memory alice holds %d", n)
	}
	b2, _, _ := newBook(t)
	b2.now = c.now
	if _, err := b2.Open(p); err != nil {
		t.Fatal(err)
	}
	if n := b2.Tokens("backup", "key:alice", l); n != 1000 {
		t.Fatalf("after a crash alice holds %d", n)
	}
	if n := b2.Tokens("backup", "key:bob", l); n != 990 {
		t.Fatalf("bob holds %d", n)
	}
	// Accepted, the upload stays charged in the file.
	a.Done(900)
	b3, _, _ := newBook(t)
	b3.now = c.now
	if _, err := b3.Open(p); err != nil {
		t.Fatal(err)
	}
	if n := b3.Tokens("backup", "key:alice", l); n != 100 {
		t.Fatalf("after Done alice holds %d", n)
	}
}

func TestSuggest(t *testing.T) {
	for in, want := range map[int64]int64{
		0: 0, 1000: 1000, 1024: 1024, 1025: 2048,
		12<<30 + 600<<20: 13 << 30, 950<<20 + 1: 951 << 20, 3 << 40: 3 << 40,
	} {
		if got := RoundUp(in); got != want {
			t.Errorf("RoundUp(%d) = %d, want %d", in, got, want)
		}
	}
	r := Row{History: 30 * time.Hour, MaxDay: 10 << 30, MaxUpload: 8 << 30}
	if rate, burst, ok := r.Suggest(0.5); !ok || rate.String() != "15G/1d" || burst != 15<<30 {
		t.Errorf("%v %d %v", rate, burst, ok)
	}
	r.MaxUpload = 12 << 30
	if rate, burst, ok := r.Suggest(0.5); !ok || rate.String() != "15G/1d" || burst != 18<<30 {
		t.Errorf("%v %d %v", rate, burst, ok)
	}
	r.History = 23 * time.Hour
	if _, _, ok := r.Suggest(0.5); ok {
		t.Error("less than a day suggested")
	}
}
