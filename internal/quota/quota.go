// Package quota bounds how fast an identity uploads to an endpoint: a
// token bucket per endpoint and identity (auth.OwnerKey), refilled
// continuously at the rate of the class the identity falls in, charged
// with the received bytes. The buckets and the stats of the last 7 days
// are kept in a file under the lukd root, so a restart never refills them.
package quota

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"luk/internal/auth"
	"luk/internal/config"
	"luk/internal/wire"
)

// Window is how long the hourly stats are kept.
const Window = 7 * 24 * time.Hour

// Path is the state file under root.
func Path(root string) string { return filepath.Join(root, "quota.json") }

// Limit is the quota in force for one identity on an endpoint: the class
// (empty for the top-level rate), its rate and burst, the mode of the
// endpoint, and the classes with members the identity matches when it
// matches more than one.
type Limit struct {
	Mode    string
	Class   string
	Rate    config.Rate
	Burst   int64
	Matched []string
}

// Match returns the classes of q that apply to id: the classes with
// members it matches, in config order, or else the catch-all alone. in is
// the index of the class in force, -1 when none applies (no limit). Of
// several classes the lowest wins: the lowest rate, then the lower burst,
// then the first.
func Match(q *config.Quota, id *wire.Identity) (classes []config.QuotaClass, in int) {
	all := q.Classes()
	for _, cl := range all {
		if len(cl.Members) > 0 && auth.Allowed(id, cl.Members) {
			classes = append(classes, cl)
		}
	}
	if len(classes) == 0 {
		if n := len(all); n > 0 && len(all[n-1].Members) == 0 {
			return all[n-1:], 0
		}
		return nil, -1
	}
	for i, cl := range classes[1:] {
		best := classes[in]
		if c := cl.Rate.Compare(*best.Rate); c < 0 || c == 0 && cl.Burst < best.Burst {
			in = i + 1
		}
	}
	return classes, in
}

// Resolve is the limit of id on an endpoint with quota q; false when no
// class applies.
func Resolve(q *config.Quota, id *wire.Identity) (Limit, bool) {
	if q == nil {
		return Limit{}, false
	}
	classes, in := Match(q, id)
	if in < 0 {
		return Limit{}, false
	}
	cl := classes[in]
	l := Limit{Mode: q.Mode, Class: cl.Name, Rate: *cl.Rate, Burst: int64(cl.Burst)}
	if len(classes) > 1 {
		for _, c := range classes {
			l.Matched = append(l.Matched, c.Name)
		}
	}
	return l, true
}

// Display is an owner key in the allow syntax: the key name, or
// <ca>#<Key ID> for a certificate.
func Display(owner string) string {
	if name, ok := strings.CutPrefix(owner, "key:"); ok {
		return name
	}
	if rest, ok := strings.CutPrefix(owner, "cert:"); ok {
		ca, keyID, _ := strings.Cut(rest, ":")
		return ca + "#" + keyID
	}
	return owner
}

// Refusal is an upload the quota refuses: TooLarge when it is larger than
// the burst (never passes), else it passes after RetryAfter.
type Refusal struct {
	TooLarge   bool
	RetryAfter time.Duration
}

func (r *Refusal) Error() string {
	if r.TooLarge {
		return wire.ErrQuotaTooLarge
	}
	return wire.ErrQuotaExceeded
}

// Hour is the stats of one hour of an identity on an endpoint: the bytes
// and uploads accepted, the largest of them, the uploads refused (or that
// passive mode would have refused) and the lowest bucket level after an
// upload.
type Hour struct {
	Start   time.Time `json:"start"`
	Bytes   int64     `json:"bytes"`
	Uploads int       `json:"uploads"`
	Max     int64     `json:"max"`
	Refused int       `json:"refused"`
	Low     *int64    `json:"low,omitempty"`
}

// entry is the bucket of one identity on one endpoint.
type entry struct {
	Endpoint string    `json:"endpoint"`
	Owner    string    `json:"owner"`
	Class    string    `json:"class,omitempty"`
	Mode     string    `json:"mode"`
	Rate     string    `json:"rate"`
	Burst    int64     `json:"burst"`
	Tokens   float64   `json:"tokens"`
	Updated  time.Time `json:"updated"`
	Hours    []Hour    `json:"hours,omitempty"`

	rate config.Rate
	// active counts the uploads in flight; their entry is never pruned.
	active int
	// inflight is what the uploads in flight took so far: the state file
	// counts it as still in the bucket, so a crash gives it back.
	inflight float64
}

type state struct {
	Entries []*entry `json:"entries"`
}

// refill adds what the rate gave since the last update, up to the burst.
func (e *entry) refill(now time.Time) {
	if now.After(e.Updated) {
		if e.rate.Per > 0 {
			add := float64(e.rate.Size) * float64(now.Sub(e.Updated)) / float64(e.rate.Per)
			e.Tokens = math.Min(float64(e.Burst), e.Tokens+add)
		}
		e.Updated = now
	}
}

// apply makes l the limit of e; a new rate or burst clamps the tokens to
// the new burst.
func (e *entry) apply(l Limit) {
	if e.rate != l.Rate || e.Burst != l.Burst {
		e.rate, e.Rate, e.Burst = l.Rate, l.Rate.String(), l.Burst
		e.Tokens = math.Min(e.Tokens, float64(l.Burst))
	}
	e.Class, e.Mode = l.Class, l.Mode
}

// hour is the stats of the hour of now, added when missing.
func (e *entry) hour(now time.Time) *Hour {
	start := now.UTC().Truncate(time.Hour)
	if n := len(e.Hours); n > 0 && e.Hours[n-1].Start.Equal(start) {
		return &e.Hours[n-1]
	}
	e.Hours = append(e.Hours, Hour{Start: start})
	return &e.Hours[len(e.Hours)-1]
}

type key struct{ endpoint, owner string }

// Book holds the buckets. Its state is written to its file after every
// upload that changed it; a Book without a file keeps it in memory.
type Book struct {
	mu      sync.Mutex
	path    string
	entries map[key]*entry
	warned  map[key]bool
	log     *slog.Logger
	now     func() time.Time
}

// New is a Book in memory; Open gives it its file.
func New(log *slog.Logger, now func() time.Time) *Book {
	return &Book{entries: map[key]*entry{}, warned: map[key]bool{}, log: log, now: now}
}

// Open loads the state of path and writes it there from now on. A
// missing file is an empty state; a file that is not valid JSON is
// renamed to <path>.corrupt-<UTC time>, whose name is returned, and the
// state starts empty.
func (b *Book) Open(path string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, err := read(path)
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	if errors.As(err, &syn) || errors.As(err, &typ) {
		aside := path + ".corrupt-" + b.now().UTC().Format("20060102T150405Z")
		if rerr := os.Rename(path, aside); rerr != nil {
			return "", rerr
		}
		b.path = path
		return aside, nil
	}
	if err != nil {
		return "", err
	}
	b.path = path
	for _, e := range st.Entries {
		b.entries[key{e.Endpoint, e.Owner}] = e
	}
	return "", nil
}

// read loads a state file; entries with a rate that does not parse are
// dropped.
func read(path string) (*state, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &state{}, nil
	}
	if err != nil {
		return nil, err
	}
	st := &state{}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, err
	}
	st.Entries = slices.DeleteFunc(st.Entries, func(e *entry) bool {
		if e == nil {
			return true
		}
		size, per, err := wire.ParseRate(e.Rate)
		e.rate = config.Rate{Size: size, Per: per}
		return err != nil
	})
	return st, nil
}

// entry is the bucket of k under l, refilled to now; a new identity
// starts full.
func (b *Book) entry(k key, l Limit, now time.Time) *entry {
	e := b.entries[k]
	if e == nil {
		e = &entry{Endpoint: k.endpoint, Owner: k.owner, Tokens: float64(l.Burst), Updated: now}
		b.entries[k] = e
	}
	e.refill(now)
	e.apply(l)
	return e
}

// Tokens is what the bucket of owner on endpoint holds now under l,
// without changing it.
func (b *Book) Tokens(endpoint, owner string, l Limit) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[key{endpoint, owner}]
	if !ok {
		return l.Burst
	}
	c := *e
	c.refill(b.now())
	c.apply(l)
	return int64(c.Tokens)
}

// Begin starts the accounting of one upload of owner to endpoint under l.
// The first time per process that an identity matches several classes it
// logs a warning.
func (b *Book) Begin(endpoint, owner string, l Limit) *Charge {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key{endpoint, owner}
	if len(l.Matched) > 1 && !b.warned[k] {
		b.warned[k] = true
		b.log.Warn(fmt.Sprintf("quota: %s matches %s; using %s", Display(owner), strings.Join(l.Matched, ", "), l.Class), "endpoint", endpoint)
	}
	b.entry(k, l, b.now()).active++
	return &Charge{b: b, k: k, l: l}
}

// Charge is the accounting of one upload: what it took from the bucket,
// given back when it is not stored.
type Charge struct {
	b     *Book
	k     key
	l     Limit
	taken float64
	// over marks a passive upload past the limit: it is no longer charged.
	over bool
	done bool
}

// Check reports whether an upload of n bytes would pass now (a dry run),
// without charging or counting anything.
func (c *Charge) Check(n int64) error {
	c.b.mu.Lock()
	defer c.b.mu.Unlock()
	if c.l.Mode == config.QuotaPassive {
		return nil
	}
	if r := c.refusal(c.b.entry(c.k, c.l, c.b.now()), n); r != nil {
		return r
	}
	return nil
}

// refusal is the answer to taking n more bytes from e, nil when they
// pass.
func (c *Charge) refusal(e *entry, n int64) *Refusal {
	need := c.taken + float64(n)
	if need > float64(c.l.Burst) {
		return &Refusal{TooLarge: true}
	}
	if e.Tokens >= float64(n) {
		return nil
	}
	// What the bucket holds once this upload gave back what it took.
	have := math.Min(float64(c.l.Burst), e.Tokens+c.taken)
	wait := time.Duration((need - have) / float64(c.l.Rate.Size) * float64(c.l.Rate.Per))
	return &Refusal{RetryAfter: max(time.Second, (wait + time.Second - 1).Truncate(time.Second))}
}

// Take charges n received bytes. Over the limit it gives back what the
// upload took and returns a *Refusal; in passive mode it logs and counts
// what would have been refused, stops charging the upload and returns nil.
func (c *Charge) Take(n int64) error {
	c.b.mu.Lock()
	defer c.b.mu.Unlock()
	if c.over || c.done || n <= 0 {
		return nil
	}
	now := c.b.now()
	e := c.b.entry(c.k, c.l, now)
	r := c.refusal(e, n)
	if r == nil {
		e.Tokens -= float64(n)
		e.inflight += float64(n)
		c.taken += float64(n)
		return nil
	}
	size := int64(c.taken) + n
	e.Tokens = math.Min(float64(c.l.Burst), e.Tokens+c.taken)
	e.inflight -= c.taken
	c.taken = 0
	e.hour(now).Refused++
	msg := "quota: refused"
	if c.l.Mode == config.QuotaPassive {
		msg = "quota: would refuse"
	}
	attrs := []any{"endpoint", c.k.endpoint, "sender", Display(c.k.owner), "class", c.l.Class, "size", size, "tokens", int64(e.Tokens)}
	if r.TooLarge {
		attrs = append(attrs, "reason", "larger than burst")
	} else {
		attrs = append(attrs, "retry", r.RetryAfter)
	}
	c.b.log.Info(msg, attrs...)
	c.b.persist(now)
	if c.l.Mode == config.QuotaPassive {
		c.over = true
		return nil
	}
	return r
}

// Reader charges every byte read from r; a read over the limit fails with
// the *Refusal.
func (c *Charge) Reader(r io.Reader) io.Reader { return &reader{r: r, c: c} }

type reader struct {
	r io.Reader
	c *Charge
}

func (r *reader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		if qerr := r.c.Take(int64(n)); qerr != nil {
			return 0, qerr
		}
	}
	return n, err
}

// Done ends an upload stored with n bytes: what it took stays taken and
// the stats count it.
func (c *Charge) Done(n int64) {
	c.b.mu.Lock()
	defer c.b.mu.Unlock()
	if c.done {
		return
	}
	c.done = true
	now := c.b.now()
	e := c.b.entry(c.k, c.l, now)
	e.active--
	e.inflight -= c.taken
	h := e.hour(now)
	h.Bytes += n
	h.Uploads++
	h.Max = max(h.Max, n)
	if t := int64(e.Tokens); h.Low == nil || t < *h.Low {
		h.Low = &t
	}
	c.b.persist(now)
}

// Cancel ends an upload that was not stored: what it took goes back.
// After Done it does nothing.
func (c *Charge) Cancel() {
	c.b.mu.Lock()
	defer c.b.mu.Unlock()
	if c.done {
		return
	}
	c.done = true
	now := c.b.now()
	e := c.b.entry(c.k, c.l, now)
	e.active--
	if c.taken > 0 {
		e.Tokens = math.Min(float64(e.Burst), e.Tokens+c.taken)
		e.inflight -= c.taken
		c.taken = 0
		c.b.persist(now)
	}
}

// persist drops the stats older than Window and the idle entries with a
// full bucket and no stats (a new identity starts the same), then writes
// the state with what the uploads in flight took still in the buckets:
// an upload counts once it is accepted. A failed write is logged; the
// next one retries.
func (b *Book) persist(now time.Time) {
	for k, e := range b.entries {
		if e.active > 0 {
			continue
		}
		e.Hours = slices.DeleteFunc(e.Hours, func(h Hour) bool { return now.Sub(h.Start) > Window })
		c := *e
		c.refill(now)
		if len(e.Hours) == 0 && c.Tokens >= float64(c.Burst) {
			delete(b.entries, k)
		}
	}
	if b.path == "" {
		return
	}
	st := state{Entries: make([]*entry, 0, len(b.entries))}
	for _, e := range b.entries {
		c := *e
		c.Tokens = math.Min(float64(c.Burst), c.Tokens+c.inflight)
		st.Entries = append(st.Entries, &c)
	}
	slices.SortFunc(st.Entries, func(x, y *entry) int {
		return strings.Compare(x.Endpoint+"\x00"+x.Owner, y.Endpoint+"\x00"+y.Owner)
	})
	if err := write(b.path, st); err != nil {
		b.log.Warn("quota state not written", "file", b.path, "error", err)
	}
}

func write(path string, st state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".quota.json.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0o640)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Row is the state of one identity on one endpoint as lukd quota ls shows
// it: the bucket now, the bytes and uploads of the last 24 hours and 7
// days, the lowest level after an upload and the refusals of the last 7
// days; for a suggestion the largest volume of a day (UTC) and the largest
// upload of the last 7 days, and how long the stats go back (History).
type Row struct {
	Endpoint  string
	Identity  string
	Class     string
	Mode      string
	Rate      string
	Burst     int64
	Tokens    int64
	Bytes24h  int64
	Uploads24 int
	Bytes7d   int64
	Uploads7d int
	Low       *int64
	Refused   int
	MaxDay    int64
	MaxUpload int64
	History   time.Duration
}

// Report reads the state file at path (it works without the daemon), the
// rows by endpoint and identity.
func Report(path string, now time.Time) ([]Row, error) {
	st, err := read(path)
	if err != nil {
		return nil, err
	}
	var rows []Row
	for _, e := range st.Entries {
		e.refill(now)
		r := Row{Endpoint: e.Endpoint, Identity: Display(e.Owner), Class: e.Class, Mode: e.Mode, Rate: e.Rate, Burst: e.Burst, Tokens: int64(e.Tokens)}
		days := map[time.Time]int64{}
		for _, h := range e.Hours {
			age := now.Sub(h.Start)
			if age > Window {
				continue
			}
			r.History = max(r.History, age)
			day := h.Start.UTC().Truncate(24 * time.Hour)
			days[day] += h.Bytes
			r.MaxDay = max(r.MaxDay, days[day])
			r.MaxUpload = max(r.MaxUpload, h.Max)
			if age <= 24*time.Hour {
				r.Bytes24h += h.Bytes
				r.Uploads24 += h.Uploads
			}
			r.Bytes7d += h.Bytes
			r.Uploads7d += h.Uploads
			r.Refused += h.Refused
			if h.Low != nil && (r.Low == nil || *h.Low < *r.Low) {
				low := *h.Low
				r.Low = &low
			}
		}
		rows = append(rows, r)
	}
	slices.SortFunc(rows, func(x, y Row) int {
		return strings.Compare(x.Endpoint+"\x00"+x.Identity, y.Endpoint+"\x00"+y.Identity)
	})
	return rows, nil
}

// Suggest proposes a limit from the stats of r with margin (0.5 is 50%):
// the rate is the largest volume of a day, the burst the largest upload,
// each with the margin and rounded up (RoundUp), the burst never below
// the size of the rate. False with less than a day of stats or no upload.
func (r Row) Suggest(margin float64) (rate config.Rate, burst int64, ok bool) {
	if r.History < 24*time.Hour || r.MaxDay == 0 {
		return config.Rate{}, 0, false
	}
	day := RoundUp(int64(math.Ceil(float64(r.MaxDay) * (1 + margin))))
	burst = max(RoundUp(int64(math.Ceil(float64(r.MaxUpload)*(1+margin)))), day)
	return config.Rate{Size: day, Per: 24 * time.Hour}, burst, true
}

// RoundUp rounds n up to whole units of the largest unit (K, M, G, T) it
// reaches: 12.6G is 13G, 950.2M is 951M; below 1K it stays.
func RoundUp(n int64) int64 {
	u := int64(1)
	for u < 1<<40 && n >= u<<10 {
		u <<= 10
	}
	return (n + u - 1) / u * u
}
