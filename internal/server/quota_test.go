package server

import (
	"crypto/rand"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/quota"
	"luk/internal/wire"
)

// quotaFixture puts quota on the endpoint backup (body limit 1K) and sets
// a clock the test moves.
func quotaFixture(t *testing.T, q string) (*fixture, *time.Time) {
	t.Helper()
	f := newFixtureWith(t, func(s string) string {
		return strings.Replace(s, `limits: {body: {size: 1K}}}`, `limits: {body: {size: 1K}}, quota: `+q+`}`, 1)
	})
	now := time.Now()
	f.srv.SetClock(func() time.Time { return now })
	return f, &now
}

// fresh is n bytes of new content, so no upload is deduplicated.
func fresh(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func stream() wire.Meta {
	return wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Tags: []string{"prod"}}
}

func TestQuotaSignedSize(t *testing.T) {
	f, now := quotaFixture(t, `{rate: 100/1h, burst: 300}`)
	body := fresh(200)
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body})
	receipt(t, rec, http.StatusAccepted)

	// 100 tokens left: refused before the body, back in an hour.
	body = fresh(200)
	read := 0
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body, tamper: countBody(&read)})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "3600" || read != 0 ||
		!strings.Contains(rec.Body.String(), `"`+wire.ErrQuotaExceeded+`"`) {
		t.Fatalf("%d %q read %d: %s", rec.Code, rec.Header().Get("Retry-After"), read, rec.Body)
	}
	// Larger than the burst never passes.
	big := fresh(301)
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(big, "prod"), body: big})
	if rec.Code != http.StatusRequestEntityTooLarge || rec.Header().Get("Retry-After") != "" ||
		!strings.Contains(rec.Body.String(), wire.ErrQuotaTooLarge) {
		t.Fatalf("%d: %s", rec.Code, rec.Body)
	}
	// A dry run is checked the same and charges nothing.
	m := fileMeta(body, "prod")
	m.DryRun = true
	if rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: m, chunked: true}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("dry run %d: %s", rec.Code, rec.Body)
	}
	*now = now.Add(time.Hour)
	if rec, _ = f.do(t, req{ts: *now, signer: f.user, path: "/backup", meta: m, chunked: true}); rec.Code != http.StatusOK {
		t.Fatalf("dry run %d: %s", rec.Code, rec.Body)
	}
	rec, _ = f.do(t, req{ts: *now, signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body})
	receipt(t, rec, http.StatusAccepted)
	body = fresh(200)
	// Every identity has its own bucket.
	rec, _ = f.do(t, req{ts: *now, signer: f.hostCert(t), path: "/backup", meta: fileMeta(body, "prod"), body: body})
	receipt(t, rec, http.StatusAccepted)
}

func TestQuotaStream(t *testing.T) {
	f, _ := quotaFixture(t, `{rate: 100/1h, burst: 300}`)
	do := func(n int) int {
		rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: stream(), body: fresh(n), chunked: true})
		return rec.Code
	}
	if c := do(250); c != http.StatusAccepted {
		t.Fatal(c)
	}
	// Cut at the limit; what it took goes back.
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: stream(), body: fresh(100), chunked: true})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1800" {
		t.Fatalf("%d %q: %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
	if e := entries(t, filepath.Join(f.root, "q/backup")); len(e) != 1 {
		t.Fatalf("queue %v", e)
	}
	if c := do(50); c != http.StatusAccepted {
		t.Fatal(c)
	}
	// A stream over the burst never passes.
	f2, _ := quotaFixture(t, `{rate: 100/1h, burst: 300}`)
	rec, _ = f2.do(t, req{signer: f2.user, path: "/backup", meta: stream(), body: fresh(400), chunked: true})
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), wire.ErrQuotaTooLarge) {
		t.Fatalf("%d: %s", rec.Code, rec.Body)
	}
}

func TestQuotaFailedUploadGivesBack(t *testing.T) {
	f, _ := quotaFixture(t, `{rate: 100/1h, burst: 300}`)
	body := fresh(300)
	m := fileMeta(body, "prod")
	m.SHA256 = strings.Repeat("0", 64)
	if rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: m, body: body}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("%d: %s", rec.Code, rec.Body)
	}
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body})
	receipt(t, rec, http.StatusAccepted)
}

func TestQuotaDedupIsFree(t *testing.T) {
	f, _ := dedupFixture(t, func(s string) string {
		return strings.Replace(s, `respond: url, storage: drop}`, `respond: url, storage: drop, quota: {rate: 20/1d}}`, 1)
	})
	body := []byte("the same content")
	f.put(t, f.user, fileMeta(body), body)
	f.settle(t)
	if second, n := f.put(t, f.user, fileMeta(body), body); n != 0 || !second.Deduplicated {
		t.Fatalf("read %d: %+v", n, second)
	}
}

func TestQuotaPassive(t *testing.T) {
	f, _ := quotaFixture(t, `{mode: passive, rate: 100/1h, burst: 300}`)
	p := filepath.Join(f.root, "quota.json")
	if _, err := f.srv.quota.Open(p); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		body := fresh(250)
		rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body})
		receipt(t, rec, http.StatusAccepted)
	}
	rows, err := quota.Report(p, f.srv.now())
	if err != nil || len(rows) != 1 {
		t.Fatalf("%+v %v", rows, err)
	}
	// The refused upload was not charged, as enforce would not have.
	r := rows[0]
	if r.Mode != "passive" || r.Identity != "robert.socha" || r.Uploads24 != 2 || r.Bytes24h != 500 || r.Refused != 1 || r.Tokens != 50 || r.Low == nil || *r.Low != 50 {
		t.Fatalf("%+v", r)
	}
}

// The buckets live in a file under root: a restart does not refill them.
func TestQuotaPersisted(t *testing.T) {
	f, now := quotaFixture(t, `{rate: 100/1h, burst: 300}`)
	p := filepath.Join(f.root, "quota.json")
	if _, err := f.srv.quota.Open(p); err != nil {
		t.Fatal(err)
	}
	body := fresh(300)
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body})
	receipt(t, rec, http.StatusAccepted)

	s := New(f.srv.config(), slog.New(slog.DiscardHandler))
	s.SetClock(func() time.Time { return *now })
	if _, err := s.quota.Open(p); err != nil {
		t.Fatal(err)
	}
	small := []byte("x")
	rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(small, "prod"), body: small, via: s.Handler(s.config().Addrs()[0].Addr)})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "36" {
		t.Fatalf("%d %q: %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("%v %v", fi, err)
	}
}

// Of several classes the lowest applies; a reload to a lower burst clamps
// the bucket.
func TestQuotaClasses(t *testing.T) {
	f, _ := quotaFixture(t, `{class: [
    {name: big, members: ["hosts:*"], rate: 1K/1h},
    {name: small, members: ["hosts#luk.*"], rate: 100/1h, burst: 200},
    {name: rest, rate: 500/1h}]}`)
	host := f.hostCert(t)
	list := decodeList(t, f.list(t, listReq{signer: host}))
	q := list.Endpoints[0].Quota
	if q == nil || q.Rate != "100/1h" || q.Burst != 200 || q.Tokens != 200 || q.Mode != "enforce" {
		t.Fatalf("%+v", q)
	}
	list = decodeList(t, f.list(t, listReq{signer: f.user}))
	for _, e := range list.Endpoints {
		if e.Name == "backup" && (e.Quota == nil || e.Quota.Rate != "500/1h") {
			t.Fatalf("%+v", e.Quota)
		}
		if e.Name == "drop" && e.Quota != nil {
			t.Fatalf("drop %+v", e.Quota)
		}
	}
	body := fresh(150)
	rec, _ := f.do(t, req{signer: host, path: "/backup", meta: fileMeta(body, "prod"), body: body})
	receipt(t, rec, http.StatusAccepted)
	if q := decodeList(t, f.list(t, listReq{signer: host})).Endpoints[0].Quota; q.Tokens != 50 {
		t.Fatalf("%+v", q)
	}
}

// A reload applies new limits to the buckets it keeps: a lower burst
// clamps them.
func TestQuotaReload(t *testing.T) {
	f, _ := quotaFixture(t, `{rate: 100/1h, burst: 300}`)
	body := fresh(100)
	rec, _ := f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body})
	receipt(t, rec, http.StatusAccepted)
	next := *f.srv.config()
	next.Endpoint = maps.Clone(next.Endpoint)
	ep := *next.Endpoint["backup"]
	ep.Quota = &config.Quota{Mode: config.QuotaEnforce, Rate: &config.Rate{Size: 100, Per: time.Hour}, Burst: 150}
	next.Endpoint["backup"] = &ep
	f.srv.apply(&next)
	if q := decodeList(t, f.list(t, listReq{signer: f.user})).Endpoints[0].Quota; q == nil || q.Burst != 150 || q.Tokens != 150 {
		t.Fatalf("%+v", q)
	}
	body = fresh(160)
	if rec, _ = f.do(t, req{signer: f.user, path: "/backup", meta: fileMeta(body, "prod"), body: body}); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("%d: %s", rec.Code, rec.Body)
	}
}
