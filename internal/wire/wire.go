// Package wire holds what the client and the server must agree on: request
// headers, the client meta, the signed canonical text and the answers.
package wire

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	Namespace       = "luk-upload@v1"
	HeaderMeta      = "Luk-Meta"
	HeaderTimestamp = "Luk-Timestamp"
	HeaderNonce     = "Luk-Nonce"
	HeaderSignature = "Luk-Signature"

	// LinkNamespace signs the requests that manage a stored link; an
	// upload signature never verifies as one, nor the other way round.
	LinkNamespace    = "luk-link@v1"
	HeaderLink       = "Luk-Link"
	HeaderLinkAction = "Luk-Link-Action"

	// GetNamespace signs a download from an expose with auth.ssh; no
	// other signature verifies as one, nor a get signature as anything
	// else.
	GetNamespace = "luk-get@v1"
	// ListNamespace signs the endpoint listing (EndpointsPath); no other
	// signature verifies as one, nor a list signature as anything else.
	ListNamespace = "luk-list@v1"
	// EndpointsPath is the endpoint listing, on every listener.
	EndpointsPath = "/.well-known/luk/endpoints"
	// WellKnown is reserved: no endpoint or expose path is equal to it or
	// under it.
	WellKnown = "/.well-known"
	// HeaderExpires (RFC 3339, UTC) and HeaderOnce ("true") announce the
	// expiry and the once flag of a private file in the answers of an
	// expose with auth.ssh; absent without expiry and when not once.
	HeaderExpires = "Luk-Expires"
	HeaderOnce    = "Luk-Once"

	LinkRemove    = "remove"
	LinkTTL       = "ttl"
	LinkReplace   = "replace"
	LinkList      = "list"
	MaxMetaHeader = 16384
	MaxNameLen    = 255

	SourceFile     = "file"
	SourcePipe     = "pipe"
	SourceStdin    = "stdin"
	SourceTerminal = "terminal"

	PortalDirect   = "direct"
	PortalReveal   = "reveal"
	PortalDownload = "download"

	// Access of a private upload (Meta.Access): only the owner, or any
	// identity the protect expose allows, downloads it with a signed get.
	// Empty is public.
	AccessPrivate = "private"
	AccessAny     = "any"

	// SchemeLuk is the scheme of the URL of a private upload; it always
	// means HTTPS.
	SchemeLuk = "luk"

	// What the server did with the client ttl (Receipt.TTLNote).
	TTLCapped  = "capped"
	TTLRaised  = "raised"
	TTLIgnored = "ignored"

	// TTLMax as a client ttl asks for the longest lifetime the storage
	// allows: its ttl.max, or no expiry without one.
	TTLMax = "max"

	// ErrTimestampWindow is the 401 error of a request whose timestamp is
	// outside auth.clock_skew of the server clock; the client tells its
	// clock offset from the Date of the answer.
	ErrTimestampWindow = "timestamp outside the allowed window"

	// ErrQuotaExceeded is the 429 error of an upload over the quota of its
	// sender on the endpoint, with Retry-After; ErrQuotaTooLarge the 413
	// error of an upload larger than that quota can ever take. Neither
	// names the configured limits.
	ErrQuotaExceeded = "quota exceeded"
	ErrQuotaTooLarge = "upload exceeds the quota of this endpoint"
)

var (
	tagRe = regexp.MustCompile(`^[a-z0-9._-]+$`)
	shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Backup struct {
	Hostname string `json:"hostname"`
	Path     string `json:"path"`
	Mtime    string `json:"mtime,omitempty"`
}

// Meta is what the client asserts about an upload. It is signed.
type Meta struct {
	File      string   `json:"file,omitempty"`
	Source    string   `json:"source"`
	Type      string   `json:"type,omitempty"`
	Size      *int64   `json:"size,omitempty"`
	SHA256    string   `json:"sha256,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	TTL       string   `json:"ttl,omitempty"`
	Once      bool     `json:"once,omitempty"`
	Portal    string   `json:"portal"`
	PrettyURL bool     `json:"pretty_url,omitempty"`
	NoOwner   bool     `json:"no_owner,omitempty"`
	Mutable   bool     `json:"mutable,omitempty"`
	Access    string   `json:"access,omitempty"`
	Backup    *Backup  `json:"backup,omitempty"`
	DryRun    bool     `json:"dry_run,omitempty"`
	// Permanent is the permanent name the upload is a new version of (see
	// CheckPermanentName); empty for an ordinary upload.
	Permanent string `json:"permanent,omitempty"`
}

// MaxPermanentName bounds the length of a permanent name.
const MaxPermanentName = 1024

// CheckPermanentName refuses a permanent name that is not a clean
// relative name: empty, longer than MaxPermanentName, absolute, with a
// control character, an empty, . or .. element, or an element longer
// than MaxNameLen. An element current or starting with current. is
// reserved: lukd keeps the version of a name in such a directory.
func CheckPermanentName(name string) error {
	switch {
	case name == "":
		return errors.New("empty permanent name")
	case len(name) > MaxPermanentName:
		return fmt.Errorf("permanent name longer than %d bytes", MaxPermanentName)
	case HasControl(name):
		return fmt.Errorf("permanent name %q holds a control character", name)
	case strings.HasPrefix(name, "/"):
		return fmt.Errorf("permanent name %q is absolute", name)
	}
	for _, e := range strings.Split(name, "/") {
		switch {
		case e == "":
			return fmt.Errorf("permanent name %q has an empty element", name)
		case e == "." || e == "..":
			return fmt.Errorf("permanent name %q: element %q is not a name", name, e)
		case len(e) > MaxNameLen:
			return fmt.Errorf("permanent name %q: an element is longer than %d bytes", name, MaxNameLen)
		case e == "current" || strings.HasPrefix(e, "current."):
			return fmt.Errorf("permanent name %q: element %q is reserved", name, e)
		}
	}
	return nil
}

// PermanentConflicts names the options a permanent upload must not set
// (once, a portal, access, mutable, pretty_url); none when it sets none.
func (m Meta) PermanentConflicts() []string {
	var set []string
	for _, f := range []struct {
		name string
		on   bool
	}{
		{"once", m.Once}, {"portal " + m.Portal, m.Portal != PortalDirect}, {"access " + m.Access, m.Access != ""},
		{"mutable", m.Mutable}, {"pretty_url", m.PrettyURL},
	} {
		if f.on {
			set = append(set, f.name)
		}
	}
	return set
}

// Normalize lowercases, deduplicates and sorts the tags, then validates.
func (m *Meta) Normalize() error {
	seen := map[string]bool{}
	var tags []string
	for _, t := range m.Tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if !tagRe.MatchString(t) {
			return fmt.Errorf("invalid tag %q (allowed: a-z 0-9 . _ -)", t)
		}
		if !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}
	sort.Strings(tags)
	m.Tags = tags
	return m.Validate()
}

// HasControl reports whether s holds a control character (C0, DEL, C1).
// Names and types from a client never do: they reach logs, terminals,
// line output and command lines.
func HasControl(s string) bool { return strings.ContainsFunc(s, unicode.IsControl) }

// Validate checks a normalized meta.
func (m Meta) Validate() error {
	for i, t := range m.Tags {
		if !tagRe.MatchString(t) || (i > 0 && m.Tags[i-1] >= t) {
			return errors.New("tags must be lowercase, unique and sorted")
		}
	}
	if m.TTL != "" {
		if err := CheckTTL(m.TTL); err != nil {
			return err
		}
	}
	switch m.Portal {
	case PortalDirect, PortalReveal, PortalDownload:
	default:
		return fmt.Errorf("invalid portal %q (direct, reveal, download)", m.Portal)
	}
	switch m.Access {
	case "", AccessPrivate, AccessAny:
	default:
		return fmt.Errorf("invalid access %q (private, any)", m.Access)
	}
	if m.Access != "" && m.Portal != PortalDirect {
		return fmt.Errorf("access %s takes no portal (%s)", m.Access, m.Portal)
	}
	if strings.Contains(m.File, "/") || HasControl(m.File) || len(m.File) > MaxNameLen {
		return fmt.Errorf("invalid file name %q", m.File)
	}
	if b := m.Backup; b != nil && (strings.Contains(b.Hostname, "/") || HasControl(b.Hostname) || strings.HasPrefix(b.Hostname, ".") || len(b.Hostname) > MaxNameLen) {
		return fmt.Errorf("invalid backup hostname %q", b.Hostname)
	}
	if m.Type != "" {
		if _, _, err := mime.ParseMediaType(m.Type); err != nil || HasControl(m.Type) || len(m.Type) > MaxNameLen {
			return fmt.Errorf("invalid type %q", m.Type)
		}
	}
	switch m.Source {
	case SourceFile, SourceTerminal:
		if m.Size == nil || m.SHA256 == "" {
			return fmt.Errorf("source %s requires size and sha256", m.Source)
		}
	case SourcePipe, SourceStdin:
		// A stream sent again (luk send --links) knows both from the
		// first answer.
		if (m.Size == nil) != (m.SHA256 == "") {
			return fmt.Errorf("source %s carries both size and sha256 or neither", m.Source)
		}
	default:
		return fmt.Errorf("invalid source %q (file, pipe, stdin, terminal)", m.Source)
	}
	if m.Size != nil && *m.Size < 0 {
		return errors.New("negative size")
	}
	if m.SHA256 != "" && !shaRe.MatchString(m.SHA256) {
		return errors.New("sha256 must be 64 lowercase hex characters")
	}
	return nil
}

func EncodeMeta(m Meta) (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func DecodeMeta(s string) (Meta, error) {
	var m Meta
	if err := decodeJSON(s, &m); err != nil {
		return m, err
	}
	return m, m.Validate()
}

// decodeJSON decodes base64url s into the JSON object v, refusing unknown
// fields and trailing data.
func decodeJSON(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("meta: %w", err)
	}
	if t := bytes.TrimSpace(b); len(t) == 0 || t[0] != '{' {
		return errors.New("meta: not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("meta: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("meta: data after the JSON object")
	}
	return nil
}

// CanonicalText is what the client signs and the server verifies.
func CanonicalText(host, path, timestamp, nonce, meta string) []byte {
	return []byte(strings.Join([]string{Namespace, "PUT", host, path, timestamp, nonce, meta}, "\n"))
}

// GetCanonicalText is what the client signs and the server verifies for a
// download from an expose with auth.ssh: the method (GET or HEAD), the
// Host, the request target (GetTarget), the timestamp and the nonce.
func GetCanonicalText(method, host, target, timestamp, nonce string) []byte {
	return []byte(strings.Join([]string{GetNamespace, method, host, target, timestamp, nonce}, "\n"))
}

// QueryRecursive is the query of a signed listing (luk-get@v1 on a
// directory URL) of every file below the directory, named relative to it.
const QueryRecursive = "recursive=1"

// ListEntry is a line of the signed listing of a directory: a directory
// (Dir, its name ending with a slash) or a file with its size, stored time
// (RFC 3339 in UTC) and sha256.
type ListEntry struct {
	Name     string `json:"name"`
	Dir      bool   `json:"dir,omitempty"`
	Size     *int64 `json:"size,omitempty"`
	Received string `json:"received,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

// GetTarget is the request target a luk-get@v1 signature covers: the path
// as requested (escaped) and, when the request has a query, "?" and the
// raw query as sent. A request without a query signs its path alone.
func GetTarget(escapedPath, rawQuery string) string {
	if rawQuery == "" {
		return escapedPath
	}
	return escapedPath + "?" + rawQuery
}

// ListCanonicalText is what the client signs and the server verifies for
// the endpoint listing: the method (GET), the Host, the path as requested
// (escaped), the timestamp and the nonce.
func ListCanonicalText(method, host, path, timestamp, nonce string) []byte {
	return []byte(strings.Join([]string{ListNamespace, method, host, path, timestamp, nonce}, "\n"))
}

// LinkMethod is the HTTP method of a link action; false for an unknown
// action.
func LinkMethod(action string) (string, bool) {
	switch action {
	case LinkRemove:
		return "DELETE", true
	case LinkTTL:
		return "PATCH", true
	case LinkReplace:
		return "PUT", true
	case LinkList:
		return "GET", true
	}
	return "", false
}

// LinkCanonicalText is what the client signs and the server verifies for
// a link request: the method, the Host, the endpoint path, the link URL
// (empty for a list) and the action as sent, then the timestamp, the nonce and the meta.
func LinkCanonicalText(method, host, path, link, action, timestamp, nonce, meta string) []byte {
	return []byte(strings.Join([]string{LinkNamespace, method, host, path, link, action, timestamp, nonce, meta}, "\n"))
}

// LinkMeta is the meta of a remove, ttl or list link request; a replace sends
// an upload Meta instead.
type LinkMeta struct {
	TTL string `json:"ttl,omitempty"`
}

func EncodeLinkMeta(m LinkMeta) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeLinkMeta decodes the meta of a remove or ttl request strictly; a
// ttl, when present, is a positive duration or TTLMax.
func DecodeLinkMeta(s string) (LinkMeta, error) {
	var m LinkMeta
	if err := decodeJSON(s, &m); err != nil {
		return m, err
	}
	if m.TTL != "" {
		if err := CheckTTL(m.TTL); err != nil {
			return m, err
		}
	}
	return m, nil
}

// ValidateReplace checks the meta of a replace: it describes the new
// content only (file, source, type, size, sha256); everything else of the
// link stays as stored, so the other fields must be left out and portal
// must be direct.
func (m Meta) ValidateReplace() error {
	var set []string
	for _, f := range []struct {
		name string
		on   bool
	}{
		{"tags", len(m.Tags) > 0}, {"ttl", m.TTL != ""}, {"once", m.Once}, {"pretty_url", m.PrettyURL},
		{"no_owner", m.NoOwner}, {"mutable", m.Mutable}, {"access", m.Access != ""},
		{"backup", m.Backup != nil}, {"dry_run", m.DryRun}, {"portal", m.Portal != PortalDirect},
		{"permanent", m.Permanent != ""},
	} {
		if f.on {
			set = append(set, f.name)
		}
	}
	if len(set) > 0 {
		return fmt.Errorf("replace meta must not set %s", strings.Join(set, ", "))
	}
	return nil
}

func NewNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func ValidNonce(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 16
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ParseDuration accepts Go durations plus whole days ("7d").
func ParseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		if n == "" || !isAllDigits(n) {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		v, err := strconv.Atoi(n)
		if err != nil || v < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		maxDays := int64(math.MaxInt64) / int64(24*time.Hour)
		if int64(v) > maxDays {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(v) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// ParseTTL reads a client ttl: a positive duration, or TTLMax (max true,
// d 0).
func ParseTTL(s string) (d time.Duration, max bool, err error) {
	if s == TTLMax {
		return 0, true, nil
	}
	if d, err := ParseDuration(s); err == nil && d > 0 {
		return d, false, nil
	}
	return 0, false, ttlError(s)
}

// CheckTTL validates a client ttl (see ParseTTL).
func CheckTTL(s string) error {
	_, _, err := ParseTTL(s)
	return err
}

// ttlError names the units a ttl takes; a bare number has none on purpose.
func ttlError(ttl string) error {
	if isAllDigits(ttl) {
		return fmt.Errorf("invalid ttl %q: add a unit, e.g. %sm, %sh or %sd", ttl, ttl, ttl, ttl)
	}
	return fmt.Errorf("invalid ttl %q: use a number with a unit (s, m, h, d), e.g. 90m, 12h or 7d, or max", ttl)
}

// FormatDuration is the short form ParseDuration reads back: whole days as
// "7d", else the Go form without zero minutes or seconds ("1h", "1h30m").
func FormatDuration(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	s := d.String()
	if t, ok := strings.CutSuffix(s, "m0s"); ok {
		s = t + "m"
	}
	if t, ok := strings.CutSuffix(s, "h0m"); ok {
		s = t + "h"
	}
	return s
}

// ParseSize accepts bytes or a K, M, G, T suffix in either case (powers
// of 1024).
func ParseSize(s string) (int64, error) {
	orig := s
	mult := int64(1)
	for i, u := range []string{"K", "M", "G", "T"} {
		if n, ok := strings.CutSuffix(strings.ToUpper(s), u); ok {
			s = n
			mult = 1 << (10 * (i + 1))
			break
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid size %q", orig)
	}
	if mult > 1 && v > math.MaxInt64/mult {
		return 0, fmt.Errorf("invalid size %q", orig)
	}
	return v * mult, nil
}

// FormatSize is the short form ParseSize reads back: the largest unit that
// divides n ("10G", "1536M"), else bytes.
func FormatSize(n int64) string {
	for i, u := range []string{"T", "G", "M", "K"} {
		if m := int64(1) << (10 * (4 - i)); n != 0 && n%m == 0 {
			return strconv.FormatInt(n/m, 10) + u
		}
	}
	return strconv.FormatInt(n, 10)
}

// HumanSize is n in the units of ParseSize with one decimal when not
// whole ("12.5G", "50G", "512").
func HumanSize(n int64) string {
	if n < 1024 && n > -1024 {
		return strconv.FormatInt(n, 10)
	}
	v, unit := float64(n)/1024, "K"
	for _, u := range []string{"M", "G", "T"} {
		if math.Abs(v) < 1024 {
			break
		}
		v, unit = v/1024, u
	}
	s := strconv.FormatFloat(v, 'f', 1, 64)
	return strings.TrimSuffix(s, ".0") + unit
}

// ParseRate reads a quota rate, <size>/<duration> ("10G/1d"): both
// positive.
func ParseRate(s string) (int64, time.Duration, error) {
	sz, per, ok := strings.Cut(s, "/")
	if !ok {
		return 0, 0, fmt.Errorf("invalid rate %q: want <size>/<duration>, e.g. 10G/1d", s)
	}
	n, err := ParseSize(sz)
	if err != nil || n <= 0 {
		return 0, 0, fmt.Errorf("invalid rate %q: want <size>/<duration>, e.g. 10G/1d", s)
	}
	d, err := ParseDuration(per)
	if err != nil || d <= 0 {
		return 0, 0, fmt.Errorf("invalid rate %q: want <size>/<duration>, e.g. 10G/1d", s)
	}
	return n, d, nil
}

// FormatRate is the form ParseRate reads back.
func FormatRate(size int64, per time.Duration) string {
	return FormatSize(size) + "/" + FormatDuration(per)
}

type Identity struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	CA          string   `json:"ca,omitempty"`
	KeyID       string   `json:"key_id,omitempty"`
	Principals  []string `json:"principals,omitempty"`
	Serial      uint64   `json:"serial,omitempty"`
	Fingerprint string   `json:"fingerprint"`
}

// ServerMeta of a dry run: the body is never sent, so there is no size or
// sha256.
type ServerMeta struct {
	Received string `json:"received"`
}

type Respond struct {
	Mode string `json:"mode"`
	URL  string `json:"url,omitempty"`
}

// Receipt is how a client reads a stored upload answer: 201 (respond: url)
// carries URL and Expires (empty when the upload never expires), 202
// (respond: accept) carries neither. TTL is the lifetime the server gave
// the upload (none: it never expires) and TTLNote what it did with the
// client ttl (TTLCapped, TTLRaised, TTLIgnored; none: applied as asked).
// TTLMin and TTLMax are the ttl.min and ttl.max of the storage (none: no
// such bound).
type Receipt struct {
	ID      string `json:"id"`
	URL     string `json:"url,omitempty"`
	Expires string `json:"expires,omitempty"`
	TTL     string `json:"ttl,omitempty"`
	TTLNote string `json:"ttl_note,omitempty"`
	TTLMin  string `json:"ttl_min,omitempty"`
	TTLMax  string `json:"ttl_max,omitempty"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	// Deduplicated marks an upload answered without its body: the server
	// already held the content for the sender (see Created).
	Deduplicated bool `json:"deduplicated,omitempty"`
	// Permanent is the permanent name of a permanent upload, whose URL is
	// the permanent URL; VersionURL is then the URL of the stored version.
	Permanent  string `json:"permanent,omitempty"`
	VersionURL string `json:"version_url,omitempty"`
}

// Created is the 201 answer; it always carries url and expires.
// Deduplicated marks an upload answered before 100 Continue, its content
// taken from what the server holds for the sender.
type Created struct {
	ID           string `json:"id"`
	URL          string `json:"url"`
	Expires      string `json:"expires"`
	TTL          string `json:"ttl,omitempty"`
	TTLNote      string `json:"ttl_note,omitempty"`
	TTLMin       string `json:"ttl_min,omitempty"`
	TTLMax       string `json:"ttl_max,omitempty"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	Deduplicated bool   `json:"deduplicated,omitempty"`
	// Permanent and VersionURL are those of a permanent upload (see
	// Receipt).
	Permanent  string `json:"permanent,omitempty"`
	VersionURL string `json:"version_url,omitempty"`
}

// Response is the debug answer of a dry run. Schedule lists the matched
// pipelines in the order they start: those without a queue group first,
// then each group by name, in ascending order.
type Response struct {
	ID        string      `json:"id"`
	Identity  Identity    `json:"identity"`
	Endpoint  string      `json:"endpoint"`
	Client    Meta        `json:"client"`
	Server    ServerMeta  `json:"server"`
	Pipelines []string    `json:"pipelines"`
	Schedule  []Scheduled `json:"schedule"`
	Claimed   *Claimed    `json:"claimed,omitempty"`
	Respond   Respond     `json:"respond"`
}

// Claimed is the pipeline of a dry run that claimed the upload and the
// other matching pipelines it left out.
type Claimed struct {
	Pipeline string   `json:"pipeline"`
	Skipped  []string `json:"skipped"`
}

// Scheduled is a matched pipeline of a dry run with its queue group (none:
// it runs concurrently with every other) and its order in the group.
type Scheduled struct {
	Pipeline string `json:"pipeline"`
	Group    string `json:"group,omitempty"`
	Order    int    `json:"order"`
}

// LinkAnswer is the answer of a link request: remove (URL, Removed), ttl
// (URL, Expires, TTL, TTLNote, TTLMin, TTLMax as in an upload answer) or
// replace (202: URL, the ID of the queued content, its Size and SHA256).
type LinkAnswer struct {
	URL     string `json:"url"`
	Removed bool   `json:"removed,omitempty"`
	Expires string `json:"expires,omitempty"`
	TTL     string `json:"ttl,omitempty"`
	TTLNote string `json:"ttl_note,omitempty"`
	TTLMin  string `json:"ttl_min,omitempty"`
	TTLMax  string `json:"ttl_max,omitempty"`
	ID      string `json:"id,omitempty"`
	Size    *int64 `json:"size,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

// LinkListAnswer is the answer of a link list: the links of the caller on
// the endpoint, newest first; Truncated when there were more than
// MaxLinkList.
type LinkListAnswer struct {
	Links     []LinkEntry `json:"links"`
	Truncated bool        `json:"truncated,omitempty"`
}

// MaxLinkList caps the entries of a link list answer.
const MaxLinkList = 10000

// LinkEntry is one link of a list answer.
type LinkEntry struct {
	URL      string `json:"url"`
	File     string `json:"file,omitempty"`
	Size     int64  `json:"size"`
	Received string `json:"received"`
	Expires  string `json:"expires,omitempty"`
	Once     bool   `json:"once"`
	Mutable  bool   `json:"mutable"`
	Portal   string `json:"portal"`
	Access   string `json:"access,omitempty"`
	Updated  string `json:"updated,omitempty"`
	// Permanent is the permanent name the file is a version of, and
	// PermanentURL its permanent URL; empty for any other file.
	Permanent    string `json:"permanent,omitempty"`
	PermanentURL string `json:"permanent_url,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// EndpointList is the answer of the endpoint listing: the endpoints of the
// listener the request came in on whose allow admits the signer, by name.
type EndpointList struct {
	Endpoints []EndpointInfo `json:"endpoints"`
}

// EndpointInfo is what a client may use of one endpoint: where it is and
// which upload options it takes.
type EndpointInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
	URL  string `json:"url"`
	// Respond is url (the answer carries the URL of the upload) or accept.
	Respond string `json:"respond"`
	// Secret: reveal uploads (--secret) go to a volatile storage.
	Secret bool `json:"secret"`
	// Pretty: the endpoint offers pretty_url.
	Pretty bool `json:"pretty"`
	// Permanent: an entry of permanent.names grants the signer.
	Permanent bool         `json:"permanent"`
	Private   PrivateModes `json:"private"`
	Link      LinkActions  `json:"link"`
	TTL       *TTLPolicy   `json:"ttl,omitempty"`
	// SecretTTL is the policy of the secret storage when it differs from TTL.
	SecretTTL *TTLPolicy `json:"secret_ttl,omitempty"`
	// Quota is the upload quota of the signer on the endpoint; absent
	// without one.
	Quota *QuotaInfo `json:"quota,omitempty"`
	// BackupHostname is which backup.hostname the signer may send:
	// BackupHostAny, BackupHostPrincipal or BackupHostNone; absent when the
	// endpoint does not restrict it (any).
	BackupHostname string `json:"backup_hostname,omitempty"`
}

// What backup.hostname a signer may send to an endpoint: any, one of
// the principals of its certificate, or none.
const (
	BackupHostAny       = "any"
	BackupHostPrincipal = "principal"
	BackupHostNone      = "none"
)

// QuotaInfo is the quota of one identity on an endpoint: Mode enforce or
// passive, Rate the refill (<size>/<duration>), Burst the capacity of the
// bucket and Tokens what it holds now, both in bytes.
type QuotaInfo struct {
	Mode   string `json:"mode"`
	Rate   string `json:"rate"`
	Burst  int64  `json:"burst"`
	Tokens int64  `json:"tokens"`
}

// PrivateModes is the access modes of private uploads an endpoint accepts.
type PrivateModes struct {
	Owner bool `json:"owner"`
	Any   bool `json:"any"`
}

// LinkActions is what the owner may do with a link of the endpoint;
// Replace is also what a mutable upload needs.
type LinkActions struct {
	Remove  bool `json:"remove"`
	TTL     bool `json:"ttl"`
	Replace bool `json:"replace"`
	List    bool `json:"list"`
}

// TTLPolicy is the ttl policy of a storage: whether a client ttl counts
// (User), its bounds and the lifetime of an upload without one (Default),
// in the short duration form; each empty when there is none.
type TTLPolicy struct {
	User    bool   `json:"user"`
	Min     string `json:"min,omitempty"`
	Max     string `json:"max,omitempty"`
	Default string `json:"default,omitempty"`
}
