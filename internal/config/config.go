// Package config loads and validates the lukd configuration.
package config

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"luk/internal/sshsig"
	"luk/internal/wire"
)

// DefaultRoot is `root` when absent.
const DefaultRoot = "/var/lib/luk"

// DataName and RootName are the two entries of root (see SPEC, Service,
// State): data holds everything lukd writes and is the base of relative
// paths; root is root's, the workspaces of lukd run.
const (
	DataName = "data"
	RootName = "root"
)

// DefaultNonces is the directory of the nonce cache when auth.nonces is
// absent: on the tmpfs /run, created by tmpfiles.d.
const DefaultNonces = "/run/luk/nonces"

// DefaultClockSkew is auth.clock_skew when absent.
const DefaultClockSkew = time.Minute

// DefaultPipelineTimeout bounds one run step when `timeout` is absent.
const DefaultPipelineTimeout = time.Hour

// MaxPipelineTimeout is the age after which the janitor removes work
// directories; a run step must end before it.
const MaxPipelineTimeout = 7 * 24 * time.Hour

type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := wire.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

type Size int64

func (s *Size) UnmarshalYAML(n *yaml.Node) error {
	var v string
	if err := n.Decode(&v); err != nil {
		return err
	}
	b, err := wire.ParseSize(v)
	if err != nil {
		return err
	}
	*s = Size(b)
	return nil
}

// StringList accepts a scalar or a sequence.
type StringList []string

func (l *StringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = StringList{n.Value}
		return nil
	}
	var v []string
	if err := n.Decode(&v); err != nil {
		return err
	}
	*l = v
	return nil
}

type Config struct {
	Root     string               `yaml:"root"`
	Listen   map[string]*Listen   `yaml:"listen"`
	Limits   Limits               `yaml:"limits"`
	Auth     Auth                 `yaml:"auth"`
	Endpoint map[string]*Endpoint `yaml:"endpoint"`
	Pipeline map[string]*Pipeline `yaml:"pipeline"`
	Storage  map[string]*Storage  `yaml:"storage"`
	Expose   map[string]*Expose   `yaml:"expose"`
	GPG      GPG                  `yaml:"gpg"`
	Log      Log                  `yaml:"log"`

	// Path is the main file and Files every file Load read (the main file,
	// the snippets, the ssh.d files); empty after Parse.
	Path  string   `yaml:"-"`
	Files []string `yaml:"-"`
	// IdentityPath is the identity key file next to the main file; empty
	// after Parse.
	IdentityPath string `yaml:"-"`
	// PasswordDir is the password.d directory next to the main file;
	// empty after Parse.
	PasswordDir string `yaml:"-"`
}

// Log configures the lukd log: Level is debug, info (the default), warn or
// error.
type Log struct {
	Level string `yaml:"level"`
}

// LogLevel is the level of log.level.
func (c *Config) LogLevel() slog.Level {
	switch c.Log.Level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// GPG configures the keys of encrypt steps: Keys is the directory of the
// key files (*.asc, *.gpg, *.pgp, *.key) of `key` recipients (gpg.d next
// to the main file by default), WKD.Cache how long a key fetched through
// the Web Key Directory is used before a refetch.
type GPG struct {
	Keys string `yaml:"keys"`
	WKD  struct {
		Cache Duration `yaml:"cache"`
	} `yaml:"wkd"`
}

// DefaultWKDCache is gpg.wkd.cache when absent.
const DefaultWKDCache = 24 * time.Hour

// Limits bound connection-level resource use on every listener; zero values
// take the defaults.
type Limits struct {
	Conn   ConnLimits   `yaml:"conn"`
	Header HeaderLimits `yaml:"header"`
	Queue  QueueLimits  `yaml:"queue"`
	Failed FailedLimits `yaml:"failed"`
	// Channel bounds the channel sessions of the receive role.
	Channel ChannelLimits `yaml:"channel"`
	// Uploads bounds the uploads in parts open at once.
	Uploads UploadLimits `yaml:"uploads"`
}

// UploadLimits: Total is the number of uploads in parts open at once,
// Identity the number open at once per identity.
type UploadLimits struct {
	Total    int `yaml:"total"`
	Identity int `yaml:"identity"`
}

// ChannelLimits: Auth is the time from a handshake to its OP, Pending the
// number of sessions without an OP kept at once (the oldest is dropped for
// a new one), Idle the time a session with its OP is kept without a
// request.
type ChannelLimits struct {
	Auth    Duration `yaml:"auth"`
	Pending int      `yaml:"pending"`
	Idle    Duration `yaml:"idle"`
}

// FailedLimits: Age is how long a failure record is kept; 0 keeps it
// until it is removed.
type FailedLimits struct {
	Age *Duration `yaml:"age"`
}

// MaxAge is Age, or DefaultFailedAge when unset.
func (l FailedLimits) MaxAge() time.Duration {
	if l.Age == nil {
		return DefaultFailedAge
	}
	return time.Duration(*l.Age)
}

// QueueLimits: Reserve is the free space kept on the queue filesystem.
type QueueLimits struct {
	Reserve Size `yaml:"reserve"`
}

type ConnLimits struct {
	Max  int      `yaml:"max" json:"max"`
	Idle Duration `yaml:"idle" json:"idle"`
}

type HeaderLimits struct {
	Timeout Duration `yaml:"timeout" json:"timeout"`
}

// EndpointLimits bound the requests of an endpoint.
type EndpointLimits struct {
	Body BodyLimits `yaml:"body"`
}

type BodyLimits struct {
	Size Size     `yaml:"size"`
	Idle Duration `yaml:"idle"`
	// Rate is the slowest a part may arrive, in bytes per second: a part
	// must arrive within its size / Rate. 0 turns it off; unset is
	// DefaultBodyRate.
	Rate *Size `yaml:"rate"`
}

// BytesPerSecond is Rate, DefaultBodyRate when unset.
func (b BodyLimits) BytesPerSecond() int64 {
	if b.Rate == nil {
		return DefaultBodyRate
	}
	return int64(*b.Rate)
}

// Parts is how an upload in parts is cut: every part but the last has
// Size bytes, and a client sends at most Parallel of them at once.
type Parts struct {
	Size     Size `yaml:"size"`
	Parallel int  `yaml:"parallel"`
}

const (
	DefaultConnMax       = 1024
	DefaultConnIdle      = 60 * time.Second
	DefaultHeaderTimeout = 10 * time.Second
	DefaultBodyIdle      = 2 * time.Minute
	DefaultQueueReserve  = 1 << 30
	DefaultFailedAge     = 3 * 24 * time.Hour
)

const (
	DefaultChannelAuth    = 60 * time.Second
	DefaultChannelPending = 1024
	DefaultChannelIdle    = 2 * time.Minute
)

const (
	DefaultPartSize = 8 << 20
	MinPartSize     = 64 << 10
	// MaxPartSize is the largest part whose frames the nonce of a
	// message can number (32768 frames, the last one empty).
	MaxPartSize            = 2<<30 - 64<<10
	DefaultPartParallel    = 4
	MaxPartParallel        = 64
	DefaultBodyRate        = 64 << 10
	DefaultUploadsTotal    = 256
	DefaultUploadsIdentity = 8
)

// Listen is a named listener. Several listeners may share an address;
// requests are routed among them by Host (and SNI for TLS).
type Listen struct {
	Name string     `yaml:"-" json:"-"`
	Addr string     `yaml:"addr" json:"addr"`
	Host StringList `yaml:"host" json:"host"`
	TLS  *TLS       `yaml:"tls" json:"tls"`
	// ACME makes a plain listener answer the HTTP-01 challenges of every
	// tls mode acme listener and redirect their names to https.
	ACME bool `yaml:"acme" json:"acme"`
	// Public is the base URL of answers, without a trailing slash; derived
	// from tls, host and port when absent (empty when nothing names a host).
	Public string `yaml:"public" json:"public"`
}

// Serves reports whether the listener answers for the hostname (lowercase,
// without port); a listener without a host list answers for any.
func (l *Listen) Serves(host string) bool {
	return len(l.Host) == 0 || slices.Contains(l.Host, host)
}

// TLS is the certificate of a listener: mode self (lukd tls generate
// creates it), files (an external tool provides it, lukd only reads it) or
// acme (lukd obtains and renews it for the names of the host list).
type TLS struct {
	Mode string `yaml:"mode" json:"mode"`
	Cert string `yaml:"cert" json:"cert"`
	Key  string `yaml:"key" json:"key"`
	Host string `yaml:"host" json:"host"`

	Algorithm string `yaml:"algorithm" json:"algorithm"`

	// Mode acme: the contact address, the ACME directory URL (default Let's
	// Encrypt production) and the optional external account binding.
	Email     string `yaml:"email" json:"email"`
	Directory string `yaml:"directory" json:"directory"`
	EAB       EAB    `yaml:"eab" json:"eab"`
}

// DefaultACMEDirectory is tls.directory of an acme listener when absent.
const DefaultACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// EAB is an ACME external account binding: the key id and the HMAC key
// (base64url), inline or in KeyFile. After validation Key holds the key
// of either source and KeySum its sha256, which the running file keeps
// instead of the key.
type EAB struct {
	KID     string `yaml:"kid" json:"kid"`
	Key     string `yaml:"key" json:"-"`
	KeyFile string `yaml:"key_file" json:"key_file"`
	KeySum  string `yaml:"-" json:"key_sha256"`
}

// Set reports whether the binding is configured.
func (e EAB) Set() bool { return e != EAB{} }

// MAC is the decoded HMAC key. CAs print it base64url, some in standard
// base64, padded or not; a wrongly decoded key only shows as a failed
// registration, so each is tried.
func (e EAB) MAC() ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(e.Key); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

// sameTLS compares two tls settings; the EAB key by its sum only, as the
// running file does not hold it.
func sameTLS(a, b *TLS) bool {
	x, y := *a, *b
	x.EAB.Key, y.EAB.Key = "", ""
	return x == y
}

type Auth struct {
	ClockSkew Duration `yaml:"clock_skew"`
	// Nonces is the directory the receive role keeps its nonce cache in,
	// on a tmpfs (see DefaultNonces).
	Nonces string `yaml:"nonces"`
	Keys   []Key  `yaml:"keys"`
	CA     []CA   `yaml:"ca"`
}

// Key is an identity of plain keys: an auth.keys entry with its one key,
// or a ssh.d/<name>.pub file (File) with one key per line.
type Key struct {
	Name   string          `yaml:"name"`
	Key    string          `yaml:"key"`
	Parsed []ssh.PublicKey `yaml:"-"`
	File   string          `yaml:"-"`
}

// CA is a certificate authority: an auth.ca entry with its one key, or a
// ssh.d/ca/<type>/<name>.pub file (File) with one key per line. An auth.ca
// entry without key holds the revoked list of the file CA of its name.
type CA struct {
	Name    string          `yaml:"name"`
	Type    string          `yaml:"type"`
	Key     string          `yaml:"key"`
	Revoked Revoked         `yaml:"revoked"`
	Parsed  []ssh.PublicKey `yaml:"-"`
	File    string          `yaml:"-"`
}

type Revoked struct {
	KeyIDs  []string `yaml:"key_ids"`
	Serials []uint64 `yaml:"serials"`
}

type Endpoint struct {
	Name     string         `yaml:"-"`
	Listen   StringList     `yaml:"listen"`
	Endpoint string         `yaml:"endpoint"`
	Path     string         `yaml:"path"`
	Allow    []string       `yaml:"allow"`
	Respond  string         `yaml:"respond"`
	Storage  string         `yaml:"storage"`
	Limits   EndpointLimits `yaml:"limits"`
	// Parts is how an upload inside the channel is cut.
	Parts Parts `yaml:"parts"`
	// Pretty, when present, lets the identities of pretty.allow ask for a
	// proquint .Random (pretty_url); anyone else is refused.
	Pretty *Pretty `yaml:"pretty"`
	// Link is who may manage the links they own; only with respond url.
	Link Link `yaml:"link"`
	// Private is who may send which private modes; only with respond url,
	// and the respond storage needs protect.
	Private Private `yaml:"private"`
	// Backup is who may set which backup.hostname (luk send --backup).
	Backup Backup `yaml:"backup"`
	// Secret, when set, takes the reveal uploads of the identities of
	// secret.allow (respond url only): into its own queue directory and
	// only into its storage, without the pipelines of the endpoint.
	Secret *Secret `yaml:"secret"`
	// Quota, when set, bounds how fast each identity uploads to the
	// endpoint (see Quota).
	Quota *Quota `yaml:"quota"`
	// Permanent, when set, allocates the permanent names of the endpoint
	// (respond url only): each upload with one is a new version of it,
	// served at <expose url><path>/<name>.
	Permanent *Permanent `yaml:"permanent"`
}

// Permanent is the permanent names of an endpoint: Path is the prefix of
// their names in the respond storage (DefaultPermanentPath), Names the
// exact names and patterns that may be published, each with who may
// publish it.
type Permanent struct {
	Path  string                    `yaml:"path"`
	Names map[string]*PermanentName `yaml:"names"`
}

func (p *Permanent) UnmarshalYAML(n *yaml.Node) error {
	type raw Permanent
	return decodeCapabilities(n, "permanent", []string{"path", "names"}, nil, (*raw)(p))
}

// PermanentName is an entry of permanent.names: who may publish the
// names it covers (Allow) and, for a pattern, the most distinct names it
// holds (Max, default DefaultPermanentMax).
type PermanentName struct {
	Allow Identities `yaml:"allow"`
	Max   *int       `yaml:"max"`
}

func (e *PermanentName) UnmarshalYAML(n *yaml.Node) error {
	type raw PermanentName
	return decodeCapabilities(n, "permanent.names entry", []string{"allow", "max"}, []string{"allow"}, (*raw)(e))
}

const (
	// DefaultPermanentPath is permanent.path when absent.
	DefaultPermanentPath = "permanent"
	// DefaultPermanentMax is the max of a pattern of permanent.names
	// without one.
	DefaultPermanentMax = 100
)

// MaxOf is the most distinct names a pattern entry holds.
func (e *PermanentName) MaxOf() int {
	if e.Max == nil {
		return DefaultPermanentMax
	}
	return *e.Max
}

// IsPattern reports whether a key of permanent.names is a pattern (holds
// *, ? or [) rather than an exact name.
func IsPattern(key string) bool { return strings.ContainsAny(key, `*?[\`) }

// literals counts the characters of a pattern that match only
// themselves: every character but *, ?, a [...] class and the backslash
// of an escape.
func literals(pat string) int {
	n := 0
	for i := 0; i < len(pat); i++ {
		switch pat[i] {
		case '*', '?':
		case '\\':
			if i+1 < len(pat) {
				i++
				n++
			}
		case '[':
			for i++; i < len(pat) && pat[i] != ']'; i++ {
				if pat[i] == '\\' {
					i++
				}
			}
		default:
			n++
		}
	}
	return n
}

// Entry finds the entry of permanent.names that covers name: the exact
// entry of that name, else the matching pattern (path.Match, * within one
// element) with the most literal characters, a tie going to the pattern
// that sorts first. key is the entry's key; false when none covers it.
func (p *Permanent) Entry(name string) (key string, e *PermanentName, ok bool) {
	if p == nil {
		return "", nil, false
	}
	if e, ok := p.Names[name]; ok && !IsPattern(name) {
		return name, e, true
	}
	best := -1
	for k, v := range p.Names {
		if !IsPattern(k) {
			continue
		}
		if m, err := path.Match(k, name); err != nil || !m {
			continue
		}
		if n := literals(k); n > best || n == best && k < key {
			key, e, best = k, v, n
		}
	}
	return key, e, best >= 0
}

// Quota is a token bucket per identity on an endpoint: Rate refills it,
// Burst is its capacity (the size part of Rate when absent). Mode passive
// accounts and logs without refusing. Rate and Burst at the top are the
// catch-all; Class assigns other limits by identity, a class without
// members being the catch-all instead.
type Quota struct {
	Mode  string       `yaml:"mode"`
	Rate  *Rate        `yaml:"rate"`
	Burst Size         `yaml:"burst"`
	Class []QuotaClass `yaml:"class"`
}

// Quota modes.
const (
	QuotaEnforce = "enforce"
	QuotaPassive = "passive"
)

// QuotaClass is a limit for the identities of Members (allow syntax); a
// class without members is the catch-all.
type QuotaClass struct {
	Name    string   `yaml:"name"`
	Members []string `yaml:"members"`
	Rate    *Rate    `yaml:"rate"`
	Burst   Size     `yaml:"burst"`
}

// Rate is a refill rate: Size bytes per Per.
type Rate struct {
	Size int64
	Per  time.Duration
}

func (r *Rate) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	size, per, err := wire.ParseRate(s)
	if err != nil {
		return err
	}
	*r = Rate{Size: size, Per: per}
	return nil
}

func (r Rate) String() string { return wire.FormatRate(r.Size, r.Per) }

// Compare orders rates by bytes per time: -1, 0 or 1.
func (r Rate) Compare(o Rate) int {
	// Size times Per may overflow int64; the float error is far below a byte
	// per day.
	return cmp.Compare(float64(r.Size)*float64(o.Per), float64(o.Size)*float64(r.Per))
}

// Classes is the classes of q with the catch-all last: the top-level rate
// and burst as a class without a name, or the class without members.
func (q *Quota) Classes() []QuotaClass {
	var out []QuotaClass
	var all *QuotaClass
	for i := range q.Class {
		if len(q.Class[i].Members) == 0 {
			all = &q.Class[i]
			continue
		}
		out = append(out, q.Class[i])
	}
	if q.Rate != nil {
		all = &QuotaClass{Rate: q.Rate, Burst: q.Burst}
	}
	if all != nil {
		out = append(out, *all)
	}
	return out
}

// Secret is where the reveal uploads of an endpoint go: the queue
// directory Path and the local exposed Storage, both meant to be in RAM
// (tmpfs).
type Secret struct {
	Path    string `yaml:"path"`
	Storage string `yaml:"storage"`
	// Reserve is the free space kept on the filesystem of Path, in place
	// of limits.queue.reserve; DefaultSecretReserve when absent.
	Reserve Size `yaml:"reserve"`
	// Allow is who may send secret uploads; a reveal upload of anyone
	// else is an upload as to an endpoint without secret.
	Allow Identities `yaml:"allow"`
}

func (sc *Secret) UnmarshalYAML(n *yaml.Node) error {
	type raw Secret
	return decodeCapabilities(n, "secret", []string{"path", "storage", "reserve", "allow"}, []string{"allow"}, (*raw)(sc))
}

// DefaultSecretReserve is secret.reserve when absent: a tmpfs is small.
const DefaultSecretReserve = 16 << 20

// SecretReserves maps every secret queue directory to its reserve; a
// directory shared by endpoints keeps the largest.
func (c *Config) SecretReserves() map[string]int64 {
	out := map[string]int64{}
	for _, e := range c.Endpoint {
		if sc := e.Secret; sc != nil && int64(sc.Reserve) > out[sc.Path] {
			out[sc.Path] = int64(sc.Reserve)
		}
	}
	return out
}

// Secrets reports whether the endpoint keeps uploads with the portal in
// its secret queue and storage; one goes there when its signer also
// matches secret.allow.
func (e *Endpoint) Secrets(portal string) bool {
	return e.Secret != nil && portal == wire.PortalReveal
}

// Identities is a list of identities in the syntax of an endpoint allow
// (see auth.Allowed): who is granted a capability of an endpoint. Absent
// or empty grants it to no one.
type Identities []string

// identitiesHint is how a value that is not a list is refused.
const identitiesHint = `a list of identities, e.g. ["*"]`

func (l *Identities) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: %s", n.Line, identitiesHint)}}
	}
	v := []string{}
	if err := n.Decode(&v); err != nil {
		return err
	}
	*l = v
	return nil
}

// decodeCapabilities decodes the mapping n into out (a pointer to a struct
// type of the yaml keys known), refusing unknown keys as a strict decoder
// does and naming the key (<block>.<key>) of a value of lists that is not
// a list.
func decodeCapabilities(n *yaml.Node, block string, known, lists []string, out any) error {
	if n.Kind == yaml.MappingNode {
		var errs []string
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			switch {
			case !slices.Contains(known, k.Value):
				errs = append(errs, fmt.Sprintf("line %d: field %s not found in %s", k.Line, k.Value, block))
			case slices.Contains(lists, k.Value) && v.Kind != yaml.SequenceNode && v.ShortTag() != "!!null":
				errs = append(errs, fmt.Sprintf("line %d: %s.%s: %s", k.Line, block, k.Value, identitiesHint))
			}
		}
		if len(errs) > 0 {
			return &yaml.TypeError{Errors: errs}
		}
	}
	return n.Decode(out)
}

// Private is who may send which private uploads to an endpoint: Owner
// those only the owner downloads (wire.AccessPrivate), Any those every
// identity the protect expose allows downloads (wire.AccessAny). List is
// who also gets, in a link list, the files of access any others sent
// through the endpoint that it may download, read-only.
type Private struct {
	Owner Identities `yaml:"owner"`
	Any   Identities `yaml:"any"`
	List  Identities `yaml:"list"`
}

func (p *Private) UnmarshalYAML(n *yaml.Node) error {
	type raw Private
	keys := []string{"owner", "any", "list"}
	return decodeCapabilities(n, "private", keys, keys, (*raw)(p))
}

// Offered reports whether any identity may send private uploads.
func (p Private) Offered() bool { return len(p.Owner) > 0 || len(p.Any) > 0 }

// Of is who may send an upload of the access mode (empty: public, which
// needs no entry: nil); ok is false for an unknown mode.
func (p Private) Of(access string) (who Identities, ok bool) {
	switch access {
	case "":
		return nil, true
	case wire.AccessPrivate:
		return p.Owner, true
	case wire.AccessAny:
		return p.Any, true
	}
	return nil, false
}

// Backup is the backup capabilities of an endpoint: without Hostname
// every identity the endpoint admits sends any backup.hostname.
type Backup struct {
	Hostname *BackupHostname `yaml:"hostname"`
}

func (b *Backup) UnmarshalYAML(n *yaml.Node) error {
	type raw Backup
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k, v := n.Content[i], n.Content[i+1]; k.Value == "hostname" && v.Kind != yaml.MappingNode {
				return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: backup.hostname: a mapping of any and principal, e.g. {any: [\"*\"]}", k.Line)}}
			}
		}
	}
	return decodeCapabilities(n, "backup", []string{"hostname"}, nil, (*raw)(b))
}

// BackupHostname is who may send which backup.hostname: Any every one,
// Principal only one of the principals of its own certificate. An
// identity in neither list sends none.
type BackupHostname struct {
	Any       Identities `yaml:"any"`
	Principal Identities `yaml:"principal"`
}

func (h *BackupHostname) UnmarshalYAML(n *yaml.Node) error {
	type raw BackupHostname
	keys := []string{"any", "principal"}
	return decodeCapabilities(n, "backup.hostname", keys, keys, (*raw)(h))
}

// Link is who may do what with the links they own on an endpoint: remove
// one, set a new ttl, replace the content of a mutable upload (and send
// one); list their links.
type Link struct {
	Remove  Identities `yaml:"remove"`
	TTL     Identities `yaml:"ttl"`
	Replace Identities `yaml:"replace"`
	List    Identities `yaml:"list"`
}

func (l *Link) UnmarshalYAML(n *yaml.Node) error {
	type raw Link
	keys := []string{"remove", "ttl", "replace", "list"}
	return decodeCapabilities(n, "link", keys, keys, (*raw)(l))
}

// Offered reports whether any identity may do any link action.
func (l Link) Offered() bool {
	return len(l.Remove) > 0 || len(l.TTL) > 0 || len(l.Replace) > 0 || len(l.List) > 0
}

// Of is who may do the link action (wire.LinkRemove, wire.LinkTTL,
// wire.LinkReplace, wire.LinkList); nil for an unknown one.
func (l Link) Of(action string) Identities {
	switch action {
	case wire.LinkRemove:
		return l.Remove
	case wire.LinkTTL:
		return l.TTL
	case wire.LinkReplace:
		return l.Replace
	case wire.LinkList:
		return l.List
	}
	return nil
}

// Pretty is who may ask for a proquint .Random (Allow) and its size, a
// multiple of 16 bits from MinPrettyBits to MaxPrettyBits; 0 takes
// MinPrettyBits.
type Pretty struct {
	Bits  int        `yaml:"bits"`
	Allow Identities `yaml:"allow"`
}

func (p *Pretty) UnmarshalYAML(n *yaml.Node) error {
	type raw Pretty
	return decodeCapabilities(n, "pretty", []string{"bits", "allow"}, []string{"allow"}, (*raw)(p))
}

const (
	MinPrettyBits = 64
	MaxPrettyBits = 128
)

type Pipeline struct {
	Name     string   `yaml:"-"`
	Endpoint []string `yaml:"endpoint"`
	Tags     []string `yaml:"tags"`
	// Claim makes a matching pipeline the only one of the upload.
	Claim   bool     `yaml:"claim"`
	Timeout Duration `yaml:"timeout"`
	Queue   Queue    `yaml:"queue"`
	Steps   []Step   `yaml:"steps"`
	// MovedConcurrency catches the key moved to queue.concurrency, so the
	// error names the new place.
	MovedConcurrency any `yaml:"concurrency"`
}

// Queue schedules the runs of a pipeline. Concurrency bounds its runs
// across all uploads. The matched pipelines of one upload that share a
// Group run in ascending Order, one order after the other; without a
// Group a pipeline runs concurrently with every other.
type Queue struct {
	Group       string `yaml:"group"`
	Order       int    `yaml:"order"`
	Concurrency int    `yaml:"concurrency"`
}

// Step is one step of a pipeline. Tee makes a run step a consumer: it
// leaves out/ empty and the next step gets the set it got. Relay names a
// job of lukd run that consumes the set the same way. Jobs names the jobs
// of lukd run the program of a run step may start with luk-job run.
type Step struct {
	Run     RunSpec           `yaml:"run"`
	Tee     bool              `yaml:"tee"`
	Relay   string            `yaml:"relay"`
	Jobs    []string          `yaml:"jobs"`
	Store   StringList        `yaml:"store"`
	Encrypt *Encrypt          `yaml:"encrypt"`
	Env     map[string]string `yaml:"env"`
}

// RunSpec is the run key of a step: a program (an absolute path) or
// {job: NAME}, a job of lukd run that runs as the step.
type RunSpec struct {
	Program string
	Job     string
	// invalid marks a value of another form, reported by validation.
	invalid bool
}

func (r RunSpec) Set() bool { return r.Program != "" || r.Job != "" || r.invalid }

// String is what the step errors name: the program, or "job <job>".
func (r RunSpec) String() string {
	if r.Job != "" {
		return "job " + r.Job
	}
	return r.Program
}

// UnmarshalYAML takes a string (the program) or a mapping with exactly
// the key job. Anything else is kept as invalid for validation to report
// with the step, so the error names the pipeline and the step.
func (r *RunSpec) UnmarshalYAML(n *yaml.Node) error {
	*r = RunSpec{}
	switch {
	case n.Kind == yaml.ScalarNode && n.Tag == "!!str":
		r.Program = n.Value
	case n.Kind == yaml.MappingNode && len(n.Content) == 2 && n.Content[0].Value == "job" &&
		n.Content[1].Kind == yaml.ScalarNode && n.Content[1].Tag == "!!str":
		r.Job = n.Content[1].Value
	default:
		r.invalid = true
	}
	return nil
}

// Encrypt encrypts every file of the set to the recipients: WKD addresses
// are looked up through the Web Key Directory, Key addresses in gpg.keys.
// Strict fails the step when any recipient is unusable. Addresses are
// lowercased by validation. Insecure adds password based encryption.
type Encrypt struct {
	WKD      StringList `yaml:"wkd"`
	Key      StringList `yaml:"key"`
	Strict   bool       `yaml:"strict"`
	Insecure *Insecure  `yaml:"insecure"`
}

// Insecure is the password based encryption of an encrypt step, weaker
// than the recipients' keys: the passwords sit in password.d on the
// server. Symmetric names passwords that also decrypt the .gpg file;
// OpenSSL writes the matching files in the openssl enc format instead.
type Insecure struct {
	Symmetric StringList `yaml:"symmetric"`
	OpenSSL   *OpenSSL   `yaml:"openssl"`
}

// OpenSSL encrypts the files whose name (as it enters the step) matches
// one of the Files globs (path.Match) with the password Key, as
// <name>.enc in the format of openssl enc -aes-256-cbc -pbkdf2.
type OpenSSL struct {
	Key   string     `yaml:"key"`
	Files StringList `yaml:"files"`
}

// Match reports whether the file name goes to the openssl format.
func (o *OpenSSL) Match(name string) bool {
	if o == nil {
		return false
	}
	for _, g := range o.Files {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

type Storage struct {
	Type   string `yaml:"type"`
	Base   string `yaml:"base"`
	Path   string `yaml:"path"`
	Bucket string `yaml:"bucket"`
	Prefix string `yaml:"prefix"`
	// Expose serves the public files of the storage (local only); with
	// auth.ssh only to signed requests of the identities it allows.
	Expose string `yaml:"expose"`
	// Protect is the expose with auth.ssh that serves the private files
	// of the storage (local only).
	Protect string `yaml:"protect"`
	// Conflict is version (default), reject or replace.
	Conflict string `yaml:"conflict"`
	// Catalog keeps <base>/.db/catalog.json (local only).
	Catalog bool `yaml:"catalog"`
	// Shard places the files under that many levels of sha256 hex pair
	// directories (local only, 0-4).
	Shard int `yaml:"shard"`
	// Dedup (default true) keeps the newest version instead of adding an
	// identical one; conflict version only.
	Dedup *bool `yaml:"dedup"`
	// Hardlink (default true) keeps one copy of each content: stored files
	// with the same sha256 are hardlinks of one object (local only).
	Hardlink *bool `yaml:"hardlink"`
	// Links.Max is the most stored names holding one content (sha256)
	// that one identity (owner key) may have here (local with hardlink
	// only); 0 is DefaultLinksMax.
	Links struct {
		Max int `yaml:"max"`
	} `yaml:"links"`
	// Random is the alphabet and length of .Random; empty keeps the
	// default: DefaultRandomLength characters of RandomAlphabet.
	Random Random `yaml:"random"`
	// TTL is the lifetime policy of stored files (local only): see
	// Lifetime.
	TTL struct {
		// User lets the client ttl count, clamped to Min and Max.
		User bool     `yaml:"user"`
		Min  Duration `yaml:"min"`
		Max  Duration `yaml:"max"`
	} `yaml:"ttl"`
	// Cleanup.Age removes files without an expiry once they are that old
	// (local only).
	Cleanup struct {
		Age Duration `yaml:"age"`
	} `yaml:"cleanup"`
	// Retention prunes the stored files of each series (local only): the
	// first rule whose origin globs match the origin of a file applies
	// (see RetentionRule).
	Retention []Retention `yaml:"retention"`
	// Watch holds the monitoring rules of the series (local only): the
	// first rule whose origin and file globs match a series applies (see
	// WatchRule).
	Watch []Watch `yaml:"watch"`

	pathTmpl *template.Template
	nested   []string
	// permanent maps the endpoints whose respond storage this is and that
	// have permanent names to their permanent block.
	permanent map[string]*Permanent
}

// Permanents maps the endpoints whose respond storage this is and that
// have permanent names to their permanent block (see Endpoint.Permanent);
// nil for none.
func (s *Storage) Permanents() map[string]*Permanent { return s.permanent }

// Retention is one retention rule of a storage: Origin holds globs
// (path.Match) on the origin of a file, none for every origin; Keep holds
// the counts of files kept per series.
type Retention struct {
	Origin StringList `yaml:"origin"`
	Keep   Keep       `yaml:"keep"`
}

// Keep holds the counts of a retention rule: the Last newest files, the
// newest file of each of the newest Daily days, Weekly ISO weeks, Monthly
// months and Yearly years (UTC), and every file received within Within
// before now.
type Keep struct {
	Last    int      `yaml:"last" json:"last,omitempty"`
	Daily   int      `yaml:"daily" json:"daily,omitempty"`
	Weekly  int      `yaml:"weekly" json:"weekly,omitempty"`
	Monthly int      `yaml:"monthly" json:"monthly,omitempty"`
	Yearly  int      `yaml:"yearly" json:"yearly,omitempty"`
	Within  Duration `yaml:"within" json:"-"`
}

// keepJSON is Keep in JSON: Within in the form of the configuration
// ("2d").
type keepJSON struct {
	Last    int    `json:"last,omitempty"`
	Daily   int    `json:"daily,omitempty"`
	Weekly  int    `json:"weekly,omitempty"`
	Monthly int    `json:"monthly,omitempty"`
	Yearly  int    `json:"yearly,omitempty"`
	Within  string `json:"within,omitempty"`
}

func (k Keep) MarshalJSON() ([]byte, error) {
	j := keepJSON{k.Last, k.Daily, k.Weekly, k.Monthly, k.Yearly, ""}
	if k.Within != 0 {
		j.Within = wire.FormatDuration(time.Duration(k.Within))
	}
	return json.Marshal(j)
}

func (k *Keep) UnmarshalJSON(b []byte) error {
	var j keepJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*k = Keep{Last: j.Last, Daily: j.Daily, Weekly: j.Weekly, Monthly: j.Monthly, Yearly: j.Yearly}
	if j.Within != "" {
		d, err := wire.ParseDuration(j.Within)
		if err != nil {
			return err
		}
		k.Within = Duration(d)
	}
	return nil
}

// Matches reports whether the rule applies to origin: it has no globs, or
// one of them matches.
func (r Retention) Matches(origin string) bool {
	if len(r.Origin) == 0 {
		return true
	}
	for _, g := range r.Origin {
		if ok, _ := path.Match(g, origin); ok {
			return true
		}
	}
	return false
}

// RetentionRule is the index of the first retention rule matching origin,
// -1 when none does.
func (s *Storage) RetentionRule(origin string) int {
	for i, r := range s.Retention {
		if r.Matches(origin) {
			return i
		}
	}
	return -1
}

// Watch is one watch rule of a storage: Origin and File hold globs
// (path.Match) on the origin and the file name of a series, none for any;
// the checks are those set: Every bounds the age of the newest copy,
// Size.Min and Size.Max its size, Size.Step the difference to the copy
// before it, and Same the number of newest copies with one sha256.
type Watch struct {
	Origin StringList `yaml:"origin"`
	File   StringList `yaml:"file"`
	Every  *Duration  `yaml:"every"`
	Size   WatchSize  `yaml:"size"`
	Same   *int       `yaml:"same"`
}

// WatchSize holds the size checks of a watch rule.
type WatchSize struct {
	Min  *Size `yaml:"min"`
	Max  *Size `yaml:"max"`
	Step *Size `yaml:"step"`
}

// Matches reports whether the rule applies to the series of origin and
// file: each glob list is empty or has a match.
func (w Watch) Matches(origin, file string) bool {
	return globsMatch(w.Origin, origin) && globsMatch(w.File, file)
}

func globsMatch(globs StringList, s string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, g := range globs {
		if ok, _ := path.Match(g, s); ok {
			return true
		}
	}
	return false
}

// WatchRule is the index of the first watch rule matching the series of
// origin and file, -1 when none does.
func (s *Storage) WatchRule(origin, file string) int {
	for i, w := range s.Watch {
		if w.Matches(origin, file) {
			return i
		}
	}
	return -1
}

type Random struct {
	Alphabet string `yaml:"alphabet"`
	Length   int    `yaml:"length"`
}

// Random names carry at least MinRandomBits bits and at most MaxRandomLength
// characters. RandomAlphabet (letters and digits without the look-alikes
// i, l, o, 0, 1) is the alphabet of a length without one, and of the default
// .Random with DefaultRandomLength characters.
const (
	MinRandomBits       = 128
	MaxRandomLength     = 128
	RandomAlphabet      = "aAbBcCdDeEfFgGhHjJkKmMnNpPqQrRsStTuUvVwWxXyYzZ23456789"
	DefaultRandomLength = 32
)

// check validates r and fills the default alphabet and length.
func (r *Random) check() error {
	if r.Alphabet == "" {
		r.Alphabet = RandomAlphabet
		if r.Length == 0 {
			r.Length = DefaultRandomLength
		}
	}
	if len(r.Alphabet) < 2 {
		return errors.New("alphabet needs at least 2 characters")
	}
	for i, c := range []byte(r.Alphabet) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '~' || c == '-') {
			return fmt.Errorf("alphabet character %q is not one of A-Z a-z 0-9 _ ~ -", c)
		}
		if strings.IndexByte(r.Alphabet[:i], c) >= 0 {
			return fmt.Errorf("alphabet character %q is repeated", c)
		}
	}
	bits := math.Log2(float64(len(r.Alphabet)))
	min := int(math.Ceil(MinRandomBits / bits))
	switch {
	case r.Length == 0:
		r.Length = min
	case r.Length < 0 || r.Length > MaxRandomLength:
		return fmt.Errorf("length must be 1 to %d", MaxRandomLength)
	case r.Length < min:
		return fmt.Errorf("length %d gives %.1f bits, under %d; the minimum length for this alphabet is %d", r.Length, float64(r.Length)*bits, MinRandomBits, min)
	}
	return nil
}

// DefaultLinksMax is links.max of a storage without one.
const DefaultLinksMax = 100

// MaxLinks is links.max, DefaultLinksMax when unset.
func (s *Storage) MaxLinks() int { return cmp.Or(s.Links.Max, DefaultLinksMax) }

// PathTemplate is the parsed Path of a local storage.
func (s *Storage) PathTemplate() *template.Template { return s.pathTmpl }

// Nested is the paths, relative to the expose (or protect) of the storage
// and ending with a slash, of the other exposes nested in it on a listener
// they share ("volatile/" for /volatile/ in /): the stored names under them
// would never be served, so they are reserved.
func (s *Storage) Nested() []string { return s.nested }

// Lifetime is the lifetime of an upload stored here for the client ttl
// (empty: none; else as wire.ParseTTL reads it) and what became of that
// ttl (wire.TTLCapped, wire.TTLRaised, wire.TTLIgnored, or empty when
// applied as asked or not given). With ttl.user the client ttl is clamped
// to min and max, and max is the lifetime without one and for
// wire.TTLMax; otherwise the lifetime is max. 0 never expires.
func (s *Storage) Lifetime(ttl string) (time.Duration, string) {
	hi, lo := time.Duration(s.TTL.Max), time.Duration(s.TTL.Min)
	client, max, err := wire.ParseTTL(ttl)
	switch {
	case ttl == "" || err != nil:
		return hi, ""
	case !s.TTL.User:
		return hi, wire.TTLIgnored
	case max:
		return hi, ""
	case hi > 0 && client > hi:
		return hi, wire.TTLCapped
	case lo > 0 && client < lo:
		return lo, wire.TTLRaised
	}
	return client, ""
}

type Expose struct {
	Listen StringList `yaml:"listen"`
	Path   string     `yaml:"path"`
	Auth   ExposeAuth `yaml:"auth"`
	// Plain states that the expose serves without authentication on
	// purpose: no auth, and no warning for a catalog or an index on it.
	Plain bool `yaml:"plain"`
	// Index answers the directory URLs of the expose with an HTML listing
	// of the files it serves; never with auth.ssh alone (the expose of a
	// storage with auth.ssh answers the signed listing instead). With
	// auth.basic and auth.ssh the unsigned requests get the HTML listing.
	Index bool `yaml:"index"`
	// MovedTTL and MovedCleanup catch the keys moved to the storage, so
	// the error names the new place.
	MovedTTL     any `yaml:"ttl"`
	MovedCleanup any `yaml:"cleanup"`
}

// ExposeAuth is the optional authentication of an expose: Basic (htpasswd
// bcrypt entries), SSH (signed luk-get@v1 requests) or both, where either
// suffices: a signed request is judged by SSH alone, an unsigned one by
// Basic.
type ExposeAuth struct {
	Basic []string `yaml:"basic"`
	SSH   *SSHAuth `yaml:"ssh"`
}

// SSHAuth makes an expose serve only signed luk-get@v1 requests, and only
// private files. Allow, with the syntax of an endpoint allow, is who may
// download the files every identity may (wire.AccessAny); the owner of a
// file only it may (wire.AccessPrivate) needs no entry.
type SSHAuth struct {
	Allow []string `yaml:"allow"`
}

func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	if err := lastDocument(dec); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// DecodeStrict decodes the one YAML document of data into v: unknown keys
// and a second document are errors. Empty data, or only comments, leaves v
// as it is.
func DecodeStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return lastDocument(dec)
}

// lastDocument checks that the document dec decoded was the last one;
// trailing comments and blank lines are not a document.
func lastDocument(dec *yaml.Decoder) error {
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return errors.New("more than one YAML document")
	case errors.Is(err, io.EOF):
		return nil
	default:
		return err
	}
}

func (c *Config) Validate() error { return errors.Join(c.validate()...) }

func (c *Config) validate() []error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	for name, e := range c.Endpoint {
		if e == nil {
			c.Endpoint[name] = &Endpoint{}
		}
	}
	for name, p := range c.Pipeline {
		if p == nil {
			c.Pipeline[name] = &Pipeline{}
		}
	}
	for name, s := range c.Storage {
		if s == nil {
			c.Storage[name] = &Storage{}
		}
	}
	for name, x := range c.Expose {
		if x == nil {
			c.Expose[name] = &Expose{}
		}
	}

	if c.Root == "" {
		c.Root = DefaultRoot
	}
	rootOK := filepath.IsAbs(c.Root)
	if !rootOK {
		bad("root: must be an absolute path")
	} else {
		c.Root = filepath.Clean(c.Root)
	}
	// resolve anchors a relative path at <root>/data and rejects one that
	// escapes it.
	data := c.DataDir()
	resolve := func(field, p string) string {
		if p == "" || filepath.IsAbs(p) || !rootOK {
			return p
		}
		full := filepath.Join(data, p)
		if rel, err := filepath.Rel(data, full); err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			bad("%s: %q escapes %s", field, p, data)
			return p
		}
		return full
	}

	c.validateListen(bad, resolve)

	if c.GPG.Keys != "" {
		if !filepath.IsAbs(c.GPG.Keys) {
			bad("gpg.keys: must be an absolute path")
		} else {
			c.GPG.Keys = filepath.Clean(c.GPG.Keys)
		}
	}
	switch c.Log.Level {
	case "", "debug", "info", "warn", "error":
	default:
		bad("log.level: %q is not debug, info, warn or error", c.Log.Level)
	}
	if c.GPG.WKD.Cache < 0 {
		bad("gpg.wkd.cache must be positive")
	}
	if c.GPG.WKD.Cache == 0 {
		c.GPG.WKD.Cache = Duration(DefaultWKDCache)
	}

	l := &c.Limits
	if l.Conn.Max < 0 {
		bad("limits.conn.max must be at least 1")
	}
	if l.Conn.Max == 0 {
		l.Conn.Max = DefaultConnMax
	}
	for _, d := range []struct {
		name string
		v    *Duration
		def  time.Duration
	}{
		{"limits.conn.idle", &l.Conn.Idle, DefaultConnIdle},
		{"limits.header.timeout", &l.Header.Timeout, DefaultHeaderTimeout},
		{"limits.channel.auth", &l.Channel.Auth, DefaultChannelAuth},
		{"limits.channel.idle", &l.Channel.Idle, DefaultChannelIdle},
	} {
		if *d.v < 0 {
			bad("%s must be positive", d.name)
		}
		if *d.v == 0 {
			*d.v = Duration(d.def)
		}
	}

	if l.Channel.Pending < 0 {
		bad("limits.channel.pending must be at least 1")
	}
	if l.Channel.Pending == 0 {
		l.Channel.Pending = DefaultChannelPending
	}
	for _, n := range []struct {
		name string
		v    *int
		def  int
	}{
		{"limits.uploads.total", &l.Uploads.Total, DefaultUploadsTotal},
		{"limits.uploads.identity", &l.Uploads.Identity, DefaultUploadsIdentity},
	} {
		if *n.v < 0 {
			bad("%s must be at least 1", n.name)
		}
		if *n.v == 0 {
			*n.v = n.def
		}
	}

	if l.Queue.Reserve < 0 {
		bad("limits.queue.reserve must not be negative")
	}
	if l.Queue.Reserve == 0 {
		l.Queue.Reserve = DefaultQueueReserve
	}
	if l.Failed.Age != nil && *l.Failed.Age < 0 {
		bad("limits.failed.age must not be negative")
	}

	if c.Auth.ClockSkew == 0 {
		c.Auth.ClockSkew = Duration(DefaultClockSkew)
	}
	if c.Auth.ClockSkew < 0 || c.Auth.ClockSkew > Duration(time.Hour) {
		bad("auth.clock_skew must be positive and at most 1h")
	}
	if c.Auth.Nonces == "" {
		c.Auth.Nonces = DefaultNonces
	}
	if !filepath.IsAbs(c.Auth.Nonces) {
		bad("auth.nonces must be an absolute path")
	}
	keyOwner := map[string]string{}
	names := map[string]bool{}
	for i := range c.Auth.Keys {
		k := &c.Auth.Keys[i]
		if k.Name == "" || k.Name == allowAll || strings.ContainsAny(k.Name, ":#") || names[k.Name] {
			bad("auth.keys[%d]: name %q empty, *, duplicated or contains ':' or '#'", i, k.Name)
		}
		names[k.Name] = true
		if k.File == "" {
			pub, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(k.Key))
			if err != nil {
				bad("auth.keys %s: %v", k.Name, err)
				continue
			}
			if len(opts) > 0 {
				bad("auth.keys %s: authorized_keys options are not supported", k.Name)
				continue
			}
			k.Parsed = []ssh.PublicKey{pub}
		}
		for _, pub := range k.Parsed {
			if err := sshsig.CheckKey(pub); err != nil {
				bad("auth.keys %s: %v", k.Name, err)
			}
			if other, ok := keyOwner[string(pub.Marshal())]; ok {
				bad("auth.keys %s: same key as %s", k.Name, other)
			}
			keyOwner[string(pub.Marshal())] = k.Name
		}
	}
	cas := map[string]bool{}
	caOwner := map[string]string{}
	for i := range c.Auth.CA {
		ca := &c.Auth.CA[i]
		if ca.Name == "" || ca.Name == allowAll || strings.ContainsAny(ca.Name, ":#") || names[ca.Name] || cas[ca.Name] {
			bad("auth.ca[%d]: name %q empty, *, duplicated or contains ':' or '#'", i, ca.Name)
		}
		cas[ca.Name] = true
		if ca.Type != "host" && ca.Type != "user" {
			bad("auth.ca %s: type must be host or user", ca.Name)
		}
		if ca.File == "" {
			if ca.Key == "" {
				bad("auth.ca %s: no key and no ssh.d/ca file of that name", ca.Name)
				continue
			}
			pub, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(ca.Key))
			if err != nil {
				bad("auth.ca %s: %v", ca.Name, err)
				continue
			}
			if len(opts) > 0 {
				bad("auth.ca %s: authorized_keys options are not supported", ca.Name)
				continue
			}
			ca.Parsed = []ssh.PublicKey{pub}
		}
		for _, pub := range ca.Parsed {
			if err := sshsig.CheckKey(pub); err != nil {
				bad("auth.ca %s: %v", ca.Name, err)
			}
			id := ca.Type + " " + string(pub.Marshal())
			if other, ok := caOwner[id]; ok {
				bad("auth.ca %s: same %s key as %s", ca.Name, ca.Type, other)
			}
			caOwner[id] = ca.Name
		}
	}
	// CA keys belong in auth.ca; one listed in ssh.d is a mistake.
	for _, k := range c.Auth.Keys {
		if k.File == "" {
			continue
		}
		for _, pub := range k.Parsed {
			for _, ca := range c.Auth.CA {
				for _, cp := range ca.Parsed {
					if bytes.Equal(pub.Marshal(), cp.Marshal()) {
						bad("auth.keys %s: the key of CA %s", k.Name, ca.Name)
					}
				}
			}
		}
	}

	for name, e := range c.Endpoint {
		e.Name = name
		if !strings.HasPrefix(e.Endpoint, "/") || (len(e.Endpoint) > 1 && strings.HasSuffix(e.Endpoint, "/")) {
			bad("endpoint %s: endpoint %q must be an absolute path without a trailing slash", name, e.Endpoint)
		}
		if wellKnown(e.Endpoint) {
			bad("endpoint %s: endpoint %q is under %s, which lukd reserves", name, e.Endpoint, wire.WellKnown)
		}
		c.checkListenRefs(bad, "endpoint "+name, e.Listen)
		if e.Path == "" {
			bad("endpoint %s: path is required", name)
		}
		e.Path = resolve("endpoint."+name+".path", e.Path)
		if len(e.Allow) == 0 {
			bad("endpoint %s: allow is empty", name)
		}
		checkAllow(bad, "endpoint "+name, e.Allow, names, cas)
		if e.Respond == "" {
			e.Respond = "accept"
		}
		switch e.Respond {
		case "accept":
		case "url":
			st, ok := c.Storage[e.Storage]
			if !ok {
				bad("endpoint %s: respond url needs a known storage", name)
			} else if st.Expose == "" {
				bad("endpoint %s: storage %s is not exposed", name, e.Storage)
			}
		default:
			bad("endpoint %s: respond must be accept or url", name)
		}
		bh := cmp.Or(e.Backup.Hostname, &BackupHostname{})
		for _, c := range []struct {
			key string
			who Identities
		}{
			{"link.remove", e.Link.Remove}, {"link.ttl", e.Link.TTL}, {"link.replace", e.Link.Replace}, {"link.list", e.Link.List},
			{"private.owner", e.Private.Owner}, {"private.any", e.Private.Any}, {"private.list", e.Private.List},
			{"backup.hostname.any", bh.Any}, {"backup.hostname.principal", bh.Principal},
		} {
			checkAllow(bad, "endpoint "+name+": "+c.key, c.who, names, cas)
		}
		if e.Link.Offered() && e.Respond != "url" {
			bad("endpoint %s: link needs respond url", name)
		}
		if e.Private.Offered() || len(e.Private.List) > 0 {
			key := "private"
			if !e.Private.Offered() {
				key = "private.list"
			}
			if e.Respond != "url" {
				bad("endpoint %s: %s needs respond url", name, key)
			} else if st, ok := c.Storage[e.Storage]; ok && st.Protect == "" {
				bad("endpoint %s: %s needs storage %s to have protect", name, key, e.Storage)
			}
		}
		if sc := e.Secret; sc != nil {
			if e.Respond != "url" {
				bad("endpoint %s: secret needs respond url", name)
			}
			if sc.Allow == nil {
				bad("endpoint %s: secret.allow is required: %s", name, identitiesHint)
			}
			checkAllow(bad, "endpoint "+name+": secret.allow", sc.Allow, names, cas)
			if sc.Path == "" {
				bad("endpoint %s: secret.path is required", name)
			}
			if sc.Reserve < 0 {
				bad("endpoint %s: secret.reserve must not be negative", name)
			}
			if sc.Reserve == 0 {
				sc.Reserve = DefaultSecretReserve
			}
			sc.Path = resolve("endpoint."+name+".secret.path", sc.Path)
			st, ok := c.Storage[sc.Storage]
			switch {
			case !ok:
				bad("endpoint %s: secret.storage %q is not a known storage", name, sc.Storage)
			case st.Type != "local":
				bad("endpoint %s: secret storage %s is not a local storage", name, sc.Storage)
			case st.Expose == "":
				bad("endpoint %s: secret storage %s is not exposed", name, sc.Storage)
			case sc.Storage == e.Storage:
				bad("endpoint %s: secret.storage must differ from storage", name)
			}
		}
		bl := &e.Limits.Body
		if bl.Size < 0 {
			bad("endpoint %s: limits.body.size must not be negative", name)
		}
		if bl.Idle < 0 {
			bad("endpoint %s: limits.body.idle must be positive", name)
		}
		if bl.Idle == 0 {
			bl.Idle = Duration(DefaultBodyIdle)
		}
		if bl.Rate == nil {
			r := Size(DefaultBodyRate)
			bl.Rate = &r
		} else if *bl.Rate < 0 {
			bad("endpoint %s: limits.body.rate must not be negative", name)
		}
		pt := &e.Parts
		switch {
		case pt.Size == 0:
			pt.Size = DefaultPartSize
		case pt.Size < MinPartSize || pt.Size > MaxPartSize || pt.Size%MinPartSize != 0:
			bad("endpoint %s: parts.size must be a multiple of 64KiB from 64KiB to 2GiB-64KiB", name)
		}
		switch {
		case pt.Parallel == 0:
			pt.Parallel = DefaultPartParallel
		case pt.Parallel < 1 || pt.Parallel > MaxPartParallel:
			bad("endpoint %s: parts.parallel must be 1 to %d", name, MaxPartParallel)
		}
		if e.Quota != nil {
			e.Quota.validate(bad, "endpoint "+name, names, cas, c.Auth.Keys)
		}
		if pr := e.Pretty; pr != nil {
			if pr.Allow == nil {
				bad("endpoint %s: pretty.allow is required: %s", name, identitiesHint)
			}
			checkAllow(bad, "endpoint "+name+": pretty.allow", pr.Allow, names, cas)
			switch {
			case pr.Bits == 0:
				pr.Bits = MinPrettyBits
			case pr.Bits < MinPrettyBits || pr.Bits > MaxPrettyBits:
				bad("endpoint %s: pretty.bits must be %d to %d", name, MinPrettyBits, MaxPrettyBits)
			default:
				pr.Bits = (pr.Bits + 15) / 16 * 16
			}
		}
	}

	for name, p := range c.Pipeline {
		p.Name = name
		if !ValidPipelineName(name) {
			bad("pipeline %q: the name must be of [A-Za-z0-9_.-], not starting with a dot or a dash", name)
		}
		if len(p.Endpoint) == 0 {
			bad("pipeline %s: endpoint is required", name)
		}
		if p.Claim && len(p.Tags) == 0 {
			bad("pipeline %s: claim needs tags", name)
		}
		for _, e := range p.Endpoint {
			if _, ok := c.Endpoint[e]; !ok {
				bad("pipeline %s: unknown endpoint %q", name, e)
			}
		}
		m := wire.Meta{Portal: wire.PortalDirect, Source: wire.SourceStdin, Tags: append([]string(nil), p.Tags...)}
		if err := m.Normalize(); err != nil {
			bad("pipeline %s: %v", name, err)
		} else {
			p.Tags = m.Tags
		}
		if p.MovedConcurrency != nil {
			bad("pipeline %s: concurrency moved to queue.concurrency", name)
		}
		if p.Queue.Concurrency == 0 {
			p.Queue.Concurrency = 1
		}
		if p.Timeout == 0 {
			p.Timeout = Duration(DefaultPipelineTimeout)
		}
		if p.Queue.Concurrency < 0 || p.Timeout < 0 {
			bad("pipeline %s: negative queue.concurrency or timeout", name)
		}
		if g := p.Queue.Group; g != "" && !ValidPipelineName(g) {
			bad("pipeline %s: queue.group %q: the name must be of [A-Za-z0-9_.-], not starting with a dot or a dash", name, g)
		}
		if p.Queue.Order < 0 {
			bad("pipeline %s: queue.order must not be negative", name)
		}
		if p.Queue.Order != 0 && p.Queue.Group == "" {
			bad("pipeline %s: queue.order needs queue.group", name)
		}
		if time.Duration(p.Timeout) >= MaxPipelineTimeout {
			bad("pipeline %s: timeout must be under %v (the work directory cleanup age)", name, MaxPipelineTimeout)
		}
		if len(p.Steps) == 0 {
			bad("pipeline %s: no steps", name)
		}
		for i, s := range p.Steps {
			kinds := 0
			for _, set := range []bool{s.Run.Set(), len(s.Store) > 0, s.Encrypt != nil, s.Relay != ""} {
				if set {
					kinds++
				}
			}
			if kinds != 1 {
				bad("pipeline %s: step %d needs exactly one of run, store, encrypt or relay", name, i+1)
			}
			if s.Encrypt != nil {
				c.validateEncrypt(bad, fmt.Sprintf("pipeline %s: step %d: encrypt", name, i+1), s.Encrypt)
			}
			switch {
			case s.Run.invalid, s.Run.Program != "" && !filepath.IsAbs(s.Run.Program):
				bad("pipeline %s: step %d: run must be an absolute path or {job: NAME}", name, i+1)
			case s.Run.Job != "":
				if !ValidJobName(s.Run.Job) {
					bad("pipeline %s: step %d: run.job %q: invalid job name", name, i+1, s.Run.Job)
				}
				if s.Tee || len(s.Env) > 0 || len(s.Jobs) > 0 {
					bad("pipeline %s: step %d: run job takes no tee, env or jobs", name, i+1)
				}
			}
			if s.Relay != "" {
				if !ValidJobName(s.Relay) {
					bad("pipeline %s: step %d: relay %q: invalid job name", name, i+1, s.Relay)
				}
				if s.Tee || len(s.Env) > 0 {
					bad("pipeline %s: step %d: relay takes no tee or env", name, i+1)
				}
			} else if s.Tee && !s.Run.Set() {
				bad("pipeline %s: step %d: tee needs run", name, i+1)
			}
			if len(s.Jobs) > 0 && !s.Run.Set() {
				bad("pipeline %s: step %d: jobs needs run", name, i+1)
			}
			for j, job := range s.Jobs {
				switch {
				case !ValidJobName(job):
					bad("pipeline %s: step %d: jobs: %q: invalid job name", name, i+1, job)
				case slices.Contains(s.Jobs[:j], job):
					bad("pipeline %s: step %d: jobs: %s listed twice", name, i+1, job)
				}
			}
			for _, k := range sortedKeys(s.Env) {
				if strings.HasPrefix(k, "LUK_") {
					bad("pipeline %s: step %d: env.%s: LUK_* names are reserved", name, i+1, k)
				}
			}
			for _, st := range s.Store {
				if sc, ok := c.Storage[st]; !ok {
					bad("pipeline %s: step %d: unknown storage %q", name, i+1, st)
				} else if sc != nil && sc.Type == "s3" {
					bad("pipeline %s: step %d: storage %s: s3 storage is not implemented yet", name, i+1, st)
				}
			}
		}
		// A replace publishes all its stores or none (see the dispatcher):
		// tractable only for pipelines of store steps.
		for _, en := range p.Endpoint {
			if e := c.Endpoint[en]; e == nil || len(e.Link.Replace) == 0 {
				continue
			}
			for i, s := range p.Steps {
				if len(s.Store) == 0 {
					what := "run"
					switch {
					case s.Encrypt != nil:
						what = "encrypt"
					case s.Relay != "":
						what = "relay"
					}
					bad("endpoint %s: link.replace needs pipelines of store steps only: pipeline %s step %d is %s", en, name, i+1, what)
				}
			}
		}
	}

	for name, s := range c.Storage {
		switch s.Type {
		case "local":
			if s.Base == "" {
				bad("storage %s: base is required", name)
			}
			s.Base = resolve("storage."+name+".base", s.Base)
			if s.Path == "" {
				bad("storage %s: path is required", name)
			} else if t, err := template.New(name).Option("missingkey=error").Parse(s.Path); err != nil {
				bad("storage %s: path: %v", name, err)
			} else if err := t.Execute(io.Discard, pathVars); err != nil {
				bad("storage %s: path: %v", name, err)
			} else {
				s.pathTmpl = t
			}
		case "s3":
			if s.Bucket == "" {
				bad("storage %s: bucket is required", name)
			}
		default:
			bad("storage %s: type must be local or s3", name)
		}
		switch s.Conflict {
		case "":
			s.Conflict = "version"
		case "version", "reject", "replace":
		default:
			bad("storage %s: conflict must be version, reject or replace", name)
		}
		if _, ok := c.Expose[s.Expose]; s.Expose != "" && !ok {
			bad("storage %s: unknown expose %q", name, s.Expose)
		}
		if s.Expose != "" && s.Type != "local" {
			bad("storage %s: only a local storage can be exposed", name)
		}
		if x, ok := c.Expose[s.Expose]; ok && x.Index && s.Shard > 0 {
			bad("storage %s: shard on expose %s with index; index needs a storage without shard", name, s.Expose)
		}
		if s.Protect != "" {
			x, ok := c.Expose[s.Protect]
			switch {
			case s.Type != "local":
				bad("storage %s: protect needs a local storage", name)
			case !ok:
				bad("storage %s: unknown protect expose %q", name, s.Protect)
			case x.Auth.SSH == nil:
				bad("storage %s: protect expose %s needs auth.ssh", name, s.Protect)
			case len(x.Auth.Basic) > 0:
				bad("expose %s: auth.basic on a protect expose (storage %s): a password names no owner of private files", s.Protect, name)
			case s.Protect == s.Expose:
				bad("storage %s: expose and protect must differ", name)
			}
		}
		if s.Catalog && s.Type != "local" {
			bad("storage %s: catalog needs a local storage", name)
		}
		if s.Hardlink != nil && s.Type != "local" {
			bad("storage %s: hardlink needs a local storage", name)
		}
		if s.Links.Max < 0 {
			bad("storage %s: links.max must be at least 1", name)
		} else if s.Links.Max != 0 && s.Type != "local" {
			bad("storage %s: links.max needs a local storage", name)
		}
		if s.Shard < 0 || s.Shard > 4 {
			bad("storage %s: shard must be 0 to 4", name)
		} else if s.Shard != 0 && s.Type != "local" {
			bad("storage %s: shard needs a local storage", name)
		}
		if s.TTL.Max < 0 {
			bad("storage %s: ttl.max must be positive", name)
		}
		if s.TTL.Min < 0 {
			bad("storage %s: ttl.min must be positive", name)
		}
		if s.TTL.Min != 0 && !s.TTL.User {
			bad("storage %s: ttl.min needs ttl.user", name)
		}
		if s.TTL.Min > 0 && s.TTL.Max > 0 && s.TTL.Min > s.TTL.Max {
			bad("storage %s: ttl.min must not exceed ttl.max", name)
		}
		if s.Cleanup.Age < 0 {
			bad("storage %s: cleanup.age must be positive", name)
		}
		if (s.TTL.Max != 0 || s.TTL.Min != 0 || s.TTL.User || s.Cleanup.Age != 0) && s.Type != "local" {
			bad("storage %s: ttl and cleanup.age need a local storage", name)
		}
		if len(s.Retention) > 0 && s.Type != "local" {
			bad("storage %s: retention needs a local storage", name)
		}
		if len(s.Retention) > 0 && s.Conflict == "replace" {
			bad("storage %s: retention needs conflict version or reject, not replace", name)
		}
		for i, r := range s.Retention {
			for _, g := range r.Origin {
				if g == "" {
					bad("storage %s: retention rule %d: empty origin glob", name, i+1)
				} else if _, err := path.Match(g, ""); err != nil {
					bad("storage %s: retention rule %d: origin %q: %v", name, i+1, g, err)
				}
			}
			k := r.Keep
			switch {
			case k.Last < 0 || k.Daily < 0 || k.Weekly < 0 || k.Monthly < 0 || k.Yearly < 0:
				bad("storage %s: retention rule %d: keep counts must not be negative", name, i+1)
			case k.Within < 0:
				bad("storage %s: retention rule %d: keep.within must not be negative", name, i+1)
			case k == Keep{}:
				bad("storage %s: retention rule %d: keep needs a count above 0 (last, daily, weekly, monthly, yearly) or within", name, i+1)
			}
			if len(r.Origin) == 0 && i < len(s.Retention)-1 {
				bad("storage %s: retention rule %d matches every origin and must be the last: the rules after it are unreachable", name, i+1)
			}
		}
		if len(s.Watch) > 0 && s.Type != "local" {
			bad("storage %s: watch needs a local storage", name)
		}
		for i, w := range s.Watch {
			for _, l := range []struct {
				key   string
				globs StringList
			}{{"origin", w.Origin}, {"file", w.File}} {
				for _, g := range l.globs {
					if g == "" {
						bad("storage %s: watch rule %d: empty %s glob", name, i+1, l.key)
					} else if _, err := path.Match(g, ""); err != nil {
						bad("storage %s: watch rule %d: %s %q: %v", name, i+1, l.key, g, err)
					}
				}
			}
			if w.Every != nil && *w.Every <= 0 {
				bad("storage %s: watch rule %d: every must be above 0", name, i+1)
			}
			for _, z := range []struct {
				key string
				v   *Size
			}{{"min", w.Size.Min}, {"max", w.Size.Max}, {"step", w.Size.Step}} {
				if z.v != nil && *z.v <= 0 {
					bad("storage %s: watch rule %d: size.%s must be above 0", name, i+1, z.key)
				}
			}
			if w.Size.Min != nil && w.Size.Max != nil && *w.Size.Min > *w.Size.Max {
				bad("storage %s: watch rule %d: size.min must not exceed size.max", name, i+1)
			}
			if w.Same != nil && *w.Same < 2 {
				bad("storage %s: watch rule %d: same must be at least 2", name, i+1)
			}
			if w.Every == nil && w.Size == (WatchSize{}) && w.Same == nil {
				bad("storage %s: watch rule %d: needs a check (every, size.min, size.max, size.step, same)", name, i+1)
			}
			if len(w.Origin) == 0 && len(w.File) == 0 && i < len(s.Watch)-1 {
				bad("storage %s: watch rule %d matches every series and must be the last: the rules after it are unreachable", name, i+1)
			}
		}
		if s.Random != (Random{}) {
			if s.Type != "local" {
				bad("storage %s: random needs a local storage", name)
			}
			if err := s.Random.check(); err != nil {
				bad("storage %s: random: %v", name, err)
			}
		}
	}

	// The 201 URL must point at a storage a pipeline of the endpoint writes.
	for _, en := range sortedKeys(c.Endpoint) {
		e := c.Endpoint[en]
		if e.Respond != "url" || c.Storage[e.Storage] == nil {
			continue
		}
		written := false
		for _, p := range c.Pipeline {
			if !slices.Contains(p.Endpoint, en) {
				continue
			}
			for _, st := range p.Steps {
				written = written || slices.Contains(st.Store, e.Storage)
			}
		}
		if !written {
			bad("endpoint %s: no pipeline of it stores to storage %s", en, e.Storage)
		}
	}

	// A pretty URL replaces .Random, so it needs a URL that uses it.
	for _, en := range sortedKeys(c.Endpoint) {
		e := c.Endpoint[en]
		if e.Pretty == nil {
			continue
		}
		if e.Respond != "url" {
			bad("endpoint %s: pretty needs respond url", en)
		} else if st := c.Storage[e.Storage]; st != nil && st.pathTmpl != nil && !usesRandom(st.pathTmpl) {
			bad("endpoint %s: pretty needs a path of storage %s that uses .Random", en, e.Storage)
		}
		if sc := e.Secret; sc != nil {
			if st := c.Storage[sc.Storage]; st != nil && st.pathTmpl != nil && !usesRandom(st.pathTmpl) {
				bad("endpoint %s: pretty needs a path of secret storage %s that uses .Random", en, sc.Storage)
			}
		}
	}

	// A local base is owned by one storage; queues live outside every base.
	for i, a := range sortedKeys(c.Storage) {
		sa := c.Storage[a]
		if sa.Type != "local" || !filepath.IsAbs(sa.Base) {
			continue
		}
		for _, b := range sortedKeys(c.Storage)[i+1:] {
			if sb := c.Storage[b]; sb.Type == "local" && nested(sa.Base, sb.Base) {
				bad("storage %s and %s: bases %s and %s overlap", a, b, sa.Base, sb.Base)
			}
		}
		for _, e := range sortedKeys(c.Endpoint) {
			if p := c.Endpoint[e].Path; filepath.IsAbs(p) && nested(p, sa.Base) {
				bad("endpoint %s: path %s overlaps storage %s base %s", e, p, a, sa.Base)
			}
		}
		if w := c.WorkDir(); w != "" && nested(w, sa.Base) {
			bad("storage %s: base %s overlaps the work directory %s", a, sa.Base, w)
		}
	}
	for _, e := range sortedKeys(c.Endpoint) {
		if p, w := c.Endpoint[e].Path, c.WorkDir(); w != "" && filepath.IsAbs(p) && nested(p, w) {
			bad("endpoint %s: path %s overlaps the work directory %s", e, p, w)
		}
	}
	c.checkSecretPaths(bad)
	c.checkQueuePaths(bad)
	c.checkRootPart(bad)

	owner := map[string]string{}
	for _, name := range sortedKeys(c.Storage) {
		for _, e := range []string{c.Storage[name].Expose, c.Storage[name].Protect} {
			if e == "" {
				continue
			}
			if other, ok := owner[e]; ok && other != name {
				bad("expose %s: used by storages %s and %s", e, other, name)
			}
			owner[e] = name
		}
	}

	for name, x := range c.Expose {
		c.checkListenRefs(bad, "expose "+name, x.Listen)
		if !strings.HasPrefix(x.Path, "/") || !strings.HasSuffix(x.Path, "/") || path.Clean(x.Path)+"/" != x.Path && x.Path != "/" {
			bad("expose %s: path %q must be absolute and end with a slash", name, x.Path)
		}
		if wellKnown(x.Path) {
			bad("expose %s: path %q is under %s, which lukd reserves", name, x.Path, wire.WellKnown)
		}
		if x.MovedTTL != nil || x.MovedCleanup != nil {
			n, _, ok := c.StorageOfExpose(name)
			if !ok {
				n = "<n>"
			}
			if x.MovedTTL != nil {
				bad("expose %s: ttl moved to storage.%s.ttl.max", name, n)
			}
			if x.MovedCleanup != nil {
				bad("expose %s: cleanup moved to storage.%s.cleanup.age", name, n)
			}
		}
		if x.Plain && (x.Auth.SSH != nil || len(x.Auth.Basic) > 0) {
			bad("expose %s: plain excludes auth", name)
		}
		if x.Index && x.Auth.SSH != nil && len(x.Auth.Basic) == 0 {
			bad("expose %s: index excludes auth.ssh alone: an auth.ssh expose serves only signed GETs (and the signed listing)", name)
		}
		if ssh := x.Auth.SSH; ssh != nil {
			checkAllow(bad, "expose "+name+": auth.ssh", ssh.Allow, names, cas)
			if _, _, ok := c.StorageServedBy(name); ok && len(x.Listen) > 0 {
				if l := c.Listen[x.Listen[0]]; l != nil && !strings.HasPrefix(l.Public, "https://") {
					bad("expose %s: listen %s (first of the expose) needs an https public URL: the files of an auth.ssh expose have luk:// URLs, which mean https", name, x.Listen[0])
				}
			}
		}
		for _, b := range x.Auth.Basic {
			user, hash, ok := strings.Cut(b, ":")
			if !ok {
				bad("expose %s: basic entry must be user:hash", name)
				continue
			}
			if _, err := bcrypt.Cost([]byte(BcryptHash(hash))); err != nil {
				bad("expose %s: basic %s: not a bcrypt hash: %v", name, user, err)
			}
		}
	}
	for _, en := range sortedKeys(c.Endpoint) {
		e := c.Endpoint[en]
		if e.Respond != "url" {
			continue
		}
		storages := []string{e.Storage}
		if e.Secret != nil {
			storages = append(storages, e.Secret.Storage)
		}
		for _, sn := range storages {
			st := c.Storage[sn]
			if st == nil {
				continue
			}
			x := c.Expose[st.Expose]
			if x == nil || len(x.Listen) == 0 {
				continue
			}
			if l := c.Listen[x.Listen[0]]; l != nil && l.Public == "" {
				bad("endpoint %s: listen %s (first of expose %s) has no public URL; set public or host", en, x.Listen[0], st.Expose)
			}
		}
	}
	c.checkPaths(bad)
	c.nestExposes()
	c.validatePermanent(bad, names, cas)
	c.validateACME(bad)
	return errs
}

// validatePermanent checks the permanent blocks of the endpoints and
// records them in their respond storages (see Storage.Permanents).
func (c *Config) validatePermanent(bad func(string, ...any), names, cas map[string]bool) {
	for _, st := range c.Storage {
		st.permanent = nil
	}
	for _, en := range sortedKeys(c.Endpoint) {
		e := c.Endpoint[en]
		p := e.Permanent
		if p == nil {
			continue
		}
		if p.Path == "" {
			p.Path = DefaultPermanentPath
		}
		if err := wire.CheckPermanentName(p.Path); err != nil || IsPattern(p.Path) {
			bad("endpoint %s: permanent.path %q must be a clean relative name without wildcards", en, p.Path)
		}
		if len(p.Names) == 0 {
			bad("endpoint %s: permanent.names is empty", en)
		}
		for _, k := range sortedKeys(p.Names) {
			ne := p.Names[k]
			if ne == nil {
				ne = &PermanentName{}
				p.Names[k] = ne
			}
			what := fmt.Sprintf("endpoint %s: permanent.names %q", en, k)
			if err := checkPermanentKey(k); err != nil {
				bad("%s: %v", what, err)
			}
			if ne.Allow == nil {
				bad("%s: allow is required: %s", what, identitiesHint)
			}
			checkAllow(bad, what+": allow", ne.Allow, names, cas)
			switch {
			case ne.Max != nil && !IsPattern(k):
				bad("%s: max applies to patterns only", what)
			case ne.Max != nil && *ne.Max < 1:
				bad("%s: max must be at least 1", what)
			}
		}
		if e.Respond != "url" {
			bad("endpoint %s: permanent needs respond url", en)
			continue
		}
		st := c.Storage[e.Storage]
		if st == nil {
			continue
		}
		x := c.Expose[st.Expose]
		switch {
		case st.Type != "local":
			bad("endpoint %s: permanent needs a local storage, not %s", en, e.Storage)
			continue
		case x == nil:
			bad("endpoint %s: permanent needs storage %s to have an expose", en, e.Storage)
			continue
		case x.Auth.SSH != nil:
			bad("endpoint %s: permanent needs an expose without auth.ssh (storage %s, expose %s)", en, e.Storage, st.Expose)
			continue
		}
		pre := p.Path + "/"
		for _, n := range st.nested {
			if strings.HasPrefix(pre, n) || strings.HasPrefix(n, pre) {
				bad("endpoint %s: permanent.path %s overlaps the nested expose under %s of expose %s", en, p.Path, n, st.Expose)
			}
		}
		if st.Catalog && (p.Path == CatalogName || strings.HasPrefix(p.Path, CatalogName+"/")) {
			bad("endpoint %s: permanent.path %s overlaps the catalog of storage %s", en, p.Path, e.Storage)
		}
		for _, on := range sortedKeys(st.permanent) {
			o := st.permanent[on]
			switch {
			case o.Path == p.Path:
				bad("endpoint %s and %s: the same permanent.path %s on storage %s", on, en, p.Path, e.Storage)
			case strings.HasPrefix(pre, o.Path+"/") || strings.HasPrefix(o.Path+"/", pre):
				bad("endpoint %s and %s: permanent.path %s and %s nest on storage %s", on, en, o.Path, p.Path, e.Storage)
			}
		}
		if st.permanent == nil {
			st.permanent = map[string]*Permanent{}
		}
		st.permanent[en] = p
	}
}

// CatalogName is the top-level name a storage with catalog serves its
// catalog under (store.CatalogName).
const CatalogName = "catalog.json"

// checkPermanentKey checks a key of permanent.names: an exact name is a
// clean relative name (wire.CheckPermanentName); a pattern is valid for
// path.Match and each of its elements is non-empty, not . or .. and free
// of control characters.
func checkPermanentKey(k string) error {
	if !IsPattern(k) {
		return wire.CheckPermanentName(k)
	}
	if _, err := path.Match(k, ""); err != nil {
		return fmt.Errorf("bad pattern: %v", err)
	}
	if len(k) > wire.MaxPermanentName || wire.HasControl(k) || strings.HasPrefix(k, "/") {
		return errors.New("bad pattern: too long, absolute or with a control character")
	}
	for _, el := range strings.Split(k, "/") {
		if el == "" || el == "." || el == ".." {
			return fmt.Errorf("bad pattern: element %q is not a name", el)
		}
	}
	return nil
}

// PermanentOverlap reports whether two keys of permanent.names may cover
// the same name: two equal keys, an exact name a pattern matches, or two
// patterns of as many elements whose elements pair up as equal, as a
// literal element the other matches, with a bare * on either side, or as
// two patterns of which one matches the shortest name of the other (see
// elementsMeet). It is a guess for a warning: two patterns can meet
// otherwise (a*b and *ab*), and a class makes it assume they do.
func PermanentOverlap(a, b string) bool {
	if a == b {
		return true
	}
	pa, pb := IsPattern(a), IsPattern(b)
	switch {
	case !pa && !pb:
		return false
	case pa && !pb:
		m, _ := path.Match(a, b)
		return m
	case !pa && pb:
		m, _ := path.Match(b, a)
		return m
	}
	ea, eb := strings.Split(a, "/"), strings.Split(b, "/")
	if len(ea) != len(eb) {
		return false
	}
	for i := range ea {
		x, y := ea[i], eb[i]
		if x == y || x == "*" || y == "*" {
			continue
		}
		if !IsPattern(x) {
			if m, _ := path.Match(y, x); m {
				continue
			}
		}
		if !IsPattern(y) {
			if m, _ := path.Match(x, y); m {
				continue
			}
		}
		if IsPattern(x) && IsPattern(y) && elementsMeet(x, y) {
			continue
		}
		return false
	}
	return true
}

// elementsMeet guesses whether two pattern elements match a common name:
// a pattern with a class or an escape may; otherwise each is tried on the
// shortest name of the other (its * dropped, its ? an a).
func elementsMeet(x, y string) bool {
	if strings.ContainsAny(x, `[\`) || strings.ContainsAny(y, `[\`) {
		return true
	}
	shortest := func(p string) string { return strings.ReplaceAll(strings.ReplaceAll(p, "*", ""), "?", "a") }
	mx, _ := path.Match(x, shortest(y))
	my, _ := path.Match(y, shortest(x))
	return mx || my
}

// checkQueuePaths keeps every queue directory (endpoint path,
// secret.path) apart from the directories and files lukd keeps itself, and
// endpoint paths apart from each other unless equal: the start of the
// receive role removes what it takes for half-received entries from every
// queue directory.
func (c *Config) checkQueuePaths(bad func(string, ...any)) {
	own := map[string]string{}
	if filepath.IsAbs(c.Root) {
		own[filepath.Join(c.DataDir(), "acme")] = "the ACME cache"
		own[c.GPGCacheDir()] = "the WKD key cache"
	}
	if filepath.IsAbs(c.Auth.Nonces) {
		own[filepath.Clean(c.Auth.Nonces)] = "auth.nonces"
	}
	type queueDir struct{ what, path string }
	var qs []queueDir
	for _, en := range sortedKeys(c.Endpoint) {
		e := c.Endpoint[en]
		if filepath.IsAbs(e.Path) {
			qs = append(qs, queueDir{"endpoint " + en + ": path", e.Path})
		}
		if sc := e.Secret; sc != nil && filepath.IsAbs(sc.Path) {
			qs = append(qs, queueDir{"endpoint " + en + ": secret.path", sc.Path})
		}
	}
	for _, q := range qs {
		for _, d := range sortedKeys(own) {
			if nested(q.path, d) {
				bad("%s %s overlaps %s %s", q.what, q.path, own[d], d)
			}
		}
		for _, ln := range sortedKeys(c.Listen) {
			t := c.Listen[ln].TLS
			if t == nil {
				continue
			}
			for _, f := range []string{t.Cert, t.Key} {
				if filepath.IsAbs(f) && filepath.Clean(f) != filepath.Clean(q.path) && nested(f, q.path) {
					bad("%s %s holds the TLS file %s of listener %s", q.what, q.path, f, ln)
				}
			}
		}
	}
	names := sortedKeys(c.Endpoint)
	for i, a := range names {
		pa := c.Endpoint[a].Path
		if !filepath.IsAbs(pa) {
			continue
		}
		for _, b := range names[i+1:] {
			if pb := c.Endpoint[b].Path; filepath.IsAbs(pb) && filepath.Clean(pa) != filepath.Clean(pb) && nested(pa, pb) {
				bad("endpoint %s and %s: paths %s and %s nest", a, b, pa, pb)
			}
		}
	}
}

// checkRootPart keeps every configured path out of <root>/root, the part
// of the root that is root's.
func (c *Config) checkRootPart(bad func(string, ...any)) {
	dir := c.RootDir()
	if dir == "" {
		return
	}
	paths := map[string]string{"auth.nonces": c.Auth.Nonces, "gpg.keys": c.GPG.Keys}
	for n, e := range c.Endpoint {
		paths["endpoint."+n+".path"] = e.Path
		if e.Secret != nil {
			paths["endpoint."+n+".secret.path"] = e.Secret.Path
		}
	}
	for n, s := range c.Storage {
		paths["storage."+n+".base"] = s.Base
	}
	for n, l := range c.Listen {
		if l.TLS != nil {
			paths["listen."+n+".tls.cert"] = l.TLS.Cert
			paths["listen."+n+".tls.key"] = l.TLS.Key
			paths["listen."+n+".tls.eab.key_file"] = l.TLS.EAB.KeyFile
		}
	}
	for _, k := range sortedKeys(paths) {
		p := paths[k]
		if !filepath.IsAbs(p) {
			continue
		}
		if p := filepath.Clean(p); p == dir || strings.HasPrefix(p, dir+"/") {
			bad("%s: %s lies in %s", k, p, dir)
		}
	}
}

// checkSecretPaths keeps every secret queue a queue of its own: outside
// every local base, the queue of every endpoint, the other secret queues
// (an equal one is shared) and the work directory.
func (c *Config) checkSecretPaths(bad func(string, ...any)) {
	for i, en := range sortedKeys(c.Endpoint) {
		sc := c.Endpoint[en].Secret
		if sc == nil || !filepath.IsAbs(sc.Path) {
			continue
		}
		for _, sn := range sortedKeys(c.Storage) {
			if st := c.Storage[sn]; st.Type == "local" && filepath.IsAbs(st.Base) && nested(sc.Path, st.Base) {
				bad("endpoint %s: secret.path %s overlaps storage %s base %s", en, sc.Path, sn, st.Base)
			}
		}
		for _, on := range sortedKeys(c.Endpoint) {
			if p := c.Endpoint[on].Path; filepath.IsAbs(p) && nested(sc.Path, p) {
				bad("endpoint %s: secret.path %s overlaps the queue %s of endpoint %s", en, sc.Path, p, on)
			}
		}
		for _, on := range sortedKeys(c.Endpoint)[i+1:] {
			if o := c.Endpoint[on].Secret; o != nil && filepath.IsAbs(o.Path) && filepath.Clean(o.Path) != filepath.Clean(sc.Path) && nested(sc.Path, o.Path) {
				bad("endpoint %s: secret.path %s overlaps secret.path %s of endpoint %s", en, sc.Path, o.Path, on)
			}
		}
		if w := c.WorkDir(); w != "" && nested(sc.Path, w) {
			bad("endpoint %s: secret.path %s overlaps the work directory %s", en, sc.Path, w)
		}
	}
}

// nestExposes records in every storage the paths of the exposes nested in
// its expose and protect on a listener they share (see Storage.Nested).
func (c *Config) nestExposes() {
	for _, sn := range sortedKeys(c.Storage) {
		st := c.Storage[sn]
		st.nested = nil
		for _, xn := range []string{st.Expose, st.Protect} {
			x := c.Expose[xn]
			if x == nil {
				continue
			}
			for _, on := range sortedKeys(c.Expose) {
				o := c.Expose[on]
				rel, ok := strings.CutPrefix(o.Path, x.Path)
				if on == xn || !ok || rel == "" || !slices.ContainsFunc(o.Listen, func(l string) bool { return slices.Contains(x.Listen, l) }) {
					continue
				}
				if !slices.Contains(st.nested, rel) {
					st.nested = append(st.nested, rel)
				}
			}
		}
		sort.Strings(st.nested)
	}
}

// allowAll admits every identity in an allow list (auth.AllowAll).
const allowAll = "*"

// checkAllow validates an allow list: key names, "<ca>:<glob>" (over the
// principals) or "<ca>#<glob>" (over the Key ID) of known CAs, or
// allowAll.
func checkAllow(bad func(string, ...any), who string, allow []string, names, cas map[string]bool) {
	for _, a := range allow {
		ca, glob, isCA := a, "", false
		if i := strings.IndexAny(a, ":#"); i >= 0 {
			ca, glob, isCA = a[:i], a[i+1:], true
		}
		switch {
		case a == allowAll:
		case !isCA && !names[a]:
			bad("%s: allow %q is not a known key", who, a)
		case isCA && !cas[ca]:
			bad("%s: allow %q names an unknown CA", who, a)
		case isCA:
			if _, err := path.Match(glob, "x"); err != nil || glob == "" {
				bad("%s: allow %q has a bad pattern", who, a)
			}
		}
	}
}

// validate checks a quota and sets its defaults: the mode, and the burst
// of each rate. A plain key that matches more than one class with members
// is an error; for certificates that is decided per request.
func (q *Quota) validate(bad func(string, ...any), who string, names, cas map[string]bool, keys []Key) {
	who += ": quota"
	switch q.Mode {
	case "":
		q.Mode = QuotaEnforce
	case QuotaEnforce, QuotaPassive:
	default:
		bad("%s: mode %q is not enforce or passive", who, q.Mode)
	}
	if q.Rate == nil && q.Burst != 0 {
		bad("%s: burst needs rate", who)
	}
	if q.Rate == nil && len(q.Class) == 0 {
		bad("%s: needs rate or class", who)
	}
	if q.Burst < 0 {
		bad("%s: burst must be positive", who)
	}
	if q.Rate != nil && q.Burst == 0 {
		q.Burst = Size(q.Rate.Size)
	}
	seen := map[string]bool{}
	catchAll := ""
	for i := range q.Class {
		cl := &q.Class[i]
		if cl.Name == "" || seen[cl.Name] {
			bad("%s: class[%d]: name %q empty or duplicated", who, i, cl.Name)
		}
		seen[cl.Name] = true
		cw := who + ": class " + cl.Name
		if cl.Rate == nil {
			bad("%s: rate is required", cw)
		} else if cl.Burst == 0 {
			cl.Burst = Size(cl.Rate.Size)
		}
		if cl.Burst < 0 {
			bad("%s: burst must be positive", cw)
		}
		if len(cl.Members) == 0 {
			switch {
			case catchAll != "":
				bad("%s: classes %s and %s both have no members; one catch-all only", who, catchAll, cl.Name)
			case q.Rate != nil:
				bad("%s: class %s has no members and rate is set at the top; one catch-all only", who, cl.Name)
			}
			catchAll = cl.Name
			continue
		}
		checkAllow(bad, cw+": members", cl.Members, names, cas)
	}
	for _, k := range keys {
		var in []string
		for _, cl := range q.Class {
			if slices.Contains(cl.Members, k.Name) || slices.Contains(cl.Members, allowAll) {
				in = append(in, cl.Name)
			}
		}
		if len(in) > 1 {
			bad("%s: key %s matches classes %s; a plain key may be in one class only", who, k.Name, strings.Join(in, ", "))
		}
	}
}

// validateEncrypt checks and lowercases the recipient addresses.
func (c *Config) validateEncrypt(bad func(string, ...any), who string, e *Encrypt) {
	if len(e.WKD)+len(e.Key) == 0 {
		bad("%s: no recipient (wkd or key)", who)
	}
	if len(e.Key) > 0 && c.GPG.Keys == "" {
		bad("%s: key recipients need gpg.keys", who)
	}
	seen := map[string]string{}
	for _, l := range []struct {
		name string
		list StringList
	}{{"wkd", e.WKD}, {"key", e.Key}} {
		for i, a := range l.list {
			addr := strings.ToLower(a)
			l.list[i] = addr
			if !validAddress(a) {
				bad("%s: %s %q is not a plain e-mail address", who, l.name, a)
				continue
			}
			if other, ok := seen[addr]; ok {
				bad("%s: %s is listed twice (%s and %s)", who, addr, other, l.name)
			}
			seen[addr] = l.name
		}
	}
	if in := e.Insecure; in != nil {
		validateInsecure(bad, who+": insecure", in)
	}
}

func validateInsecure(bad func(string, ...any), who string, in *Insecure) {
	if len(in.Symmetric) == 0 && in.OpenSSL == nil {
		bad("%s: needs symmetric or openssl", who)
	}
	seen := map[string]bool{}
	for _, n := range in.Symmetric {
		if !ValidPasswordName(n) {
			bad("%s: symmetric %q: invalid password name", who, n)
		} else if seen[n] {
			bad("%s: symmetric %s is listed twice", who, n)
		}
		seen[n] = true
	}
	o := in.OpenSSL
	if o == nil {
		return
	}
	switch {
	case o.Key == "":
		bad("%s: openssl needs key", who)
	case !ValidPasswordName(o.Key):
		bad("%s: openssl key %q: invalid password name", who, o.Key)
	}
	if len(o.Files) == 0 {
		bad("%s: openssl needs files", who)
	}
	for _, g := range o.Files {
		// A file name of the set never holds a slash.
		if _, err := path.Match(g, ""); g == "" || err != nil || strings.Contains(g, "/") {
			bad("%s: openssl files %q: invalid glob", who, g)
		}
	}
}

// PasswordNames lists the passwords the encrypt steps name, sorted, each
// once.
func (c *Config) PasswordNames() []string {
	seen := map[string]bool{}
	for _, p := range c.Pipeline {
		for _, s := range p.Steps {
			if s.Encrypt == nil || s.Encrypt.Insecure == nil {
				continue
			}
			in := s.Encrypt.Insecure
			for _, n := range in.Symmetric {
				seen[n] = true
			}
			if in.OpenSSL != nil {
				seen[in.OpenSSL.Key] = true
			}
		}
	}
	return sortedKeys(seen)
}

// OpenSSLPasswordNames lists the passwords used for the openssl format.
func (c *Config) OpenSSLPasswordNames() map[string]bool {
	seen := map[string]bool{}
	for _, p := range c.Pipeline {
		for _, s := range p.Steps {
			if s.Encrypt != nil && s.Encrypt.Insecure != nil && s.Encrypt.Insecure.OpenSSL != nil {
				seen[s.Encrypt.Insecure.OpenSSL.Key] = true
			}
		}
	}
	return seen
}

// validAddress accepts a bare local@domain address that is safe as a file
// name.
func validAddress(a string) bool {
	m, err := mail.ParseAddress(a)
	if err != nil || m.Name != "" || m.Address != a || strings.ContainsAny(a, "/\\\"<>()[],;: \t") || strings.HasPrefix(a, ".") {
		return false
	}
	local, domain, ok := strings.Cut(a, "@")
	return ok && local != "" && domain != "" && !strings.Contains(domain, "@")
}

// GPGCacheDir holds the keys fetched through WKD; empty without an
// absolute root.
func (c *Config) GPGCacheDir() string {
	if !filepath.IsAbs(c.Root) {
		return ""
	}
	return filepath.Join(c.DataDir(), "gpg-cache")
}

// BcryptHash rewrites an htpasswd $2y$ hash to the $2a$ form Go reads.
func BcryptHash(h string) string {
	if strings.HasPrefix(h, "$2y$") {
		return "$2a$" + h[4:]
	}
	return h
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for n := range m {
		k = append(k, n)
	}
	sort.Strings(k)
	return k
}

// ExposeOf returns the expose of a storage.
func (c *Config) ExposeOf(storage string) (*Expose, bool) {
	s, ok := c.Storage[storage]
	if !ok || s.Expose == "" {
		return nil, false
	}
	x, ok := c.Expose[s.Expose]
	return x, ok
}

// StorageOfExpose returns the storage exposed under the given expose name.
func (c *Config) StorageOfExpose(expose string) (string, *Storage, bool) {
	for _, n := range sortedKeys(c.Storage) {
		if c.Storage[n].Expose == expose {
			return n, c.Storage[n], true
		}
	}
	return "", nil, false
}

// StorageOfProtect returns the storage whose private files the expose
// serves (storage protect).
func (c *Config) StorageOfProtect(expose string) (string, *Storage, bool) {
	for _, n := range sortedKeys(c.Storage) {
		if c.Storage[n].Protect == expose {
			return n, c.Storage[n], true
		}
	}
	return "", nil, false
}

// StorageServedBy returns the storage the expose serves, as its expose
// or as its protect.
func (c *Config) StorageServedBy(expose string) (string, *Storage, bool) {
	if n, st, ok := c.StorageOfExpose(expose); ok {
		return n, st, true
	}
	return c.StorageOfProtect(expose)
}

var pathVars = map[string]string{"Sender": "", "Endpoint": "", "Year": "", "Month": "", "Day": "", "Hour": "", "Minute": "", "Seconds": "", "Id": "", "Random": "", "File": "", "Tags": "", "Hostname": "", "Origin": ""}

// usesRandom reports whether the output of t depends on .Random.
func usesRandom(t *template.Template) bool {
	var a, b strings.Builder
	v := maps.Clone(pathVars)
	_ = t.Execute(&a, v)
	v["Random"] = "r"
	_ = t.Execute(&b, v)
	return a.String() != b.String()
}

var (
	uniqueName = regexp.MustCompile(`\.(Random|Id)\b`)
	fileName   = regexp.MustCompile(`\.File\b`)
	jobName    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	// pipelineName fits a pipeline name into the work directory path,
	// the state directory and lock file of lukd run and the dynamic user.
	pipelineName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
)

// maxJobName caps the name of a job of lukd run.
const maxJobName = 64

// maxPipelineName caps a pipeline name, a directory name of its work
// directories and, for lukd run, of state directories and lock files.
const maxPipelineName = 128

// ValidJobName reports whether n may name a job of lukd run (the base name
// of its file in run.d) and so the job of a relay step.
func ValidJobName(n string) bool { return len(n) <= maxJobName && jobName.MatchString(n) }

// ValidPipelineName reports whether n may name a pipeline: [A-Za-z0-9_.-],
// not starting with a dot or a dash, at most maxPipelineName bytes. lukd
// run refuses a work directory of any other pipeline name.
func ValidPipelineName(n string) bool {
	return len(n) <= maxPipelineName && pipelineName.MatchString(n)
}

// ValidPasswordName reports whether n may name a password: the file of it
// in password.d follows the name rule of a job file in run.d.
func ValidPasswordName(n string) bool { return ValidJobName(n) }

// Warnings lists valid but suspicious settings.
func (c *Config) Warnings() []string {
	var w []string
	for _, n := range sortedKeys(c.Listen) {
		if l := c.Listen[n]; l.ACME {
			if _, port, _ := net.SplitHostPort(l.Addr); port != "80" {
				w = append(w, fmt.Sprintf("listen %s: acme: true on port %s; the CA checks HTTP-01 on port 80, which must reach it", n, port))
			}
		}
	}
	used := map[string]bool{}
	for _, p := range c.Pipeline {
		for _, e := range p.Endpoint {
			used[e] = true
		}
	}
	urlStorage := map[string]bool{}
	for _, n := range sortedKeys(c.Endpoint) {
		e := c.Endpoint[n]
		if !used[n] {
			w = append(w, fmt.Sprintf("endpoint %s: no pipeline uses it", n))
		}
		if e.Respond == "url" {
			urlStorage[e.Storage] = true
			if e.Secret != nil {
				urlStorage[e.Secret.Storage] = true
			}
		}
	}
	for _, n := range sortedKeys(c.Storage) {
		s := c.Storage[n]
		if urlStorage[n] && s.Type == "local" && s.Conflict == "version" && !uniqueName.MatchString(s.Path) {
			w = append(w, fmt.Sprintf("storage %s: conflict version with a path using neither .Random nor .Id; the answered URL may not match the stored name", n))
		}
		if x, ok := c.Expose[s.Expose]; ok && s.Catalog && len(x.Auth.Basic) == 0 && x.Auth.SSH == nil && !x.Plain {
			w = append(w, fmt.Sprintf("storage %s: catalog on expose %s without auth publishes every stored name", n, s.Expose))
		}
	}
	for _, n := range sortedKeys(c.Endpoint) {
		p := c.Endpoint[n].Permanent
		if p == nil {
			continue
		}
		keys := sortedKeys(p.Names)
		for i, a := range keys {
			for _, b := range keys[i+1:] {
				if IsPattern(a) && IsPattern(b) && literals(a) == literals(b) && PermanentOverlap(a, b) {
					w = append(w, fmt.Sprintf("endpoint %s: permanent.names %q and %q may cover the same names with as many literal characters; %q, which sorts first, takes them", n, a, b, a))
				}
			}
		}
	}
	for _, n := range sortedKeys(c.Expose) {
		if x := c.Expose[n]; x.Index && x.Auth.SSH == nil && len(x.Auth.Basic) == 0 && !x.Plain {
			w = append(w, fmt.Sprintf("expose %s: index without auth lists every stored name", n))
		}
	}
	for _, pn := range sortedKeys(c.Pipeline) {
		p := c.Pipeline[pn]
		run, renamed, warned := false, "", map[string]bool{}
		for _, st := range p.Steps {
			if st.Run.Set() || st.Relay != "" {
				// A tee or relay step passes its set on unchanged.
				if st.Run.Set() && !st.Tee {
					run, renamed = true, "a run"
				}
				continue
			}
			if st.Encrypt != nil {
				if renamed == "" {
					renamed = "an encrypt"
				}
				continue
			}
			for _, sn := range st.Store {
				s := c.Storage[sn]
				if renamed == "" || warned[sn] || s == nil {
					continue
				}
				warned[sn] = true
				for _, en := range p.Endpoint {
					if e := c.Endpoint[en]; e != nil && e.Respond == "url" && e.Storage == sn {
						w = append(w, fmt.Sprintf("endpoint %s: pipeline %s has %s step before storing to %s; the answered URL will not match the produced names", en, pn, renamed, sn))
					}
				}
				if run && s.Type == "local" && !fileName.MatchString(s.Path) {
					w = append(w, fmt.Sprintf("pipeline %s: storage %s after a run step with a path without .File; files of one set collide", pn, sn))
				}
			}
		}
	}
	return w
}

// DataDir is <root>/data; empty without an absolute root.
func (c *Config) DataDir() string {
	if !filepath.IsAbs(c.Root) {
		return ""
	}
	return filepath.Join(c.Root, DataName)
}

// RootDir is <root>/root, root's part of the root; empty without an
// absolute root.
func (c *Config) RootDir() string {
	if !filepath.IsAbs(c.Root) {
		return ""
	}
	return filepath.Join(c.Root, RootName)
}

// WorkDir holds the run step work directories; empty without an absolute root.
func (c *Config) WorkDir() string {
	if !filepath.IsAbs(c.Root) {
		return ""
	}
	return filepath.Join(c.DataDir(), "work")
}

// nested reports whether one of the paths is equal to or inside the other.
func nested(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	in := func(x, y string) bool {
		return x == y || strings.HasPrefix(x, strings.TrimSuffix(y, "/")+"/")
	}
	return in(a, b) || in(b, a)
}

func (c *Config) validateListen(bad func(string, ...any), resolve func(string, string) string) {
	if len(c.Listen) == 0 {
		bad("listen: at least one listener")
	}
	for _, name := range sortedKeys(c.Listen) {
		l := c.Listen[name]
		if l == nil {
			l = &Listen{}
			c.Listen[name] = l
		}
		l.Name = name
		if _, _, err := net.SplitHostPort(l.Addr); err != nil {
			bad("listen %s: addr %q must be host:port", name, l.Addr)
		}
		seen := map[string]bool{}
		for i, h := range l.Host {
			h = strings.ToLower(h)
			l.Host[i] = h
			if h == "" || strings.ContainsAny(h, ":/ ") || seen[h] {
				bad("listen %s: host %q empty, duplicated or not a plain host name", name, h)
			}
			seen[h] = true
		}
		if t := l.TLS; t != nil && t.Mode == "acme" {
			c.validateACMEListen(bad, resolve, l)
		} else if t != nil {
			switch t.Mode {
			case "self":
				switch t.Algorithm {
				case "":
					t.Algorithm = "ed25519"
				case "ed25519", "ecdsa-p256":
				default:
					bad("listen %s: tls.algorithm %q must be ed25519 or ecdsa-p256", name, t.Algorithm)
				}
			case "files":
				if t.Algorithm != "" {
					bad("listen %s: tls.algorithm applies to mode self only", name)
				}
			default:
				bad("listen %s: tls mode %q must be self, files or acme", name, t.Mode)
			}
			if t.Email != "" || t.Directory != "" || t.EAB.Set() {
				bad("listen %s: tls email, directory and eab apply to mode acme only", name)
			}
			t.Cert = resolve("listen."+name+".tls.cert", t.Cert)
			t.Key = resolve("listen."+name+".tls.key", t.Key)
			if t.Cert == "" || t.Key == "" || (t.Host == "" && t.Mode == "self") {
				if t.Mode == "files" {
					bad("listen %s: tls mode files needs cert and key", name)
				} else {
					bad("listen %s: tls needs cert, key and host", name)
				}
			} else if filepath.Clean(t.Cert) == filepath.Clean(t.Key) {
				bad("listen %s: tls cert and key must be different files", name)
			}
		}
		if l.ACME && l.TLS != nil {
			bad("listen %s: acme: true is a plain HTTP listener and cannot have tls", name)
		}
		if l.Public == "" {
			l.Public = defaultPublic(l)
		} else if u, err := url.Parse(l.Public); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			bad("listen %s: public %q must be an http(s) URL without a path", name, l.Public)
		} else {
			l.Public = u.Scheme + "://" + u.Host
		}
	}
	for _, group := range c.Addrs() {
		ls := group.Listen
		if len(ls) < 2 {
			continue
		}
		owner := map[string]string{}
		certs := map[string]string{}
		for _, l := range ls {
			if len(l.Host) == 0 {
				bad("listen %s: host is required when several listeners share %s", l.Name, group.Addr)
			}
			for _, h := range l.Host {
				if other, ok := owner[h]; ok {
					bad("listen %s and %s: host %s on the same address %s", other, l.Name, h, group.Addr)
				}
				owner[h] = l.Name
			}
			if (l.TLS == nil) != (ls[0].TLS == nil) {
				bad("listen %s: address %s mixes tls and plain listeners", l.Name, group.Addr)
			}
			if l.TLS != nil && l.TLS.Cert != "" {
				if other, ok := certs[filepath.Clean(l.TLS.Cert)]; ok {
					bad("listen %s and %s: listeners sharing %s need their own tls.cert", other, l.Name, group.Addr)
				}
				certs[filepath.Clean(l.TLS.Cert)] = l.Name
			}
		}
	}
}

// validateACMEListen checks a tls mode acme listener: names a public CA
// can issue for, no certificate files, an https directory and a complete
// external account binding, whose key_file it reads.
func (c *Config) validateACMEListen(bad func(string, ...any), resolve func(string, string) string, l *Listen) {
	t, name := l.TLS, l.Name
	if t.Cert != "" || t.Key != "" || t.Host != "" || t.Algorithm != "" {
		bad("listen %s: tls cert, key, host and algorithm do not apply to mode acme", name)
	}
	if len(l.Host) == 0 {
		bad("listen %s: tls mode acme needs host, the names of the certificates", name)
	}
	for _, h := range l.Host {
		if strings.Contains(h, "*") || net.ParseIP(h) != nil || !strings.Contains(strings.Trim(h, "."), ".") {
			bad("listen %s: host %q: tls mode acme needs plain DNS names (no wildcard, no IP)", name, h)
		}
	}
	if t.Email != "" {
		if a, err := mail.ParseAddress(t.Email); err != nil || a.Address != t.Email {
			bad("listen %s: tls.email %q is not a plain address", name, t.Email)
		}
	}
	if t.Directory == "" {
		t.Directory = DefaultACMEDirectory
	} else if u, err := url.Parse(t.Directory); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		bad("listen %s: tls.directory %q must be an https URL", name, t.Directory)
	}
	e := &t.EAB
	if !e.Set() {
		return
	}
	if e.KID == "" {
		bad("listen %s: tls.eab needs kid", name)
	}
	switch {
	case (e.Key == "") == (e.KeyFile == ""):
		bad("listen %s: tls.eab needs exactly one of key and key_file", name)
		return
	case e.KeyFile != "":
		e.KeyFile = resolve("listen."+name+".tls.eab.key_file", e.KeyFile)
		data, err := os.ReadFile(e.KeyFile)
		if err != nil {
			bad("listen %s: tls.eab.key_file: %v", name, err)
			return
		}
		e.Key = strings.TrimSpace(string(data))
	}
	if mac, err := e.MAC(); err != nil || len(mac) == 0 {
		bad("listen %s: tls.eab key is not base64url (or base64)", name)
		return
	}
	sum := sha256.Sum256([]byte(e.Key))
	e.KeySum = hex.EncodeToString(sum[:])
}

// validateACME ties the acme listeners together: HTTP-01 needs a plain
// acme: true listener, which carries nothing else, and listeners of one
// directory share its account, so they agree on email and eab.
func (c *Config) validateACME(bad func(string, ...any)) {
	var acme, http []string
	byDir := map[string]*Listen{}
	for _, n := range sortedKeys(c.Listen) {
		l := c.Listen[n]
		if l.ACME {
			http = append(http, n)
		}
		if l.TLS == nil || l.TLS.Mode != "acme" {
			continue
		}
		acme = append(acme, n)
		if o, ok := byDir[l.TLS.Directory]; !ok {
			byDir[l.TLS.Directory] = l
		} else if o.TLS.Email != l.TLS.Email || o.TLS.EAB.KID != l.TLS.EAB.KID || o.TLS.EAB.Key != l.TLS.EAB.Key {
			bad("listen %s and %s: acme listeners of %s share an account and need the same email and eab", o.Name, n, l.TLS.Directory)
		}
	}
	for _, n := range acme {
		if len(http) == 0 {
			bad("listen %s: tls mode acme needs a plain listener with acme: true for HTTP-01 (port 80)", n)
		}
	}
	for _, n := range http {
		if len(acme) == 0 {
			bad("listen %s: acme: true without a tls mode acme listener", n)
		}
	}
	for _, n := range http {
		for _, en := range sortedKeys(c.Endpoint) {
			if slices.Contains(c.Endpoint[en].Listen, n) {
				bad("endpoint %s: listen %s has acme: true and serves only ACME challenges and redirects", en, n)
			}
		}
		for _, xn := range sortedKeys(c.Expose) {
			if slices.Contains(c.Expose[xn].Listen, n) {
				bad("expose %s: listen %s has acme: true and serves only ACME challenges and redirects", xn, n)
			}
		}
	}
}

// ACMECacheDir is the autocert cache of an ACME directory: account key,
// certificates and challenge state, one directory per directory URL so
// staging and production never mix.
func (c *Config) ACMECacheDir(directory string) string {
	if !filepath.IsAbs(c.Root) {
		return ""
	}
	slug := directory
	if u, err := url.Parse(directory); err == nil && u.Host != "" {
		slug = u.Host + u.Path
	}
	slug = strings.Trim(nonSlug.ReplaceAllString(slug, "_"), "_.")
	return filepath.Join(c.DataDir(), "acme", slug)
}

var nonSlug = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// defaultPublic is https://<first host or tls.host>[:port] (http:// without
// tls), the port omitted when it is the scheme default; empty when no host
// name is known and the address is unspecified.
func defaultPublic(l *Listen) string {
	h, port, err := net.SplitHostPort(l.Addr)
	if err != nil {
		return ""
	}
	scheme, def := "http", "80"
	if l.TLS != nil {
		scheme, def = "https", "443"
	}
	host := h
	switch {
	case len(l.Host) > 0:
		host = l.Host[0]
	case l.TLS != nil && l.TLS.Host != "":
		host = l.TLS.Host
	case h == "":
		return ""
	default:
		if ip := net.ParseIP(h); ip != nil && ip.IsUnspecified() {
			return ""
		}
	}
	if port == def {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		return scheme + "://" + host
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

func (c *Config) checkListenRefs(bad func(string, ...any), who string, names StringList) {
	if len(names) == 0 {
		bad("%s: listen is required", who)
	}
	seen := map[string]bool{}
	for _, n := range names {
		if _, ok := c.Listen[n]; !ok {
			bad("%s: unknown listen %q", who, n)
		}
		if seen[n] {
			bad("%s: listen %s named twice", who, n)
		}
		seen[n] = true
	}
}

// wellKnown reports whether the request path p is wire.WellKnown or under
// it (the endpoint listing, ACME HTTP-01).
func wellKnown(p string) bool {
	p = path.Clean("/" + p)
	return p == wire.WellKnown || strings.HasPrefix(p, wire.WellKnown+"/")
}

// checkPaths rejects, per listener, an endpoint path used twice and paths
// of endpoints and exposes that overlap (routing is by path alone).
func (c *Config) checkPaths(bad func(string, ...any)) {
	for _, ln := range sortedKeys(c.Listen) {
		var eps, xs []string
		for _, n := range sortedKeys(c.Endpoint) {
			if slices.Contains(c.Endpoint[n].Listen, ln) {
				eps = append(eps, n)
			}
		}
		for _, n := range sortedKeys(c.Expose) {
			if slices.Contains(c.Expose[n].Listen, ln) {
				xs = append(xs, n)
			}
		}
		for i, a := range eps {
			for _, b := range eps[i+1:] {
				if c.Endpoint[a].Endpoint == c.Endpoint[b].Endpoint {
					bad("endpoint %s and %s: path %s used twice on listen %s", a, b, c.Endpoint[a].Endpoint, ln)
				}
			}
		}
		for _, xn := range xs {
			p := c.Expose[xn].Path
			for _, en := range eps {
				ep := c.Endpoint[en].Endpoint
				if strings.HasPrefix(ep+"/", p) || strings.HasPrefix(p, ep+"/") {
					bad("expose %s: path %s overlaps endpoint %s (%s) on listen %s", xn, p, en, ep, ln)
				}
			}
		}
		// Nested exposes route by the longest path; one path names one
		// expose.
		for i, a := range xs {
			for _, b := range xs[i+1:] {
				if p := c.Expose[a].Path; p == c.Expose[b].Path {
					bad("expose %s and %s: path %s used twice on listen %s", a, b, p, ln)
				}
			}
		}
	}
}

// AddrGroup is the listeners sharing one address, sorted by name.
type AddrGroup struct {
	Addr   string
	Listen []*Listen
}

// Addrs groups the listeners by address, in the order of the first
// listener name of each address.
func (c *Config) Addrs() []AddrGroup {
	var out []AddrGroup
	idx := map[string]int{}
	for _, n := range sortedKeys(c.Listen) {
		l := c.Listen[n]
		if l == nil {
			continue
		}
		i, ok := idx[l.Addr]
		if !ok {
			i = len(out)
			idx[l.Addr] = i
			out = append(out, AddrGroup{Addr: l.Addr})
		}
		out[i].Listen = append(out[i].Listen, l)
	}
	return out
}

// ListenNames returns the listener names, sorted.
func (c *Config) ListenNames() []string { return sortedKeys(c.Listen) }

// ExposeURL is the public of the first listener of the expose followed by
// its path.
func (c *Config) ExposeURL(expose string) (string, bool) {
	x, ok := c.Expose[expose]
	if !ok || len(x.Listen) == 0 {
		return "", false
	}
	l, ok := c.Listen[x.Listen[0]]
	if !ok || l.Public == "" {
		return "", false
	}
	return l.Public + x.Path, true
}

// ProtectURL is the base of the URLs of the private files of a storage:
// the URL of its protect expose (ExposeURL) with the scheme luk, and the
// first listener of that expose, whose certificate a luk:// URL may pin.
func (c *Config) ProtectURL(storage string) (string, *Listen, bool) {
	st, ok := c.Storage[storage]
	if !ok || st.Protect == "" {
		return "", nil, false
	}
	return c.signedURL(st.Protect)
}

// PublicURL is the base of the URLs of the public files of a storage: the
// URL of its expose (ExposeURL); for an expose with auth.ssh that URL with
// the scheme luk and the first listener of the expose (as ProtectURL),
// with auth.basic too that https URL and the first listener (a browser
// opens it, luk get signs it), else no listener.
func (c *Config) PublicURL(storage string) (string, *Listen, bool) {
	st, ok := c.Storage[storage]
	if !ok || st.Expose == "" {
		return "", nil, false
	}
	if x := c.Expose[st.Expose]; x != nil && x.Auth.SSH != nil {
		base, l, ok := c.signedURL(st.Expose)
		if ok && len(x.Auth.Basic) > 0 {
			base = "https://" + strings.TrimPrefix(base, wire.SchemeLuk+"://")
		}
		return base, l, ok
	}
	base, ok := c.ExposeURL(st.Expose)
	return base, nil, ok
}

// signedURL is the luk:// base of an expose with an https public URL and
// its first listener.
func (c *Config) signedURL(expose string) (string, *Listen, bool) {
	base, ok := c.ExposeURL(expose)
	rest, https := strings.CutPrefix(base, "https://")
	if !ok || !https {
		return "", nil, false
	}
	return wire.SchemeLuk + "://" + rest, c.Listen[c.Expose[expose].Listen[0]], true
}

// Restart is the part of a configuration a running lukd cannot change:
// root, everything under listen, the connection limits bound to the
// listeners and their http.Server (limits.conn.*, limits.header.timeout)
// and the nonce cache directory (auth.nonces). A role keeps the one it
// runs with in its running file for lukd check.
type Restart struct {
	Root   string             `json:"root"`
	Listen map[string]*Listen `json:"listen"`
	Conn   ConnLimits         `json:"conn"`
	Header HeaderLimits       `json:"header"`
	Nonces string             `json:"nonces,omitempty"`
}

// Restart returns the restart-only settings of c.
func (c *Config) Restart() Restart {
	return Restart{Root: c.Root, Listen: c.Listen, Conn: c.Limits.Conn, Header: c.Limits.Header, Nonces: c.Auth.Nonces}
}

// Changes names every restart-only setting that differs between r and
// next, in a stable order: what a running lukd refuses to reload. Empty
// when none differs.
func (r Restart) Changes(next Restart) []string {
	var out []string
	if r.Root != next.Root {
		out = append(out, "root")
	}
	names := sortedKeys(r.Listen)
	for _, n := range sortedKeys(next.Listen) {
		if _, ok := r.Listen[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		a, b := r.Listen[n], next.Listen[n]
		if a == nil || b == nil {
			out = append(out, "listen."+n)
			continue
		}
		if a.Addr != b.Addr {
			out = append(out, "listen."+n+".addr")
		}
		if !slices.Equal(a.Host, b.Host) {
			out = append(out, "listen."+n+".host")
		}
		if a.Public != b.Public {
			out = append(out, "listen."+n+".public")
		}
		if a.ACME != b.ACME {
			out = append(out, "listen."+n+".acme")
		}
		if (a.TLS == nil) != (b.TLS == nil) || a.TLS != nil && !sameTLS(a.TLS, b.TLS) {
			out = append(out, "listen."+n+".tls")
		}
	}
	if r.Conn.Max != next.Conn.Max {
		out = append(out, "limits.conn.max")
	}
	if r.Conn.Idle != next.Conn.Idle {
		out = append(out, "limits.conn.idle")
	}
	if r.Header.Timeout != next.Header.Timeout {
		out = append(out, "limits.header.timeout")
	}
	// A running file without it predates the setting.
	if r.Nonces != "" && r.Nonces != next.Nonces {
		out = append(out, "auth.nonces")
	}
	return out
}
