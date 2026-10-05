// Package status keeps the status directory <root>/status: the liveness
// file of each role (see Alive) and process/status.json, the last
// pipeline result per (pipeline, sender) and the evaluation of the watch
// rules of the storages. For the pipelines lukd reports facts only; their
// thresholds live in the monitoring check that reads the file. The watch
// rules hold their thresholds in the lukd configuration.
package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"

	"luk/internal/queue"
	"luk/internal/wire"
)

// MaxError caps the stored error text.
const MaxError = 4 << 10

const (
	tmpPattern = ".status.json.tmp-*"
	maxAside   = 2
)

var (
	rename  = os.Rename
	syncDir = (*os.File).Sync
)

// Path is the status file under root, written by the process role.
func Path(root string) string { return filepath.Join(RoleDir(root, "process"), "status.json") }

type Entry struct {
	Pipeline     string   `json:"pipeline"`
	Sender       string   `json:"sender"`
	Tags         []string `json:"tags"`
	LastID       string   `json:"last_id"`
	LastReceived string   `json:"last_received"`
	// LastAccepted and LastAcceptedSeq are the acceptance order of the
	// last upload (see queue.Accepted); 0 for one recorded before them.
	LastAccepted    int64  `json:"last_accepted,omitempty"`
	LastAcceptedSeq int    `json:"last_accepted_seq,omitempty"`
	LastSuccess     string `json:"last_success,omitempty"`
	LastFailure     string `json:"last_failure,omitempty"`
	FailedStep      int    `json:"failed_step"`
	Error           string `json:"error,omitempty"`
	Size            int64  `json:"size"`
	Failed          int    `json:"failed"`
	// OlderSkipped counts the uploads a store step skipped because the
	// stored file was accepted after them (conflict replace): with a sound
	// clock only uploads that overlapped; a growing count points at an
	// acceptance order gone wrong.
	OlderSkipped int `json:"older_skipped"`
}

// Watch is the evaluation of one series a watch rule of a storage applies
// to, or of a rule no series matches (Pipeline, Origin and File empty).
// State is OK, WARN or CRIT; Message names every failed check.
type Watch struct {
	Storage        string `json:"storage"`
	Rule           int    `json:"rule"`
	Pipeline       string `json:"pipeline"`
	Origin         string `json:"origin"`
	File           string `json:"file"`
	State          string `json:"state"`
	Message        string `json:"message"`
	NewestReceived string `json:"newest_received,omitempty"`
	Size           int64  `json:"size"`
	Copies         int    `json:"copies"`
	Evaluated      string `json:"evaluated"`
}

// file is the content of status.json.
type file struct {
	Pipelines []Entry `json:"pipelines"`
	Watch     []Watch `json:"watch"`
}

// Result is one finished pipeline run; a non-empty Error marks a failure
// at Step.
type Result struct {
	Pipeline, Sender, ID, Received string
	// Accepted is the acceptance order of the upload; zero when unknown.
	Accepted queue.Acceptance
	Tags     []string
	Size     int64
	Step     int
	Error    string
}

// Key identifies an entry.
type Key struct{ Pipeline, Sender string }

type Store struct {
	path string
	now  func() time.Time

	mu      sync.Mutex
	entries map[Key]Entry
	watch   []Watch
	// dirty marks entries the file does not hold yet: the last write failed.
	dirty bool
}

// New returns an empty store writing to path.
func New(path string) *Store {
	return &Store{path: path, now: time.Now, entries: map[Key]Entry{}}
}

// Open loads path; a missing file gives an empty store. A file that is not
// valid JSON is renamed to status.json.corrupt-<UTC time> (the newest
// maxAside are kept), its new name is returned and the store starts empty.
// Any other read error is returned. Leftover temporary files are removed.
func Open(path string) (*Store, string, error) {
	dir := filepath.Dir(path)
	if tmps, err := filepath.Glob(filepath.Join(dir, tmpPattern)); err == nil {
		for _, t := range tmps {
			os.Remove(t)
		}
	}
	s := New(path)
	es, err := read(path)
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	if errors.As(err, &syn) || errors.As(err, &typ) {
		aside := path + ".corrupt-" + s.now().UTC().Format("20060102T150405.000000000Z")
		if rerr := os.Rename(path, aside); rerr != nil {
			return nil, "", rerr
		}
		pruneAside(path)
		return s, aside, nil
	}
	if err != nil {
		return nil, "", err
	}
	for _, e := range es.Pipelines {
		s.entries[Key{e.Pipeline, e.Sender}] = e
	}
	s.watch = es.Watch
	return s, "", nil
}

func pruneAside(path string) {
	ms, err := filepath.Glob(path + ".corrupt-*")
	if err != nil || len(ms) <= maxAside {
		return
	}
	sort.Strings(ms)
	for _, m := range ms[:len(ms)-maxAside] {
		os.Remove(m)
	}
}

// read loads path: an object with pipelines and watch, or the array of
// pipeline entries an older lukd wrote.
func read(path string) (file, error) {
	f := file{Pipelines: []Entry{}, Watch: []Watch{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if t := bytes.TrimLeft(b, " \t\r\n"); len(t) > 0 && t[0] == '[' {
		err = json.Unmarshal(b, &f.Pipelines)
	} else {
		err = json.Unmarshal(b, &f)
	}
	if err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	if f.Pipelines == nil {
		f.Pipelines = []Entry{}
	}
	if f.Watch == nil {
		f.Watch = []Watch{}
	}
	return f, nil
}

// Record updates the entry of r and rewrites the file atomically. A failure
// keeps last_success; a success keeps the last failure fields.
func (s *Store) Record(r Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := Key{r.Pipeline, r.Sender}
	e, seen := s.entries[k]
	e.Pipeline, e.Sender = r.Pipeline, r.Sender
	if !seen || !olderThan(r, e) {
		e.LastID, e.LastReceived, e.Size = r.ID, r.Received, r.Size
		e.LastAccepted, e.LastAcceptedSeq = r.Accepted.NS, r.Accepted.Seq
		e.Tags = append([]string{}, r.Tags...)
	}
	now := s.now().UTC().Format(time.RFC3339)
	if r.Error == "" {
		e.LastSuccess = now
	} else {
		e.LastFailure, e.FailedStep, e.Error = now, r.Step, CapError(r.Error)
	}
	s.entries[k] = e
	return s.persist()
}

// olderThan reports whether the upload of r came before the last one of
// e: by acceptance order when both have one, else by received time.
func olderThan(r Result, e Entry) bool {
	if r.Accepted.NS != 0 && e.LastAccepted != 0 {
		return r.Accepted.Compare(queue.Acceptance{NS: e.LastAccepted, Seq: e.LastAcceptedSeq}) < 0
	}
	return older(r.Received, e.LastReceived)
}

// older reports whether received a is before b; unparsable times are not.
func older(a, b string) bool {
	ta, err := time.Parse(time.RFC3339, a)
	if err != nil {
		return false
	}
	tb, err := time.Parse(time.RFC3339, b)
	return err == nil && ta.Before(tb)
}

// SkippedOlder counts an upload of the key skipped as older than the
// stored file and rewrites the file.
func (s *Store) SkippedOlder(k Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[k]
	if !ok {
		e = Entry{Pipeline: k.Pipeline, Sender: k.Sender, Tags: []string{}}
	}
	e.OlderSkipped++
	s.entries[k] = e
	return s.persist()
}

// SetFailed sets the failed count of every entry from counts (absent keys
// count 0), adding an entry for a key it does not have yet, and rewrites the
// file when a count changed or an earlier write failed.
func (s *Store) SetFailed(counts map[Key]int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for k, e := range s.entries {
		if n := counts[k]; e.Failed != n {
			e.Failed = n
			s.entries[k] = e
			changed = true
		}
	}
	for k, n := range counts {
		if _, ok := s.entries[k]; !ok && n > 0 {
			s.entries[k] = Entry{Pipeline: k.Pipeline, Sender: k.Sender, Tags: []string{}, Failed: n}
			changed = true
		}
	}
	if !changed && !s.dirty {
		return nil
	}
	return s.persist()
}

// SetWatch replaces the watch evaluations and rewrites the file when they
// changed or an earlier write failed.
func (s *Store) SetWatch(ws []Watch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Equal(s.watch, ws) && !s.dirty {
		return nil
	}
	s.watch = slices.Clone(ws)
	return s.persist()
}

// Watch returns the watch evaluations.
func (s *Store) Watch() []Watch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.watch)
}

// CapError keeps the last MaxError bytes, on a rune boundary.
func CapError(s string) string {
	if len(s) <= MaxError {
		return s
	}
	s = s[len(s)-MaxError:]
	for len(s) > 0 && !utf8.RuneStart(s[0]) {
		s = s[1:]
	}
	return s
}

// Entries returns the entries sorted by pipeline and sender.
func (s *Store) Entries() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sorted()
}

func (s *Store) sorted() []Entry {
	es := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		es = append(es, e)
	}
	sort.Slice(es, func(i, j int) bool {
		if es[i].Pipeline != es[j].Pipeline {
			return es[i].Pipeline < es[j].Pipeline
		}
		return es[i].Sender < es[j].Sender
	})
	return es
}

// persist writes the file and keeps the store dirty until a write
// succeeds, so a later unchanged update retries it.
func (s *Store) persist() error {
	err := s.write()
	s.dirty = err != nil
	return err
}

func (s *Store) write() error {
	w := s.watch
	if w == nil {
		w = []Watch{}
	}
	b, err := json.MarshalIndent(file{Pipelines: s.sorted(), Watch: w}, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(s.path)
	f, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
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
		err = rename(tmp, s.path)
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
	return syncDir(d)
}

// Print writes the file at path: the raw JSON, or a table of the
// pipelines and, when there are any, one of the watch evaluations. A
// missing file prints empty lists.
func Print(w io.Writer, path string, raw bool) error {
	if raw {
		b, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			_, err = io.WriteString(w, "{\n  \"pipelines\": [],\n  \"watch\": []\n}\n")
			return err
		}
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	}
	f, err := read(path)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PIPELINE\tSENDER\tFAILED\tLAST RECEIVED\tLAST SUCCESS\tLAST FAILURE\tSTEP\tSIZE\tLAST ID\tERROR")
	for _, e := range f.Pipelines {
		step := ""
		if e.FailedStep > 0 {
			step = strconv.Itoa(e.FailedStep)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", clean(e.Pipeline), clean(e.Sender), e.Failed, dash(clean(e.LastReceived)),
			dash(clean(e.LastSuccess)), dash(clean(e.LastFailure)), dash(step), e.Size, dash(clean(e.LastID)), dash(OneLine(e.Error)))
	}
	if err := tw.Flush(); err != nil || len(f.Watch) == 0 {
		return err
	}
	fmt.Fprintln(w)
	return PrintWatch(w, f.Watch)
}

// PrintWatch writes watch evaluations as a table: the storage, the series
// (origin/file, or the rule a series no matches), the pipeline, the rule,
// the state, the newest copy, its size, the number of copies and the
// message.
func PrintWatch(w io.Writer, ws []Watch) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STORAGE\tSERIES\tPIPELINE\tRULE\tSTATE\tNEWEST\tSIZE\tCOPIES\tMESSAGE")
	for _, x := range ws {
		series, size := clean(x.Origin)+"/"+clean(x.File), wire.HumanSize(x.Size)
		if x.Origin == "" && x.File == "" && x.Copies == 0 {
			series, size = "-", "-"
		}
		rule := "-"
		if x.Rule > 0 {
			rule = strconv.Itoa(x.Rule)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", clean(x.Storage), series, dash(clean(x.Pipeline)), rule,
			dash(clean(x.State)), dash(clean(x.NewestReceived)), size, x.Copies, dash(oneLine(x.Message, 200)))
	}
	return tw.Flush()
}

// OneLine is the first line of s with control characters escaped, cut to
// 80 characters.
func OneLine(s string) string { return oneLine(s, 80) }

// oneLine is the first line of s with control characters escaped, cut to
// n characters.
func oneLine(s string, n int) string {
	msg, _, _ := strings.Cut(s, "\n")
	msg = clean(msg)
	if r := []rune(msg); len(r) > n {
		msg = string(r[:n-3]) + "..."
	}
	return msg
}

// Clean replaces control characters with their Go escape.
func Clean(s string) string { return clean(s) }

// clean replaces control characters with their Go escape, so a field can
// neither drive the terminal nor break the table.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
