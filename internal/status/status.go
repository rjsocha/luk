// Package status keeps <root>/status.json: the last pipeline result per
// (pipeline, sender). lukd reports facts only; thresholds live in the
// monitoring check that reads the file.
package status

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"
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

// Path is the status file under root.
func Path(root string) string { return filepath.Join(root, "status.json") }

type Entry struct {
	Pipeline     string   `json:"pipeline"`
	Sender       string   `json:"sender"`
	Tags         []string `json:"tags"`
	LastID       string   `json:"last_id"`
	LastReceived string   `json:"last_received"`
	LastSuccess  string   `json:"last_success,omitempty"`
	LastFailure  string   `json:"last_failure,omitempty"`
	FailedStep   int      `json:"failed_step"`
	Error        string   `json:"error,omitempty"`
	Size         int64    `json:"size"`
	Failed       int      `json:"failed"`
}

// Result is one finished pipeline run; a non-empty Error marks a failure
// at Step.
type Result struct {
	Pipeline, Sender, ID, Received string
	Tags                           []string
	Size                           int64
	Step                           int
	Error                          string
}

// Key identifies an entry.
type Key struct{ Pipeline, Sender string }

type Store struct {
	path string
	now  func() time.Time

	mu      sync.Mutex
	entries map[Key]Entry
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
	for _, e := range es {
		s.entries[Key{e.Pipeline, e.Sender}] = e
	}
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

func read(path string) ([]Entry, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return es, nil
}

// Record updates the entry of r and rewrites the file atomically. A failure
// keeps last_success; a success keeps the last failure fields.
func (s *Store) Record(r Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := Key{r.Pipeline, r.Sender}
	e, seen := s.entries[k]
	e.Pipeline, e.Sender = r.Pipeline, r.Sender
	if !seen || !older(r.Received, e.LastReceived) {
		e.LastID, e.LastReceived, e.Size = r.ID, r.Received, r.Size
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

// older reports whether received a is before b; unparsable times are not.
func older(a, b string) bool {
	ta, err := time.Parse(time.RFC3339, a)
	if err != nil {
		return false
	}
	tb, err := time.Parse(time.RFC3339, b)
	return err == nil && ta.Before(tb)
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
	b, err := json.MarshalIndent(s.sorted(), "", "  ")
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

// Print writes the file at path: the raw JSON, or a table. A missing file
// prints an empty list.
func Print(w io.Writer, path string, raw bool) error {
	if raw {
		b, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			_, err = io.WriteString(w, "[]\n")
			return err
		}
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	}
	es, err := read(path)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PIPELINE\tSENDER\tFAILED\tLAST RECEIVED\tLAST SUCCESS\tLAST FAILURE\tSTEP\tSIZE\tLAST ID\tERROR")
	for _, e := range es {
		step := ""
		if e.FailedStep > 0 {
			step = strconv.Itoa(e.FailedStep)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", clean(e.Pipeline), clean(e.Sender), e.Failed, dash(clean(e.LastReceived)),
			dash(clean(e.LastSuccess)), dash(clean(e.LastFailure)), dash(step), e.Size, dash(clean(e.LastID)), dash(OneLine(e.Error)))
	}
	return tw.Flush()
}

// OneLine is the first line of s with control characters escaped, cut to
// 80 characters.
func OneLine(s string) string {
	msg, _, _ := strings.Cut(s, "\n")
	msg = clean(msg)
	if r := []rune(msg); len(r) > 80 {
		msg = string(r[:77]) + "..."
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
