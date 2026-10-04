package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
)

var t0 = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func result(pipeline, sender, id string, errText string, step int) Result {
	return Result{
		Pipeline: pipeline, Sender: sender, ID: id, Tags: []string{"prod"},
		Received: "2026-09-30T11:59:00Z", Size: 42, Step: step, Error: errText,
	}
}

func open(t *testing.T) (*Store, string) {
	t.Helper()
	p := Path(t.TempDir())
	s, _, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	now := t0
	s.now = func() time.Time { now = now.Add(time.Minute); return now }
	return s, p
}

func readFile(t *testing.T, p string) []Entry {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var es []Entry
	if err := json.Unmarshal(b, &es); err != nil {
		t.Fatal(err)
	}
	return es
}

func TestRecordSuccessAndFailure(t *testing.T) {
	s, p := open(t)
	if err := s.Record(result("devdb", "alice", "id1", "", 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(result("devdb", "bob", "id2", "run /x: exit status 1", 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(result("archive", "alice", "id3", "", 0)); err != nil {
		t.Fatal(err)
	}
	es := readFile(t, p)
	if len(es) != 3 || es[0].Pipeline != "archive" || es[1].Sender != "alice" || es[2].Sender != "bob" {
		t.Fatalf("entries %+v", es)
	}
	ok, bad := es[1], es[2]
	if ok.LastSuccess != t0.Add(time.Minute).Format(time.RFC3339) || ok.LastFailure != "" || ok.LastID != "id1" ||
		ok.Size != 42 || ok.LastReceived != "2026-09-30T11:59:00Z" || strings.Join(ok.Tags, ",") != "prod" {
		t.Fatalf("success %+v", ok)
	}
	if bad.LastSuccess != "" || bad.LastFailure != t0.Add(2*time.Minute).Format(time.RFC3339) || bad.FailedStep != 2 || bad.Error != "run /x: exit status 1" {
		t.Fatalf("failure %+v", bad)
	}
}

func TestFailureKeepsLastSuccess(t *testing.T) {
	s, p := open(t)
	s.Record(result("devdb", "alice", "id1", "", 0))
	s.Record(result("devdb", "alice", "id2", "boom", 3))
	es := readFile(t, p)
	if len(es) != 1 {
		t.Fatalf("entries %+v", es)
	}
	e := es[0]
	if e.LastSuccess != t0.Add(time.Minute).Format(time.RFC3339) || e.LastFailure != t0.Add(2*time.Minute).Format(time.RFC3339) ||
		e.FailedStep != 3 || e.Error != "boom" || e.LastID != "id2" {
		t.Fatalf("entry %+v", e)
	}
	s.Record(result("devdb", "alice", "id3", "", 0))
	e = readFile(t, p)[0]
	if e.LastSuccess != t0.Add(3*time.Minute).Format(time.RFC3339) || e.LastFailure == "" || e.Error != "boom" {
		t.Fatalf("after success %+v", e)
	}
}

func TestErrorCapped(t *testing.T) {
	s, p := open(t)
	s.Record(result("p", "a", "id", strings.Repeat("x", 5000)+"END", 1))
	e := readFile(t, p)[0]
	if len(e.Error) > MaxError || !strings.HasSuffix(e.Error, "END") {
		t.Fatalf("error %d bytes", len(e.Error))
	}
}

func TestAtomicWrite(t *testing.T) {
	s, p := open(t)
	if err := s.Record(result("p", "a", "id", "", 0)); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "status.json" {
		t.Fatalf("dir holds %v", ents)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
	old := rename
	rename = func(string, string) error { return errors.New("rename failed") }
	t.Cleanup(func() { rename = old })
	before, _ := os.ReadFile(p)
	if err := s.Record(result("q", "a", "id", "", 0)); err == nil {
		t.Fatal("no error")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("file changed by a failed write")
	}
	if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 1 {
		t.Fatalf("temp file left: %v", ents)
	}
}

func TestReloadAfterRestart(t *testing.T) {
	s, p := open(t)
	s.Record(result("devdb", "alice", "id1", "", 0))
	s2, aside, err := Open(p)
	if err != nil || aside != "" {
		t.Fatal(err)
	}
	s2.now = func() time.Time { return t0.Add(time.Hour) }
	s2.Record(result("devdb", "alice", "id2", "boom", 1))
	es := readFile(t, p)
	if len(es) != 1 || es[0].LastSuccess != t0.Add(time.Minute).Format(time.RFC3339) || es[0].Error != "boom" {
		t.Fatalf("entries %+v", es)
	}
}

func TestOpenCorruptMovedAside(t *testing.T) {
	dir := t.TempDir()
	p := Path(dir)
	for i := range 4 {
		if err := os.WriteFile(p, []byte("{"), 0o640); err != nil {
			t.Fatal(err)
		}
		s, aside, err := Open(p)
		if err != nil || s == nil || !strings.HasPrefix(filepath.Base(aside), "status.json.corrupt-") {
			t.Fatalf("open %d: %v %q", i, err, aside)
		}
		if b, err := os.ReadFile(aside); err != nil || string(b) != "{" {
			t.Fatalf("aside %q %v", b, err)
		}
		if len(s.Entries()) != 0 || exists(p) {
			t.Fatal("not empty or corrupt file still in place")
		}
	}
	ms, _ := filepath.Glob(filepath.Join(dir, "status.json.corrupt-*"))
	if len(ms) != 2 {
		t.Fatalf("aside files %v", ms)
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func TestOpenReadErrorFails(t *testing.T) {
	p := Path(t.TempDir())
	if err := os.Mkdir(p, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(p); err == nil {
		t.Fatal("unreadable status accepted")
	}
}

func TestOpenRemovesTempFiles(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, ".status.json.tmp-123")
	other := filepath.Join(dir, ".keep")
	os.WriteFile(tmp, []byte("x"), 0o640)
	os.WriteFile(other, []byte("x"), 0o640)
	if _, _, err := Open(Path(dir)); err != nil {
		t.Fatal(err)
	}
	if exists(tmp) || !exists(other) {
		t.Fatal("temp file kept or other file removed")
	}
}

func TestFailedStepAlwaysPresent(t *testing.T) {
	s, p := open(t)
	s.Record(result("p", "a", "id", "", 0))
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"failed_step": 0`) {
		t.Fatalf("file %s", b)
	}
}

func TestOlderResultKeepsNewerUpload(t *testing.T) {
	s, p := open(t)
	newer := result("p", "a", "new", "", 0)
	newer.Received, newer.Size = "2026-09-30T12:00:00Z", 100
	older := result("p", "a", "old", "boom", 1)
	older.Received, older.Size = "2026-09-30T11:00:00Z", 5
	s.Record(newer)
	s.Record(older)
	e := readFile(t, p)[0]
	if e.LastID != "new" || e.LastReceived != newer.Received || e.Size != 100 || e.LastFailure == "" || e.Error != "boom" {
		t.Fatalf("entry %+v", e)
	}
}

func TestPrintSanitizes(t *testing.T) {
	s, p := open(t)
	s.Record(result("p", "a\x1b[2Jb\tc", "id", "x\x1b]0;t\x07y\x7f\u0085z\nsecond", 1))
	var b bytes.Buffer
	if err := Print(&b, p, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, r := range out {
		if r != '\n' && unicode.IsControl(r) {
			t.Fatalf("control rune %q in:\n%s", r, out)
		}
	}
	if !strings.Contains(out, `a\x1b[2Jb\tc`) || !strings.Contains(out, `x\x1b]0;t\ay\x7f\u0085z`) || strings.Contains(out, "second") {
		t.Fatalf("table:\n%s", out)
	}
}

func TestPrint(t *testing.T) {
	s, p := open(t)
	s.Record(result("devdb", "alice", "id1", "", 0))
	s.Record(result("devdb", "bob", "id2", "run /x: exit status 1\nlast line of output", 2))
	var b bytes.Buffer
	if err := Print(&b, p, false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "PIPELINE") || !strings.Contains(lines[1], "alice") ||
		!strings.Contains(lines[2], "bob") || !strings.Contains(lines[2], "run /x: exit status 1") || strings.Contains(b.String(), "last line") {
		t.Fatalf("table:\n%s", b.String())
	}
	b.Reset()
	if err := Print(&b, p, true); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if b.String() != string(raw) {
		t.Fatalf("json:\n%s", b.String())
	}
}

func TestPrintMissing(t *testing.T) {
	p := Path(t.TempDir())
	var b bytes.Buffer
	if err := Print(&b, p, false); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n"); len(lines) != 1 || !strings.HasPrefix(lines[0], "PIPELINE") {
		t.Fatalf("table:\n%s", b.String())
	}
	b.Reset()
	if err := Print(&b, p, true); err != nil || strings.TrimSpace(b.String()) != "[]" {
		t.Fatalf("json %q %v", b.String(), err)
	}
}

func TestSetFailed(t *testing.T) {
	s, p := open(t)
	s.Record(result("p", "a", "id1", "boom", 1))
	s.Record(result("q", "a", "id2", "", 0))
	if err := s.SetFailed(map[Key]int{{"p", "a"}: 2, {"r", "b"}: 1}); err != nil {
		t.Fatal(err)
	}
	es := readFile(t, p)
	if len(es) != 3 || es[0].Failed != 2 || es[1].Failed != 0 || es[2].Pipeline != "r" || es[2].Sender != "b" || es[2].Failed != 1 {
		t.Fatalf("entries %+v", es)
	}
	if !strings.Contains(func() string { b, _ := os.ReadFile(p); return string(b) }(), `"failed": 0`) {
		t.Fatal("failed missing for zero")
	}
	s.Record(result("p", "a", "id3", "", 0))
	if es := readFile(t, p); es[0].Failed != 2 || es[0].Error != "boom" {
		t.Fatalf("record lost the count or the history: %+v", es[0])
	}
	if err := s.SetFailed(nil); err != nil {
		t.Fatal(err)
	}
	for _, e := range readFile(t, p) {
		if e.Failed != 0 {
			t.Fatalf("entry %+v", e)
		}
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	old := st.ModTime().Add(-time.Hour)
	os.Chtimes(p, old, old)
	if err := s.SetFailed(map[Key]int{}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); !st.ModTime().Equal(old) {
		t.Fatal("unchanged counts rewrote the file")
	}
}

func TestPrintFailedColumn(t *testing.T) {
	s, p := open(t)
	s.Record(result("p", "a", "id1", "boom", 1))
	s.SetFailed(map[Key]int{{"p", "a"}: 3})
	var b bytes.Buffer
	if err := Print(&b, p, false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(b.String(), "\n")
	if !strings.Contains(lines[0], "FAILED") || !strings.Contains(lines[1], " 3 ") {
		t.Fatalf("table:\n%s", b.String())
	}
}

func TestOneLine(t *testing.T) {
	if got := OneLine("a\x1bb\nsecond"); got != `a\x1bb` {
		t.Fatalf("%q", got)
	}
	if got := OneLine(strings.Repeat("x", 100)); len(got) != 80 || !strings.HasSuffix(got, "...") {
		t.Fatalf("%q", got)
	}
	if got := CapError(strings.Repeat("y", MaxError+10)); len(got) != MaxError {
		t.Fatalf("%d", len(got))
	}
}

// A failed write leaves the store dirty: the next SetFailed with the same
// counts writes again, in both directions.
func TestSetFailedRetriesFailedWrite(t *testing.T) {
	for _, tc := range []struct {
		name     string
		from, to int
	}{{"0to1", 0, 1}, {"1to0", 1, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s, p := open(t)
			k := Key{"p", "a"}
			s.Record(result("p", "a", "id", "", 0))
			if err := s.SetFailed(map[Key]int{k: tc.from}); err != nil {
				t.Fatal(err)
			}
			old := rename
			rename = func(string, string) error { return errors.New("rename failed") }
			if err := s.SetFailed(map[Key]int{k: tc.to}); err == nil {
				t.Fatal("no error")
			}
			rename = old
			if err := s.SetFailed(map[Key]int{k: tc.to}); err != nil {
				t.Fatal(err)
			}
			if es := readFile(t, p); es[0].Failed != tc.to {
				t.Fatalf("on disk failed=%d, want %d", es[0].Failed, tc.to)
			}
		})
	}
}

// A failed fsync of the directory also leaves the store dirty.
func TestSetFailedRetriesFailedSync(t *testing.T) {
	s, p := open(t)
	k := Key{"p", "a"}
	s.Record(result("p", "a", "id", "", 0))
	old := syncDir
	t.Cleanup(func() { syncDir = old })
	syncDir = func(*os.File) error { return errors.New("fsync failed") }
	if err := s.SetFailed(map[Key]int{k: 1}); err == nil {
		t.Fatal("no error")
	}
	calls := 0
	syncDir = func(d *os.File) error { calls++; return d.Sync() }
	if err := s.SetFailed(map[Key]int{k: 1}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("retry wrote %d times", calls)
	}
	if es := readFile(t, p); es[0].Failed != 1 {
		t.Fatalf("on disk %+v", es[0])
	}
}
