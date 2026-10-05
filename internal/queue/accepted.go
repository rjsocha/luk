package queue

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Acceptance is the acceptance order of a queue entry: when the receive
// role accepted the upload (the start of an upload in parts, the commit
// of any other), in Unix nanoseconds (NS), and Seq, which orders entries
// accepted within the same nanosecond by one process.
type Acceptance struct {
	NS  int64
	Seq int
}

// Compare orders a and b: by NS, then by Seq.
func (a Acceptance) Compare(b Acceptance) int {
	switch {
	case a.NS < b.NS:
		return -1
	case a.NS > b.NS:
		return 1
	case a.Seq < b.Seq:
		return -1
	case a.Seq > b.Seq:
		return 1
	}
	return 0
}

// MarkPath is the file under root holding the acceptance mark of the
// receive role (see Accepted.Persist).
func MarkPath(root string) string { return filepath.Join(root, "accepted.json") }

// markWindow is how far past the value handed out the persisted mark is
// moved, so the mark is written about once per window, not per upload.
var markWindow = time.Minute

// Accepted hands out acceptance orders that never go backwards while the
// process runs: the wall clock read once at the start plus the time
// elapsed since, measured on the monotonic clock, so a step of the wall
// clock (NTP, an administrator) does not reorder the entries of the
// process. Two calls within the same nanosecond get increasing Seq. With
// a mark (see Persist) a new process starts after every value an earlier
// one handed out, whatever the wall clock says: an order that went
// backwards would make the new uploads older than the stored files.
type Accepted struct {
	elapsed func() time.Duration
	// base is the order at elapsed 0: the wall clock at the start, moved
	// forward past the mark.
	base int64

	mu   sync.Mutex
	last Acceptance
	// path is the mark file, empty without one; reserved the mark it
	// holds: no value above it is handed out before it is moved.
	path     string
	reserved int64
	onErr    func(error)
}

// NewAccepted starts the acceptance clock of the process.
func NewAccepted() *Accepted {
	start := time.Now()
	return newAccepted(start, func() time.Duration { return time.Since(start) })
}

func newAccepted(start time.Time, elapsed func() time.Duration) *Accepted {
	return &Accepted{base: start.UnixNano(), elapsed: elapsed}
}

// Persist keeps the mark of a in the file path: the orders continue after
// the mark it holds, and from now on the file is moved ahead of every
// value before it is handed out (synced, a window at a time), so neither
// a restart with the wall clock moved back nor a crash reuses one. A
// missing file starts from the wall clock; one that does not read is an
// error. A later failure to move the mark goes to onErr, and the value is
// handed out anyway: the next call tries again.
func (a *Accepted) Persist(path string, onErr func(error)) error {
	mark, err := readMark(path)
	if err != nil {
		return fmt.Errorf("%s: %w (remove it to start the order from the wall clock)", path, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.base + int64(a.elapsed())
	if now <= mark {
		a.base += mark + 1 - now
		now = mark + 1
	}
	next := max(now, a.last.NS) + int64(markWindow)
	if err := writeMark(path, next); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	a.path, a.reserved, a.onErr = path, next, onErr
	return nil
}

// Next is the acceptance order of an entry accepted now.
func (a *Accepted) Next() Acceptance {
	a.mu.Lock()
	defer a.mu.Unlock()
	ns := a.base + int64(a.elapsed())
	if ns <= a.last.NS {
		a.last.Seq++
	} else {
		a.last = Acceptance{NS: ns}
	}
	if a.path != "" && a.last.NS > a.reserved {
		next := a.last.NS + int64(markWindow)
		if err := writeMark(a.path, next); err != nil {
			a.onErr(err)
		} else {
			a.reserved = next
		}
	}
	return a.last
}

type markFile struct {
	Mark int64 `json:"mark"`
}

// readMark is the mark held in path, 0 for a missing file.
func readMark(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var m markFile
	if err := json.Unmarshal(b, &m); err != nil {
		return 0, err
	}
	return m.Mark, nil
}

// writeMark replaces path with the mark atomically and durably.
func writeMark(path string, mark int64) error {
	b, err := json.Marshal(markFile{Mark: mark})
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(append(b, '\n'))
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
