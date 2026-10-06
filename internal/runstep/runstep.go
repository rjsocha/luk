// Package runstep holds the parts of the run step contract that lukd and the
// luk-job helper share: output names, per-file meta and the fail message.
package runstep

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"luk/internal/wire"
)

const (
	// MetaExt marks the per-file meta next to a file in in/ and out/.
	MetaExt = ".meta.json"
	// MaxMeta caps a per-file meta.
	MaxMeta = 64 << 10
	// FailFile is the file in the work directory holding the step error.
	FailFile = "fail"
	// MaxFail caps the fail message.
	MaxFail = 4 << 10
)

// ValidName reports whether n may name a file of the set: not empty, not
// starting with a dot, without a slash or a control character, at most
// wire.MaxNameLen bytes.
func ValidName(n string) bool {
	return n != "" && !strings.HasPrefix(n, ".") && !strings.Contains(n, "/") && !wire.HasControl(n) && len(n) <= wire.MaxNameLen
}

// SetNames is the file set of in/ whose regular files are named regular:
// those names sorted, without a <name>.meta.json next to its file <name>,
// which is that file's meta.
func SetNames(regular []string) []string {
	have := make(map[string]bool, len(regular))
	for _, n := range regular {
		have[n] = true
	}
	names := []string{}
	for n := range have {
		if base, ok := strings.CutSuffix(n, MetaExt); ok && have[base] {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// CheckMeta validates a per-file meta (a JSON object of at most MaxMeta
// bytes) and returns it compacted.
func CheckMeta(b []byte) (json.RawMessage, error) {
	if len(b) > MaxMeta {
		return nil, fmt.Errorf("larger than %d bytes", MaxMeta)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil || obj == nil {
		return nil, errors.New("not a JSON object")
	}
	var c bytes.Buffer
	if err := json.Compact(&c, b); err != nil {
		return nil, err
	}
	return c.Bytes(), nil
}

// FailText turns b into a fail message: valid UTF-8, control characters
// other than newline and tab replaced by a space, trimmed and capped at
// MaxFail bytes on a rune boundary.
func FailText(b []byte) string {
	s := strings.ToValidUTF8(string(b), "�")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > MaxFail {
		s = s[:MaxFail]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
