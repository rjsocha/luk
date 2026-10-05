package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxPassword bounds a password file.
const maxPassword = 4096

// ReadPassword reads the password name of the password directory dir:
// the content of dir/name with one trailing newline stripped. A missing,
// empty or oversized file is an error naming it. lukd reads it when an
// encrypt step runs, so a changed file takes effect without a reload.
func ReadPassword(dir, name string) ([]byte, error) {
	if dir == "" {
		return nil, errors.New("no password directory")
	}
	p := filepath.Join(dir, name)
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxPassword+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if len(b) > maxPassword {
		return nil, fmt.Errorf("%s: larger than %d bytes", p, maxPassword)
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	if len(b) == 0 {
		return nil, fmt.Errorf("%s: empty password", p)
	}
	return b, nil
}
