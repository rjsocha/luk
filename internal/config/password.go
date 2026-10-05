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

// maxOpenSSLPassword is what the openssl CLI reads from -pass file: (one
// line of at most 1023 bytes); a longer password could not be used to
// decrypt with it.
const maxOpenSSLPassword = 1023

// ReadPassword reads the password name of the password directory dir:
// the content of dir/name with one trailing newline stripped. A missing,
// empty or oversized file, or one that holds more than one line, is an
// error naming it (the documented decrypt commands read the first line
// only). lukd reads it when an
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
	if bytes.ContainsAny(b, "\r\n") {
		return nil, fmt.Errorf("%s: password has more than one line", p)
	}
	return b, nil
}

// ReadOpenSSLPassword is ReadPassword for the password of the openssl
// format, which the openssl CLI reads from a file up to 1023 bytes only.
func ReadOpenSSLPassword(dir, name string) ([]byte, error) {
	b, err := ReadPassword(dir, name)
	if err != nil {
		return nil, err
	}
	if len(b) > maxOpenSSLPassword {
		return nil, fmt.Errorf("%s: longer than %d bytes, which the openssl command reads at most", filepath.Join(dir, name), maxOpenSSLPassword)
	}
	return b, nil
}
