package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"luk/internal/config"
	"luk/internal/store"
)

const dirHint = "the directory must be owned by the service user and inside ReadWritePaths of the unit"

// prepareDirs creates the queue (secret queues 0700), local storage, work
// and WKD cache directories and checks that the process can write to them
// and, with tls, read the TLS files and write the ACME caches.
func prepareDirs(cfg *config.Config, tls bool) error {
	var errs []error
	for _, d := range []string{cfg.WorkDir(), cfg.GPGCacheDir()} {
		if d != "" {
			errs = append(errs, prepareWritable(d))
		}
	}
	for _, name := range sortedKeys(cfg.Endpoint) {
		e := cfg.Endpoint[name]
		errs = append(errs, prepareWritable(e.Path))
		if e.Secret != nil {
			errs = append(errs, prepareWritableMode(e.Secret.Path, 0o700))
		}
	}
	for _, name := range sortedKeys(cfg.Storage) {
		if s := cfg.Storage[name]; s.Type == "local" {
			errs = append(errs, prepareStorage(name, s))
		}
	}
	acme := map[string]bool{}
	for _, name := range sortedKeys(cfg.Listen) {
		l := cfg.Listen[name]
		if l.TLS == nil || !tls {
			continue
		}
		if l.TLS.Mode == "acme" {
			if d := cfg.ACMECacheDir(l.TLS.Directory); !acme[d] {
				acme[d] = true
				errs = append(errs, prepareACMEDir(d))
			}
			continue
		}
		for _, p := range []string{l.TLS.Cert, l.TLS.Key} {
			errs = append(errs, prepareReadable(p, l.TLS.Mode == "self"))
		}
	}
	return errors.Join(errs...)
}

func prepareWritable(dir string) error { return prepareWritableMode(dir, 0o750) }

// prepareStorage refuses a local storage base holding anything but the
// two trees of a base (see store.CheckLayout), then creates them and
// checks that the process can write to them. A storage with permanent
// names needs renameat2 RENAME_EXCHANGE on its filesystem (see
// store.ProbeExchange).
func prepareStorage(name string, st *config.Storage) error {
	base := st.Base
	if err := store.CheckLayout(base); err != nil {
		return fmt.Errorf("storage %s: %w", name, err)
	}
	err := errors.Join(prepareWritable(filepath.Join(base, store.DBDir)), prepareWritable(filepath.Join(base, store.DataDir)))
	if err == nil && len(st.Permanents()) > 0 {
		if perr := store.ProbeExchange(base); perr != nil {
			err = fmt.Errorf("storage %s: permanent names: %w", name, perr)
		}
	}
	return err
}

// prepareWritableMode is prepareWritable creating missing directories with
// mode perm (less the umask).
func prepareWritableMode(dir string, perm os.FileMode) error {
	if err := os.MkdirAll(dir, perm); err != nil {
		return fmt.Errorf("%s: %v (%s)", dir, err, dirHint)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%s: %v", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory", dir)
	}
	f, err := os.CreateTemp(dir, ".luk-write-check-*")
	if err != nil {
		return fmt.Errorf("%s: not writable: %v (%s)", dir, err, dirHint)
	}
	f.Close()
	return os.Remove(f.Name())
}

// prepareReadable checks that an existing TLS file is readable; for a self
// listener it also creates the parent directory for lukd tls generate.
func prepareReadable(file string, self bool) error {
	hint := "the file must be readable by the service user"
	if self {
		hint = "run lukd tls generate as the service user"
		dir := filepath.Dir(file)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("%s: %v (%s)", dir, err, dirHint)
		}
	}
	f, err := os.Open(file)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("%s: %v (%s)", file, err, hint)
	}
	return f.Close()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
