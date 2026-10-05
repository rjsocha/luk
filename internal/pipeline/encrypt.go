package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"luk/internal/config"
	"luk/internal/gpgkeys"
	"luk/internal/runstep"
)

// recipients resolves the recipients of e: an unusable one is logged and
// skipped, or fails the step when e is strict; none usable fails it.
func (d *Dispatcher) recipients(j Job, keys *gpgkeys.Resolver, name string, step int, e *config.Encrypt) ([]*openpgp.Entity, []string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-d.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	type lookup struct {
		addr string
		wkd  bool
	}
	var all []lookup
	for _, a := range e.WKD {
		all = append(all, lookup{a, true})
	}
	for _, a := range e.Key {
		all = append(all, lookup{a, false})
	}
	var ents []*openpgp.Entity
	var fps, unusable []string
	seen := map[string]bool{}
	for _, l := range all {
		var rc gpgkeys.Recipient
		var err error
		if l.wkd {
			rc, err = keys.WKD(ctx, l.addr)
		} else {
			rc, err = keys.Key(l.addr)
		}
		select {
		case <-d.stop:
			return nil, nil, errInterrupted
		default:
		}
		for _, n := range rc.Notes {
			d.log.Warn("recipient key", "id", j.Entry.ID, "pipeline", name, "step", step, "recipient", l.addr, "warning", n)
		}
		if err != nil {
			d.log.Warn("recipient unusable", "id", j.Entry.ID, "pipeline", name, "step", step, "recipient", l.addr, "error", err)
			unusable = append(unusable, l.addr+": "+err.Error())
			continue
		}
		for _, ent := range rc.Entities {
			if fp := gpgkeys.Fingerprint(ent); !seen[fp] {
				seen[fp] = true
				ents = append(ents, ent)
				fps = append(fps, fp)
			}
		}
	}
	switch {
	case e.Strict && len(unusable) > 0:
		return nil, nil, fmt.Errorf("unusable recipients (strict): %s", strings.Join(unusable, "; "))
	case len(ents) == 0:
		return nil, nil, fmt.Errorf("no usable recipient: %s", strings.Join(unusable, "; "))
	}
	return ents, fps, nil
}

// encryptStep encrypts every file of set to out/<name>.gpg of dir, or to
// out/<name>.enc in the openssl format when insecure.openssl matches its
// name; the result is the next set, each file with its meta extended by
// the encryption, the recipient fingerprints, the password names and the
// plain file. The passwords are read here, so a changed file takes effect
// on the next run without a reload.
func (d *Dispatcher) encryptStep(j Job, keys *gpgkeys.Resolver, passwordDir, name string, step int, e *config.Encrypt, set []file, dir string) ([]file, error) {
	var symmetric []string
	var ossl *config.OpenSSL
	if in := e.Insecure; in != nil {
		symmetric, ossl = in.Symmetric, in.OpenSSL
	}
	var passwords [][]byte
	for _, n := range symmetric {
		pw, err := config.ReadPassword(passwordDir, n)
		if err != nil {
			return nil, fmt.Errorf("password %s: %w", n, err)
		}
		passwords = append(passwords, pw)
	}
	var osslPassword []byte
	if ossl != nil {
		pw, err := config.ReadPassword(passwordDir, ossl.Key)
		if err != nil {
			return nil, fmt.Errorf("password %s: %w", ossl.Key, err)
		}
		osslPassword = pw
	}
	// The recipients are looked up only for a set that has a file for
	// them.
	var ents []*openpgp.Entity
	var fps []string
	if slices.ContainsFunc(set, func(f file) bool { return !ossl.Match(f.name) }) {
		var err error
		if ents, fps, err = d.recipients(j, keys, name, step, e); err != nil {
			return nil, err
		}
	}
	in, out, err := prepareWork(dir, set)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if keys.Now != nil {
		now = keys.Now()
	}
	var next []file
	nossl := 0
	for _, f := range set {
		kind, ext, seal, pwNames, to := "gpg", ".gpg", gpgSeal(ents, passwords, now), symmetric, fps
		if ossl.Match(f.name) {
			kind, ext, seal, pwNames, to = "openssl", ".enc", opensslSeal(osslPassword), []string{ossl.Key}, nil
			nossl++
		}
		o := file{name: f.name + ext, produced: true}
		if !runstep.ValidName(o.name) {
			return nil, fmt.Errorf("%q: name too long", o.name)
		}
		o.path = filepath.Join(out, o.name)
		plain, err := encryptFile(filepath.Join(in, f.name), o.path, seal, d.stop)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		o.size, o.sha256 = plain.outSize, plain.outSum
		if o.meta, err = encryptedMeta(f.meta, kind, to, pwNames, f.name, plain.size, plain.sum); err != nil {
			return nil, err
		}
		next = append(next, o)
	}
	attrs := []any{"id", j.Entry.ID, "pipeline", name, "step", step, "files", len(next), "recipients", fps}
	if len(symmetric) > 0 {
		attrs = append(attrs, "passwords", symmetric)
	}
	if ossl != nil {
		attrs = append(attrs, "openssl", nossl)
	}
	d.log.Info("encrypted", attrs...)
	return next, nil
}

// gpgSeal opens a binary OpenPGP message to the recipients to and the
// passwords. A password gets the Argon2 S2K of RFC 9580.
func gpgSeal(to []*openpgp.Entity, passwords [][]byte, now time.Time) func(io.Writer) (io.WriteCloser, error) {
	return func(w io.Writer) (io.WriteCloser, error) {
		cfg := gpgkeys.Config(now)
		if len(passwords) > 0 {
			cfg.S2KConfig = &s2k.Config{S2KMode: s2k.Argon2S2K}
		}
		return openpgp.EncryptWithParams(w, to, nil, &openpgp.EncryptParams{Config: cfg, Passwords: passwords})
	}
}

// opensslSeal opens the openssl enc format with the password.
func opensslSeal(password []byte) func(io.Writer) (io.WriteCloser, error) {
	return func(w io.Writer) (io.WriteCloser, error) {
		return newOpenSSLWriter(w, password)
	}
}

type encrypted struct {
	size, outSize int64
	sum, outSum   string
}

// encryptFile streams src through seal into dst, hashing both sides on
// the way.
func encryptFile(src, dst string, seal func(io.Writer) (io.WriteCloser, error), stop <-chan struct{}) (encrypted, error) {
	var r encrypted
	in, err := openRegular(src)
	if err != nil {
		return r, err
	}
	defer in.Close()
	of, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return r, err
	}
	defer of.Close()
	ow := &hashWriter{w: of, h: sha256.New()}
	pt, err := seal(ow)
	if err != nil {
		return r, err
	}
	ih := sha256.New()
	r.size, err = io.Copy(pt, stopReader{r: io.TeeReader(in, ih), stop: stop})
	if cerr := pt.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = of.Close()
	}
	if err == nil {
		err = os.Chmod(dst, 0o440)
	}
	if err != nil {
		return r, err
	}
	r.sum, r.outSize, r.outSum = hex.EncodeToString(ih.Sum(nil)), ow.n, hex.EncodeToString(ow.h.Sum(nil))
	return r, nil
}

type hashWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (w *hashWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.h.Write(p[:n])
	w.n += int64(n)
	return n, err
}

// stopReader fails with errInterrupted once stop is closed.
type stopReader struct {
	r    io.Reader
	stop <-chan struct{}
}

func (s stopReader) Read(p []byte) (int, error) {
	select {
	case <-s.stop:
		return 0, errInterrupted
	default:
	}
	return s.r.Read(p)
}

// encryptedMeta extends the meta in by the encryption kind (gpg or
// openssl), the recipient fingerprints (gpg only) and the names of the
// passwords that decrypt the file (when there are any).
func encryptedMeta(in json.RawMessage, kind string, fps, passwords []string, name string, size int64, sum string) (json.RawMessage, error) {
	m := map[string]json.RawMessage{}
	if in != nil {
		if err := json.Unmarshal(in, &m); err != nil {
			return nil, errors.New("meta of the input is not a JSON object")
		}
	}
	add := map[string]any{
		"encryption": kind,
		"plain":      map[string]any{"name": name, "size": size, "sha256": sum},
	}
	if kind == "gpg" {
		add["recipients"] = fps
	}
	if len(passwords) > 0 {
		add["passwords"] = passwords
	}
	for k, v := range add {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		m[k] = b
	}
	return json.Marshal(m)
}
