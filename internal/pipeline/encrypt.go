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
	"strings"
	"time"

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

// encryptStep encrypts every file of set to out/<name>.gpg of dir; the
// result is the next set, each file with its meta extended by the
// encryption, the recipient fingerprints and the plain file.
func (d *Dispatcher) encryptStep(j Job, keys *gpgkeys.Resolver, name string, step int, e *config.Encrypt, set []file, dir string) ([]file, error) {
	ents, fps, err := d.recipients(j, keys, name, step, e)
	if err != nil {
		return nil, err
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
	for _, f := range set {
		o := file{name: f.name + ".gpg", produced: true}
		if !runstep.ValidName(o.name) {
			return nil, fmt.Errorf("%q: name too long", o.name)
		}
		o.path = filepath.Join(out, o.name)
		plain, err := encryptFile(filepath.Join(in, f.name), o.path, ents, now, d.stop)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		o.size, o.sha256 = plain.outSize, plain.outSum
		if o.meta, err = encryptedMeta(f.meta, fps, f.name, plain.size, plain.sum); err != nil {
			return nil, err
		}
		next = append(next, o)
	}
	d.log.Info("encrypted", "id", j.Entry.ID, "pipeline", name, "step", step, "files", len(next), "recipients", fps)
	return next, nil
}

type encrypted struct {
	size, outSize int64
	sum, outSum   string
}

// encryptFile streams src into a binary OpenPGP message at dst, hashing
// both sides on the way.
func encryptFile(src, dst string, to []*openpgp.Entity, now time.Time, stop <-chan struct{}) (encrypted, error) {
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
	pt, err := openpgp.EncryptWithParams(ow, to, nil, &openpgp.EncryptParams{Config: gpgkeys.Config(now)})
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

func encryptedMeta(in json.RawMessage, fps []string, name string, size int64, sum string) (json.RawMessage, error) {
	m := map[string]json.RawMessage{}
	if in != nil {
		if err := json.Unmarshal(in, &m); err != nil {
			return nil, errors.New("meta of the input is not a JSON object")
		}
	}
	for k, v := range map[string]any{
		"encryption": "gpg",
		"recipients": fps,
		"plain":      map[string]any{"name": name, "size": size, "sha256": sum},
	} {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		m[k] = b
	}
	return json.Marshal(m)
}
