package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"luk/internal/gpgkeys"
	"luk/internal/gpgring"
	"luk/internal/wire"
)

// gpgType is the Content-Type of a --gpg upload without --type.
const gpgType = "application/pgp-encrypted"

// gpgLong and gpgExample are the help of --gpg, shown when gpg is in PATH;
// without it the flag is hidden.
const (
	gpgLong = `
--gpg ADDRESS|FINGERPRINT (repeatable) encrypts the content here, before anything
is sent, into one binary OpenPGP message to the keys named, taken from the gpg
keyring of the user. Each must name exactly one key that gpg holds valid (validity
full or ultimate: a key you signed, or your own), enabled and able to encrypt;
else nothing is sent. The upload is named NAME.gpg and, without --type, is
application/pgp-encrypted; a file is sent with the size and hash of the message,
so --links works; a stream is encrypted as it goes. It takes no --secret.`
	gpgExample = `
  luk send --file report.pdf --gpg anna@example.net --portal --once --links 2`
)

// gpgRecipients finds the keys of the --gpg recipients in the GnuPG
// keyring of the user, one key per recipient.
func gpgRecipients(ctx context.Context, to []string) ([]*openpgp.Entity, error) {
	var ents []*openpgp.Entity
	seen := map[string]bool{}
	for _, who := range to {
		e, err := gpgring.Find(ctx, who)
		if err != nil {
			return nil, usageError{fmt.Errorf("--gpg: %w", err)}
		}
		if fp := gpgkeys.Fingerprint(e); !seen[fp] {
			seen[fp] = true
			ents = append(ents, e)
		}
	}
	return ents, nil
}

// gpgSeal opens a binary OpenPGP message to the recipients.
func gpgSeal(w io.Writer, to []*openpgp.Entity) (io.WriteCloser, error) {
	return openpgp.EncryptWithParams(w, to, nil, &openpgp.EncryptParams{Config: gpgkeys.Config(time.Now())})
}

// gpgInput turns the content c into its OpenPGP message to the recipients,
// named <name>.gpg. A file is encrypted into an unlinked temporary file,
// which is sent with its signed size and hash like any file; a stream is
// encrypted while it is sent.
func gpgInput(c content, closer io.Closer, to []*openpgp.Entity, meta *wire.Meta) (content, io.Closer, error) {
	if meta.File != "" {
		meta.File += ".gpg"
	}
	if c.source == nil {
		pr, pw := io.Pipe()
		go func() {
			w, err := gpgSeal(pw, to)
			if err == nil {
				if _, err = io.Copy(w, c.body); err == nil {
					err = w.Close()
				}
			}
			pw.CloseWithError(err)
		}()
		return content{body: pr, size: -1}, closer, nil
	}
	tmp, err := gpgTemp()
	if err != nil {
		return content{}, closer, err
	}
	both := closers{tmp, closer}
	h := sha256.New()
	w, err := gpgSeal(io.MultiWriter(tmp, h), to)
	if err == nil {
		if _, err = io.Copy(w, io.NewSectionReader(c.source, 0, c.size)); err == nil {
			err = w.Close()
		}
	}
	var st os.FileInfo
	if err == nil {
		st, err = tmp.Stat()
	}
	if err != nil {
		return content{}, both, err
	}
	n := st.Size()
	meta.Size, meta.SHA256 = &n, hex.EncodeToString(h.Sum(nil))
	return content{source: tmp, size: n, mtime: st.ModTime()}, both, nil
}

// gpgTemp is an unlinked temporary file in TMPDIR, by default /var/tmp:
// the message of a large file does not belong in a tmpfs.
func gpgTemp() (*os.File, error) {
	dir := os.Getenv("TMPDIR")
	if dir == "" {
		dir = "/var/tmp"
	}
	f, err := os.CreateTemp(dir, "luk-*.gpg")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// closers closes every closer that is set.
type closers []io.Closer

func (c closers) Close() error {
	var first error
	for _, cl := range c {
		if cl == nil {
			continue
		}
		if err := cl.Close(); first == nil {
			first = err
		}
	}
	return first
}
