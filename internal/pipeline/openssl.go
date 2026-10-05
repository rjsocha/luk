package pipeline

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// The format of openssl enc -aes-256-cbc -pbkdf2 -salt with the defaults
// of OpenSSL 1.1.1 and 3.x: "Salted__", the salt, then AES-256-CBC with
// PKCS#7 padding, key and IV from PBKDF2-HMAC-SHA256 of the password.
const (
	opensslMagic = "Salted__"
	opensslIter  = 10000
	opensslSaltN = 8
)

// opensslSalt fills the salt; replaced by tests for a fixed vector.
var opensslSalt = func(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// opensslWriter encrypts what is written to it into w, holding back at
// most one block: the last one gets the padding on Close.
type opensslWriter struct {
	w    io.Writer
	cbc  cipher.BlockMode
	buf  []byte
	out  []byte
	done bool
}

func newOpenSSLWriter(w io.Writer, password []byte) (*opensslWriter, error) {
	salt := make([]byte, opensslSaltN)
	if err := opensslSalt(salt); err != nil {
		return nil, err
	}
	km, err := pbkdf2.Key(sha256.New, string(password), salt, opensslIter, 32+aes.BlockSize)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(km[:32])
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(append([]byte(opensslMagic), salt...)); err != nil {
		return nil, err
	}
	return &opensslWriter{w: w, cbc: cipher.NewCBCEncrypter(b, km[32:])}, nil
}

func (o *opensslWriter) Write(p []byte) (int, error) {
	if o.done {
		return 0, errors.New("write after close")
	}
	o.buf = append(o.buf, p...)
	// Keep the tail (up to one full block) for Close: the padding of an
	// input that ends on a block boundary is a block of its own.
	n := len(o.buf) - 1
	n -= n % aes.BlockSize
	if n <= 0 {
		return len(p), nil
	}
	o.out = append(o.out[:0], o.buf[:n]...)
	o.cbc.CryptBlocks(o.out, o.out)
	o.buf = append(o.buf[:0], o.buf[n:]...)
	if _, err := o.w.Write(o.out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close pads and writes the last block; it does not close w.
func (o *opensslWriter) Close() error {
	if o.done {
		return nil
	}
	o.done = true
	pad := aes.BlockSize - len(o.buf)%aes.BlockSize
	for range pad {
		o.buf = append(o.buf, byte(pad))
	}
	o.cbc.CryptBlocks(o.buf, o.buf)
	_, err := o.w.Write(o.buf)
	return err
}
