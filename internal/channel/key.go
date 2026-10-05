package channel

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

const (
	keyBegin = "-----BEGIN LUK IDENTITY KEY-----\n"
	keyEnd   = "\n-----END LUK IDENTITY KEY-----\n"
)

// Key is the static X25519 identity of lukd.
type Key struct {
	Private, Public []byte
}

func GenerateKey() (Key, error) {
	priv := make([]byte, keySize)
	if _, err := rand.Read(priv); err != nil {
		return Key{}, err
	}
	return keyFrom(priv)
}

func keyFrom(priv []byte) (Key, error) {
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return Key{}, err
	}
	return Key{Private: priv, Public: pub}, nil
}

// LoadKey reads an identity key file. A file that others can read or that
// the group can write is refused: the key is the identity of lukd, and the
// group exists only so that lukd (group luk) can read it.
func LoadKey(path string) (Key, error) {
	f, err := os.Open(path)
	if err != nil {
		return Key{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Key{}, err
	}
	if m := fi.Mode().Perm(); m&0o027 != 0 {
		return Key{}, fmt.Errorf("channel: identity key %s has mode %04o: want 0640 or stricter", path, m)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(f); err != nil {
		return Key{}, err
	}
	s := b.String()
	if len(s) < len(keyBegin)+len(keyEnd) || s[:len(keyBegin)] != keyBegin || s[len(s)-len(keyEnd):] != keyEnd {
		return Key{}, fmt.Errorf("channel: identity key %s: not a LUK IDENTITY KEY", path)
	}
	priv, err := base64.StdEncoding.Strict().DecodeString(s[len(keyBegin) : len(s)-len(keyEnd)])
	if err != nil || len(priv) != keySize {
		return Key{}, fmt.Errorf("channel: identity key %s: not a 32-byte base64 key", path)
	}
	return keyFrom(priv)
}

// Marshal is the content of an identity key file.
func (k Key) Marshal() []byte {
	return []byte(keyBegin + base64.StdEncoding.EncodeToString(k.Private) + keyEnd)
}

// WriteKey replaces path atomically, so that a crash never leaves lukd with
// a truncated identity.
func WriteKey(path string, k Key) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o640); err == nil {
		if _, err = f.Write(k.Marshal()); err == nil {
			err = f.Sync()
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
