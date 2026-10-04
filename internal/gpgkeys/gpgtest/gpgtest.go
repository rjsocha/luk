// Package gpgtest generates OpenPGP keys for tests.
package gpgtest

import (
	"bytes"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func config(created time.Time, lifetime time.Duration) *packet.Config {
	return &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Curve:           packet.Curve25519,
		KeyLifetimeSecs: uint32(lifetime / time.Second),
		Time:            func() time.Time { return created },
	}
}

// New is a key for email with an encryption subkey.
func New(t testing.TB, email string) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("Test", "", email, config(time.Now().Add(-time.Minute), 0))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Expired is a key for email that expired an hour ago.
func Expired(t testing.TB, email string) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("Test", "", email, config(time.Now().Add(-3*time.Hour), 2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Revoked is a revoked key for email.
func Revoked(t testing.TB, email string) *openpgp.Entity {
	t.Helper()
	e := New(t, email)
	if err := e.Revoke(packet.KeyCompromised, "test", config(time.Now().Add(-time.Minute), 0)); err != nil {
		t.Fatal(err)
	}
	return e
}

// Public is the binary public key ring of the entities.
func Public(t testing.TB, ents ...*openpgp.Entity) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, e := range ents {
		if err := e.Serialize(&b); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

// Armored is the armored public key ring of the entities.
func Armored(t testing.TB, ents ...*openpgp.Entity) []byte {
	t.Helper()
	return armored(t, openpgp.PublicKeyType, Public(t, ents...))
}

// ArmoredPrivate is the armored secret key of e.
func ArmoredPrivate(t testing.TB, e *openpgp.Entity) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := e.SerializePrivate(&b, nil); err != nil {
		t.Fatal(err)
	}
	return armored(t, openpgp.PrivateKeyType, b.Bytes())
}

func armored(t testing.TB, typ string, data []byte) []byte {
	var b bytes.Buffer
	w, err := armor.Encode(&b, typ, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Decrypt reads an OpenPGP message with the secret keys of ents.
func Decrypt(t testing.TB, msg []byte, ents ...*openpgp.Entity) []byte {
	t.Helper()
	md, err := openpgp.ReadMessage(bytes.NewReader(msg), openpgp.EntityList(ents), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(md.UnverifiedBody); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
