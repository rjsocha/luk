// Package sshsig signs and verifies OpenSSH signatures (PROTOCOL.sshsig),
// the format of `ssh-keygen -Y sign`. The signer is any ssh.Signer: an
// agent key, a key file, or a certificate signer.
package sshsig

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	magic   = "SSHSIG"
	version = 1
	hashAlg = "sha512"
	begin   = "-----BEGIN SSH SIGNATURE-----"
	end     = "-----END SSH SIGNATURE-----"
)

// Signature is a parsed SSHSIG.
type Signature struct {
	Key       ssh.PublicKey
	Namespace string
	Sig       *ssh.Signature
}

type wireSig struct {
	Version   uint32
	Key       []byte
	Namespace string
	Reserved  string
	HashAlg   string
	Sig       []byte
}

func signedData(namespace string, message []byte) []byte {
	h := sha512.Sum512(message)
	return append([]byte(magic), ssh.Marshal(struct {
		Namespace, Reserved, HashAlg string
		Hash                         []byte
	}{namespace, "", hashAlg, h[:]})...)
}

func baseType(k ssh.PublicKey) string {
	if c, ok := k.(*ssh.Certificate); ok {
		return c.Key.Type()
	}
	return k.Type()
}

// Sign signs message under namespace. RSA keys sign with rsa-sha2-512.
func Sign(signer ssh.Signer, namespace string, message []byte) (*Signature, error) {
	data := signedData(namespace, message)
	pub := signer.PublicKey()
	var sig *ssh.Signature
	var err error
	if baseType(pub) == ssh.KeyAlgoRSA {
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("sshsig: RSA signer cannot use rsa-sha2-512")
		}
		sig, err = as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
	} else {
		sig, err = signer.Sign(rand.Reader, data)
	}
	if err != nil {
		return nil, fmt.Errorf("sshsig: sign: %w", err)
	}
	return &Signature{Key: pub, Namespace: namespace, Sig: sig}, nil
}

// Marshal returns the raw SSHSIG blob.
func (s *Signature) Marshal() []byte {
	return append([]byte(magic), ssh.Marshal(wireSig{
		Version:   version,
		Key:       s.Key.Marshal(),
		Namespace: s.Namespace,
		HashAlg:   hashAlg,
		Sig:       ssh.Marshal(s.Sig),
	})...)
}

// Armor encodes s like ssh-keygen -Y sign.
func (s *Signature) Armor() []byte {
	enc := base64.StdEncoding.EncodeToString(s.Marshal())
	var b strings.Builder
	b.WriteString(begin + "\n")
	for len(enc) > 70 {
		b.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	b.WriteString(enc + "\n" + end + "\n")
	return []byte(b.String())
}

// ParseBlob decodes a raw SSHSIG blob.
func ParseBlob(blob []byte) (*Signature, error) {
	if !bytes.HasPrefix(blob, []byte(magic)) {
		return nil, errors.New("sshsig: bad magic")
	}
	var w wireSig
	if err := ssh.Unmarshal(blob[len(magic):], &w); err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	if w.Version != version || w.HashAlg != hashAlg {
		return nil, fmt.Errorf("sshsig: unsupported version %d or hash %q", w.Version, w.HashAlg)
	}
	key, err := ssh.ParsePublicKey(w.Key)
	if err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	sig := new(ssh.Signature)
	if err := ssh.Unmarshal(w.Sig, sig); err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	return &Signature{Key: key, Namespace: w.Namespace, Sig: sig}, nil
}

// Parse decodes an armored SSHSIG.
func Parse(armored []byte) (*Signature, error) {
	s := strings.TrimSpace(string(armored))
	if !strings.HasPrefix(s, begin) || !strings.HasSuffix(s, end) {
		return nil, errors.New("sshsig: not an armored SSH signature")
	}
	s = strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimPrefix(s, begin), end)), "")
	blob, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	return ParseBlob(blob)
}

// MinRSABits is the smallest RSA modulus CheckKey accepts.
const MinRSABits = 2048

// CheckKey refuses keys too weak to be trusted: DSA (ssh-dss, 1024 bits
// with SHA-1) and RSA below MinRSABits. For a certificate it checks the
// certified key; its CA key is the caller's (a configured key).
func CheckKey(pub ssh.PublicKey) error {
	if c, ok := pub.(*ssh.Certificate); ok {
		pub = c.Key
	}
	switch pub.Type() {
	case ssh.KeyAlgoDSA:
		return fmt.Errorf("%s keys are not accepted", ssh.KeyAlgoDSA)
	case ssh.KeyAlgoRSA:
		ck, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("unreadable RSA key")
		}
		k, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return errors.New("unreadable RSA key")
		}
		if n := k.N.BitLen(); n < MinRSABits {
			return fmt.Errorf("RSA key of %d bits, at least %d required", n, MinRSABits)
		}
	}
	return nil
}

// CheckFormat refuses the signature formats hashed with SHA-1: ssh-rsa
// (RSA keys sign rsa-sha2-256 or rsa-sha2-512 instead) and ssh-dss.
func CheckFormat(format string) error {
	if format == ssh.KeyAlgoRSA || format == ssh.KeyAlgoDSA {
		return fmt.Errorf("signature format %s (SHA-1) is not accepted", format)
	}
	return nil
}

// Verify checks that s signs message under namespace with its embedded key,
// refusing weak keys and SHA-1 signature formats (see CheckKey,
// CheckFormat). Who that key belongs to is the caller's decision.
func (s *Signature) Verify(namespace string, message []byte) error {
	if s.Namespace != namespace {
		return fmt.Errorf("sshsig: namespace %q, want %q", s.Namespace, namespace)
	}
	if err := CheckFormat(s.Sig.Format); err != nil {
		return fmt.Errorf("sshsig: %w", err)
	}
	if err := CheckKey(s.Key); err != nil {
		return fmt.Errorf("sshsig: %w", err)
	}
	return s.Key.Verify(signedData(namespace, message), s.Sig)
}
