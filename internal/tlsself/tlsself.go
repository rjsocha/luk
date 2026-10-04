// Package tlsself makes the self-signed certificate lukd serves and computes
// the SPKI pin clients trust it by.
package tlsself

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
}

func PinFile(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s: no PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return Pin(cert), nil
}

const (
	Ed25519   = "ed25519"
	ECDSAP256 = "ecdsa-p256"
)

func newKey(algorithm string) (crypto.PublicKey, crypto.Signer, error) {
	switch algorithm {
	case "", Ed25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		return pub, priv, err
	case ECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv.Public(), priv, nil
	}
	return nil, nil, fmt.Errorf("unknown tls algorithm %q", algorithm)
}

// Generate writes a 10-year self-signed certificate with a key of the given
// algorithm (ed25519 when empty). It never overwrites: a new key means a new
// pin for every client.
func Generate(certPath, keyPath, host, algorithm string) (string, error) {
	if filepath.Clean(certPath) == filepath.Clean(keyPath) {
		return "", fmt.Errorf("%s: certificate and key must be different files", certPath)
	}
	pub, priv, err := newKey(algorithm)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	for _, p := range []string{certPath, keyPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "", err
		}
	}
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", err
	}
	if err := writeNew(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		os.Remove(keyPath)
		return "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	return Pin(cert), nil
}

func writeNew(p string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists; remove it to generate a new key (the pin changes)", p)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(p)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(p)
		return err
	}
	return nil
}
