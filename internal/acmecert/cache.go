package acmecert

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	// StatusFile is written by the receive role into each cache directory.
	StatusFile = "status.json"
	// RenewSuffix names a renewal request: <name>.renew in the cache
	// directory.
	RenewSuffix = ".renew"
	// AccountFile is the account key of a cache directory.
	AccountFile = accountFile
	// certSuffix names a certificate: <name>.pem.
	certSuffix = ".pem"
	// keepResults bounds the request results kept in status.json.
	keepResults = 32
)

// Status is status.json of a cache directory: the state of every name of
// the running manager and the results of the renewal requests.
type Status struct {
	Directory string                    `json:"directory"`
	Written   time.Time                 `json:"written"`
	Hosts     map[string]*HostStatus    `json:"hosts"`
	Requests  map[string]*RequestResult `json:"requests"`
}

// HostStatus is the state of one name. Serial and NotAfter are those of
// the certificate the daemon serves.
type HostStatus struct {
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	NextRetry   time.Time `json:"next_retry,omitzero"`
	Serial      string    `json:"serial,omitempty"`
	NotAfter    time.Time `json:"not_after,omitzero"`
}

// RequestResult is the outcome of a renewal request, keyed by its nonce.
type RequestResult struct {
	Host      string    `json:"host"`
	Requested time.Time `json:"requested,omitzero"`
	Done      time.Time `json:"done"`
	Serial    string    `json:"serial,omitempty"`
	NotAfter  time.Time `json:"not_after,omitzero"`
	Error     string    `json:"error,omitempty"`
}

// Request is the content of a <name>.renew file.
type Request struct {
	Requested time.Time `json:"requested"`
	Nonce     string    `json:"nonce"`
}

// ReadStatus reads status.json of the cache directory dir; nil without
// one.
func ReadStatus(dir string) (*Status, error) {
	data, err := os.ReadFile(filepath.Join(dir, StatusFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, StatusFile), err)
	}
	return &st, nil
}

// WriteRequest asks the manager of the cache directory dir to renew host
// now and returns the nonce its result is recorded under.
func WriteRequest(dir, host string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	req := Request{Requested: time.Now().UTC(), Nonce: hex.EncodeToString(b)}
	data, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return req.Nonce, writeFile(RequestFile(dir, host), append(data, '\n'))
}

// CancelRequest removes the request of host when it still carries nonce
// (the manager has not taken it).
func CancelRequest(dir, host, nonce string) {
	p := RequestFile(dir, host)
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var req Request
	if json.Unmarshal(data, &req) == nil && req.Nonce == nonce {
		_ = os.Remove(p)
	}
}

// RequestFile is the renewal request of host in dir.
func RequestFile(dir, host string) string { return filepath.Join(dir, host+RenewSuffix) }

// CertFile is the certificate of host in dir.
func CertFile(dir, host string) string { return filepath.Join(dir, host+certSuffix) }

// CertNames lists the names with a certificate in dir, in name order.
func CertNames(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		n, ok := strings.CutSuffix(e.Name(), certSuffix)
		if ok && n != "" && !strings.HasPrefix(n, ".") && e.Type().IsRegular() {
			names = append(names, n)
		}
	}
	return names, nil
}

// LoadLeaf reads the certificate of host in dir.
func LoadLeaf(dir, host string) (*x509.Certificate, error) {
	c, err := loadPair(CertFile(dir, host))
	if err != nil {
		return nil, err
	}
	return c.Leaf, nil
}

func loadPair(p string) (*tls.Certificate, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if pair.Leaf == nil {
		if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	return &pair, nil
}

// RenewAt is when the manager renews a certificate: 30 days or a third of
// its lifetime before its end, whichever is shorter. The hourly check
// after that time renews it.
func RenewAt(leaf *x509.Certificate) time.Time {
	before := leaf.NotAfter.Sub(leaf.NotBefore) / 3
	before = min(before, 30*24*time.Hour)
	return leaf.NotAfter.Add(-before)
}

// Serial is the serial number of a certificate in hex.
func Serial(leaf *x509.Certificate) string { return leaf.SerialNumber.Text(16) }

// Revoke revokes the certificate of host cached in dir at the CA of
// directory, signed with the account key of dir, and returns it.
// httpClient nil is the default client.
func Revoke(ctx context.Context, directory, dir, host string, reason acme.CRLReasonCode, httpClient *http.Client) (*x509.Certificate, error) {
	leaf, err := LoadLeaf(dir, host)
	if err != nil {
		return nil, err
	}
	key, err := loadAccountKey(filepath.Join(dir, accountFile))
	if err != nil {
		return nil, err
	}
	c := &acme.Client{Key: key, DirectoryURL: directory, HTTPClient: httpClient, UserAgent: "lukd"}
	if err := c.RevokeCert(ctx, nil, leaf.Raw, reason); err != nil {
		return nil, err
	}
	return leaf, nil
}

func loadAccountKey(p string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("%s: no EC private key", p)
	}
	return x509.ParseECPrivateKey(b.Bytes)
}
