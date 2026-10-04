// Package acmetest is a minimal ACME CA for tests: one TLS directory that
// registers accounts, validates http-01 challenges by fetching them from
// a given address and signs the CSRs with its own root. It checks no
// signatures; it is only as strict as the tests need.
package acmetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type CA struct {
	Srv  *httptest.Server
	Root *x509.Certificate
	key  *ecdsa.PrivateKey

	mu sync.Mutex
	// http01 is host:port where challenges are fetched (the acme: true
	// listener); set with SetHTTP01.
	http01   string
	lifetime time.Duration
	n        int
	accounts map[string]string // kid -> jwk thumbprint
	orders   map[string]*order
	authz    map[string]*authz
	// Registrations lists the payload of every new account request.
	Registrations []Registration
	// Issued counts the certificates signed.
	Issued  int
	revoked []Revocation
}

// Revocation is a revokeCert request the CA accepted.
type Revocation struct {
	Serial string // hex
	Reason int
}

// Registration is what a client sent to newAccount.
type Registration struct {
	Contact []string
	EAB     bool
}

type order struct {
	id     string
	names  []string
	authz  []string
	status string
	chain  []byte
}

type authz struct {
	id, name, token, status, account string
}

// New starts the CA; it stops with the test.
func New(t testing.TB) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acmetest root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(der)
	ca := &CA{Root: root, key: key, lifetime: 90 * 24 * time.Hour,
		accounts: map[string]string{}, orders: map[string]*order{}, authz: map[string]*authz{}}
	ca.Srv = httptest.NewTLSServer(http.HandlerFunc(ca.serve))
	t.Cleanup(ca.Srv.Close)
	return ca
}

// Directory is the directory URL.
func (ca *CA) Directory() string { return ca.Srv.URL + "/dir" }

// Client talks to the CA (it trusts the test server certificate).
func (ca *CA) Client() *http.Client { return ca.Srv.Client() }

// SetHTTP01 sets host:port the challenges are fetched from.
func (ca *CA) SetHTTP01(addr string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.http01 = addr
}

// SetLifetime sets the validity of the certificates signed from now on.
func (ca *CA) SetLifetime(d time.Duration) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.lifetime = d
}

// Revoked returns the revocations accepted so far.
func (ca *CA) Revoked() []Revocation {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return slices.Clone(ca.revoked)
}

// Count returns the number of certificates signed.
func (ca *CA) Count() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.Issued
}

func (ca *CA) serve(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	ca.n++
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", ca.n))
	ca.mu.Unlock()
	base := ca.Srv.URL
	switch {
	case r.URL.Path == "/dir":
		writeJSON(w, http.StatusOK, map[string]any{
			"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order",
			"revokeCert": base + "/revoke", "keyChange": base + "/keychange",
			"meta": map[string]any{"termsOfService": base + "/tos"},
		})
		return
	case r.URL.Path == "/nonce":
		w.WriteHeader(http.StatusOK)
		return
	case r.Method != http.MethodPost:
		problem(w, http.StatusMethodNotAllowed, "malformed", "POST only")
		return
	}
	var jws struct{ Protected, Payload string }
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		problem(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	var prot struct {
		KID string          `json:"kid"`
		JWK json.RawMessage `json:"jwk"`
	}
	if b, err := base64.RawURLEncoding.DecodeString(jws.Protected); err != nil || json.Unmarshal(b, &prot) != nil {
		problem(w, http.StatusBadRequest, "malformed", "protected header")
		return
	}
	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	ca.mu.Lock()
	defer ca.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch parts[0] {
	case "account":
		ca.account(w, prot.JWK, payload)
	case "revoke":
		ca.revoke(w, prot.KID, payload)
	case "order":
		if len(parts) == 1 {
			ca.newOrder(w, prot.KID, payload)
		} else {
			ca.writeOrder(w, http.StatusOK, ca.orders[parts[1]])
		}
	case "authz":
		ca.writeAuthz(w, ca.authz[parts[1]])
	case "chal":
		ca.challenge(w, ca.authz[parts[1]])
	case "finalize":
		ca.finalize(w, ca.orders[parts[1]], payload)
	case "cert":
		o := ca.orders[parts[1]]
		if o == nil || o.chain == nil {
			problem(w, http.StatusNotFound, "malformed", "no certificate")
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(o.chain)
	default:
		problem(w, http.StatusNotFound, "malformed", "unknown path")
	}
}

func (ca *CA) account(w http.ResponseWriter, jwk json.RawMessage, payload []byte) {
	var req struct {
		Contact            []string        `json:"contact"`
		EAB                json.RawMessage `json:"externalAccountBinding"`
		OnlyReturnExisting bool            `json:"onlyReturnExisting"`
	}
	_ = json.Unmarshal(payload, &req)
	thumb, err := thumbprint(jwk)
	if err != nil {
		problem(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	kid := ca.Srv.URL + "/acct/" + thumb
	if req.OnlyReturnExisting {
		if _, ok := ca.accounts[kid]; !ok {
			problem(w, http.StatusBadRequest, "accountDoesNotExist", "unknown account")
			return
		}
		w.Header().Set("Location", kid)
		writeJSON(w, http.StatusOK, map[string]any{"status": "valid"})
		return
	}
	ca.Registrations = append(ca.Registrations, Registration{Contact: req.Contact, EAB: len(req.EAB) > 0})
	code := http.StatusCreated
	if _, ok := ca.accounts[kid]; ok {
		code = http.StatusOK
	}
	ca.accounts[kid] = thumb
	w.Header().Set("Location", kid)
	writeJSON(w, code, map[string]any{"status": "valid", "contact": req.Contact})
}

func (ca *CA) newOrder(w http.ResponseWriter, kid string, payload []byte) {
	if _, ok := ca.accounts[kid]; !ok {
		problem(w, http.StatusUnauthorized, "accountDoesNotExist", "unknown account")
		return
	}
	var req struct {
		Identifiers []struct{ Type, Value string }
	}
	_ = json.Unmarshal(payload, &req)
	ca.n++
	o := &order{id: fmt.Sprint(ca.n), status: "pending"}
	for _, id := range req.Identifiers {
		ca.n++
		z := &authz{id: fmt.Sprint(ca.n), name: id.Value, token: fmt.Sprintf("token-%d", ca.n), status: "pending", account: ca.accounts[kid]}
		ca.authz[z.id] = z
		o.names = append(o.names, id.Value)
		o.authz = append(o.authz, z.id)
	}
	ca.orders[o.id] = o
	ca.writeOrder(w, http.StatusCreated, o)
}

func (ca *CA) writeOrder(w http.ResponseWriter, code int, o *order) {
	if o == nil {
		problem(w, http.StatusNotFound, "malformed", "no order")
		return
	}
	if o.status == "pending" {
		ready := true
		for _, id := range o.authz {
			ready = ready && ca.authz[id].status == "valid"
		}
		if ready {
			o.status = "ready"
		}
	}
	base := ca.Srv.URL
	var ids []map[string]string
	for _, n := range o.names {
		ids = append(ids, map[string]string{"type": "dns", "value": n})
	}
	var az []string
	for _, id := range o.authz {
		az = append(az, base+"/authz/"+id)
	}
	v := map[string]any{"status": o.status, "identifiers": ids, "authorizations": az, "finalize": base + "/finalize/" + o.id}
	if o.chain != nil {
		v["certificate"] = base + "/cert/" + o.id
	}
	w.Header().Set("Location", base+"/order/"+o.id)
	writeJSON(w, code, v)
}

func (ca *CA) writeAuthz(w http.ResponseWriter, z *authz) {
	if z == nil {
		problem(w, http.StatusNotFound, "malformed", "no authorization")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     z.status,
		"identifier": map[string]string{"type": "dns", "value": z.name},
		"challenges": []map[string]string{
			{"type": "tls-alpn-01", "url": ca.Srv.URL + "/chal/" + z.id + "/alpn", "token": z.token, "status": "pending"},
			{"type": "http-01", "url": ca.Srv.URL + "/chal/" + z.id, "token": z.token, "status": z.status},
		},
	})
}

// challenge fetches the key authorization from the http01 address with
// the name as Host, as a CA does on port 80.
func (ca *CA) challenge(w http.ResponseWriter, z *authz) {
	if z == nil {
		problem(w, http.StatusNotFound, "malformed", "no authorization")
		return
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+ca.http01+"/.well-known/acme-challenge/"+z.token, nil)
	req.Host = z.name
	z.status = "invalid"
	if res, err := http.DefaultClient.Do(req); err == nil {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode == http.StatusOK && string(body) == z.token+"."+z.account {
			z.status = "valid"
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"type": "http-01", "url": ca.Srv.URL + "/chal/" + z.id, "token": z.token, "status": z.status})
}

func (ca *CA) finalize(w http.ResponseWriter, o *order, payload []byte) {
	if o == nil || o.status != "ready" {
		problem(w, http.StatusForbidden, "orderNotReady", "order not ready")
		return
	}
	var req struct{ CSR string }
	_ = json.Unmarshal(payload, &req)
	der, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		problem(w, http.StatusBadRequest, "badCSR", err.Error())
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || !slices.Equal(csr.DNSNames, o.names) {
		problem(w, http.StatusBadRequest, "badCSR", "names differ from the order")
		return
	}
	ca.n++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(ca.n)),
		Subject:      pkix.Name{CommonName: o.names[0]},
		DNSNames:     o.names,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ca.lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Root, csr.PublicKey, ca.key)
	if err != nil {
		problem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	o.chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Root.Raw})...)
	o.status = "valid"
	ca.Issued++
	ca.writeOrder(w, http.StatusOK, o)
}

// revoke accepts a certificate this CA signed, once, from a known
// account.
func (ca *CA) revoke(w http.ResponseWriter, kid string, payload []byte) {
	if _, ok := ca.accounts[kid]; !ok {
		problem(w, http.StatusUnauthorized, "accountDoesNotExist", "unknown account")
		return
	}
	var req struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"`
	}
	_ = json.Unmarshal(payload, &req)
	der, err := base64.RawURLEncoding.DecodeString(req.Certificate)
	if err != nil {
		problem(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.CheckSignatureFrom(ca.Root) != nil {
		problem(w, http.StatusNotFound, "malformed", "not issued here")
		return
	}
	serial := cert.SerialNumber.Text(16)
	for _, r := range ca.revoked {
		if r.Serial == serial {
			problem(w, http.StatusBadRequest, "alreadyRevoked", "already revoked")
			return
		}
	}
	ca.revoked = append(ca.revoked, Revocation{Serial: serial, Reason: req.Reason})
	w.WriteHeader(http.StatusOK)
}

func thumbprint(jwk json.RawMessage) (string, error) {
	var k struct{ Crv, X, Y string }
	if err := json.Unmarshal(jwk, &k); err != nil || k.Crv != "P-256" {
		return "", fmt.Errorf("unsupported jwk %s", jwk)
	}
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	if err1 != nil || err2 != nil {
		return "", fmt.Errorf("bad jwk %s", jwk)
	}
	return acme.JWKThumbprint(&ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, code int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail})
}
