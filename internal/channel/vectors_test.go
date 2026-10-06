package channel

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"

	"luk/internal/sshsig"
	"luk/internal/wire"
)

// protocolDoc is the client contract whose test vectors this test
// recomputes, so the document cannot drift from the code.
const protocolDoc = "../../doc/PROTOCOL.md"

// vector is one named value of the vector block of the document.
type vector struct {
	name, value string
	// wrap marks a value that the document splits over lines.
	wrap bool
}

// seq is n bytes counting up from first.
func seq(first byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = first + byte(i)
	}
	return b
}

// computeVectors runs the exchange of the document with its fixed inputs
// and returns every value in the order of the document.
func computeVectors(t *testing.T) []vector {
	t.Helper()
	var out []vector
	add := func(name, value string, wrap bool) { out = append(out, vector{name, value, wrap}) }
	hx := func(name string, b []byte) { add(name, hex.EncodeToString(b), true) }

	const (
		host      = "lukd.example:8443"
		path      = "/drop"
		timestamp = "2026-10-06T12:00:00Z"
	)
	clientSeed := seq(0x00, 32)
	serverPriv := seq(0x20, 32)
	clientEph := seq(0x40, 32)
	serverEph := seq(0x60, 32)
	nonceBytes := seq(0x80, 16)
	data := []byte("hello, luk\n")

	hx("client.seed", clientSeed)
	hx("server.static.private", serverPriv)
	hx("client.ephemeral.private", clientEph)
	hx("server.ephemeral.private", serverEph)
	add("host", host, false)
	add("path", path, false)
	add("timestamp", timestamp, false)
	hx("nonce.bytes", nonceBytes)
	hx("part.data", data)

	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(clientSeed))
	if err != nil {
		t.Fatal(err)
	}
	add("client.public", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), false)
	add("client.fingerprint", ssh.FingerprintSHA256(signer.PublicKey()), false)
	k, err := keyFrom(serverPriv)
	if err != nil {
		t.Fatal(err)
	}
	hx("server.static.public", k.Public)
	add("server.pin.key", KeyString(k.Public), false)
	add("server.pin.words", Words(k.Public), false)

	// The handshake, with the ephemeral keys read from the fixed inputs.
	hs, msg1, err := newClientHandshake(bytes.NewReader(clientEph), host, path)
	if err != nil {
		t.Fatal(err)
	}
	hx("prologue", Prologue(host, path))
	hx("handshake.request", msg1)
	srv, msg2, err := serverHandshake(bytes.NewReader(serverEph), k, host, path, msg1)
	if err != nil {
		t.Fatal(err)
	}
	hx("handshake.response", msg2)
	cli, peer, err := hs.Finish(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(peer, k.Public) || !bytes.Equal(cli.H(), srv.H()) || cli.ID() != srv.ID() {
		t.Fatal("the two sides of the handshake disagree")
	}
	k1, k2 := noiseNX(t, Prologue(host, path), msg1[1:], serverEph, serverPriv, msg2, cli.H())
	hx("h", cli.H())
	add("h.base64url", base64.RawURLEncoding.EncodeToString(cli.H()), false)
	id := cli.ID()
	hx("channel.id", id[:])
	hx("transport.k1", k1[:])
	hx("transport.k2", k2[:])

	// The signed OP of an upload of part.data as a file, as luk builds it.
	sum := sha256.Sum256(data)
	size := int64(len(data))
	meta := wire.Meta{File: "hello.txt", Source: wire.SourceFile, Size: &size, SHA256: hex.EncodeToString(sum[:]), Portal: wire.PortalDirect}
	metaS, err := wire.EncodeMeta(meta)
	if err != nil {
		t.Fatal(err)
	}
	metaJSON, _ := base64.RawURLEncoding.DecodeString(metaS)
	add("meta.json", string(metaJSON), false)
	add("meta", metaS, true)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	add("nonce", nonce, false)
	text := wire.CanonicalText(host, path, timestamp, nonce, metaS, cli.H())
	hx("signed.text", text)
	sig, err := sshsig.Sign(signer, wire.Namespace, text)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify(wire.Namespace, text); err != nil {
		t.Fatal(err)
	}
	sigS := base64.StdEncoding.EncodeToString(sig.Marshal())
	add("signature", sigS, true)
	header := http.Header{}
	header.Set(wire.HeaderMeta, metaS)
	header.Set(wire.HeaderTimestamp, timestamp)
	header.Set(wire.HeaderNonce, nonce)
	header.Set(wire.HeaderSignature, sigS)
	var op bytes.Buffer
	if err := WriteHead(&op, Request{Method: http.MethodPut, Target: path, Header: header}); err != nil {
		t.Fatal(err)
	}
	hx("op.plaintext", op.Bytes())

	// A message sealed by the client, opened by lukd: its clear header and
	// its frames, the first of them shown.
	message := func(prefix string, n Nonce, plain []byte) {
		var sealed bytes.Buffer
		if err := cli.SealRequest(&sealed, n, bytes.NewReader(plain)); err != nil {
			t.Fatal(err)
		}
		var nb [8]byte
		binary.BigEndian.PutUint64(nb[:], n.Uint64())
		hx(prefix+".nonce", nb[:])
		hx(prefix+".header", sealed.Bytes()[:requestHeaderSize])
		frame0 := sealed.Bytes()[requestHeaderSize:min(sealed.Len(), requestHeaderSize+sealedFrame)]
		hx(prefix+".frame0", frame0)
		// A message of one frame, sealed by hand under k1: the nonce with
		// frame 0 and last set, the clear header as the AD.
		one := n
		one.Last = true
		if len(plain) >= FrameSize || !bytes.Equal(noise.CipherChaChaPoly.Cipher(k1).Encrypt(nil, one.Uint64(), sealed.Bytes()[:requestHeaderSize], plain), frame0) {
			t.Fatalf("%s: k1 does not give the frame of the session", prefix)
		}
		r := bytes.NewReader(sealed.Bytes())
		gotID, gotN, hdr, err := ParseRequestHeader(r)
		if err != nil || gotID != id || gotN != n {
			t.Fatalf("%s: header: %v", prefix, err)
		}
		got, err := io.ReadAll(srv.OpenRequest(r, hdr, gotN))
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%s: lukd does not open the message: %v", prefix, err)
		}
	}
	opNonce := Nonce{Kind: KindOp}
	message("op", opNonce, op.Bytes())
	message("part", Nonce{Kind: KindPart}, data)

	// The answer of lukd to the OP: the parts offer, as lukd writes it.
	var offer wire.PartsOffer
	offer.Parts.Size, offer.Parts.Parallel, offer.Parts.Idle, offer.Parts.Rate = 8<<20, 4, 120, 64<<10
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetIndent("", "  ")
	if err := enc.Encode(offer); err != nil {
		t.Fatal(err)
	}
	var resp bytes.Buffer
	if err := WriteHead(&resp, Response{Status: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}}); err != nil {
		t.Fatal(err)
	}
	resp.Write(body.Bytes())
	hx("response.plaintext", resp.Bytes())
	var sealed bytes.Buffer
	fw, err := srv.SealResponse(&sealed, opNonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(resp.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	hx("response.header", sealed.Bytes()[:responseHeaderSize])
	hx("response.frame0", sealed.Bytes()[responseHeaderSize:])
	if !bytes.Equal(noise.CipherChaChaPoly.Cipher(k2).Encrypt(nil, ResponseNonce(1, 0, true), srv.responseAD(opNonce, 1), resp.Bytes()), sealed.Bytes()[responseHeaderSize:]) {
		t.Fatal("k2 does not give the answer of the session")
	}
	rc, err := cli.OpenResponse(bytes.NewReader(sealed.Bytes()), opNonce)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	if err != nil || !bytes.Equal(got, resp.Bytes()) {
		t.Fatalf("luk does not open the answer: %v", err)
	}
	return out
}

// noiseNX runs the responder side of Noise_NX_25519_ChaChaPoly_SHA256 by
// the Noise specification, apart from the library the channel uses: it
// must give the same message 2 and handshake hash, and returns the two
// transport keys of Split (k1 initiator to responder, k2 back).
func noiseNX(t *testing.T, prologue, ce, se, ss, msg2, wantH []byte) (k1, k2 [32]byte) {
	t.Helper()
	const name = "Noise_NX_25519_ChaChaPoly_SHA256"
	// The name is 32 bytes long: it is the initial hash as it is.
	h := [32]byte([]byte(name))
	ck := h
	mix := func(data []byte) { h = sha256.Sum256(append(h[:], data...)) }
	hkdf := func(ikm []byte) (a, b [32]byte) {
		mac := func(key, data []byte) []byte { m := hmac.New(sha256.New, key); m.Write(data); return m.Sum(nil) }
		tk := mac(ck[:], ikm)
		o1 := mac(tk, []byte{1})
		o2 := mac(tk, append(append([]byte{}, o1...), 2))
		return [32]byte(o1), [32]byte(o2)
	}
	dh := func(priv, pub []byte) []byte {
		out, err := curve25519.X25519(priv, pub)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	pub := func(priv []byte) []byte { return dh(priv, curve25519.Basepoint) }
	var k [32]byte
	var n uint64
	mixKey := func(ikm []byte) { ck, k = hkdf(ikm); n = 0 }
	encrypt := func(pt []byte) []byte {
		var nonce [12]byte
		binary.LittleEndian.PutUint64(nonce[4:], n)
		n++
		aead, err := chacha20poly1305.New(k[:])
		if err != nil {
			t.Fatal(err)
		}
		c := aead.Seal(nil, nonce[:], pt, h[:])
		mix(c)
		return c
	}
	mix(prologue)
	mix(ce)  // -> e
	mix(nil) // empty payload, no key yet
	sep := pub(se)
	out := append([]byte{typeHandshake}, sep...)
	mix(sep)                               // <- e
	mixKey(dh(se, ce))                     // ee
	out = append(out, encrypt(pub(ss))...) // s
	mixKey(dh(ss, ce))                     // es
	out = append(out, encrypt(nil)...)     // empty payload
	if !bytes.Equal(out, msg2) || !bytes.Equal(h[:], wantH) {
		t.Fatal("the Noise specification gives another handshake than the channel")
	}
	return hkdf(nil)
}

// formatVectors is the vector block as the document holds it.
func formatVectors(vs []vector) string {
	const col, width = 26, 64
	var b strings.Builder
	for _, v := range vs {
		val := v.value
		first := true
		for {
			chunk := val
			if v.wrap && len(chunk) > width {
				chunk = val[:width]
			}
			name := ""
			if first {
				name = v.name
			}
			fmt.Fprintf(&b, "%-*s%s\n", col, name, chunk)
			val, first = val[len(chunk):], false
			if val == "" {
				break
			}
		}
	}
	return b.String()
}

// docVectors parses the vector block of the document: a name and its
// value per line, a line starting with blanks continuing the value
// above.
func docVectors(doc string) ([]vector, error) {
	const open, end = "```vectors\n", "```"
	i := strings.Index(doc, open)
	if i < 0 {
		return nil, fmt.Errorf("no %q block", strings.TrimSpace(open))
	}
	block := doc[i+len(open):]
	j := strings.Index(block, end)
	if j < 0 {
		return nil, fmt.Errorf("vector block not closed")
	}
	var vs []vector
	sc := bufio.NewScanner(strings.NewReader(block[:j]))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.TrimSpace(line) == "":
		case line[0] == ' ':
			if len(vs) == 0 {
				return nil, fmt.Errorf("continuation without a name: %q", line)
			}
			vs[len(vs)-1].value += strings.TrimSpace(line)
		default:
			name, value, _ := strings.Cut(line, " ")
			vs = append(vs, vector{name: name, value: strings.TrimSpace(value)})
		}
	}
	return vs, nil
}

func TestProtocolVectors(t *testing.T) {
	raw, err := os.ReadFile(protocolDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	want := computeVectors(t)
	got, err := docVectors(doc)
	if err != nil {
		t.Fatal(err)
	}
	bad := len(got) != len(want)
	for i := range min(len(got), len(want)) {
		if got[i].name != want[i].name || got[i].value != want[i].value {
			t.Errorf("vector %d: document has %s = %s, the code gives %s = %s", i, got[i].name, got[i].value, want[i].name, want[i].value)
			bad = true
		}
	}
	if len(got) != len(want) {
		t.Errorf("document has %d vectors, the code gives %d", len(got), len(want))
	}
	// The readable forms in the document show the same values.
	values := map[string]string{}
	for _, v := range want {
		values[v.name] = v.value
	}
	text, _ := hex.DecodeString(values["signed.text"])
	for _, s := range []string{"```text\n" + string(text) + "\n```", "`" + values["meta.json"] + "`"} {
		if !strings.Contains(doc, s) {
			t.Errorf("document does not show %q", s)
			bad = true
		}
	}
	if bad {
		t.Logf("the vector block the code gives:\n%s", formatVectors(want))
	}
}
