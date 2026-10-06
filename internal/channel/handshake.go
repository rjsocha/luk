// Package channel is the end-to-end protocol between luk and the lukd
// endpoints: a Noise NX handshake authenticates lukd by its static
// identity key, then requests and responses travel as AEAD frames with
// explicit nonces. TLS, when present, is only transport. The package does
// no HTTP: callers carry the bodies built and read here.
package channel

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"
)

const (
	handshakeRequestSize = 1 + 32
	prologuePrefix       = "luk-channel@1\n"
)

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// Prologue binds the handshake to the URL the client posts to, so that a
// handshake relayed to another endpoint does not finish.
func Prologue(host, path string) []byte {
	return []byte(prologuePrefix + host + "\n" + path)
}

// ClientHandshake is the initiator between its two messages. It finishes
// once.
type ClientHandshake struct {
	hs   *noise.HandshakeState
	used bool
}

// NewClientHandshake starts a handshake and returns the request body.
func NewClientHandshake(host, path string) (*ClientHandshake, []byte, error) {
	return newClientHandshake(rand.Reader, host, path)
}

// newClientHandshake is NewClientHandshake with the ephemeral key read
// from random; the test vectors fix it.
func newClientHandshake(random io.Reader, host, path string) (*ClientHandshake, []byte, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite,
		Random:      random,
		Pattern:     noise.HandshakeNX,
		Initiator:   true,
		Prologue:    Prologue(host, path),
	})
	if err != nil {
		return nil, nil, err
	}
	msg, _, _, err := hs.WriteMessage([]byte{typeHandshake}, nil)
	if err != nil {
		return nil, nil, err
	}
	return &ClientHandshake{hs: hs}, msg, nil
}

// Finish reads the response body and returns the session and the static
// key of lukd. The caller must check that key against its pins before the
// session carries anything.
func (c *ClientHandshake) Finish(respBody []byte) (*Session, []byte, error) {
	if c.used {
		return nil, nil, errors.New("channel: handshake already finished")
	}
	c.used = true
	if len(respBody) == 0 || respBody[0] != typeHandshake {
		return nil, nil, errors.New("channel: not a handshake response")
	}
	payload, cs1, cs2, err := c.hs.ReadMessage(nil, respBody[1:])
	if err != nil {
		return nil, nil, fmt.Errorf("channel: handshake: %w", err)
	}
	if len(payload) != 0 || cs1 == nil || cs2 == nil {
		return nil, nil, errors.New("channel: handshake response is malformed")
	}
	return sessionFrom(cs1.Cipher(), cs2.Cipher(), c.hs.ChannelBinding()), c.hs.PeerStatic(), nil
}

// ServerHandshake answers a handshake request with the identity key k.
func ServerHandshake(k Key, host, path string, reqBody []byte) (*Session, []byte, error) {
	return serverHandshake(rand.Reader, k, host, path, reqBody)
}

// serverHandshake is ServerHandshake with the ephemeral key read from
// random; the test vectors fix it.
func serverHandshake(random io.Reader, k Key, host, path string, reqBody []byte) (*Session, []byte, error) {
	if len(reqBody) != handshakeRequestSize || reqBody[0] != typeHandshake {
		return nil, nil, errors.New("channel: not a handshake request")
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Random:        random,
		Pattern:       noise.HandshakeNX,
		Prologue:      Prologue(host, path),
		StaticKeypair: noise.DHKey{Private: k.Private, Public: k.Public},
	})
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, reqBody[1:]); err != nil {
		return nil, nil, fmt.Errorf("channel: handshake: %w", err)
	}
	msg, cs1, cs2, err := hs.WriteMessage([]byte{typeHandshake}, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("channel: handshake: %w", err)
	}
	// The first cipher state is the initiator's sending direction.
	return sessionFrom(cs2.Cipher(), cs1.Cipher(), hs.ChannelBinding()), msg, nil
}
