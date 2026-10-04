package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}

// LoadSigner picks the signing key: "" - the first key of the SSH agent;
// SHA256:... - the agent key with that fingerprint; a .pub file - that key in
// the agent; anything else - a private key file, with PATH-cert.pub used as
// its certificate when present.
func LoadSigner(keyArg string) (ssh.Signer, error) {
	if keyArg == "" {
		s, _, err := FirstAgentSigner()
		return s, err
	}
	if strings.HasPrefix(keyArg, fingerprintPrefix) {
		if err := ValidateFingerprint(keyArg); err != nil {
			return nil, err
		}
		signers, err := agentSigners()
		if err != nil {
			return nil, err
		}
		for _, s := range signers {
			if hasFingerprint(s.PublicKey(), keyArg) {
				return s, nil
			}
		}
		return nil, fmt.Errorf("key %s is not in the SSH agent", keyArg)
	}
	p := expandHome(keyArg)
	if strings.HasSuffix(p, ".pub") {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		signers, err := agentSigners()
		if err != nil {
			return nil, err
		}
		for _, s := range signers {
			if bytes.Equal(s.PublicKey().Marshal(), pub.Marshal()) {
				return s, nil
			}
		}
		return nil, fmt.Errorf("key %s is not in the SSH agent", ssh.FingerprintSHA256(pub))
	}
	return fileSigner(p)
}

// FirstAgentSigner returns the first key of the SSH agent and how many keys
// the agent holds.
func FirstAgentSigner() (ssh.Signer, int, error) {
	signers, err := agentSigners()
	if err != nil {
		return nil, 0, err
	}
	return signers[0], len(signers), nil
}

// AgentSigners returns the keys of the SSH agent, in agent order.
func AgentSigners() ([]ssh.Signer, error) { return agentSigners() }

const fingerprintPrefix = "SHA256:"

// ValidateFingerprint checks the form ssh.FingerprintSHA256 prints: SHA256:
// and unpadded base64 of 32 bytes.
func ValidateFingerprint(fp string) error {
	b64, ok := strings.CutPrefix(fp, fingerprintPrefix)
	if raw, err := base64.RawStdEncoding.Strict().DecodeString(b64); !ok || err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("key %q is not a fingerprint, want SHA256: and 43 base64 characters", fp)
	}
	return nil
}

// hasFingerprint matches a key, or a certificate by the key it certifies, as
// ssh-add -l prints it.
func hasFingerprint(pub ssh.PublicKey, fp string) bool {
	if ssh.FingerprintSHA256(pub) == fp {
		return true
	}
	c, ok := pub.(*ssh.Certificate)
	return ok && ssh.FingerprintSHA256(c.Key) == fp
}

// AgentKey is one key of the SSH agent.
type AgentKey struct {
	Fingerprint string
	Type        string
	Comment     string
}

// AgentKeys lists the keys of the SSH agent; a certificate is listed by the
// fingerprint of the key it certifies, as ssh-add -l prints it.
func AgentKeys() ([]AgentKey, error) {
	ag, closer, err := agentClient()
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("SSH agent: %w", err)
	}
	list := make([]AgentKey, 0, len(keys))
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		if c, ok := pub.(*ssh.Certificate); ok {
			pub = c.Key
		}
		list = append(list, AgentKey{Fingerprint: ssh.FingerprintSHA256(pub), Type: k.Format, Comment: k.Comment})
	}
	return list, nil
}

func agentClient() (agent.ExtendedAgent, io.Closer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, errors.New("no SSH agent (SSH_AUTH_SOCK is empty); pass --key with a private key file")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("SSH agent: %w", err)
	}
	return agent.NewClient(conn), conn, nil
}

func agentSigners() ([]ssh.Signer, error) {
	ag, _, err := agentClient()
	if err != nil {
		return nil, err
	}
	signers, err := ag.Signers()
	if err != nil {
		return nil, fmt.Errorf("SSH agent: %w", err)
	}
	if len(signers) == 0 {
		return nil, errors.New("SSH agent has no keys")
	}
	return signers, nil
}

func fileSigner(p string) (ssh.Signer, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		pass, perr := readPassphrase(fmt.Sprintf("passphrase for %s: ", p))
		if perr != nil {
			return nil, perr
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, pass)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	certData, err := os.ReadFile(p + "-cert.pub")
	if errors.Is(err, fs.ErrNotExist) {
		return signer, nil
	}
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return nil, fmt.Errorf("%s-cert.pub: %w", p, err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("%s-cert.pub is not a certificate", p)
	}
	return ssh.NewCertSigner(cert, signer)
}

func readPassphrase(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("key is encrypted and there is no terminal: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	pass, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return pass, err
}
