package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"luk/internal/client"
	"luk/internal/wire"
)

func newSendCmd(out io.Writer) *cobra.Command {
	var (
		endpoint, key, ttl, name, ctype, file, bwlimit string
		permanent                                      string
		tags                                           []string
		backup, once, portal, secret, quiet, stdin     bool
		dryRun, progress, asJSON, prettyURL, noOwner   bool
		mutable, private, anyID                        bool
		links                                          int
	)
	cmd := &cobra.Command{
		Use:     "send",
		Aliases: []string{"put", "push"},
		Short:   "Upload one file to a lukd endpoint, signed by an SSH key",
		Long: `Upload one file to a lukd endpoint. The request is signed with an SSH key
(a key file, or a key held by the SSH agent). Exactly one of --file, --stdin
and a bare --secret selects the content. --stdin, and --file on a pipe or other
non-regular file, stream without a signed size or hash and without a file
name unless --name gives one; --name also overrides the name of a regular file.
A bare --secret prompts on the terminal twice, masked (both entries must
match), and sends the secret with a
signed size and hash; --secret with --stdin or --file takes the secret from
there instead; a typed secret must be valid UTF-8. Without --type a --secret
upload is text/plain; charset=utf-8. --secret serves a reveal page (a Reveal
button, then the content with a copy button); --portal serves a download page (metadata and a
Download button). Neither page serves the content on the bare URL, so link
previews do not consume a --once upload. On success it prints the URL of the
upload (respond: url), or nothing (respond: accept); --json prints the server
answer as JSON instead. --ttl max asks for the longest lifetime the storage
allows (its ttl.max, else no expiry). A --ttl the server capped, raised or
ignored is noted on stderr. --pretty-url asks for a pronounceable name in the URL
(lusab-babad-gutih-tugad), on an endpoint that offers it. The portal page shows the
sender (its key name, or host or user for a certificate); --no-owner hides it.
--mutable lets luk link --file replace the content later, keeping the URL.
--private makes the upload private: only the uploading identity downloads
it, with luk get, from the luk:// URL printed; with --any every identity
lukd knows (and its protect expose allows) does. The endpoint must accept
the mode (private.owner, private.any). --dry-run runs every server check up to the body,
sends no body, stores nothing and prints the debug JSON. --links N uploads N times with the same
options, one link each (N at most 25), and prints the N URLs one per line (--json: an array
of the N answers); the repeats carry the size and sha256 of the first answer,
so the server can answer them without the content, and resend a --file when
it asks for it; a stream (--stdin, a pipe, a prompted --secret) cannot be sent
twice, which ends the run with the links made so far. --progress reports on stderr when it is a terminal; --bwlimit
caps the upload rate in bytes per second (K, M, G, T suffixes; 0 = unlimited).
--permanent NAME publishes the file as a new version of the permanent name NAME
of the endpoint (permanent.names in lukd); the URL printed is the permanent URL,
which serves the version published last (404 once it is gone), and --json adds
the URL of the stored version (version_url). It takes no --once, --secret,
--portal, --private, --mutable, --pretty-url or --links above 1.
Exit codes: 0 ok, 1 usage/config, 2 rejected, 3 transfer or server error,
4 hash mismatch, 130 interrupted.`,
		Example: `  luk send --file report.pdf
  luk put -e drop -t nightly --ttl 7d -f dump.sql.gz
  tar c dir | luk push --stdin --name dir.tar
  luk send --file <(pg_dump db) --name db.sql --type application/sql
  luk send --file report.pdf --name q3.pdf
  luk send --secret --once
  pwgen 20 1 | luk send --secret --stdin --ttl 1h
  luk send --file report.pdf --ttl max
  luk send --file report.pdf --portal --once
  luk send --file report.pdf --portal --no-owner
  luk send --file dump.sql.gz --progress --bwlimit 10M
  luk send --file report.pdf --pretty-url
  luk send --file status.html --mutable
  luk send --file keys.tar --private
  luk send --file notes.txt --private --any
  luk send --file report.pdf --json
  luk send --file report.pdf --links 3 --once
  luk send --file report.pdf --dry-run
  luk send -e drop --file hosts.krl --permanent revocation/hosts.krl`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			hasFile := file != "" || cmd.Flags().Changed("file")
			switch {
			case hasFile && stdin:
				return usageError{errors.New("--file and --stdin are mutually exclusive")}
			case !hasFile && !stdin && !secret:
				return usageError{errors.New("one of --file, --stdin or --secret is required")}
			case portal && secret:
				return usageError{errors.New("--portal and --secret are mutually exclusive")}
			case anyID && !private:
				return usageError{errors.New("--any needs --private")}
			case private && (secret || portal):
				return usageError{errors.New("--private takes no --secret or --portal: private files are fetched with luk get")}
			case links < 1:
				return usageError{errors.New("--links must be at least 1")}
			case links > maxLinks:
				return usageError{fmt.Errorf("--links is at most %d", maxLinks)}
			case dryRun && cmd.Flags().Changed("links"):
				return usageError{errors.New("--links takes no --dry-run")}
			}
			if cmd.Flags().Changed("permanent") {
				if err := permanentFlags(permanent, links, once, secret, portal, private, mutable, prettyURL); err != nil {
					return err
				}
			}
			prompt := secret && !hasFile && !stdin
			if asJSON && quiet {
				return usageError{errors.New("--json and --quiet are mutually exclusive")}
			}
			limit, err := parseBWLimit(bwlimit)
			if err != nil {
				return err
			}
			cfg, _, err := client.LoadMerged()
			if err != nil {
				return usageError{err}
			}
			url, pin, err := resolve(cfg, endpoint)
			if err != nil {
				return err
			}
			signer, agentKeys, err := signerFor(cfg, endpoint, key)
			if err != nil {
				return err
			}
			portalMode := wire.PortalDirect
			switch {
			case secret:
				portalMode = wire.PortalReveal
				if ctype == "" {
					ctype = secretType
				}
			case portal:
				portalMode = wire.PortalDownload
			}
			meta := wire.Meta{Tags: tags, TTL: ttl, Once: once, Portal: portalMode, File: name, Type: ctype, Source: wire.SourceStdin, PrettyURL: prettyURL, NoOwner: noOwner, Mutable: mutable, DryRun: dryRun, Permanent: permanent}
			switch {
			case anyID:
				meta.Access = wire.AccessAny
			case private:
				meta.Access = wire.AccessPrivate
			}
			if err := meta.Normalize(); err != nil {
				return usageError{err}
			}
			body, size, closer, err := input(file, name, stdin, prompt, backup, &meta)
			if err != nil {
				return err
			}
			if closer != nil {
				defer closer.Close()
			}
			ctx, stop := interruptContext()
			defer stop()
			opts := client.Options{URL: url, Pin: pin, Signer: signer, Meta: meta, Body: body, Size: size, BWLimit: limit}
			if progress && term.IsTerminal(int(os.Stderr.Fd())) {
				opts.Progress = os.Stderr
			}
			// With --links the answers are printed as one JSON array.
			array := cmd.Flags().Changed("links")
			var answers []any
			printJSON := func() error {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if array {
					return enc.Encode(answers)
				}
				return enc.Encode(answers[0])
			}
			for i := range links {
				if i > 0 {
					if err := again(&opts, answers[0]); err != nil {
						return err
					}
				}
				resp, err := client.Upload(ctx, opts)
				var he *client.HashMismatchError
				if errors.As(err, &he) && resp != nil {
					// Stored anyway: show what the server kept.
					enc := json.NewEncoder(cmd.ErrOrStderr())
					enc.SetIndent("", "  ")
					_ = enc.Encode(resp.Body())
				}
				var re *client.RejectedError
				switch {
				case errors.Is(err, client.ErrBodyWanted):
					err = fmt.Errorf("the server asked for the content again for link %d, and a stream cannot be sent twice; %d of %d links made", i+1, i, links)
				case array && errors.As(err, &re) && re.Status == http.StatusTooManyRequests:
					err = fmt.Errorf("%w; %d of %d links made", err, i, links)
				}
				if err != nil {
					if asJSON && array && len(answers) > 0 {
						_ = printJSON()
					}
					return unknownKeyHint(err, agentKeys)
				}
				if i == 0 {
					ttlNote(cmd.ErrOrStderr(), meta.TTL, resp.Receipt)
				}
				answers = append(answers, resp.Body())
				switch {
				case quiet:
					if q := resp.Quiet(); q != "" {
						fmt.Fprintln(out, client.Printable(q))
					}
				case !asJSON && !dryRun && resp.Receipt.URL != "":
					fmt.Fprintln(out, client.Printable(resp.Receipt.URL))
				}
			}
			if quiet || (!asJSON && !dryRun) {
				return nil
			}
			return printJSON()
		},
	}
	f := cmd.Flags()
	f.StringVarP(&file, "file", "f", "", "file to upload; a pipe or device is streamed")
	f.StringVarP(&endpoint, "endpoint", "e", "", "endpoint name from the config, or a URL (may end with #sha256//... as the pin)")
	f.StringVarP(&key, "key", "k", "", "private key file (uses PATH-cert.pub when present), a .pub file of an agent key, or SHA256:... fingerprint of an agent key")
	f.StringArrayVarP(&tags, "tag", "t", nil, "tag (repeatable)")
	f.BoolVar(&backup, "backup", false, "add backup meta: hostname, absolute path, mtime")
	f.StringVar(&ttl, "ttl", "", "lifetime, e.g. 24h or 7d, or max for the longest the storage allows")
	f.BoolVar(&once, "once", false, "delete after the first download")
	f.BoolVar(&portal, "portal", false, "download page with the metadata and a Download button before the content")
	f.BoolVar(&stdin, "stdin", false, "stream the content from standard input")
	f.BoolVar(&secret, "secret", false, "secret with a reveal page; prompts twice on the terminal, masked, unless --stdin or --file is given")
	f.StringVar(&name, "name", "", "file name in the meta (default: base name of a regular --file; none for a stream)")
	f.StringVar(&ctype, "type", "", "Content-Type for downloads (--secret: text/plain; charset=utf-8)")
	f.BoolVar(&prettyURL, "pretty-url", false, "ask for a pronounceable link name (proquint); the endpoint must offer it")
	f.BoolVar(&noOwner, "no-owner", false, "hide the sender (key name, or host or user for a certificate) on the portal page")
	f.BoolVar(&mutable, "mutable", false, "let the content be replaced later with luk link --file; the endpoint must allow it (link.replace)")
	f.BoolVar(&private, "private", false, "only the uploading identity downloads it, with luk get (meta access private); the endpoint must accept it")
	f.BoolVar(&anyID, "any", false, "with --private: every identity lukd knows downloads it (meta access any)")
	f.BoolVar(&dryRun, "dry-run", false, "run every server check up to the body; send no body, store and run nothing")
	f.BoolVar(&progress, "progress", false, "show transfer progress on stderr (terminal only)")
	f.StringVar(&bwlimit, "bwlimit", "", "limit the upload rate, bytes per second with K, M, G, T suffix (0 = unlimited)")
	f.BoolVar(&asJSON, "json", false, "print the server answer as JSON")
	f.BoolVarP(&quiet, "quiet", "q", false, "print only the URL, nothing when the endpoint answers without one (the upload id is in --json)")
	f.IntVar(&links, "links", 1, "upload N times (1 to 25) with the same options, one link each")
	f.StringVar(&permanent, "permanent", "", "publish as a new version of this permanent name of the endpoint")
	completeFlags(cmd, map[string]cobra.CompletionFunc{
		"file": completeFiles, "endpoint": completeEndpoint, "key": completeKey, "tag": completeNone,
		"ttl": completeTTL, "name": completeNone, "permanent": completeNone, "type": completeNone, "bwlimit": completeNone, "links": completeNone,
	})
	return cmd
}

// permanentFlags refuses a --permanent name that is not a clean relative
// name, and --permanent with an option it excludes.
func permanentFlags(name string, links int, once, secret, portal, private, mutable, prettyURL bool) error {
	if err := wire.CheckPermanentName(name); err != nil {
		return usageError{fmt.Errorf("--permanent: %w", err)}
	}
	var with []string
	for _, f := range []struct {
		flag string
		on   bool
	}{
		{"--once", once}, {"--secret", secret}, {"--portal", portal}, {"--private", private},
		{"--mutable", mutable}, {"--pretty-url", prettyURL}, {"--links above 1", links > 1},
	} {
		if f.on {
			with = append(with, f.flag)
		}
	}
	if len(with) > 0 {
		return usageError{fmt.Errorf("--permanent takes no %s", strings.Join(with, ", "))}
	}
	return nil
}

// again prepares opts for one more upload of the same content: the meta
// carries the size and sha256 of the first answer (a stream had none), a
// regular file is read again from its start, and any other source, already
// read, is sent only when the server needs no body.
func again(opts *client.Options, first any) error {
	r, ok := first.(*wire.Receipt)
	if !ok {
		return errors.New("no answer to repeat")
	}
	if opts.Meta.Size == nil {
		n := r.Size
		opts.Meta.Size, opts.Meta.SHA256 = &n, r.SHA256
	}
	if sk, ok := opts.Body.(io.Seeker); ok && opts.Meta.Source == wire.SourceFile {
		_, err := sk.Seek(0, io.SeekStart)
		return err
	}
	opts.NoBody, opts.Size = true, *opts.Meta.Size
	return nil
}

// maxLinks is the most uploads one luk send --links makes.
const maxLinks = 25

var askSecret = client.AskSecret

// secretType is the Content-Type of a --secret upload without --type.
const secretType = "text/plain; charset=utf-8"

// ttlNote tells on stderr when the server did not apply the ttl as asked,
// with the range the storage allows when the answer carries one.
func ttlNote(w io.Writer, asked string, r *wire.Receipt) {
	if r == nil {
		return
	}
	switch r.TTLNote {
	case wire.TTLCapped, wire.TTLRaised:
		fmt.Fprintf(w, "luk: ttl %s %s to %s by the server%s\n", asked, r.TTLNote, client.Printable(r.TTL), client.Printable(ttlRange(r.TTLMin, r.TTLMax)))
	case wire.TTLIgnored:
		fmt.Fprintln(w, "luk: ttl ignored by the server")
	}
}

// ttlRange is the " (allowed ...)" suffix of a ttl note; empty without
// bounds.
func ttlRange(lo, hi string) string {
	switch {
	case lo != "" && hi != "":
		return fmt.Sprintf(" (allowed %s to %s)", lo, hi)
	case hi != "":
		return fmt.Sprintf(" (allowed up to %s)", hi)
	case lo != "":
		return fmt.Sprintf(" (allowed from %s)", lo)
	}
	return ""
}

// parseBWLimit reads --bwlimit; empty is unlimited.
func parseBWLimit(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	limit, err := wire.ParseSize(s)
	if err != nil {
		return 0, usageError{fmt.Errorf("--bwlimit: %w", err)}
	}
	return limit, nil
}

// resolve turns an endpoint argument into its URL and pin.
func resolve(cfg *client.Config, endpoint string) (string, string, error) {
	url, pin, err := cfg.Resolve(endpoint)
	if err != nil {
		return "", "", usageError{err}
	}
	if u, perr := neturl.Parse(url); pin != "" && (perr != nil || u.Scheme != "https") {
		return "", "", usageError{errors.New("a pin needs an https endpoint")}
	}
	return url, pin, nil
}

// signerFor loads the signing key for an endpoint argument: --key, the key
// of the endpoint, the config key, else the first agent key (agentKeys is
// then the number of keys the agent holds).
func signerFor(cfg *client.Config, endpoint, key string) (ssh.Signer, int, error) {
	key = cfg.KeyFor(endpoint, key)
	var signer ssh.Signer
	var err error
	agentKeys := 0
	if key == "" {
		signer, agentKeys, err = client.FirstAgentSigner()
	} else {
		signer, err = client.LoadSigner(key)
	}
	if err != nil {
		return nil, 0, usageError{err}
	}
	return signer, agentKeys, nil
}

// unknownKeyHint points at --key when the server does not know the first
// agent key, taken by default, while the agent holds others.
func unknownKeyHint(err error, agentKeys int) error {
	var re *client.RejectedError
	if agentKeys < 2 || !errors.As(err, &re) || re.Status != http.StatusUnauthorized || !strings.HasPrefix(re.Message, "unknown key ") {
		return err
	}
	return fmt.Errorf("%w; agent holds %d keys; pick one with --key SHA256:... or set key on the endpoint (luk config endpoint add -e NAME --url URL --key SHA256:...)", err, agentKeys)
}

func secretBody(secret []byte, meta *wire.Meta) (io.Reader, int64) {
	sum := sha256.Sum256(secret)
	n := int64(len(secret))
	meta.Source = wire.SourceTerminal
	meta.Size = &n
	meta.SHA256 = hex.EncodeToString(sum[:])
	return bytes.NewReader(secret), n
}

func input(file, name string, stdin, prompt, backup bool, meta *wire.Meta) (io.Reader, int64, io.Closer, error) {
	if prompt {
		if backup {
			return nil, 0, nil, usageError{errors.New("--backup needs a regular file")}
		}
		secret, err := askSecret("secret: ")
		if err != nil {
			return nil, 0, nil, usageError{err}
		}
		again, err := askSecret("retype: ")
		if err != nil {
			return nil, 0, nil, usageError{err}
		}
		if !bytes.Equal(secret, again) {
			return nil, 0, nil, usageError{errors.New("the secrets do not match")}
		}
		if !utf8.Valid(secret) {
			return nil, 0, nil, usageError{errors.New("the secret is not valid UTF-8")}
		}
		r, n := secretBody(secret, meta)
		return r, n, nil, nil
	}
	if stdin {
		if backup {
			return nil, 0, nil, usageError{errors.New("--backup needs a regular file")}
		}
		meta.Source = wire.SourceStdin
		return os.Stdin, -1, nil, nil
	}
	path := file
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, nil, usageError{err}
	}
	if st.IsDir() {
		return nil, 0, nil, usageError{fmt.Errorf("%s is a directory", path)}
	}
	if !st.Mode().IsRegular() {
		if backup {
			return nil, 0, nil, usageError{errors.New("--backup needs a regular file")}
		}
		fh, err := os.Open(path)
		if err != nil {
			return nil, 0, nil, usageError{err}
		}
		meta.Source = wire.SourcePipe
		return fh, -1, fh, nil
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, 0, nil, usageError{err}
	}
	h := sha256.New()
	n, err := io.Copy(h, fh)
	if err != nil {
		fh.Close()
		return nil, 0, nil, err
	}
	if _, err := fh.Seek(0, io.SeekStart); err != nil {
		fh.Close()
		return nil, 0, nil, err
	}
	if name == "" {
		meta.File = filepath.Base(path)
	}
	meta.Source = wire.SourceFile
	meta.Size = &n
	meta.SHA256 = hex.EncodeToString(h.Sum(nil))
	if backup {
		host, _ := os.Hostname()
		abs, err := filepath.Abs(path)
		if err != nil {
			fh.Close()
			return nil, 0, nil, err
		}
		meta.Backup = &wire.Backup{Hostname: host, Path: abs, Mtime: st.ModTime().UTC().Format(time.RFC3339)}
	}
	return fh, n, fh, nil
}
