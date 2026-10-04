package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"luk/internal/client"
	"luk/internal/cliflags"
)

func newGetCmd(out io.Writer) *cobra.Command {
	var (
		output, key, bwlimit                   string
		force, inplace, progress, head, asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "get URL",
		Short: "Download a private file with a signed request",
		Long: `Download a private file (luk send --private) from URL: the luk:// URL luk
send printed, or the https:// URL of the same expose. luk:// always means
https. The request is signed with an SSH key; the server answers only the
owner of the file or, for luk send --private --any, an identity it allows.
A file that does not exist, has expired, was claimed or is not yours is not
found.

The server is trusted by the pin in the URL fragment (#sha256//...) when it
has one, else by the system CAs. The key is --key, else the key of the
endpoint luk config link maps the host of the URL to, else the config key,
else the first agent key.

The content goes to --output FILE (required; - for stdout); the server
never names the local file. An existing FILE is refused unless --force,
before any request is sent. The content is written to a temporary file
next to FILE and renamed on success; a failed download leaves nothing.
--inplace writes into FILE itself instead, opened once the server has
answered 200: an existing file keeps its inode (permissions, owner, hard
links), and a device or FIFO works without --force. A failed download
then leaves FILE as written, partial or with a sha256 mismatch.
--progress reports on stderr when it is a terminal; --bwlimit caps the
rate in bytes per second (K, M, G, T suffixes; 0 = unlimited).

--head sends a signed HEAD instead (it never claims a once file) and
prints what the server announces, one "key: value" per line: name, size,
content_type, sha256, expires and once (each only when announced; once
is printed as true); --json prints them as a JSON object. Exit codes as for luk send.`,
		Example: `  luk get 'luk://secure.example.com/x7Kq...#sha256//Xk9...' -o notes.txt
  luk get luk://secure.example.com/x7Kq... -o - | tar x
  luk get https://secure.example.com/x7Kq... -o notes.txt --force --progress
  luk get luk://secure.example.com/x7Kq... --head`,
		Args:              oneURL,
		ValidArgsFunction: completeNone,
		RunE: func(cmd *cobra.Command, args []string) error {
			rawURL := args[0]
			u, pin, err := client.ParseGetURL(rawURL)
			if err != nil {
				return usageError{err}
			}
			switch {
			case inplace && (head || output == "-"):
				return usageError{errors.New("--inplace takes no --head or -o -")}
			case head && output != "":
				return usageError{errors.New("--head takes no --output")}
			case !head && output == "":
				return usageError{errors.New("luk get needs -o FILE (or -o - for stdout), or --head")}
			case asJSON && !head:
				return usageError{errors.New("--json needs --head")}
			}
			limit, err := parseBWLimit(bwlimit)
			if err != nil {
				return err
			}
			if output != "-" && !head && !force {
				refuse := refuseExisting
				if inplace {
					refuse = refuseInplace
				}
				if err := refuse(output); err != nil {
					return err
				}
			}
			cfg, _, err := client.LoadMerged()
			if err != nil {
				return usageError{err}
			}
			signer, agentKeys, err := getSigner(cfg, rawURL, key)
			if err != nil {
				return err
			}
			ctx, stop := interruptContext()
			defer stop()
			o := client.GetOptions{URL: u, Pin: pin, Signer: signer, BWLimit: limit}
			if head {
				h, err := client.HeadFile(ctx, o)
				if err != nil {
					return unknownKeyHint(err, agentKeys)
				}
				return printHead(out, h, asJSON)
			}
			if progress && term.IsTerminal(int(os.Stderr.Fd())) {
				o.Progress = os.Stderr
			}
			d, err := client.Get(ctx, o)
			if err != nil {
				return unknownKeyHint(err, agentKeys)
			}
			defer d.Close()
			if output == "-" {
				if _, err := io.Copy(out, d); err != nil {
					return err
				}
				if err := d.Check(); err != nil {
					var he *client.HashMismatchError
					if errors.As(err, &he) {
						return &mismatchError{"the output is not the announced content", he}
					}
					return err
				}
				return nil
			}
			save := saveTo
			if inplace {
				save = func(target string, d *client.Download, force bool) error {
					return writeInplace(ctx, target, d, force)
				}
			}
			if err := save(output, d, force); err != nil {
				return err
			}
			fmt.Fprintln(out, output)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&output, "output", "o", "", "file to write, - for stdout (required unless --head)")
	f.BoolVar(&force, "force", false, "overwrite an existing file")
	f.BoolVar(&inplace, "inplace", false, "write into FILE directly, no temporary file (keeps its inode; devices and FIFOs work)")
	f.BoolVar(&head, "head", false, "print what the server announces (name, size, content_type, sha256, expires, once) without downloading")
	f.BoolVar(&asJSON, "json", false, "with --head: print a JSON object")
	f.StringVarP(&key, "key", "k", "", "private key file (uses PATH-cert.pub when present), a .pub file of an agent key, or SHA256:... fingerprint of an agent key")
	f.BoolVar(&progress, "progress", false, "show transfer progress on stderr (terminal only)")
	f.StringVar(&bwlimit, "bwlimit", "", "limit the download rate, bytes per second with K, M, G, T suffix (0 = unlimited)")
	_ = f.SetAnnotation("output", cliflags.AllowDash, []string{"true"})
	completeFlags(cmd, map[string]cobra.CompletionFunc{
		"output": completeFiles, "key": completeKey, "bwlimit": completeNone,
	})
	return cmd
}

// headInfo is the output of luk get --head; absent fields are left out.
type headInfo struct {
	Name        string `json:"name,omitempty"`
	Size        *int64 `json:"size,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Expires     string `json:"expires,omitempty"`
	Once        bool   `json:"once,omitempty"`
}

// printHead prints h as "key: value" lines, or as a JSON object.
func printHead(out io.Writer, h *client.Head, asJSON bool) error {
	info := headInfo{Name: h.Name, ContentType: h.Type, SHA256: h.SHA256, Expires: h.Expires, Once: h.Once}
	if h.Size >= 0 {
		info.Size = &h.Size
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	for _, kv := range []struct{ k, v string }{
		{"name", info.Name}, {"size", sizeText(info.Size)}, {"content_type", info.ContentType}, {"sha256", info.SHA256},
		{"expires", info.Expires}, {"once", onceText(info.Once)},
	} {
		if kv.v != "" {
			fmt.Fprintf(out, "%s: %s\n", kv.k, client.Printable(kv.v))
		}
	}
	return nil
}

func onceText(once bool) string {
	if once {
		return "true"
	}
	return ""
}

func sizeText(n *int64) string {
	if n == nil {
		return ""
	}
	return strconv.FormatInt(*n, 10)
}

// getSigner loads the key of luk get: flag, else the key of the endpoint
// the link mapping gives the host of the URL, else the config key, else the
// first agent key (agentKeys is then the number of keys the agent holds).
func getSigner(cfg *client.Config, rawURL, flag string) (ssh.Signer, int, error) {
	key := flag
	if key == "" {
		key = cfg.Key
		if host, err := client.LinkHost(rawURL); err == nil {
			if ep, ok := cfg.Link[host]; ok {
				key = cfg.KeyFor(ep, "")
			}
		}
	}
	if key == "" {
		signer, n, err := client.FirstAgentSigner()
		if err != nil {
			return nil, 0, usageError{err}
		}
		return signer, n, nil
	}
	signer, err := client.LoadSigner(key)
	if err != nil {
		return nil, 0, usageError{err}
	}
	return signer, 0, nil
}

// refuseExisting fails when target exists (a dangling symlink included).
func refuseExisting(target string) error {
	if _, err := os.Lstat(target); err == nil {
		return usageError{fmt.Errorf("%s exists; pass --force to overwrite it", target)}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// saveTo writes the download into a temporary file next to target and
// puts it in place once complete and checked: renamed over target with
// force, else linked, so an existing target is never replaced (renamed
// after a last check where the file system has no hard links). The
// temporary file is created with mode 0666 for the kernel to apply the
// umask (and default ACLs) as to any new file, so the umask is never read
// or changed; it is removed on any failure.
func saveTo(target string, d *client.Download, force bool) error {
	if !force {
		if err := refuseExisting(target); err != nil {
			return err
		}
	}
	tmp, err := createTemp(target)
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, err = io.Copy(tmp, d)
	if err == nil {
		err = d.Check()
	}
	var he *client.HashMismatchError
	if errors.As(err, &he) {
		err = &mismatchError{"nothing written", he}
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if force {
		return os.Rename(name, target)
	}
	err = os.Link(name, target)
	switch {
	case errors.Is(err, fs.ErrExist):
		return usageError{fmt.Errorf("%s exists; pass --force to overwrite it", target)}
	case err != nil:
		if err := refuseExisting(target); err != nil {
			return err
		}
		return os.Rename(name, target)
	}
	return nil
}

// createTemp creates .<name>.luk-<random> next to target, as
// os.CreateTemp does but with mode 0666 less the umask instead of 0600.
func createTemp(target string) (*os.File, error) {
	dir, base := filepath.Dir(target), "."+filepath.Base(target)+".luk-"
	for range 100 {
		f, err := os.OpenFile(filepath.Join(dir, base+strconv.FormatUint(rand.Uint64(), 36)), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666)
		if !errors.Is(err, fs.ErrExist) {
			return f, err
		}
	}
	return nil, fmt.Errorf("cannot create a temporary file next to %s", target)
}

// refuseInplace is refuseExisting for --inplace: a device or FIFO (also
// behind a symlink) is written without --force.
func refuseInplace(target string) error {
	if fi, err := os.Stat(target); err == nil && special(fi.Mode()) {
		return nil
	}
	return refuseExisting(target)
}

func special(m fs.FileMode) bool {
	return m&(fs.ModeDevice|fs.ModeCharDevice|fs.ModeNamedPipe) != 0
}

// writeInplace writes the download into target itself: a regular file is
// truncated, a missing one created (0666 less the umask; without force
// never over a file created meanwhile), a device or FIFO opened as it is.
// A failure leaves target as written, said in the error.
func writeInplace(ctx context.Context, target string, d *client.Download, force bool) error {
	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if fi, err := os.Stat(target); err == nil && special(fi.Mode()) {
		flag = os.O_WRONLY
	} else if !force {
		flag |= os.O_EXCL
	}
	f, err := openCtx(ctx, target, flag)
	if errors.Is(err, fs.ErrExist) {
		return usageError{fmt.Errorf("%s exists; pass --force to overwrite it", target)}
	} else if err != nil {
		return err
	}
	if _, err := io.Copy(f, d); err != nil {
		f.Close()
		return &partialError{target, err}
	}
	check := d.Check()
	err = f.Sync()
	if errors.Is(err, syscall.EINVAL) {
		err = nil
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	var he *client.HashMismatchError
	if errors.As(check, &he) {
		return &mismatchError{target + " kept as written", he}
	}
	return err
}

// openCtx opens name, giving up when ctx ends: opening a FIFO blocks
// until a reader opens it, and Ctrl-C must still end luk get.
func openCtx(ctx context.Context, name string, flag int) (*os.File, error) {
	type opened struct {
		f   *os.File
		err error
	}
	ch := make(chan opened, 1)
	go func() {
		f, err := os.OpenFile(name, flag, 0o666)
		ch <- opened{f, err}
	}()
	select {
	case o := <-ch:
		return o.f, o.err
	case <-ctx.Done():
		go func() {
			if o := <-ch; o.f != nil {
				o.f.Close()
			}
		}()
		return nil, &client.TransferError{Reason: client.Interrupted, Err: ctx.Err()}
	}
}

// partialError is a download into FILE (--inplace) that broke off.
type partialError struct {
	file string
	err  error
}

func (e *partialError) Error() string { return e.err.Error() + "; " + e.file + " is partial" }
func (e *partialError) Unwrap() error { return e.err }

// mismatchError is a sha256 mismatch of a download into a file; what
// says what became of it.
type mismatchError struct {
	what string
	err  *client.HashMismatchError
}

func (e *mismatchError) Error() string {
	return fmt.Sprintf("sha256 mismatch, %s (got %s, want %s)", e.what, e.err.Local, client.Printable(e.err.Remote))
}
func (e *mismatchError) Unwrap() error { return e.err }
