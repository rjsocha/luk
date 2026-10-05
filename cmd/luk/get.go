package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"net/url"
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
		output, key, bwlimit                                             string
		force, inplace, progress, head, asJSON, stdout, recursive, quiet bool
		remoteName, remoteHeader                                         bool
		parallel                                                         int
	)
	cmd := &cobra.Command{
		Use:   "get URL",
		Short: "Download a file or a directory with a signed request",
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

The content goes to --output FILE (required; - or -c/--stdout for stdout,
or -O); the server names the local file only with -J. An existing FILE
is refused unless --force, before the download is sent. The content is
written to a temporary file next to FILE and renamed on success; a
failed download leaves nothing.
--inplace writes into FILE itself instead, opened once the server has
answered 200: an existing file keeps its inode (permissions, owner, hard
links), and a device or FIFO works without --force. A failed download
then leaves FILE as written, partial or with a sha256 mismatch.
--progress reports on stderr when it is a terminal; --bwlimit caps the
rate in bytes per second (K, M, G, T suffixes; 0 = unlimited).

-O (--remote-name) writes FILE into the current directory, named after
the last segment of the URL path (percent-decoded), as -o FILE would;
it takes no -o, -c, --inplace or directory URL. -J (--remote-header-name, only with
-O) names it after the file name the server announces (the name --head
prints), asked with a signed HEAD first, else after the URL. Either name
must be a bare file name of at most 236 bytes: not empty, . or ..,
without a slash, a backslash or control characters; anything else is an
error and nothing is downloaded.

--head sends a signed HEAD instead (it never claims a once file) and
prints what the server announces, one "key: value" per line: name, size,
content_type, sha256, expires and once (each only when announced; once
is printed as true); --json prints them as a JSON object. Exit codes as for luk send.

A URL ending with a slash names a directory (as in rsync) of an expose
that serves every file of its storage to signed requests (an auth.ssh
expose that is the expose of a storage). Without -o it prints the
listing: NAME, SIZE, RECEIVED (local time) and SHA256 (the first 12
characters), directories first; -r lists every file below the directory
with relative names; --json prints the entries as JSON (name, dir, size,
received, sha256 in full). The listing leaves out once and portal uploads,
so a directory download never claims a once file.

-o DIR/ (ending with a slash, or an existing directory; created when
missing) downloads every file below the directory into DIR, recreating
the subdirectories. Each file goes through a temporary file and is
checked against its sha256. A file that exists in DIR with the same
sha256 is skipped; one that differs is refused unless --force; a symlink
or anything else that is not a regular file is always refused, and no
symlink in DIR is followed. Unsafe names (absolute, "..", control
characters) in the listing stop the download before any file is written.
It prints "get NAME  SIZE  TIME" or "skip NAME" per file and a summary
"N downloaded, N skipped, SIZE in TIME, RATE/s" (-q prints nothing but
errors). --progress keeps one live line on stderr when it is a terminal:
the file among all ([7/20]), its bytes and rate, the bytes of the run
against the bytes to transfer and an ETA; it is cleared before each
line of the output. --parallel N downloads up to N files at once (1 to
32, default 1), each with its own request; the lines then come in the
order the files end and the live line shows the first file in flight
with the number of the others ([7/20 +3]). --bwlimit applies to each
file, so the run stays under N times it. A failed file is reported and
the others still downloaded; the exit code is then that of the first
failure. -c, -O, --inplace and --head take no directory URL; --parallel
needs a directory URL and -o DIR/.`,
		Example: `  luk get 'luk://secure.example.com/x7Kq...#sha256//Xk9...' -o notes.txt
  luk get luk://secure.example.com/x7Kq... -c | tar x
  luk get https://secure.example.com/x7Kq... -o notes.txt --force --progress
  luk get luk://secure.example.com/x7Kq... --head
  luk get luk://secure.example.com/x7Kq... -O -J
  luk get luk://secure.example.com/v/2026/
  luk get luk://secure.example.com/v/ -r --json
  luk get luk://secure.example.com/v/2026/ -o backups/
  luk get luk://secure.example.com/v/ -o backups/ --parallel 4`,
		Args:              oneURL,
		ValidArgsFunction: completeNone,
		RunE: func(cmd *cobra.Command, args []string) error {
			rawURL := args[0]
			u, pin, err := client.ParseGetURL(rawURL)
			if err != nil {
				return usageError{err}
			}
			switch {
			case remoteHeader && !remoteName:
				return usageError{errors.New("-J needs -O")}
			case remoteName && (output != "" || stdout):
				return usageError{errors.New("-O excludes -o and -c")}
			case remoteName && head:
				return usageError{errors.New("--head takes no -O")}
			case remoteName && inplace:
				// FILE would be opened as it is, a symlink followed, at
				// a name the URL or the server chooses.
				return usageError{errors.New("--inplace takes no -O")}
			case remoteName && client.IsDirURL(u):
				return usageError{errors.New("-O takes no directory URL; use -o DIR/")}
			}
			if stdout {
				if output != "" {
					return usageError{errors.New("-c/--stdout and -o exclude each other")}
				}
				output = "-"
			}
			if client.IsDirURL(u) {
				return getDir(cmd, rawURL, u, pin, dirOptions{
					output: output, key: key, bwlimit: bwlimit, force: force, inplace: inplace, progress: progress,
					head: head, asJSON: asJSON, recursive: recursive, quiet: quiet,
					parallel: parallel, parallelSet: cmd.Flags().Changed("parallel"),
				}, out)
			}
			switch {
			case recursive:
				return usageError{errors.New("-r needs a directory URL (ending with a slash)")}
			case cmd.Flags().Changed("parallel"):
				return usageError{errors.New("--parallel needs a directory URL (ending with a slash) and -o DIR/")}
			}
			// -O names FILE after the URL now; -J after what the server
			// announces, asked below, with the URL as the fallback.
			var urlName string
			var urlNameErr error
			if remoteName {
				urlName, urlNameErr = urlFileName(u)
				if !remoteHeader {
					if urlNameErr != nil {
						return urlNameErr
					}
					output = urlName
				}
			}
			switch {
			case inplace && (head || output == "-"):
				return usageError{errors.New("--inplace takes no --head, -o - or -c")}
			case head && output != "":
				return usageError{errors.New("--head takes no --output or -c")}
			case !head && output == "" && !remoteHeader:
				return usageError{errors.New("luk get needs -o FILE, -c for stdout, or --head")}
			case asJSON && !head:
				return usageError{errors.New("--json needs --head")}
			}
			limit, err := parseBWLimit(bwlimit)
			if err != nil {
				return err
			}
			refuse := func() error {
				if output == "-" || head || force {
					return nil
				}
				if inplace {
					return refuseInplace(output)
				}
				return refuseExisting(output)
			}
			if !remoteHeader {
				if err := refuse(); err != nil {
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
			if remoteHeader {
				// A signed HEAD (which never claims a once file) names
				// the file before the download.
				h, err := client.HeadFile(ctx, o)
				if err != nil {
					return unknownKeyHint(err, agentKeys)
				}
				switch {
				case h.Name != "":
					if err := client.ValidFileName(h.Name); err != nil {
						return fmt.Errorf("unsafe file name %q announced by the server: %v; nothing downloaded", h.Name, err)
					}
					output = h.Name
				case urlNameErr != nil:
					return urlNameErr
				default:
					output = urlName
				}
				if err := refuse(); err != nil {
					return err
				}
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
			if !quiet {
				fmt.Fprintln(out, output)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&output, "output", "o", "", "file to write, - for stdout (required unless -c or --head); DIR/ for a directory URL")
	f.BoolVarP(&stdout, "stdout", "c", false, "write the content to stdout (as -o -)")
	f.BoolVar(&force, "force", false, "overwrite an existing file")
	f.BoolVar(&inplace, "inplace", false, "write into FILE directly, no temporary file (keeps its inode; devices and FIFOs work)")
	f.BoolVar(&head, "head", false, "print what the server announces (name, size, content_type, sha256, expires, once) without downloading")
	f.BoolVar(&asJSON, "json", false, "with --head: print a JSON object; with a directory URL: print the listing as JSON")
	f.BoolVarP(&recursive, "recursive", "r", false, "with a directory URL: list every file below it")
	f.BoolVarP(&quiet, "quiet", "q", false, "print nothing but errors")
	f.StringVarP(&key, "key", "k", "", "private key file (uses PATH-cert.pub when present), a .pub file of an agent key, or SHA256:... fingerprint of an agent key")
	f.BoolVar(&progress, "progress", false, "show transfer progress on stderr (terminal only)")
	f.StringVar(&bwlimit, "bwlimit", "", "limit the download rate, bytes per second with K, M, G, T suffix (0 = unlimited)")
	f.BoolVarP(&remoteName, "remote-name", "O", false, "write FILE into the current directory, named after the last segment of the URL")
	f.BoolVarP(&remoteHeader, "remote-header-name", "J", false, "with -O: name FILE after the file name the server announces")
	f.IntVar(&parallel, "parallel", 1, fmt.Sprintf("with a directory URL and -o DIR/: files downloaded at once (1 to %d)", maxGetParallel))
	_ = f.SetAnnotation("output", cliflags.AllowDash, []string{"true"})
	completeFlags(cmd, map[string]cobra.CompletionFunc{
		"output": completeFiles, "key": completeKey, "bwlimit": completeNone, "parallel": completeNone,
	})
	return cmd
}

// urlFileName is the file name of -O: the last segment of the path of u,
// percent-decoded, which must be a bare file name.
func urlFileName(u *url.URL) (string, error) {
	name, err := client.URLFileName(u)
	if err == nil {
		err = client.ValidFileName(name)
	}
	if err != nil {
		return "", usageError{fmt.Errorf("unsafe file name %q in the URL: %v; pass -o FILE", name, err)}
	}
	return name, nil
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
