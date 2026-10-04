package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"luk/internal/client"
	"luk/internal/wire"
)

// dirOptions are the flags of luk get with a directory URL.
type dirOptions struct {
	output, key, bwlimit                                     string
	force, inplace, progress, head, asJSON, recursive, quiet bool
}

// getDir runs luk get on a directory URL: the listing without -o, the
// download of every file below it with -o DIR.
func getDir(cmd *cobra.Command, rawURL string, u *url.URL, pin string, o dirOptions, out io.Writer) error {
	switch {
	case o.output == "-":
		return usageError{errors.New("-c/--stdout and -o - take no directory URL")}
	case o.inplace || o.head:
		return usageError{errors.New("--inplace and --head take no directory URL")}
	case o.output != "" && o.asJSON:
		return usageError{errors.New("--json takes no -o with a directory URL")}
	case o.output == "" && (o.force || o.progress || o.bwlimit != ""):
		return usageError{errors.New("--force, --progress and --bwlimit need -o DIR/")}
	}
	if o.output != "" {
		if err := checkDirTarget(o.output); err != nil {
			return err
		}
	}
	limit, err := parseBWLimit(o.bwlimit)
	if err != nil {
		return err
	}
	cfg, _, err := client.LoadMerged()
	if err != nil {
		return usageError{err}
	}
	signer, agentKeys, err := getSigner(cfg, rawURL, o.key)
	if err != nil {
		return err
	}
	ctx, stop := interruptContext()
	defer stop()
	g := client.GetOptions{URL: u, Pin: pin, Signer: signer, BWLimit: limit}
	ents, err := client.List(ctx, g, o.recursive || o.output != "")
	if err != nil {
		return unknownKeyHint(err, agentKeys)
	}
	if o.output == "" {
		if o.asJSON {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			return enc.Encode(ents)
		}
		return printListing(out, ents, time.Local)
	}
	if o.progress && term.IsTerminal(int(os.Stderr.Fd())) {
		g.Progress = os.Stderr
	}
	d := &dirGet{ctx: ctx, base: u, opts: g, force: o.force, out: out, errOut: cmd.ErrOrStderr(), quiet: o.quiet}
	return d.run(o.output, ents)
}

// checkDirTarget refuses a -o of a directory URL that is neither a
// directory nor a path ending with a slash.
func checkDirTarget(dir string) error {
	fi, err := os.Stat(dir)
	switch {
	case err == nil && !fi.IsDir():
		return usageError{fmt.Errorf("%s is not a directory; a directory URL needs -o DIR/", dir)}
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	case err != nil && !strings.HasSuffix(dir, "/"):
		return usageError{fmt.Errorf("%s does not exist; a directory URL needs -o DIR/ (ending with a slash) or an existing directory", dir)}
	}
	return nil
}

// printListing writes the listing as aligned columns, times in loc;
// nothing for none.
func printListing(w io.Writer, ents []wire.ListEntry, loc *time.Location) error {
	if len(ents) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSIZE\tRECEIVED\tSHA256")
	p := client.Printable
	for _, e := range ents {
		size, received, sum := "-", "-", "-"
		if !e.Dir {
			if e.Size != nil {
				size = client.HumanBytes(*e.Size)
			}
			if e.Received != "" {
				received = localTime(e.Received, loc)
			}
			if e.SHA256 != "" {
				sum = shortSum(e.SHA256)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p(e.Name), size, p(received), p(sum))
	}
	return tw.Flush()
}

// shortSum is the first 12 characters of a sha256.
func shortSum(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// dirGet downloads the files of a recursive listing into a directory.
type dirGet struct {
	ctx         context.Context
	base        *url.URL
	opts        client.GetOptions
	force       bool
	quiet       bool
	out, errOut io.Writer
	root        *os.Root

	got, skipped, failed int
	bytes                int64
	first                error
}

// dirFailed ends a directory download in which some files failed; it
// unwraps to the first failure, which gives the exit code.
type dirFailed struct {
	failed, total int
	first         error
}

func (e *dirFailed) Error() string {
	return fmt.Sprintf("%d of %d files failed", e.failed, e.total)
}
func (e *dirFailed) Unwrap() error { return e.first }

func (d *dirGet) run(dir string, ents []wire.ListEntry) error {
	var files []wire.ListEntry
	seen := map[string]bool{}
	for _, e := range ents {
		if e.Dir {
			continue
		}
		if err := client.ValidListName(e.Name); err != nil {
			return fmt.Errorf("%w; nothing downloaded", err)
		}
		if seen[e.Name] {
			return fmt.Errorf("the listing names %q twice; nothing downloaded", e.Name)
		}
		seen[e.Name] = true
		files = append(files, e)
	}
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	d.root = root
	for _, e := range files {
		if err := d.ctx.Err(); err != nil {
			return &client.TransferError{Reason: client.Interrupted, Err: err}
		}
		skipped, n, err := d.file(e)
		var te *client.TransferError
		switch {
		case errors.As(err, &te) && te.Reason == client.Interrupted:
			return err
		case err != nil:
			d.failed++
			if d.first == nil {
				d.first = err
			}
			fmt.Fprintf(d.errOut, "luk: %s: %v\n", client.Printable(e.Name), err)
		case skipped:
			d.skipped++
			d.say("skip %s\n", client.Printable(e.Name))
		default:
			d.got++
			d.bytes += n
			d.say("get %s\n", client.Printable(e.Name))
		}
	}
	if d.failed > 0 {
		d.say("%d downloaded, %d skipped, %d failed, %s\n", d.got, d.skipped, d.failed, client.HumanBytes(d.bytes))
		return &dirFailed{failed: d.failed, total: len(files), first: d.first}
	}
	d.say("%d downloaded, %d skipped, %s\n", d.got, d.skipped, client.HumanBytes(d.bytes))
	return nil
}

func (d *dirGet) say(format string, args ...any) {
	if !d.quiet {
		fmt.Fprintf(d.out, format, args...)
	}
}

// file downloads one file of the listing unless a regular file with its
// sha256 is already there (skipped); n is the number of bytes written.
func (d *dirGet) file(e wire.ListEntry) (skipped bool, n int64, err error) {
	if err := d.parents(e.Name); err != nil {
		return false, 0, err
	}
	fi, err := d.root.Lstat(e.Name)
	switch {
	case err == nil && !fi.Mode().IsRegular():
		return false, 0, usageError{fmt.Errorf("exists and is not a regular file")}
	case err == nil:
		if e.SHA256 != "" {
			same, err := d.sameSum(e.Name, e.SHA256)
			if err != nil {
				return false, 0, err
			}
			if same {
				return true, 0, nil
			}
		}
		if !d.force {
			return false, 0, usageError{errors.New("exists and differs; pass --force to overwrite it")}
		}
	case !errors.Is(err, fs.ErrNotExist):
		return false, 0, err
	}
	n, err = d.download(e.Name)
	return false, n, err
}

// parents creates the directories of name in the root; an element that
// exists as anything but a directory (a symlink included) fails.
func (d *dirGet) parents(name string) error {
	elems := strings.Split(name, "/")
	for i := 1; i < len(elems); i++ {
		p := strings.Join(elems[:i], "/")
		fi, err := d.root.Lstat(p)
		switch {
		case err == nil && !fi.IsDir():
			return usageError{fmt.Errorf("%s exists and is not a directory", client.Printable(p))}
		case err == nil:
		case errors.Is(err, fs.ErrNotExist):
			if err := d.root.Mkdir(p, 0o777); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		default:
			return err
		}
	}
	return nil
}

// sameSum reports whether the regular file name has the sha256 sum.
func (d *dirGet) sameSum(name, sum string) (bool, error) {
	f, err := d.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == sum, nil
}

// download writes the file name into a temporary file next to it, checks
// it and puts it in place: renamed over an existing file with force, else
// linked, so a file created meanwhile is never replaced.
func (d *dirGet) download(name string) (int64, error) {
	o := d.opts
	o.URL = client.ChildURL(d.base, name)
	dl, err := client.Get(d.ctx, o)
	if err != nil {
		return 0, err
	}
	defer dl.Close()
	dir, base := path.Split(name)
	var tmp *os.File
	var tmpName string
	for range 100 {
		tmpName = dir + "." + base + ".luk-" + strconv.FormatUint(rand.Uint64(), 36)
		tmp, err = d.root.OpenFile(tmpName, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o666)
		if !errors.Is(err, fs.ErrExist) {
			break
		}
	}
	if err != nil {
		return 0, err
	}
	defer d.root.Remove(tmpName)
	n, err := io.Copy(tmp, dl)
	if err == nil {
		err = dl.Check()
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
		return 0, err
	}
	if d.force {
		return n, d.root.Rename(tmpName, name)
	}
	if err := d.root.Link(tmpName, name); errors.Is(err, fs.ErrExist) {
		return 0, usageError{errors.New("exists; pass --force to overwrite it")}
	} else if err != nil {
		return 0, err
	}
	return n, nil
}
