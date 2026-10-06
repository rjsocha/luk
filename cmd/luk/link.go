package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"luk/internal/client"
	"luk/internal/wire"
)

func newLinkCmd(out io.Writer) *cobra.Command {
	var (
		endpoint, key, ttl, file, bwlimit string
		rm, stdin, asJSON, progress       bool
	)
	cmd := &cobra.Command{
		Use:   "link URL",
		Short: "Remove a link, set its ttl or replace its content",
		Long: `Manage the link URL luk send returned, as its owner: the identity that
uploaded it (any key of that identity, or a certificate of the same CA and
Key ID). Exactly one of --rm, --ttl, --file and --stdin selects the action:

  --rm             remove the link and its content
  --ttl D          set the lifetime to D from now, within the ttl.min and
                   ttl.max of the storage; max: its ttl.max, or no expiry
                   without one
  --file, --stdin  replace the content; the URL stays (the upload must have
                   been sent with --mutable)

The endpoint must allow the action (link.remove, link.ttl, link.replace in
lukd); luk link ls lists your links on an endpoint. The request goes to --endpoint, else to the endpoint mapped to the
host of the link (luk config link add), else to the default endpoint. A link
that does not exist, has expired or belongs to someone else is not found.
On success --rm prints nothing, --ttl prints the new expiry (nothing when
there is none) and notes on stderr a ttl the server capped or raised, a
replace prints the URL; --json prints the server answer instead. Exit codes as for luk send.`,
		Example: `  luk link https://drop.example.com/d/x7Kq... --rm
  luk link https://drop.example.com/d/x7Kq... --ttl 3d
  luk link https://drop.example.com/d/x7Kq... --ttl max
  luk link https://drop.example.com/d/x7Kq... --file status.html
  date | luk link https://drop.example.com/d/x7Kq... --stdin
  luk link https://drop.example.com/d/x7Kq... --rm -e drop
  luk link luk://secure.example.com/x7Kq... --rm`,
		Args:              oneURL,
		ValidArgsFunction: completeNone,
		RunE: func(cmd *cobra.Command, args []string) error {
			link := args[0]
			hasFile := file != "" || cmd.Flags().Changed("file")
			hasTTL := cmd.Flags().Changed("ttl")
			n := 0
			for _, on := range []bool{rm, hasTTL, hasFile, stdin} {
				if on {
					n++
				}
			}
			if n != 1 {
				return usageError{errors.New("exactly one of --rm, --ttl, --file or --stdin is required")}
			}
			replace := hasFile || stdin
			if !replace && (progress || bwlimit != "") {
				return usageError{errors.New("--progress and --bwlimit go with --file or --stdin")}
			}
			if hasTTL {
				if err := wire.CheckTTL(ttl); err != nil {
					return usageError{fmt.Errorf("--ttl: %w", err)}
				}
			}
			if _, err := client.LinkHost(link); err != nil {
				return usageError{err}
			}
			limit, err := parseBWLimit(bwlimit)
			if err != nil {
				return err
			}
			cfg, _, err := client.LoadMerged()
			if err != nil {
				return usageError{err}
			}
			ep, err := cfg.LinkEndpoint(link, endpoint)
			if err != nil {
				return usageError{err}
			}
			url, pins, err := resolve(cfg, ep)
			if err != nil {
				return err
			}
			signer, agentKeys, err := signerFor(cfg, ep, key)
			if err != nil {
				return err
			}
			o := client.LinkOptions{Options: client.Options{URL: url, Pins: pins, Signer: signer, BWLimit: limit}, Link: link}
			switch {
			case rm:
				o.Action = wire.LinkRemove
			case hasTTL:
				o.Action, o.TTL = wire.LinkTTL, ttl
			default:
				o.Action = wire.LinkReplace
				o.Meta = wire.Meta{Portal: wire.PortalDirect}
				src, closer, err := input(file, "", stdin, false, false, &o.Meta)
				if err != nil {
					return err
				}
				if closer != nil {
					defer closer.Close()
				}
				src.apply(&o.Options)
				if progress && term.IsTerminal(int(os.Stderr.Fd())) {
					o.Progress = os.Stderr
				}
			}
			ctx, stop := interruptContext()
			defer stop()
			a, err := client.Link(ctx, o)
			if err != nil {
				return unknownKeyHint(err, agentKeys)
			}
			if hasTTL {
				ttlNote(cmd.ErrOrStderr(), ttl, &wire.Receipt{TTL: a.TTL, TTLNote: a.TTLNote, TTLMin: a.TTLMin, TTLMax: a.TTLMax})
			}
			switch {
			case asJSON:
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(a)
			case hasTTL && a.Expires != "":
				fmt.Fprintln(out, client.Printable(a.Expires))
			case replace:
				fmt.Fprintln(out, client.Printable(a.URL))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&rm, "rm", false, "remove the link and its content")
	f.StringVar(&ttl, "ttl", "", "new lifetime from now, e.g. 24h or 7d, or max for the longest the storage allows")
	f.StringVarP(&file, "file", "f", "", "replace the content with this file; a pipe or device is streamed")
	f.BoolVar(&stdin, "stdin", false, "replace the content with standard input")
	f.StringVarP(&endpoint, "endpoint", "e", "", "endpoint name from the config, or a URL (default: by the host of the link, else config \"default\")")
	f.StringVarP(&key, "key", "k", "", "private key file (uses PATH-cert.pub when present), a .pub file of an agent key, or SHA256:... fingerprint of an agent key")
	f.BoolVar(&progress, "progress", false, "show transfer progress of a replace on stderr (terminal only)")
	f.StringVar(&bwlimit, "bwlimit", "", "limit the upload rate of a replace, bytes per second with K, M, G, T suffix (0 = unlimited)")
	f.BoolVar(&asJSON, "json", false, "print the server answer as JSON")
	completeFlags(cmd, map[string]cobra.CompletionFunc{
		"ttl": completeTTL, "file": completeFiles, "endpoint": completeEndpoint,
		"key": completeKey, "bwlimit": completeNone,
	})
	cmd.AddCommand(newLinkLsCmd(out))
	return cmd
}

// defaultLinkPage is the page size luk link ls asks for without --limit.
const defaultLinkPage = 100

func newLinkLsCmd(out io.Writer) *cobra.Command {
	var endpoint, key, after string
	var asJSON, anyOf, all, withCursor, quiet bool
	var limit int
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List your links on an endpoint",
		Long: `List the links the signing identity uploaded through an endpoint (any key
of that identity, or a certificate of the same CA and Key ID) that are still
there: not removed, expired or claimed. The endpoint must allow it (link.list
in lukd). The request goes to --endpoint, else to the default endpoint.

Columns: NAME (the file name sent, - without one), SIZE, SENT and EXPIRES in
local time (never: no expiry), FLAGS (once, mutable, reveal or download,
private or any, shared, permanent), URL (luk:// for a private file) and,
with --cursor, CURSOR; newest first. With --any, an identity of
private.list in lukd also gets the files of access any others sent that it
may download, with the flag shared: read-only, link --rm, --ttl and --file
refuse them; without private.list --any lists your links only. Nothing is
printed when there is no link. The current version of a permanent name
(luk send --permanent) is a link of its own with the flag permanent; after
the table a block per permanent name whose current version is in the
table, by name: "permanent NAME", its permanent URL ("url") and the URL
of its current version ("version", as in the table).

The list comes in pages of --limit links (default 100, at most 1000), each
link with an opaque cursor; --after CURSOR starts the page after that
link. When more links follow, the text output ends with the command of the
next page on stderr (not with --quiet): "more: luk link ls -e ENDPOINT
[--any] [--limit N] --after CURSOR", with the endpoint (given or the
default), --any and a --limit given, quoted for a shell; --all fetches
every page, one request each, and prints them as one list.

--json prints one object: "links" (name, size, sent, expires, updated,
flags, url, permanent: the name a link is the current version of, shared:
true for a file of another identity, and cursor), "permanent" (name, url,
version_url: the url of its link), both always present, and "next" (the
cursor of the last link) when more links follow.`,
		Example: `  luk link ls
  luk link ls -e drop --json
  luk link ls --all --any
  luk link ls --limit 20 --after MTc5MTI4ODAwMDAwMDAwMDAwMC4wLmIxMGE1MDE3ZjI0ZWE4OTgxYzViNjdiOWFkN2MzYjZiLjIwMjYxMDA2VDEyMDAwMFotMGExYjJjM2Q
  luk link ls --all --json | jq -r '.permanent[] | "\(.name) \(.url)"'`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 1 || limit > wire.MaxLinkPage {
				return usageError{fmt.Errorf("--limit: want 1 to %d", wire.MaxLinkPage)}
			}
			cfg, _, err := client.LoadMerged()
			if err != nil {
				return usageError{err}
			}
			url, pins, err := resolve(cfg, endpoint)
			if err != nil {
				return err
			}
			signer, agentKeys, err := signerFor(cfg, endpoint, key)
			if err != nil {
				return err
			}
			ctx, stop := interruptContext()
			defer stop()
			o, q := client.Options{URL: url, Pins: pins, Signer: signer}, client.LinkQuery{Limit: limit, After: after, Any: anyOf}
			list := client.LinkList
			if all {
				list = client.LinkListAll
			}
			a, err := list(ctx, o, q)
			if err != nil {
				return unknownKeyHint(err, agentKeys)
			}
			ls := newLinkList(a)
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(ls)
			}
			if err := printLinks(out, ls, time.Local, withCursor); err != nil {
				return err
			}
			if ls.Next != "" && !quiet {
				// The command of the next page: the endpoint (also the
				// default of the config), --any and a --limit given.
				next := []string{"luk", "link", "ls", "-e", cmp.Or(endpoint, cfg.Default)}
				if anyOf {
					next = append(next, "--any")
				}
				if cmd.Flags().Changed("limit") {
					next = append(next, "--limit", strconv.Itoa(limit))
				}
				next = append(next, "--after", ls.Next)
				fmt.Fprintf(cmd.ErrOrStderr(), "more: %s\n", client.Printable(shellJoin(next)))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&endpoint, "endpoint", "e", "", "endpoint name from the config, or a URL (default: config \"default\")")
	f.StringVarP(&key, "key", "k", "", "private key file (uses PATH-cert.pub when present), a .pub file of an agent key, or SHA256:... fingerprint of an agent key")
	f.BoolVar(&asJSON, "json", false, "print the server answer as JSON")
	f.BoolVar(&anyOf, "any", false, "also list the files of access any others sent that you may download (private.list)")
	f.IntVar(&limit, "limit", defaultLinkPage, fmt.Sprintf("links per page, 1 to %d", wire.MaxLinkPage))
	f.StringVar(&after, "after", "", "start after the link of this cursor (the next of a page)")
	f.BoolVar(&all, "all", false, "fetch every page")
	f.BoolVar(&withCursor, "cursor", false, "add the CURSOR column")
	f.BoolVarP(&quiet, "quiet", "q", false, "print no hint of the next page on stderr")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"endpoint": completeEndpoint, "key": completeKey, "limit": completeNone, "after": completeNone})
	return cmd
}

// linkList is the output of luk link ls --json: the links, newest first,
// the permanent names published by the signer whose current version is
// among them, by name, and the cursor of the next page; a permanent name
// joins the link of its current version by VersionURL == URL.
type linkList struct {
	Links     []linkItem      `json:"links"`
	Permanent []permanentItem `json:"permanent"`
	Next      string          `json:"next,omitempty"`
}

type linkItem struct {
	Name    string   `json:"name,omitempty"`
	Size    int64    `json:"size"`
	Sent    string   `json:"sent"`
	Expires string   `json:"expires,omitempty"`
	Updated string   `json:"updated,omitempty"`
	Flags   []string `json:"flags"`
	URL     string   `json:"url"`
	// Permanent is the permanent name the link is the current version of.
	Permanent string `json:"permanent,omitempty"`
	// Shared: a file of access any of another identity (private.list),
	// read-only.
	Shared bool `json:"shared,omitempty"`
	// Cursor is the place of the link in the list (luk link ls --after).
	Cursor string `json:"cursor"`
}

type permanentItem struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	VersionURL string `json:"version_url"`
}

// newLinkList is the output of the answer a. The newest link listed for
// a permanent name is its current version; an older one listed as a
// version of the same name is a plain link.
func newLinkList(a *wire.LinkListAnswer) linkList {
	out := linkList{Links: []linkItem{}, Permanent: []permanentItem{}, Next: a.Next}
	seen := map[[2]string]bool{}
	for _, l := range a.Links {
		it := linkItem{Name: l.File, Size: l.Size, Sent: l.Received, Expires: l.Expires, Updated: l.Updated, Flags: []string{}, URL: l.URL, Cursor: l.Cursor}
		if l.Once {
			it.Flags = append(it.Flags, "once")
		}
		if l.Mutable {
			it.Flags = append(it.Flags, "mutable")
		}
		if l.Portal == wire.PortalReveal || l.Portal == wire.PortalDownload {
			it.Flags = append(it.Flags, l.Portal)
		}
		if l.Access != "" {
			it.Flags = append(it.Flags, l.Access)
		}
		if l.Shared {
			it.Flags = append(it.Flags, "shared")
			it.Shared = true
		}
		if k := [2]string{l.Permanent, l.PermanentURL}; l.Permanent != "" && !seen[k] {
			// The links come newest first.
			seen[k] = true
			it.Flags = append(it.Flags, "permanent")
			it.Permanent = l.Permanent
			out.Permanent = append(out.Permanent, permanentItem{Name: l.Permanent, URL: l.PermanentURL, VersionURL: l.URL})
		}
		out.Links = append(out.Links, it)
	}
	slices.SortFunc(out.Permanent, func(a, b permanentItem) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.URL, b.URL))
	})
	return out
}

// printLinks writes the links as aligned columns, times in loc, with the
// CURSOR column when withCursor, then a block per permanent name; nothing
// for no links.
func printLinks(w io.Writer, ls linkList, loc *time.Location, withCursor bool) error {
	if len(ls.Links) == 0 {
		return nil
	}
	p := client.Printable
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	head := "NAME\tSIZE\tSENT\tEXPIRES\tFLAGS\tURL"
	if withCursor {
		head += "\tCURSOR"
	}
	fmt.Fprintln(tw, head)
	for _, l := range ls.Links {
		exp := "never"
		if l.Expires != "" {
			exp = localTime(l.Expires, loc)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s", p(cmp.Or(l.Name, "-")), client.HumanBytes(l.Size), p(localTime(l.Sent, loc)), p(exp), p(cmp.Or(strings.Join(l.Flags, ","), "-")), p(l.URL))
		if withCursor {
			fmt.Fprintf(tw, "\t%s", p(l.Cursor))
		}
		fmt.Fprintln(tw)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, pm := range ls.Permanent {
		if _, err := fmt.Fprintf(w, "\npermanent %s\n  url      %s\n  version  %s\n", p(pm.Name), p(cmp.Or(pm.URL, "-")), p(pm.VersionURL)); err != nil {
			return err
		}
	}
	return nil
}

// localTime is an RFC 3339 time in loc, to the minute; as given when it
// does not parse.
func localTime(s string, loc *time.Location) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.In(loc).Format("2006-01-02 15:04")
}
