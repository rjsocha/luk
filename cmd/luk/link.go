package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
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
			url, pin, err := resolve(cfg, ep)
			if err != nil {
				return err
			}
			signer, agentKeys, err := signerFor(cfg, ep, key)
			if err != nil {
				return err
			}
			o := client.LinkOptions{Options: client.Options{URL: url, Pin: pin, Signer: signer, BWLimit: limit}, Link: link}
			switch {
			case rm:
				o.Action = wire.LinkRemove
			case hasTTL:
				o.Action, o.TTL = wire.LinkTTL, ttl
			default:
				o.Action = wire.LinkReplace
				o.Meta = wire.Meta{Portal: wire.PortalDirect}
				body, size, closer, err := input(file, "", stdin, false, false, &o.Meta)
				if err != nil {
					return err
				}
				if closer != nil {
					defer closer.Close()
				}
				o.Body, o.Size = body, size
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

func newLinkLsCmd(out io.Writer) *cobra.Command {
	var endpoint, key string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List your links on an endpoint",
		Long: `List the links the signing identity uploaded through an endpoint (any key
of that identity, or a certificate of the same CA and Key ID) that are still
there: not removed, expired or claimed. The endpoint must allow it (link.list
in lukd). The request goes to --endpoint, else to the default endpoint.

Columns: NAME (the file name sent, - without one), SIZE, SENT and EXPIRES in
local time (never: no expiry), FLAGS (once, mutable, reveal or download,
private or any, permanent) and URL (luk:// for a private file); newest first. Nothing is printed when
there is no link. The versions of permanent names (luk send --permanent) are
links of their own; a second table lists the permanent names they belong to:
PERMANENT (the name), VERSIONS, NEWEST (sent time of the newest version) and
URL (the permanent URL). --json prints the server answer instead; a list cut at
10000 links has "truncated": true, noted on stderr otherwise.`,
		Example: `  luk link ls
  luk link ls -e drop --json`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			ctx, stop := interruptContext()
			defer stop()
			a, err := client.LinkList(ctx, client.Options{URL: url, Pin: pin, Signer: signer})
			if err != nil {
				return unknownKeyHint(err, agentKeys)
			}
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(a)
			}
			if a.Truncated {
				fmt.Fprintf(cmd.ErrOrStderr(), "luk: the server lists the newest %d links only\n", len(a.Links))
			}
			return printLinks(out, a.Links, time.Local)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&endpoint, "endpoint", "e", "", "endpoint name from the config, or a URL (default: config \"default\")")
	f.StringVarP(&key, "key", "k", "", "private key file (uses PATH-cert.pub when present), a .pub file of an agent key, or SHA256:... fingerprint of an agent key")
	f.BoolVar(&asJSON, "json", false, "print the server answer as JSON")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"endpoint": completeEndpoint, "key": completeKey})
	return cmd
}

// printLinks writes the links as aligned columns, times in loc; nothing
// for none.
func printLinks(w io.Writer, links []wire.LinkEntry, loc *time.Location) error {
	if len(links) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSIZE\tSENT\tEXPIRES\tFLAGS\tURL")
	for _, l := range links {
		var flags []string
		if l.Once {
			flags = append(flags, "once")
		}
		if l.Mutable {
			flags = append(flags, "mutable")
		}
		if l.Portal == wire.PortalReveal || l.Portal == wire.PortalDownload {
			flags = append(flags, l.Portal)
		}
		if l.Access != "" {
			flags = append(flags, l.Access)
		}
		if l.Permanent != "" {
			flags = append(flags, "permanent")
		}
		exp := "never"
		if l.Expires != "" {
			exp = localTime(l.Expires, loc)
		}
		p := client.Printable
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p(cmp.Or(l.File, "-")), client.HumanBytes(l.Size), p(localTime(l.Received, loc)), p(exp), p(cmp.Or(strings.Join(flags, ","), "-")), p(l.URL))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return printPermanentLinks(w, links, loc)
}

// printPermanentLinks writes, after the links, the permanent names their
// versions belong to: the name, the number of versions listed, the newest
// sent time and the permanent URL, by name; nothing without one.
func printPermanentLinks(w io.Writer, links []wire.LinkEntry, loc *time.Location) error {
	type perm struct {
		name, url, newest string
		versions          int
	}
	var perms []*perm
	byURL := map[string]*perm{}
	for _, l := range links {
		if l.Permanent == "" {
			continue
		}
		pm := byURL[l.PermanentURL]
		if pm == nil {
			pm = &perm{name: l.Permanent, url: l.PermanentURL}
			byURL[l.PermanentURL] = pm
			perms = append(perms, pm)
		}
		pm.versions++
		// The links come newest first.
		if pm.newest == "" {
			pm.newest = l.Received
		}
	}
	if len(perms) == 0 {
		return nil
	}
	slices.SortFunc(perms, func(a, b *perm) int { return cmp.Or(strings.Compare(a.name, b.name), strings.Compare(a.url, b.url)) })
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PERMANENT\tVERSIONS\tNEWEST\tURL")
	p := client.Printable
	for _, pm := range perms {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", p(pm.name), pm.versions, p(localTime(pm.newest, loc)), p(cmp.Or(pm.url, "-")))
	}
	return tw.Flush()
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
