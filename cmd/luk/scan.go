package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"path"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"luk/internal/channel"
	"luk/internal/client"
	"luk/internal/wire"
)

func newScanCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		key, pinFormat                        string
		pinOnly, endpoints, printCmds, asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "scan URL",
		Short: "Print the lukd key of a server and the endpoints it offers you",
		Long: `Scan the lukd server of URL: an origin (https://host:8443) or an endpoint
URL (https://host:8443/drop), http or https; a config endpoint name works
too. Without --pin and --endpoints it does both.

--pin runs the handshake of the channel and prints the key lukd presents,
the pin of its endpoints, on stdout: six words by default, the full key
with --pin-format key. This is trust on first use: compare it with "lukd
key" on the server. When the config (or the URL fragment) has pins for
that origin and the key matches none of them, the key is still printed,
the error says so and the exit code is 3. For an https URL whose
certificate chain does not verify against the system CAs, stderr also
has "download pin: sha256//...": the SPKI pin of the certificate, the
one the download links of that listener carry ("lukd tls pin").

--endpoints asks lukd, through the channel and trusting the key just
scanned, for the endpoints of that listener your key may upload to:
NAME, URL, RESPOND (url: the upload answers its URL; accept), TTL (the
lifetime without --ttl, never without one, then the range --ttl may ask
for when the storage takes it), FLAGS (secret, pretty-url, private,
any, mutable, link-rm, link-ttl, link-ls, permanent: the options the
endpoint takes from your key; backup-host:any, backup-host:principal or backup-host:none
when the endpoint restricts the --backup hostname: any, one of the
principals of your certificate, or no --backup at all)
and, when an endpoint has one, QUOTA (your upload quota: the rate, the
largest upload and what you may send now).
The key is --key, else the key of the config endpoint the URL names, else
the config key, else each key of the SSH agent in turn until the server
knows one.

When the listing fails the pin is still printed, the error follows and
the exit code is that of luk send. A key that matches no configured pin
gets no listing: the signed request is never sent to it.

--json prints one JSON object: {"pin": ..., "download_pin": ...,
"endpoints": [...]}, each only when asked for and download_pin only for
a certificate that does not verify. --print prints ready-to-run "luk
config endpoint add" commands instead, one per endpoint, the URL
carrying the lukd key as its fragment (in the --pin-format); --key the
key that listed them unless it is the config key: --key as given, the
key of the config endpoint, or the fingerprint of the agent key; with
--pin alone one command for URL, named by its last path segment, or by
the first label of the host for an origin (NAME, to replace, for an IP
address). A key that matches no configured pin gets no commands.`,
		Example: `  luk scan https://lukd.vm:8443
  luk scan --pin https://lukd.vm:8443/drop
  luk scan --pin --pin-format key http://lukd.vm:8080
  luk scan --endpoints drop --json
  luk scan --print https://lukd.vm:8443 | sh
  luk scan --pin --print https://lukd.vm:8443/drop`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError{fmt.Errorf("%s needs one URL", cmd.CommandPath())}
			}
			return nil
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeEndpoint(cmd, args, toComplete)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if printCmds && asJSON {
				return usageError{errors.New("--print and --json exclude each other")}
			}
			if pinFormat != "words" && pinFormat != "key" {
				return usageError{fmt.Errorf("--pin-format must be words or key, got %q", pinFormat)}
			}
			cfg, _, err := client.LoadMerged()
			if err != nil {
				return usageError{err}
			}
			raw, given, err := cfg.Resolve(args[0])
			if err != nil {
				return usageError{err}
			}
			u, err := neturl.Parse(raw)
			if err != nil {
				return usageError{err}
			}
			pins, err := client.PinsFor(cfg, u, strings.Join(given, ","))
			if err != nil {
				return usageError{err}
			}
			name := args[0]
			if strings.Contains(name, "://") {
				name = matchEndpoint(cfg, u)
			}
			wantPin := pinOnly || !endpoints
			wantList := endpoints || !pinOnly
			ctx, stop := interruptContext()
			defer stop()

			var cert *client.Certificate
			if wantPin && u.Scheme == "https" {
				if cert, err = client.ScanTLS(ctx, u); err != nil {
					return err
				}
			}
			peer, err := client.Scan(ctx, u)
			if err != nil {
				return err
			}
			pin, err := channel.FormatPin(peer, pinFormat)
			if err != nil {
				return err
			}
			// A scan shows what the server presents; a key the configured
			// pins do not accept is an error once it is shown.
			var mismatch error
			if len(pins) > 0 && !slices.ContainsFunc(pins, func(p channel.Pin) bool { return p.Matches(peer) }) {
				mismatch = &client.PinMismatchError{Got: peer}
			}
			var list *wire.EndpointList
			var listErr error
			var usedKey string
			// The signed listing goes only to a key the pins accept: a
			// signature for another key tells it who asks.
			if wantList && mismatch == nil {
				seen, err := channel.ParsePin(channel.KeyString(peer))
				if err != nil {
					return err
				}
				list, usedKey, listErr = listEndpoints(ctx, cfg, u, []channel.Pin{seen}, name, key)
				if errors.As(listErr, new(usageError)) {
					return listErr
				}
			}
			dpin := ""
			if wantPin {
				dpin = downloadPin(cert)
			}
			switch {
			case asJSON:
				res := scanResult{DownloadPin: dpin}
				if wantPin {
					res.Pin = pin
				}
				if list != nil {
					res.Endpoints = &list.Endpoints
				}
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(res); err != nil {
					return err
				}
			case printCmds:
				if dpin != "" {
					fmt.Fprintln(stderr, "download pin: "+dpin)
				}
				if mismatch != nil {
					break
				}
				if list != nil {
					for _, e := range list.Endpoints {
						fmt.Fprintln(stdout, addCommand(client.Printable(e.Name), client.Printable(e.URL)+"#"+pin, usedKey))
					}
				} else if wantPin {
					fmt.Fprintln(stdout, addCommand(scanName(u), originURL(u)+"#"+pin, ""))
				}
			default:
				if wantPin {
					fmt.Fprintln(stdout, pin)
				}
				if dpin != "" {
					fmt.Fprintln(stderr, "download pin: "+dpin)
				}
				if list != nil {
					if err := printEndpoints(stdout, list.Endpoints); err != nil {
						return err
					}
				}
			}
			if listErr != nil {
				listErr = fmt.Errorf("listing endpoints of %s: %w", u.Host, listErr)
			}
			return errors.Join(mismatch, listErr)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&pinOnly, "pin", false, "print the lukd key of the server, the pin of its endpoints")
	f.BoolVar(&endpoints, "endpoints", false, "list the endpoints your key may use (signed request)")
	f.BoolVar(&printCmds, "print", false, "print luk config endpoint add commands instead")
	f.BoolVar(&asJSON, "json", false, "print one JSON object with the pin and the endpoints")
	f.StringVar(&pinFormat, "pin-format", "words", "show the lukd key as words or key")
	f.StringVarP(&key, "key", "k", "", "private key file (uses PATH-cert.pub when present), a .pub file of an agent key, or SHA256:... fingerprint of an agent key")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"key": completeKey, "pin-format": completePinFormat})
	return cmd
}

// scanResult is the output of luk scan --json.
type scanResult struct {
	Pin         string               `json:"pin,omitempty"`
	DownloadPin string               `json:"download_pin,omitempty"`
	Endpoints   *[]wire.EndpointInfo `json:"endpoints,omitempty"`
}

// downloadPin is the SPKI pin of cert that download links carry: only for
// a chain that does not verify against the system CAs, as a verified one
// (an acme listener) needs none. Empty for http (cert nil).
func downloadPin(cert *client.Certificate) string {
	if cert == nil || cert.Verified {
		return ""
	}
	return cert.Pin
}

// listEndpoints asks the server of u for the endpoints of the signer,
// through the channel with the lukd keys pins. The key is flag, else the
// key of the config endpoint name, else the config key, else each agent
// key in turn, a channel each, while the server does not know it. It also
// returns the key for the commands of --print: flag, the key of the config
// endpoint, or the fingerprint of the agent key the server knew; empty for
// the config key, which every endpoint takes anyway.
func listEndpoints(ctx context.Context, cfg *client.Config, u *neturl.URL, pins []channel.Pin, name, flag string) (*wire.EndpointList, string, error) {
	key, show := flag, flag
	if key == "" {
		key = cfg.Key
		if name != "" {
			key = cfg.KeyFor(name, "")
		}
		if key != cfg.Key {
			show = key
		}
	}
	var signers []ssh.Signer
	if key == "" {
		var err error
		if signers, err = client.AgentSigners(); err != nil {
			return nil, "", usageError{err}
		}
	} else {
		s, err := client.LoadSigner(key)
		if err != nil {
			return nil, "", usageError{err}
		}
		signers = []ssh.Signer{s}
	}
	var err error
	for i, s := range signers {
		var l *wire.EndpointList
		l, err = client.ListEndpoints(ctx, u, pins, s)
		if err == nil {
			if key == "" {
				show = ssh.FingerprintSHA256(s.PublicKey())
			}
			return l, show, nil
		}
		var re *client.RejectedError
		if !errors.As(err, &re) || re.Status != http.StatusUnauthorized || !strings.HasPrefix(re.Message, "unknown key ") {
			return nil, "", err
		}
		if i == len(signers)-1 && i > 0 {
			err = fmt.Errorf("%w; none of the %d agent keys is known", err, len(signers))
		}
	}
	return nil, "", err
}

// matchEndpoint is the name of the first config endpoint (by name) whose
// URL equals u; empty for none.
func matchEndpoint(cfg *client.Config, u *neturl.URL) string {
	names := make([]string, 0, len(cfg.Endpoint))
	for n := range cfg.Endpoint {
		names = append(names, n)
	}
	sort.Strings(names)
	want := endpointKey(u)
	for _, n := range names {
		e := cfg.Endpoint[n]
		eu, err := neturl.Parse(e.URL)
		if err != nil {
			continue
		}
		if endpointKey(eu) == want {
			return n
		}
	}
	return ""
}

// endpointKey is the origin of u (scheme, lowercase host, port with the
// default made explicit) and its path without a trailing slash.
func endpointKey(u *neturl.URL) [2]string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return [2]string{u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port, strings.TrimSuffix(u.Path, "/")}
}

// originURL is u without query and fragment.
func originURL(u *neturl.URL) string {
	c := *u
	c.RawQuery, c.Fragment, c.RawFragment = "", "", ""
	return c.String()
}

// scanName is the config endpoint name for the URL: its last path
// segment, or for an origin the first label of the host, or NAME, a
// placeholder to replace, for an origin that is an IP address.
func scanName(u *neturl.URL) string {
	if p := strings.Trim(u.Path, "/"); p != "" {
		return path.Base(p)
	}
	if net.ParseIP(u.Hostname()) != nil {
		return "NAME"
	}
	return strings.SplitN(u.Hostname(), ".", 2)[0]
}

// addCommand is the luk config endpoint add command of an endpoint, with
// --key when key is set.
func addCommand(name, url, key string) string {
	args := []string{"luk", "config", "endpoint", "add", "-e", name, "--url", url}
	if key != "" {
		args = append(args, "--key", key)
	}
	return shellJoin(args)
}

// printEndpoints writes the endpoints as aligned columns; nothing for
// none.
func printEndpoints(w io.Writer, eps []wire.EndpointInfo) error {
	if len(eps) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	quotas := slices.ContainsFunc(eps, func(e wire.EndpointInfo) bool { return e.Quota != nil })
	head := "NAME\tURL\tRESPOND\tTTL\tFLAGS"
	if quotas {
		head += "\tQUOTA"
	}
	fmt.Fprintln(tw, head)
	for _, e := range eps {
		var flags []string
		for _, f := range []struct {
			on   bool
			name string
		}{
			{e.Secret, "secret"}, {e.Pretty, "pretty-url"}, {e.Private.Owner, "private"}, {e.Private.Any, "any"},
			{e.Link.Replace, "mutable"}, {e.Link.Remove, "link-rm"}, {e.Link.TTL, "link-ttl"}, {e.Link.List, "link-ls"},
			{e.Permanent, "permanent"},
		} {
			if f.on {
				flags = append(flags, f.name)
			}
		}
		if e.BackupHostname != "" {
			flags = append(flags, "backup-host:"+client.Printable(e.BackupHostname))
		}
		p := client.Printable
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", p(e.Name), p(e.URL), p(e.Respond), p(ttlText(e.TTL)), cmp.Or(strings.Join(flags, ","), "-"))
		if quotas {
			line += "\t" + p(quotaText(e.Quota))
		}
		fmt.Fprintln(tw, line)
	}
	return tw.Flush()
}

// ttlText is a ttl policy in a column: the lifetime of an upload without
// --ttl (never: no expiry), then the range of --ttl when the storage takes
// it: (1h..7d), (..7d), (1h..) or (any); - without a policy.
func ttlText(p *wire.TTLPolicy) string {
	if p == nil {
		return "-"
	}
	s := cmp.Or(p.Default, "never")
	switch {
	case !p.User:
	case p.Min == "" && p.Max == "":
		s += " (any)"
	default:
		s += " (" + p.Min + ".." + p.Max + ")"
	}
	return s
}

// quotaText is the quota of the signer in a column: the rate, the burst and
// what the bucket holds now ("10G/1d 50G (12.5G left)", passive marked);
// - without a quota.
func quotaText(q *wire.QuotaInfo) string {
	if q == nil {
		return "-"
	}
	s := q.Rate + " " + wire.FormatSize(q.Burst) + " (" + wire.HumanSize(q.Tokens) + " left"
	if q.Mode == "passive" {
		s += ", passive"
	}
	return s + ")"
}
