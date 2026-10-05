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
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"luk/internal/client"
	"luk/internal/wire"
)

func newScanCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		key                                   string
		pinOnly, endpoints, printCmds, asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "scan URL",
		Short: "Print the pin of a server and the endpoints it offers you",
		Long: `Scan the lukd server of URL: an origin (https://host:8443) or an endpoint
URL (https://host:8443/drop); a config endpoint name works too. Without
--pin and --endpoints it does both.

--pin connects without verifying the certificate chain and prints the pin
of the server's leaf certificate (sha256//<base64>, the format lukd
prints) on stdout, the certificate subject and validity on stderr. This is
trust on first use: compare it with "lukd tls pin" on the server.

--endpoints sends a signed request for /.well-known/luk/endpoints of the
origin and lists the endpoints of that listener your key may upload to:
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
knows one. The server is trusted by the pin of the config endpoint (or
of the URL fragment), else by the system CAs, else by the pin scanned in
the same run.

An http URL has no pin: --pin is a usage error and the default does the
listing only. When the listing fails the pin is still printed, the error
follows and the exit code is that of luk send.

--json prints one JSON object: {"pin": ..., "endpoints": [...]}, each
only when asked for. --print prints ready-to-run "luk config endpoint
add" commands instead, one per endpoint (https URLs carry the pin as
the fragment when the certificate chain does not verify against the
system CAs, or with --pin; --key the key that listed them unless it is
the config key: --key as given, the key of the config endpoint, or the fingerprint
of the agent key); with --pin alone one command for URL, named by its
last path segment, or by the first label of the host for an origin
(NAME, to replace, for an IP address).`,
		Example: `  luk scan https://lukd.vm:8443
  luk scan --pin https://lukd.vm:8443/drop
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
			cfg, _, err := client.LoadMerged()
			if err != nil {
				return usageError{err}
			}
			raw, pin, err := cfg.Resolve(args[0])
			if err != nil {
				return usageError{err}
			}
			u, err := neturl.Parse(raw)
			if err != nil {
				return usageError{err}
			}
			name := args[0]
			if strings.Contains(name, "://") {
				name = matchEndpoint(cfg, u, false)
			}
			if pin == "" {
				if n := matchEndpoint(cfg, u, true); n != "" {
					pin = cfg.Endpoint[n].Pin
				}
			}
			https := u.Scheme == "https"
			if !https && pinOnly {
				return usageError{fmt.Errorf("--pin needs an https URL, got %q", raw)}
			}
			wantPin := https && (pinOnly || !endpoints)
			wantList := endpoints || !pinOnly
			ctx, stop := interruptContext()
			defer stop()

			var cert *client.Certificate
			if https {
				if cert, err = client.ScanTLS(ctx, u); err != nil {
					return err
				}
				if wantPin || printCmds {
					fmt.Fprintf(stderr, "subject:    %s\nnot before: %s\nnot after:  %s\n",
						client.Printable(cert.Subject), cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
				}
			}
			var list *wire.EndpointList
			var listErr error
			var usedKey string
			if wantList {
				trust := pin
				if trust == "" && cert != nil && !cert.Verified {
					trust = cert.Pin
				}
				list, usedKey, listErr = listEndpoints(ctx, cfg, u, trust, name, key)
				if errors.As(listErr, new(usageError)) {
					return listErr
				}
			}
			switch {
			case asJSON:
				res := scanResult{}
				if wantPin {
					res.Pin = cert.Pin
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
				fragment := pinFragment(cert, pinOnly)
				if list != nil {
					for _, e := range list.Endpoints {
						fmt.Fprintln(stdout, addCommand(client.Printable(e.Name), client.Printable(e.URL)+fragment, usedKey))
					}
				} else if wantPin {
					fmt.Fprintln(stdout, addCommand(scanName(u), originURL(u)+fragment, ""))
				}
			default:
				if wantPin {
					fmt.Fprintln(stdout, cert.Pin)
				}
				if list != nil {
					if err := printEndpoints(stdout, list.Endpoints); err != nil {
						return err
					}
				}
			}
			if listErr != nil {
				return fmt.Errorf("listing endpoints of %s: %w", u.Host, listErr)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&pinOnly, "pin", false, "print the pin of the server certificate (https only)")
	f.BoolVar(&endpoints, "endpoints", false, "list the endpoints your key may use (signed request)")
	f.BoolVar(&printCmds, "print", false, "print luk config endpoint add commands instead")
	f.BoolVar(&asJSON, "json", false, "print one JSON object with the pin and the endpoints")
	f.StringVarP(&key, "key", "k", "", "private key file (uses PATH-cert.pub when present), a .pub file of an agent key, or SHA256:... fingerprint of an agent key")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"key": completeKey})
	return cmd
}

// scanResult is the output of luk scan --json.
type scanResult struct {
	Pin       string               `json:"pin,omitempty"`
	Endpoints *[]wire.EndpointInfo `json:"endpoints,omitempty"`
}

// listEndpoints asks the server of u for the endpoints of the signer,
// trusting the pin (empty: the system CAs). The key is flag, else the key
// of the config endpoint name, else the config key, else each agent key in
// turn while the server does not know it. It also returns the key for the
// commands of --print: flag, the key of the config endpoint, or the
// fingerprint of the agent key the server knew; empty for the config key,
// which every endpoint takes anyway.
func listEndpoints(ctx context.Context, cfg *client.Config, u *neturl.URL, pin, name, flag string) (*wire.EndpointList, string, error) {
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
		l, err = client.ListEndpoints(ctx, client.GetOptions{URL: u, Pin: pin, Signer: s})
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
// URL equals u, or with origin only has the scheme, host and port of u
// and a pin; empty for none.
func matchEndpoint(cfg *client.Config, u *neturl.URL, origin bool) string {
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
		got := endpointKey(eu)
		if origin && e.Pin != "" && got[0] == want[0] {
			return n
		}
		if !origin && got == want {
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

// pinFragment is the "#<pin>" the commands of --print add to an https URL:
// only for a chain that does not verify against the system CAs, or with
// --pin. A verified chain (an acme listener) is trusted by its CA, and a
// pin would break the endpoint at the next renewal. Empty for http (cert
// nil).
func pinFragment(cert *client.Certificate, pinOnly bool) string {
	if cert == nil || (cert.Verified && !pinOnly) {
		return ""
	}
	return "#" + cert.Pin
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
