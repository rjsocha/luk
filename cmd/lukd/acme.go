package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"
	"golang.org/x/term"

	"luk/internal/acmecert"
	"luk/internal/config"
	"luk/internal/server"
	"luk/internal/status"
)

// Replaced by tests: the client to the ACME directories (nil: the
// default), whether stdin is a terminal, how often renew looks for its
// result.
var (
	acmeClient      *http.Client
	stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	renewPoll       = 200 * time.Millisecond
)

var revokeReasons = map[string]acme.CRLReasonCode{
	"unspecified":          acme.CRLReasonUnspecified,
	"keyCompromise":        acme.CRLReasonKeyCompromise,
	"affiliationChanged":   acme.CRLReasonAffiliationChanged,
	"superseded":           acme.CRLReasonSuperseded,
	"cessationOfOperation": acme.CRLReasonCessationOfOperation,
}

func acmeCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acme",
		Short: "Certificates of the tls mode acme listeners",
		Long: "Certificates of the tls mode acme listeners, in the caches under <root>/acme/.\n" +
			"The running receive role renews and swaps them itself; these commands talk to\n" +
			"it only through files in the cache directories (no SIGHUP needed). Run as\n" +
			"root they run again as the owner of <root>/acme (the service user).",
		PersistentPreRunE: func(*cobra.Command, []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			dir := filepath.Join(cfg.Root, "acme")
			if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return asOwner("lukd tls acme", dir)
		},
	}

	var asJSON bool
	ls := &cobra.Command{
		Use:   "ls",
		Short: "List the cached certificates with their listeners and renewal state",
		Long: "List every cached certificate: the listeners using it per the configuration\n" +
			"(unused when no acme listener of that directory lists the name), the\n" +
			"directory host, issuer, validity, next renewal and, while lukd receive runs,\n" +
			"the last error and next retry from its status.json.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			running, err := server.RoleRunning(cfg.Root, "receive")
			if err != nil {
				return err
			}
			rows, err := acmeRows(cfg, running, time.Now())
			if err != nil {
				return err
			}
			return printACME(cmd.OutOrStdout(), rows, asJSON)
		},
	}
	ls.Flags().BoolVar(&asJSON, "json", false, "print JSON")

	var renewHost string
	var renewTimeout time.Duration
	renew := &cobra.Command{
		Use:   "renew",
		Short: "Have the running lukd receive renew a certificate now",
		Long: "Have the running lukd receive renew the certificate of a name now, regardless\n" +
			"of its expiry, and serve it without a restart. Waits for the result.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			return renewACME(cfg, strings.ToLower(renewHost), renewTimeout, cmd.OutOrStdout())
		},
	}
	renew.Flags().StringVar(&renewHost, "host", "", "certificate name")
	completeFlags(renew, map[string]cobra.CompletionFunc{"host": completeACMEHost})
	renew.Flags().DurationVar(&renewTimeout, "timeout", 2*time.Minute, "how long to wait for the result")
	renew.MarkFlagRequired("host")

	var dryRun bool
	prune := &cobra.Command{
		Use:   "prune",
		Short: "Remove the cached certificates no acme listener uses",
		Long: "Remove the cached certificates ls shows as unused. Account keys and\n" +
			"certificates in use are kept.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			return pruneACME(cfg, dryRun, cmd.OutOrStdout())
		},
	}
	prune.Flags().BoolVar(&dryRun, "dry-run", false, "only print what would be removed")

	var revokeHost, reason string
	var yes bool
	var revokeTimeout time.Duration
	revoke := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a cached certificate at the CA and replace it",
		Long: "Revoke the cached certificate of a name at the CA with the account key of the\n" +
			"cache, remove it and have the running lukd receive obtain a new one at once\n" +
			"(as renew). Reasons:\n" + strings.Join(slices.Sorted(maps.Keys(revokeReasons)), ", ") + ".\n" +
			"Asks for confirmation on a terminal; elsewhere --yes is required.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			code, ok := revokeReasons[reason]
			if !ok {
				return fmt.Errorf("--reason %q: one of %s", reason, strings.Join(slices.Sorted(maps.Keys(revokeReasons)), ", "))
			}
			return revokeACME(cfg, strings.ToLower(revokeHost), code, yes, revokeTimeout, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	revoke.Flags().StringVar(&revokeHost, "host", "", "certificate name")
	revoke.Flags().StringVar(&reason, "reason", "unspecified", "revocation reason")
	completeFlags(revoke, map[string]cobra.CompletionFunc{"host": completeACMEHost, "reason": completeReason})
	revoke.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	revoke.Flags().DurationVar(&revokeTimeout, "timeout", 2*time.Minute, "how long to wait for the new certificate")
	revoke.MarkFlagRequired("host")

	cmd.AddCommand(ls, renew, prune, revoke)
	return cmd
}

// acmeRow is one cached certificate.
type acmeRow struct {
	Name          string               `json:"name"`
	Listen        []string             `json:"listen"`
	Unused        bool                 `json:"unused"`
	File          string               `json:"file"`
	Directory     string               `json:"directory,omitempty"`
	DirectoryHost string               `json:"directory_host"`
	Issuer        string               `json:"issuer,omitempty"`
	Serial        string               `json:"serial,omitempty"`
	NotBefore     time.Time            `json:"not_before,omitzero"`
	NotAfter      time.Time            `json:"not_after,omitzero"`
	DaysLeft      int                  `json:"days_left"`
	RenewAt       time.Time            `json:"renew_at,omitzero"`
	Unreadable    string               `json:"unreadable,omitempty"`
	Daemon        *acmecert.HostStatus `json:"daemon,omitempty"`
}

// acmeListener is the acme listener serving host: the first by name that
// lists it.
func acmeListener(cfg *config.Config, host string) (*config.Listen, error) {
	for _, n := range cfg.ListenNames() {
		l := cfg.Listen[n]
		if l.TLS != nil && l.TLS.Mode == "acme" && slices.Contains(l.Host, host) {
			return l, nil
		}
	}
	return nil, fmt.Errorf("%s is not a host of any acme listener", host)
}

// acmeRows reads every certificate of every cache directory under
// <root>/acme. The daemon state of status.json is added when the receive
// role runs; a file left by a stopped one is ignored.
func acmeRows(cfg *config.Config, running bool, now time.Time) ([]acmeRow, error) {
	base := filepath.Join(cfg.Root, "acme")
	fi, err := os.Lstat(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", base)
	}
	ents, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	users := map[string]map[string][]string{}
	urls := map[string]string{}
	for _, n := range cfg.ListenNames() {
		l := cfg.Listen[n]
		if l.TLS == nil || l.TLS.Mode != "acme" {
			continue
		}
		d := cfg.ACMECacheDir(l.TLS.Directory)
		urls[d] = l.TLS.Directory
		if users[d] == nil {
			users[d] = map[string][]string{}
		}
		for _, h := range l.Host {
			users[d][h] = append(users[d][h], l.Name)
		}
	}
	rows := []acmeRow{}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(base, e.Name())
		names, err := acmecert.CertNames(dir)
		if err != nil {
			return nil, err
		}
		var st *acmecert.Status
		if running {
			if st, err = acmecert.ReadStatus(dir); err != nil {
				return nil, err
			}
		}
		u := urls[dir]
		if u == "" && st != nil {
			u = st.Directory
		}
		host, _, _ := strings.Cut(e.Name(), "_")
		if p, err := url.Parse(u); err == nil && p.Host != "" {
			host = p.Host
		}
		for _, n := range names {
			r := acmeRow{Name: n, Listen: users[dir][n], File: acmecert.CertFile(dir, n), Directory: u, DirectoryHost: host}
			if r.Listen == nil {
				r.Listen, r.Unused = []string{}, true
			}
			if leaf, err := acmecert.LoadLeaf(dir, n); err != nil {
				r.Unreadable = err.Error()
			} else {
				r.Issuer, r.Serial = leaf.Issuer.CommonName, acmecert.Serial(leaf)
				r.NotBefore, r.NotAfter = leaf.NotBefore.UTC(), leaf.NotAfter.UTC()
				r.DaysLeft = int(math.Floor(leaf.NotAfter.Sub(now).Hours() / 24))
				r.RenewAt = acmecert.RenewAt(leaf).UTC()
			}
			if st != nil {
				r.Daemon = st.Hosts[n]
			}
			rows = append(rows, r)
		}
	}
	return rows, nil
}

func printACME(w io.Writer, rows []acmeRow, asJSON bool) error {
	if asJSON {
		b, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	}
	ts := func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.UTC().Format(time.RFC3339)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tLISTEN\tDIRECTORY\tISSUER\tNOT BEFORE\tNOT AFTER\tDAYS\tRENEW AT\tLAST ERROR\tRETRY AT")
	for _, r := range rows {
		listen := "unused"
		if !r.Unused {
			listen = strings.Join(r.Listen, ",")
		}
		days, lastErr, retry := fmt.Sprint(r.DaysLeft), "-", "-"
		if r.Unreadable != "" {
			days, lastErr = "-", "unreadable: "+r.Unreadable
		}
		if d := r.Daemon; d != nil {
			if d.LastError != "" {
				lastErr = d.LastError
			}
			retry = ts(d.NextRetry)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", status.Clean(r.Name), status.Clean(listen),
			status.Clean(r.DirectoryHost), dash(status.Clean(r.Issuer)), ts(r.NotBefore), ts(r.NotAfter), days,
			ts(r.RenewAt), status.OneLine(lastErr), retry)
	}
	return tw.Flush()
}

// renewACME asks the running receive role to renew host and waits for the
// result recorded under the nonce of the request.
func renewACME(cfg *config.Config, host string, timeout time.Duration, w io.Writer) error {
	l, err := acmeListener(cfg, host)
	if err != nil {
		return err
	}
	running, err := server.RoleRunning(cfg.Root, "receive")
	if err != nil {
		return err
	}
	if !running {
		return errors.New("lukd receive is not running")
	}
	dir := cfg.ACMECacheDir(l.TLS.Directory)
	nonce, err := acmecert.WriteRequest(dir, host)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		// A status.json being replaced is read on the next round.
		if st, err := acmecert.ReadStatus(dir); err == nil && st != nil {
			if r := st.Requests[nonce]; r != nil {
				if r.Error != "" {
					return fmt.Errorf("%s: renewal failed: %s", host, status.OneLine(r.Error))
				}
				fmt.Fprintf(w, "%s: renewed, serial %s, not after %s\n", host, r.Serial, r.NotAfter.UTC().Format(time.RFC3339))
				return nil
			}
		}
		if time.Now().After(deadline) {
			acmecert.CancelRequest(dir, host, nonce)
			return fmt.Errorf("%s: no result from lukd receive within %s", host, timeout)
		}
		time.Sleep(renewPoll)
	}
}

// pruneACME removes the certificates acmeRows marks unused. A file that
// does not load as a certificate with its key is no cached certificate and
// stays.
func pruneACME(cfg *config.Config, dryRun bool, w io.Writer) error {
	rows, err := acmeRows(cfg, false, time.Now())
	if err != nil {
		return err
	}
	n := 0
	for _, r := range rows {
		if !r.Unused || r.Unreadable != "" {
			continue
		}
		n++
		if dryRun {
			fmt.Fprintf(w, "would remove %s\n", r.File)
			continue
		}
		if err := os.Remove(r.File); err != nil {
			return err
		}
		fmt.Fprintf(w, "removed %s\n", r.File)
	}
	if n == 0 {
		fmt.Fprintln(w, "nothing to prune")
	}
	return nil
}

// revokeACME revokes the cached certificate of host, removes it and asks a
// running receive role for a new one.
func revokeACME(cfg *config.Config, host string, reason acme.CRLReasonCode, yes bool, timeout time.Duration, in io.Reader, w, errw io.Writer) error {
	l, err := acmeListener(cfg, host)
	if err != nil {
		return err
	}
	dir := cfg.ACMECacheDir(l.TLS.Directory)
	leaf, err := acmecert.LoadLeaf(dir, host)
	if err != nil {
		return err
	}
	if !yes {
		if !stdinIsTerminal() {
			return errors.New("refusing to revoke without --yes: stdin is not a terminal")
		}
		fmt.Fprintf(errw, "Revoke the certificate of %s (serial %s, not after %s) at %s? [y/N] ",
			host, acmecert.Serial(leaf), leaf.NotAfter.UTC().Format(time.RFC3339), l.TLS.Directory)
		line, _ := bufio.NewReader(in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return errors.New("not revoked")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if _, err := acmecert.Revoke(ctx, l.TLS.Directory, dir, host, reason, acmeClient); err != nil {
		return fmt.Errorf("%s: revoke: %w", host, err)
	}
	fmt.Fprintf(w, "%s: revoked serial %s\n", host, acmecert.Serial(leaf))
	p := acmecert.CertFile(dir, host)
	if err := os.Remove(p); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s: removed %s\n", host, p)
	running, err := server.RoleRunning(cfg.Root, "receive")
	if err != nil {
		return err
	}
	if !running {
		fmt.Fprintf(errw, "%s: lukd receive is not running; its next start obtains a new certificate\n", host)
		return nil
	}
	return renewACME(cfg, host, timeout, w)
}
