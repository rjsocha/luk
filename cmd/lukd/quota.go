package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"luk/internal/auth"
	"luk/internal/config"
	"luk/internal/quota"
	"luk/internal/status"
	"luk/internal/wire"
)

func quotaCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quota",
		Short: "Upload quotas of the endpoints",
		Long: "Upload quotas of the endpoints: the buckets per endpoint and identity, read\n" +
			"from the state file under root (without the daemon or while it runs), and\n" +
			"which class applies to an identity.",
	}

	var lsEndpoint, margin string
	ls := &cobra.Command{
		Use:   "ls",
		Short: "List the buckets and stats per endpoint and identity",
		Long: "List the buckets per endpoint and identity (a key name, or <ca>#<Key ID>):\n" +
			"the class and mode of the last upload, the tokens now of the burst, the\n" +
			"bytes (and uploads) of the last 24 hours and 7 days, the lowest level after\n" +
			"an upload and the uploads refused (or that passive mode would have refused)\n" +
			"in the last 7 days. Identities with a full bucket and nothing in 7 days are\n" +
			"not kept.\n" +
			"SUGGEST proposes a limit from those 7 days: the rate is the largest volume\n" +
			"of a day (UTC) plus --margin, per day; the burst the largest upload plus\n" +
			"--margin, never below the size of that rate; both rounded up to whole units\n" +
			"(12.6G is 13G). - with less than a day of stats.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := parseMargin(margin)
			if err != nil {
				return err
			}
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			rows, err := quota.Report(quota.Path(cfg.Root), time.Now())
			if err != nil {
				return err
			}
			if lsEndpoint != "" {
				rows = slices.DeleteFunc(rows, func(r quota.Row) bool { return r.Endpoint != lsEndpoint })
			}
			return printQuota(cmd.OutOrStdout(), rows, m)
		},
	}
	ls.Flags().StringVar(&lsEndpoint, "endpoint", "", "only this endpoint")
	ls.Flags().StringVar(&margin, "margin", "50%", "margin of SUGGEST over the largest day and upload")

	var exEndpoint string
	explain := &cobra.Command{
		Use:   "explain CERT.pub|KEY.pub|NAME",
		Short: "Show which quota class applies to an identity",
		Long: "Show which quota class applies to an identity on every endpoint with a quota:\n" +
			"the classes it matches with the members that match, the one in force marked\n" +
			"with * (of several the lowest: the lowest rate, then the lower burst, then\n" +
			"the first), and its rate, burst and mode. The identity is a certificate or\n" +
			"a public key file, or the name of a plain key.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("%s needs one certificate, key file or key name", cmd.CommandPath())
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			if exEndpoint != "" {
				if ep, ok := cfg.Endpoint[exEndpoint]; !ok {
					return fmt.Errorf("unknown endpoint %q", exEndpoint)
				} else if ep.Quota == nil {
					return fmt.Errorf("endpoint %s has no quota", exEndpoint)
				}
			}
			id, err := explainIdentity(cfg, args[0])
			if err != nil {
				return err
			}
			return printExplain(cmd.OutOrStdout(), cfg, id, exEndpoint)
		},
	}
	explain.Flags().StringVar(&exEndpoint, "endpoint", "", "only this endpoint")

	cmd.AddCommand(ls, explain)
	return cmd
}

// explainIdentity is the identity of arg: a certificate or public key
// file, resolved as a signature with it would be now, or a plain key name.
func explainIdentity(cfg *config.Config, arg string) (*wire.Identity, error) {
	data, err := os.ReadFile(arg)
	if errors.Is(err, fs.ErrNotExist) && !strings.Contains(arg, "/") {
		for _, k := range cfg.Auth.Keys {
			if k.Name == arg {
				return &wire.Identity{Name: k.Name, Type: "key"}, nil
			}
		}
		return nil, fmt.Errorf("%s: neither a file nor a known key name", arg)
	}
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", arg, err)
	}
	return auth.New(cfg.Auth).Resolve(pub, time.Now())
}

// parseMargin reads a margin in percent ("50%" or "50") as a fraction.
func parseMargin(s string) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	if err != nil || v < 0 || math.IsInf(v, 0) {
		return 0, fmt.Errorf("--margin %q: want a percentage such as 50%%", s)
	}
	return v / 100, nil
}

func printQuota(w io.Writer, rows []quota.Row, margin float64) error {
	if len(rows) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ENDPOINT\tIDENTITY\tCLASS\tMODE\tRATE\tTOKENS\t24H\t7D\tLOW\tREFUSED\tSUGGEST")
	for _, r := range rows {
		low, suggest := "-", "-"
		if r.Low != nil {
			low = wire.HumanSize(*r.Low)
		}
		if rate, burst, ok := r.Suggest(margin); ok {
			suggest = rate.String() + " " + wire.FormatSize(burst)
		}
		fmt.Fprintln(tw, strings.Join([]string{
			status.Clean(r.Endpoint), status.Clean(r.Identity), dash(status.Clean(r.Class)), r.Mode, r.Rate,
			wire.HumanSize(r.Tokens) + "/" + wire.FormatSize(r.Burst),
			fmt.Sprintf("%s (%d)", wire.HumanSize(r.Bytes24h), r.Uploads24),
			fmt.Sprintf("%s (%d)", wire.HumanSize(r.Bytes7d), r.Uploads7d),
			low, strconv.Itoa(r.Refused), suggest,
		}, "\t"))
	}
	return tw.Flush()
}

// printExplain writes per endpoint with a quota (only one when set) the
// classes that apply to id.
func printExplain(w io.Writer, cfg *config.Config, id *wire.Identity, only string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ENDPOINT\tCLASS\tRATE\tBURST\tMODE\tMATCH")
	names := make([]string, 0, len(cfg.Endpoint))
	for n, ep := range cfg.Endpoint {
		if ep.Quota != nil && (only == "" || n == only) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	for _, n := range names {
		q := cfg.Endpoint[n].Quota
		classes, in := quota.Match(q, id)
		if in < 0 {
			fmt.Fprintf(tw, "%s\t-\t-\t-\t%s\tno class applies, no limit\n", n, q.Mode)
			continue
		}
		for i, cl := range classes {
			mark := "  "
			if i == in {
				mark = "* "
			}
			match := "(catch-all)"
			if len(cl.Members) > 0 {
				var ms []string
				for _, m := range cl.Members {
					if auth.Allowed(id, []string{m}) {
						ms = append(ms, m)
					}
				}
				match = strings.Join(ms, ",")
			}
			fmt.Fprintf(tw, "%s\t%s%s\t%s\t%s\t%s\t%s\n", n, mark, dash(cl.Name), cl.Rate, wire.FormatSize(int64(cl.Burst)), q.Mode, match)
		}
	}
	return tw.Flush()
}
