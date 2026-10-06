package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"luk/internal/config"
	"luk/internal/pipeline"
	"luk/internal/status"
)

func queueCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "queue",
		Short: "Failure records of uploads",
		Long: "Failure records of uploads. An upload whose pipelines ended with a failure\n" +
			"is deleted; what stays is its record: what the upload was and how each\n" +
			"pipeline ended. The sender sends the upload again. The commands work on\n" +
			"files and may run while lukd runs. Run as root they run again as the owner\n" +
			"of <root>/data (the service user), so the files stay readable by lukd.",
		PersistentPreRunE: func(*cobra.Command, []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			return asServiceUser("lukd queue", cfg)
		},
	}
	var asJSON bool
	ls := &cobra.Command{
		Use:   "ls",
		Short: "List the failure records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			list, err := pipeline.ListFailed(cfg)
			if err != nil {
				return err
			}
			return printFailed(cmd.OutOrStdout(), list, asJSON, time.Now())
		},
	}
	ls.Flags().BoolVar(&asJSON, "json", false, "print JSON")

	var rmID string
	rm := &cobra.Command{
		Use:   "rm",
		Short: "Remove a failure record",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			if err := pipeline.RemoveFailed(cfg, rmID); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: removed\n", rmID)
			return nil
		},
	}
	rm.Flags().StringVar(&rmID, "id", "", "entry id")
	rm.MarkFlagRequired("id")
	completeFlags(rm, map[string]cobra.CompletionFunc{"id": completeFailedID})

	cmd.AddCommand(ls, rm)
	return cmd
}

func printFailed(w io.Writer, list []pipeline.Record, asJSON bool, now time.Time) error {
	if asJSON {
		if list == nil {
			list = []pipeline.Record{}
		}
		b, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tENDPOINT\tSENDER\tPIPELINE\tSTATE\tSTEP\tAT\tAGE\tDETAIL")
	for _, r := range list {
		for _, o := range r.Pipelines {
			age, step, detail := "-", "-", status.OneLine(o.Error)
			if at, err := time.Parse(time.RFC3339, o.At); err == nil {
				age = formatAge(now.Sub(at))
			}
			if o.Failed() {
				step = strconv.Itoa(o.Step)
			}
			if !o.Failed() || detail == "" {
				detail = status.OneLine(strings.Join(o.Stored, ","))
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", status.Clean(r.ID), dash(status.Clean(r.Endpoint)),
				dash(status.Clean(r.Sender)), status.Clean(o.Pipeline), status.Clean(o.State), step,
				dash(status.Clean(o.At)), age, dash(detail))
		}
	}
	return tw.Flush()
}

func formatAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return strconv.Itoa(int(max(d, 0)/time.Minute)) + "m"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	default:
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
