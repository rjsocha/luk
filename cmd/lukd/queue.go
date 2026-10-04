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

type queuePipeline struct {
	Pipeline string `json:"pipeline"`
	Step     int    `json:"step"`
	Error    string `json:"error"`
	FailedAt string `json:"failed_at"`
}

type queueItem struct {
	ID        string          `json:"id"`
	Endpoint  string          `json:"endpoint"`
	Sender    string          `json:"sender"`
	FailedAt  string          `json:"failed_at"`
	Pipelines []queuePipeline `json:"pipelines"`
}

func queueCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "queue",
		Short: "Failed queue entries",
		Long: "Failed queue entries. The commands work on files and may run while lukd runs.\n" +
			"Run as root they run again as the owner of root (the service user), so the\n" +
			"files stay readable by lukd.",
		PersistentPreRunE: func(*cobra.Command, []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			return asOwner("lukd queue", cfg.Root)
		},
	}
	var asJSON bool
	ls := &cobra.Command{
		Use:   "ls",
		Short: "List the failed entries",
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
		Short: "Remove a failed entry and its work directories",
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

	var retryID string
	var retryPipes []string
	retry := &cobra.Command{
		Use:   "retry",
		Short: "Put a failed entry back into the queue",
		Long: "Put a failed entry back into the queue with its failed pipelines, or only\n" +
			"those given with --pipeline. A running lukd picks it up within a minute,\n" +
			"otherwise it runs at the next start.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			run, err := pipeline.RetryFailed(cfg, retryID, retryPipes)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: queued (%s), lukd runs it within a minute\n", retryID, strings.Join(run, ","))
			return nil
		},
	}
	retry.Flags().StringVar(&retryID, "id", "", "entry id")
	retry.Flags().StringArrayVar(&retryPipes, "pipeline", nil, "failed pipeline to run again (repeatable; default: all)")
	retry.MarkFlagRequired("id")
	completeFlags(retry, map[string]cobra.CompletionFunc{"id": completeFailedID, "pipeline": completeFailedPipeline})

	cmd.AddCommand(ls, rm, retry)
	return cmd
}

func printFailed(w io.Writer, list []pipeline.FailedEntry, asJSON bool, now time.Time) error {
	if asJSON {
		items := []queueItem{}
		for _, f := range list {
			it := queueItem{ID: f.ID, Endpoint: f.Meta.Sidecar.Endpoint, Sender: f.Meta.Sidecar.Sender, Pipelines: []queuePipeline{}}
			if !f.At.IsZero() {
				it.FailedAt = f.At.UTC().Format(time.RFC3339)
			}
			for _, x := range f.Meta.Failed {
				it.Pipelines = append(it.Pipelines, queuePipeline{Pipeline: x.Pipeline, Step: x.Step, Error: x.Error, FailedAt: x.At})
			}
			items = append(items, it)
		}
		b, err := json.MarshalIndent(items, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tENDPOINT\tSENDER\tPIPELINE\tSTEP\tFAILED AT\tAGE\tERROR")
	for _, f := range list {
		for _, x := range f.Meta.Failed {
			age := "-"
			if at, err := time.Parse(time.RFC3339, x.At); err == nil {
				age = formatAge(now.Sub(at))
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", status.Clean(f.ID), dash(status.Clean(f.Meta.Sidecar.Endpoint)),
				dash(status.Clean(f.Meta.Sidecar.Sender)), status.Clean(x.Pipeline), strconv.Itoa(x.Step),
				dash(status.Clean(x.At)), age, dash(status.OneLine(x.Error)))
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
