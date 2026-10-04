package main

import (
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"luk/internal/config"
	"luk/internal/pipeline"
	"luk/internal/store"
)

// completeFlags registers completion functions for flags of cmd.
func completeFlags(cmd *cobra.Command, fns map[string]cobra.CompletionFunc) {
	for name, fn := range fns {
		if err := cmd.RegisterFlagCompletionFunc(name, fn); err != nil {
			panic(err)
		}
	}
}

// completeConfig loads the configuration -c names for a completion; nil
// when it cannot be read (completion then offers nothing).
func completeConfig(cmd *cobra.Command) *config.Config {
	path := "/etc/site/lukd/config.yaml"
	if f := cmd.Flag("config"); f != nil {
		path = f.Value.String()
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil
	}
	return cfg
}

// completeNames offers names with the toComplete prefix, sorted.
func completeNames(names []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	var out []cobra.Completion
	for _, n := range slices.Sorted(slices.Values(names)) {
		if strings.HasPrefix(n, toComplete) {
			out = append(out, n)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeStorage offers the local storages: lukd storage works on them.
func completeStorage(cmd *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg := completeConfig(cmd)
	if cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for n, s := range cfg.Storage {
		if s.Type == "local" {
			names = append(names, n)
		}
	}
	return completeNames(names, toComplete)
}

// completeStored offers the stored names of the storage given with
// --storage, read as the calling user (a completion never switches to the
// owner of the base).
func completeStored(cmd *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg := completeConfig(cmd)
	name := cmd.Flag("storage").Value.String()
	if cfg == nil || cfg.Storage[name] == nil || cfg.Storage[name].Type != "local" {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	files, _ := storageFiles(cfg, name, store.FromConfig(cfg.Storage[name]), "", 0, time.Now())
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	return completeNames(names, toComplete)
}

func completeEndpoint(cmd *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg := completeConfig(cmd)
	if cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeNames(slices.Collect(maps.Keys(cfg.Endpoint)), toComplete)
}

// completeOwner offers the key names; certificates go by owner key.
func completeOwner(cmd *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg := completeConfig(cmd)
	if cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for _, k := range cfg.Auth.Keys {
		names = append(names, k.Name)
	}
	return completeNames(names, toComplete)
}

// completeFailedID offers the ids of the failed queue entries.
func completeFailedID(cmd *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg := completeConfig(cmd)
	if cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	list, _ := pipeline.ListFailed(cfg)
	var ids []string
	for _, f := range list {
		ids = append(ids, f.ID)
	}
	return completeNames(ids, toComplete)
}

// completeFailedPipeline offers the failed pipelines of the entry given
// with --id, or every pipeline without it.
func completeFailedPipeline(cmd *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg := completeConfig(cmd)
	if cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	id := cmd.Flag("id").Value.String()
	if id == "" {
		return completeNames(slices.Collect(maps.Keys(cfg.Pipeline)), toComplete)
	}
	list, _ := pipeline.ListFailed(cfg)
	var names []string
	for _, f := range list {
		if f.ID == id {
			for _, x := range f.Meta.Failed {
				names = append(names, x.Pipeline)
			}
		}
	}
	return completeNames(names, toComplete)
}

// completeACMEHost offers the certificate names of the acme listeners.
func completeACMEHost(cmd *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg := completeConfig(cmd)
	if cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for _, l := range cfg.Listen {
		if l.TLS != nil && l.TLS.Mode == "acme" {
			names = append(names, l.Host...)
		}
	}
	return completeNames(slices.Compact(slices.Sorted(slices.Values(names))), toComplete)
}

func completeReason(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return completeNames(slices.Collect(maps.Keys(revokeReasons)), toComplete)
}

func completeNone(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveNoFileComp
}
