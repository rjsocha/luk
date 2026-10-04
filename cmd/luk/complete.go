package main

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"luk/internal/client"
	"luk/internal/wire"
)

// Flag value completions. A config or agent that cannot be read completes
// nothing rather than printing an error into the shell.
var (
	completeNone  = cobra.NoFileCompletions
	completeFiles = cobra.FixedCompletions(nil, cobra.ShellCompDirectiveDefault)
	completeLayer = cobra.FixedCompletions([]cobra.Completion{"global", "user"}, cobra.ShellCompDirectiveNoFileComp)
	completeTTL   = cobra.FixedCompletions([]cobra.Completion{wire.TTLMax, "1h", "1d", "7d"}, cobra.ShellCompDirectiveNoFileComp)
)

// completeFlags registers value completions for flags of cmd; an unknown
// flag name is a programming error.
func completeFlags(cmd *cobra.Command, fns map[string]cobra.CompletionFunc) {
	for name, fn := range fns {
		if err := cmd.RegisterFlagCompletionFunc(name, fn); err != nil {
			panic(err)
		}
	}
}

// completeEndpoint offers the endpoint names of the merged config, with the
// URL as description.
func completeEndpoint(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg, _, err := client.LoadMerged()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	names := make([]string, 0, len(cfg.Endpoint))
	for n := range cfg.Endpoint {
		names = append(names, n)
	}
	sort.Strings(names)
	var list []cobra.Completion
	for _, n := range names {
		if strings.HasPrefix(n, toComplete) {
			list = append(list, cobra.CompletionWithDesc(n, cfg.Endpoint[n].URL))
		}
	}
	return list, cobra.ShellCompDirectiveNoFileComp
}

// completeAliasName offers the alias names of the merged config, with the
// expansion as description.
func completeAliasName(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg, _, err := client.LoadMerged()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var list []cobra.Completion
	for _, n := range sortedAliases(cfg) {
		if strings.HasPrefix(n, toComplete) {
			list = append(list, cobra.CompletionWithDesc(n, shellJoin(cfg.Alias[n])))
		}
	}
	return list, cobra.ShellCompDirectiveNoFileComp
}

// completeKey offers the fingerprints of the SSH agent keys, described by
// comment and type, and leaves file completion on for key files.
func completeKey(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	keys, err := client.AgentKeys()
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}
	var list []cobra.Completion
	for _, k := range keys {
		if strings.HasPrefix(k.Fingerprint, toComplete) {
			list = append(list, cobra.CompletionWithDesc(k.Fingerprint, strings.TrimSpace(k.Comment+" "+k.Type)))
		}
	}
	return list, cobra.ShellCompDirectiveDefault
}

// completeLinkHost offers the link hosts of the merged config, with the
// endpoint as description.
func completeLinkHost(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg, _, err := client.LoadMerged()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var list []cobra.Completion
	for _, h := range sortedHosts(cfg) {
		if strings.HasPrefix(h, toComplete) {
			list = append(list, cobra.CompletionWithDesc(h, cfg.Link[h]))
		}
	}
	return list, cobra.ShellCompDirectiveNoFileComp
}
