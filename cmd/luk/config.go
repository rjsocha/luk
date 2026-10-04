package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"luk/internal/client"
)

func newConfigCmd(out, errw io.Writer) *cobra.Command {
	var global bool
	cfgCmd := &cobra.Command{
		Use:   "config",
		Short: "Show or edit the luk config files",
		Long: `Show or edit the luk config. There are two layers: the global file
/etc/site/luk/config.yaml ($LUK_GLOBAL_CONFIG overrides the path) and the
user file ~/.config/luk/config.yaml ($LUK_CONFIG overrides the path). The
user layer overrides the global one: default and key replace, endpoints and
aliases merge by name, link mappings by host. A user endpoint with a url
replaces the global one of its name whole; a user endpoint without a url
sets only the key of the global one (see luk config endpoint key). Edits
write the user layer, or the global one with --global (needs root). Edits
are validated and written atomically.`,
	}
	cfgCmd.PersistentFlags().BoolVar(&global, "global", false, "write the global layer instead of the user layer")
	cfgCmd.AddCommand(
		newShowCmd(out),
		newCheckCmd(out, errw),
		newEndpointCmd(out, &global),
		newDefaultCmd(&global),
		newKeyCmd(&global),
		newLinkMapCmd(out, &global),
	)
	return cfgCmd
}

func newShowCmd(out io.Writer) *cobra.Command {
	var layer string
	cmd := &cobra.Command{
		Use:     "show",
		Short:   "Print the effective config with the source of each value",
		Example: "  luk config show\n  luk config show --layer global",
		Args:    noArgs,
		RunE: func(*cobra.Command, []string) error {
			gp, up := client.GlobalConfigPath(), client.DefaultConfigPath()
			if layer != "" {
				path := gp
				switch layer {
				case "global":
				case "user":
					path = up
				default:
					return usageError{fmt.Errorf("--layer must be global or user, got %q", layer)}
				}
				c, err := client.LoadConfig(path)
				if err != nil {
					return usageError{err}
				}
				data, err := yaml.Marshal(c)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "# %s\n%s", path, data)
				return nil
			}
			cfg, src, err := client.LoadMerged()
			if err != nil {
				return usageError{err}
			}
			fmt.Fprintf(out, "# global: %s (%s)\n# user:   %s (%s)\n", gp, exists(gp), up, exists(up))
			if cfg.Default != "" {
				fmt.Fprintf(out, "default: %s  # %s\n", cfg.Default, src.Default)
			}
			if cfg.Key != "" {
				fmt.Fprintf(out, "key: %s  # %s\n", cfg.Key, src.Key)
			}
			names := make([]string, 0, len(cfg.Endpoint))
			for n := range cfg.Endpoint {
				names = append(names, n)
			}
			sort.Strings(names)
			fmt.Fprintln(out, "endpoint:")
			for _, n := range names {
				e := cfg.Endpoint[n]
				fmt.Fprintf(out, "  %s:  # %s\n    url: %s\n", n, src.Endpoint[n], e.URL)
				if e.Pin != "" {
					fmt.Fprintf(out, "    pin: %s\n", e.Pin)
				}
				if ks := src.EndpointKey[n]; ks != "" {
					fmt.Fprintf(out, "    key: %s  # %s\n", e.Key, ks)
				} else if e.Key != "" {
					fmt.Fprintf(out, "    key: %s\n", e.Key)
				}
			}
			if len(cfg.Link) > 0 {
				fmt.Fprintln(out, "link:")
				for _, h := range sortedHosts(cfg) {
					fmt.Fprintf(out, "  %s: %s  # %s\n", h, cfg.Link[h], src.Link[h])
				}
			}
			if len(cfg.Alias) > 0 {
				fmt.Fprintln(out, "alias:")
				for _, n := range sortedAliases(cfg) {
					fmt.Fprintf(out, "  %s: %s  # %s\n", n, shellJoin(cfg.Alias[n]), src.Alias[n])
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&layer, "layer", "", "print one raw layer: global or user")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"layer": completeLayer})
	return cmd
}

func exists(path string) string {
	if _, err := os.Stat(path); err == nil {
		return "exists"
	}
	return "missing"
}

func newDefaultCmd(global *bool) *cobra.Command {
	var name string
	cmd := edit(global, "default", "Set the default endpoint", "  luk config default --endpoint drop",
		func(layer, merged *client.Config) error {
			if _, ok := merged.Endpoint[name]; !ok {
				return fmt.Errorf("unknown endpoint %q", name)
			}
			layer.Default = name
			return nil
		})
	cmd.Flags().StringVarP(&name, "endpoint", "e", "", "endpoint name from the config")
	cmd.MarkFlagRequired("endpoint")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"endpoint": completeEndpoint})
	return cmd
}

func newKeyCmd(global *bool) *cobra.Command {
	var key string
	var clear bool
	var cmd *cobra.Command
	cmd = edit(global, "key", "Set or clear the default signing key",
		"  luk config key --key ~/.ssh/id_ed25519.pub\n  luk config key --key SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s\n  luk config key --clear",
		func(layer, _ *client.Config) error {
			if err := keyOrClear(cmd, key, clear, "luk config key --clear"); err != nil {
				return err
			}
			if clear {
				layer.Key = ""
				return nil
			}
			if strings.HasPrefix(key, "SHA256:") {
				if err := client.ValidateFingerprint(key); err != nil {
					return err
				}
			}
			layer.Key = key
			return nil
		})
	cmd.Flags().StringVarP(&key, "key", "k", "", "key file path, a .pub file of an agent key, or SHA256:... fingerprint of an agent key")
	cmd.Flags().BoolVar(&clear, "clear", false, "remove the key from the layer")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"key": completeKey})
	return cmd
}

// keyOrClear checks that exactly one of --key and --clear is given and that
// --key is not empty; clearHint is the command that clears instead.
func keyOrClear(cmd *cobra.Command, key string, clear bool, clearHint string) error {
	set := cmd.Flags().Changed("key")
	switch {
	case set && clear:
		return errors.New("--key and --clear are mutually exclusive")
	case !set && !clear:
		return errors.New("one of --key or --clear is required")
	case set && key == "":
		return fmt.Errorf("--key is empty; to remove the key use: %s", clearHint)
	}
	return nil
}

// newEndpointKeyCmd sets or clears the key of one endpoint: in the user
// layer as an overlay on the global endpoint (or on the user's own entry),
// with --global in the global entry.
func newEndpointKeyCmd(global *bool) *cobra.Command {
	var name, key string
	var clear bool
	var cmd *cobra.Command
	cmd = edit(global, "key", "Set or clear the signing key of an endpoint",
		`  luk config endpoint key -e drop -k ~/.ssh/id_ed25519.pub
  luk config endpoint key -e drop -k SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
  luk config endpoint key -e drop --clear
  luk config endpoint key --global -e drop -k /etc/ssh/ssh_host_ed25519_key`,
		func(layer, merged *client.Config) error {
			if err := keyOrClear(cmd, key, clear, "luk config endpoint key -e "+name+" --clear"); err != nil {
				return err
			}
			if *global {
				if e, ok := layer.Endpoint[name]; !ok || e.IsOverlay() {
					return fmt.Errorf("unknown endpoint %q in the global config", name)
				}
				if clear {
					layer.ClearEndpointKey(name)
					return nil
				}
				return layer.SetEndpointKey(name, key)
			}
			if clear {
				if layer.ClearEndpointKey(name) {
					return nil
				}
				e, ok := merged.Endpoint[name]
				switch {
				case !ok:
					return fmt.Errorf("unknown endpoint %q", name)
				case e.Key != "":
					if _, own := layer.Endpoint[name]; !own {
						return fmt.Errorf("the key of endpoint %s is set in the global config; use --global", name)
					}
				}
				return nil
			}
			if _, ok := merged.Endpoint[name]; !ok {
				return fmt.Errorf("unknown endpoint %q", name)
			}
			return layer.SetEndpointKey(name, key)
		})
	cmd.Long = `Set or clear the signing key of an endpoint. Without --global it writes the
user layer: when the user layer has the endpoint with a url, its key is set;
otherwise an entry with only the key is written, which keeps the url and pin
of the global endpoint (an overlay). --clear removes that overlay, or the key
of the user's own entry. With --global it sets or clears the key of the
global endpoint itself. KEY is a key file path, a .pub file of an agent key,
or the SHA256:... fingerprint of an agent key.`
	cmd.Flags().StringVarP(&name, "endpoint", "e", "", "endpoint name from the config")
	cmd.Flags().StringVarP(&key, "key", "k", "", "key file path, a .pub file of an agent key, or SHA256:... fingerprint of an agent key")
	cmd.Flags().BoolVar(&clear, "clear", false, "remove the key of the endpoint from the layer")
	cmd.MarkFlagRequired("endpoint")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"endpoint": completeEndpoint, "key": completeKey})
	return cmd
}

func newEndpointCmd(out io.Writer, global *bool) *cobra.Command {
	var name, url, pin, key string
	ep := &cobra.Command{
		Use:   "endpoint",
		Short: "List, show, add or remove endpoints, or set their keys",
	}
	add := edit(global, "add", "Add or replace an endpoint",
		"  luk config endpoint add -e drop --url https://lukd.vm:8443/drop --pin sha256//Xk9...\n  luk config endpoint add -e backup --url http://lukd.vm:8080/backup --key SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
		func(layer, _ *client.Config) error { return layer.AddEndpoint(name, url, pin, key) })
	add.Flags().StringVarP(&name, "endpoint", "e", "", "endpoint name")
	add.Flags().StringVar(&url, "url", "", "endpoint URL, http or https (may end with #sha256//... as the pin)")
	add.Flags().StringVar(&pin, "pin", "", "server certificate pin, sha256//... (https only; see luk scan)")
	add.Flags().StringVarP(&key, "key", "k", "", "signing key for this endpoint: key file path or SHA256:... fingerprint of an agent key")
	add.MarkFlagRequired("endpoint")
	add.MarkFlagRequired("url")
	completeFlags(add, map[string]cobra.CompletionFunc{"endpoint": completeEndpoint, "url": completeNone, "pin": completeNone, "key": completeKey})
	var rmName string
	rm := edit(global, "rm", "Remove an endpoint (clears the default when it was the default)", "  luk config endpoint rm -e backup",
		func(layer, merged *client.Config) error {
			if _, ok := layer.Endpoint[rmName]; !ok {
				if _, inMerged := merged.Endpoint[rmName]; inMerged {
					return fmt.Errorf("endpoint %s is defined in the global config; use --global", rmName)
				}
			}
			return layer.RemoveEndpoint(rmName)
		})
	rm.Flags().StringVarP(&rmName, "endpoint", "e", "", "endpoint name")
	rm.MarkFlagRequired("endpoint")
	completeFlags(rm, map[string]cobra.CompletionFunc{"endpoint": completeEndpoint})
	ep.AddCommand(newEndpointLsCmd(out), newEndpointShowCmd(out), add, rm, newEndpointKeyCmd(global))
	return ep
}

// edit builds a command that loads the chosen layer, applies fn (which also
// sees the merged config for validation) and saves that layer alone.
func edit(global *bool, use, short, example string, fn func(layer, merged *client.Config) error) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Example: example,
		Args:    noArgs,
		RunE: func(*cobra.Command, []string) error {
			path, dirMode, fileMode := client.DefaultConfigPath(), os.FileMode(0o700), os.FileMode(0o600)
			if *global {
				path, dirMode, fileMode = client.GlobalConfigPath(), 0o755, 0o644
			}
			if path == "" {
				return usageError{errors.New("no config path: set LUK_CONFIG")}
			}
			layer, err := client.LoadConfig(path)
			if err != nil {
				return usageError{err}
			}
			// An overlay without a global endpoint does not block edits:
			// one of them is the edit that removes it.
			g, u, err := client.LoadLayers()
			if err != nil {
				return usageError{err}
			}
			merged, _ := client.Merge(g, u)
			if err := fn(layer, merged); err != nil {
				return usageError{err}
			}
			if err := client.SaveConfigMode(path, layer, dirMode, fileMode); err != nil {
				if *global && errors.Is(err, fs.ErrPermission) {
					return usageError{fmt.Errorf("%w (--global needs root)", err)}
				}
				return err
			}
			return nil
		},
	}
}

func newEndpointLsCmd(out io.Writer) *cobra.Command {
	var layer string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List endpoints: name, URL, pin, key, source, default marker",
		Long: `List endpoints, one per line: name, URL, pin or -, key or -, source, and
* for the default. The source is global or user; an endpoint whose key comes
from a user overlay on a global endpoint shows global,key:user.`,
		Example: "  luk config endpoint ls\n  luk config endpoint ls --layer global",
		Args:    noArgs,
		RunE: func(*cobra.Command, []string) error {
			var cfg *client.Config
			src := client.Sources{Endpoint: map[string]string{}, EndpointKey: map[string]string{}}
			if layer != "" {
				path, err := layerPath(layer)
				if err != nil {
					return err
				}
				if cfg, err = client.LoadConfig(path); err != nil {
					return usageError{err}
				}
				for n := range cfg.Endpoint {
					src.Endpoint[n] = layer
				}
			} else {
				var err error
				if cfg, src, err = client.LoadMerged(); err != nil {
					return usageError{err}
				}
			}
			names := make([]string, 0, len(cfg.Endpoint))
			for n := range cfg.Endpoint {
				names = append(names, n)
			}
			sort.Strings(names)
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			for _, n := range names {
				e := cfg.Endpoint[n]
				url, pin, key, source, mark := e.URL, "-", "-", src.Endpoint[n], ""
				if url == "" {
					url = "-"
				}
				if ks := src.EndpointKey[n]; ks != "" {
					source += ",key:" + ks
				}
				if e.Pin != "" {
					pin = "pin"
				}
				if e.Key != "" {
					key = e.Key
				}
				if n == cfg.Default {
					mark = "*"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", n, url, pin, key, source, mark)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&layer, "layer", "", "list one raw layer: global or user")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"layer": completeLayer})
	return cmd
}

func newEndpointShowCmd(out io.Writer) *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:     "show",
		Short:   "Print one endpoint from the merged config",
		Example: "  luk config endpoint show -e drop",
		Args:    noArgs,
		RunE: func(*cobra.Command, []string) error {
			cfg, src, err := client.LoadMerged()
			if err != nil {
				return usageError{err}
			}
			e, ok := cfg.Endpoint[name]
			if !ok {
				return usageError{fmt.Errorf("unknown endpoint %q", name)}
			}
			pin, key := e.Pin, e.Key
			if pin == "" {
				pin = "-"
			}
			if key == "" {
				key = "-"
			}
			fmt.Fprintf(out, "name:    %s\nurl:     %s\n", name, e.URL)
			if e.Pin != "" {
				// The URL with the pin as its fragment, as endpoint add takes it.
				fmt.Fprintf(out, "         %s#%s\n", e.URL, e.Pin)
			}
			source := src.Endpoint[name]
			if ks := src.EndpointKey[name]; ks != "" {
				source += ", key: " + ks
			}
			fmt.Fprintf(out, "pin:     %s\nkey:     %s\nsource:  %s\ndefault: %t\n",
				pin, key, source, name == cfg.Default)
			return nil
		},
	}
	cmd.Flags().StringVarP(&name, "endpoint", "e", "", "endpoint name")
	cmd.MarkFlagRequired("endpoint")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"endpoint": completeEndpoint})
	return cmd
}

func layerPath(layer string) (string, error) {
	switch layer {
	case "global":
		return client.GlobalConfigPath(), nil
	case "user":
		return client.DefaultConfigPath(), nil
	}
	return "", usageError{fmt.Errorf("--layer must be global or user, got %q", layer)}
}

func newCheckCmd(out, errw io.Writer) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate config files",
		Long: `Validate config files without changing them. With --file, validate that one
file on its own: the global and user layers are not read, so it works as an
Ansible validate step. Without --file, validate each existing layer and then
the merged result. Prints ok and exits 0, or lists every problem and exits 1.
A key file that does not exist only produces a warning; a SHA256: fingerprint
is only checked for its form.`,
		Example: "  luk config check\n  luk config check --file ./config.yaml\n  # Ansible: template: ... validate: \"luk config check --file %s\"",
		Args:    noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			builtin, flags := builtinOf(cmd.Root()), aliasFlagCheck(cmd.Root())
			if cmd.Flags().Changed("file") {
				c, err := loadStrict(file)
				if err == nil {
					err = errors.Join(client.ValidateConfig(c, client.Standalone), client.ValidateAliases(c, builtin, flags))
				}
				if err != nil {
					return usageError{err}
				}
				warnKey(errw, c)
				fmt.Fprintln(out, "ok")
				return nil
			}
			var problems []error
			var layers []*client.Config
			for i, path := range []string{client.GlobalConfigPath(), client.DefaultConfigPath()} {
				c, err := client.LoadConfig(path)
				if err != nil {
					problems = append(problems, err)
					layers = append(layers, &client.Config{})
					continue
				}
				layers = append(layers, c)
				if _, err := os.Stat(path); err != nil {
					continue
				}
				fmt.Fprintf(out, "checked %s\n", path)
				problems = append(problems, prefixed(path, client.ValidateConfig(c, []client.Layer{client.GlobalLayer, client.UserLayer}[i]))...)
				problems = append(problems, prefixed(path, client.ValidateAliases(c, builtin, flags))...)
				warnKey(errw, c)
			}
			merged, src := client.Merge(layers[0], layers[1])
			if err := client.UnmatchedError(client.DefaultConfigPath(), src); err != nil {
				problems = append(problems, err)
			}
			if err := client.ValidateDefault(merged); err != nil {
				problems = append(problems, err)
			}
			if err := client.ValidateLinks(merged, merged.Endpoint); err != nil {
				problems = append(problems, err)
			}
			if err := errors.Join(problems...); err != nil {
				return usageError{err}
			}
			fmt.Fprintln(out, "ok")
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "validate only this file, ignoring the global and user layers")
	completeFlags(cmd, map[string]cobra.CompletionFunc{"file": completeFiles})
	return cmd
}

func loadStrict(path string) (*client.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return client.ParseConfig(path, data)
}

func prefixed(path string, err error) []error {
	if err == nil {
		return nil
	}
	var list []error
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		list = j.Unwrap()
	} else {
		list = []error{err}
	}
	for i, e := range list {
		list[i] = fmt.Errorf("%s: %w", path, e)
	}
	return list
}

func warnKey(errw io.Writer, c *client.Config) {
	keys := []string{c.Key}
	names := make([]string, 0, len(c.Endpoint))
	for n := range c.Endpoint {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		keys = append(keys, c.Endpoint[n].Key)
	}
	for _, k := range keys {
		warnKeyFile(errw, k)
	}
}

func warnKeyFile(errw io.Writer, raw string) {
	key := raw
	if key == "" || strings.HasPrefix(key, "SHA256:") {
		return
	}
	if rest, ok := strings.CutPrefix(key, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		key = filepath.Join(home, rest)
	}
	if !filepath.IsAbs(key) {
		return
	}
	f, err := os.Open(key)
	if err != nil {
		fmt.Fprintf(errw, "luk: warning: key %s: %v\n", raw, err)
		return
	}
	f.Close()
}

func sortedHosts(cfg *client.Config) []string {
	hosts := make([]string, 0, len(cfg.Link))
	for h := range cfg.Link {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// newLinkMapCmd edits the mappings of link hosts to endpoints (luk link).
func newLinkMapCmd(out io.Writer, global *bool) *cobra.Command {
	lc := &cobra.Command{
		Use:   "link",
		Short: "List, add or remove the endpoints luk link uses per link host",
	}
	var url, endpoint string
	add := edit(global, "add", "Use an endpoint for the links of the host of a URL",
		"  luk config link add --url https://drop.example.com/d/ --endpoint drop",
		func(layer, merged *client.Config) error { return layer.AddLink(url, endpoint, merged) })
	add.Flags().StringVar(&url, "url", "", "a link or any http(s) URL of its host; the host is kept, without the port")
	add.Flags().StringVarP(&endpoint, "endpoint", "e", "", "endpoint name from the config")
	add.MarkFlagRequired("url")
	add.MarkFlagRequired("endpoint")
	completeFlags(add, map[string]cobra.CompletionFunc{"url": completeNone, "endpoint": completeEndpoint})
	var host string
	rm := edit(global, "rm", "Remove the endpoint of a link host", "  luk config link rm --host drop.example.com",
		func(layer, merged *client.Config) error {
			if _, ok := layer.Link[host]; !ok {
				if _, inMerged := merged.Link[host]; inMerged {
					return fmt.Errorf("link %s is defined in the global config; use --global", host)
				}
			}
			return layer.RemoveLink(host)
		})
	rm.Flags().StringVar(&host, "host", "", "link host, as luk config link ls prints it")
	rm.MarkFlagRequired("host")
	completeFlags(rm, map[string]cobra.CompletionFunc{"host": completeLinkHost})
	ls := &cobra.Command{
		Use:     "ls",
		Short:   "List link hosts: host, endpoint, source",
		Example: "  luk config link ls",
		Args:    noArgs,
		RunE: func(*cobra.Command, []string) error {
			cfg, src, err := client.LoadMerged()
			if err != nil {
				return usageError{err}
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			for _, h := range sortedHosts(cfg) {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", h, cfg.Link[h], src.Link[h])
			}
			return tw.Flush()
		},
	}
	lc.AddCommand(ls, add, rm)
	return lc
}
