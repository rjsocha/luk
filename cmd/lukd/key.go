package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"

	"github.com/spf13/cobra"

	"luk/internal/channel"
	"luk/internal/config"
)

// checkIdentity reports a missing or unusable identity key with the way to
// create it; lukd cannot authenticate to its clients without the key.
func checkIdentity(cfg *config.Config) error {
	_, err := channel.LoadKey(cfg.IdentityPath)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("identity key %s is missing: run lukd key generate", cfg.IdentityPath)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("identity key %s cannot be read by %s (it must be readable by the user running lukd, mode 0640 root:luk): %w", cfg.IdentityPath, whoami(), err)
	}
	return fmt.Errorf("identity key %s: %w (replace it with lukd key generate --force)", cfg.IdentityPath, err)
}

func whoami() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "the current user"
}

func keyCmd(cfgPath *string) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Print the pin of the identity key",
		Long: "Print the pin of the identity key: the words (default) or the full key\n" +
			"(--pin-format key). Clients pin it to authenticate lukd (luk scan, luk config\n" +
			"endpoint add). The key file is identity.key next to the main configuration file.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := config.IdentityPath(*cfgPath)
			k, err := channel.LoadKey(path)
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("identity key %s is missing: run lukd key generate", path)
			}
			if err != nil {
				return err
			}
			pin, err := channel.FormatPin(k.Public, format)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), pin)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "pin-format", "words", "pin format: words or key")
	completeFlags(cmd, map[string]cobra.CompletionFunc{
		"pin-format": cobra.FixedCompletions([]string{"words", "key"}, cobra.ShellCompDirectiveNoFileComp),
	})

	var ifMissing, force bool
	gen := &cobra.Command{
		Use:   "generate",
		Short: "Create the identity key and print its pin",
		Long: "Create the identity key and print its pin. An existing key is kept: the\n" +
			"command fails, unless --if-missing (then it does nothing) or --force (rotate:\n" +
			"every client must learn the new pin). Run as root the file becomes root:luk.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ifMissing && force {
				return errors.New("--if-missing and --force exclude each other")
			}
			path := config.IdentityPath(*cfgPath)
			if _, err := os.Lstat(path); err == nil {
				if ifMissing {
					return nil
				}
				if !force {
					return fmt.Errorf("%s exists: use --force to replace it (clients must learn the new pin)", path)
				}
			} else if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			k, err := channel.GenerateKey()
			if err != nil {
				return err
			}
			if err := channel.WriteKeyGroup(path, k, serviceGID()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), channel.Words(k.Public))
			if force {
				// The receive role reads the key at start and on SIGHUP: a
				// running lukd still presents the old one.
				fmt.Fprintln(cmd.ErrOrStderr(), "reload lukd (systemctl reload lukd) for the new key to take effect")
			}
			return nil
		},
	}
	gen.Flags().BoolVar(&ifMissing, "if-missing", false, "do nothing when the key exists")
	gen.Flags().BoolVar(&force, "force", false, "replace an existing key")
	cmd.AddCommand(gen)
	return cmd
}

// serviceGID is the group luk when run as root and the group exists, else
// -1 (tests, a user without the group): the key then keeps the group it
// gets from its creator.
func serviceGID() int {
	if geteuid() != 0 {
		return -1
	}
	g, err := user.LookupGroup("luk")
	if err != nil {
		return -1
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return gid
}
