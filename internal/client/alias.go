package client

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// ValidateAlias checks one alias: a name that can be typed as a command and
// is not a built-in command, and a non-empty expansion whose first word is a
// built-in command (so an alias never expands to another alias). flags, when
// not nil, checks the flags of the expansion.
func ValidateAlias(name string, argv []string, builtin func(string) bool, flags func([]string) error) error {
	switch {
	case name == "":
		return errors.New("alias name is empty")
	case strings.HasPrefix(name, "-") || strings.IndexFunc(name, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) >= 0:
		return fmt.Errorf("alias %q: name must not start with - or contain spaces", name)
	case builtin(name):
		return fmt.Errorf("alias %q: shadows the built-in command %s", name, name)
	case len(argv) == 0:
		return fmt.Errorf("alias %q: expansion is empty", name)
	case !builtin(argv[0]):
		return fmt.Errorf("alias %q: expansion must start with a built-in command, got %q", name, argv[0])
	}
	if flags != nil {
		if err := flags(argv); err != nil {
			return fmt.Errorf("alias %q: %w", name, err)
		}
	}
	return nil
}

// ValidateAliases checks every alias of one layer and returns every problem,
// joined.
func ValidateAliases(c *Config, builtin func(string) bool, flags func([]string) error) error {
	names := make([]string, 0, len(c.Alias))
	for n := range c.Alias {
		names = append(names, n)
	}
	sort.Strings(names)
	var errs []error
	for _, n := range names {
		if err := ValidateAlias(n, c.Alias[n], builtin, flags); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// AddAlias adds or replaces an alias after validating it.
func (c *Config) AddAlias(name string, argv []string, builtin func(string) bool, flags func([]string) error) error {
	if err := ValidateAlias(name, argv, builtin, flags); err != nil {
		return err
	}
	if c.Alias == nil {
		c.Alias = map[string][]string{}
	}
	c.Alias[name] = argv
	return nil
}

func (c *Config) RemoveAlias(name string) error {
	if _, ok := c.Alias[name]; !ok {
		return fmt.Errorf("unknown alias %q", name)
	}
	delete(c.Alias, name)
	return nil
}
