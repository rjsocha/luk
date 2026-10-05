package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"luk/internal/channel"
	"luk/internal/wire"
)

// LinkOptions is a link request to the endpoint o.URL: Action (wire.LinkRemove,
// wire.LinkTTL or wire.LinkReplace; a list goes through LinkList) on the stored upload at Link. TTL is
// the new lifetime of a ttl; a replace sends the new content as an upload
// does (Meta, Body, Size, Progress, BWLimit).
type LinkOptions struct {
	Options
	Link   string
	Action string
	TTL    string
}

// Link sends a link request through the channel and returns the server
// answer: 200 for remove and ttl, 202 for a replace, whose sha256 is
// compared with the content sent. A replace sends its content in parts as
// an upload does.
func Link(ctx context.Context, o LinkOptions) (*wire.LinkAnswer, error) {
	method, ok := wire.LinkMethod(o.Action)
	if !ok || o.Action == wire.LinkList {
		return nil, fmt.Errorf("unknown link action %q", o.Action)
	}
	if o.Action == wire.LinkReplace {
		return linkReplace(ctx, o, method)
	}
	metaS, err := wire.EncodeLinkMeta(wire.LinkMeta{TTL: o.TTL})
	if err != nil {
		return nil, err
	}
	resp, err := linkOp(ctx, o.Options, method, o.Link, o.Action, metaS)
	if err != nil {
		return nil, err
	}
	if resp.Status >= 400 {
		return nil, rejection(resp)
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("unexpected answer %d %s to a link %s", resp.Status, http.StatusText(resp.Status), o.Action)
	}
	a := &wire.LinkAnswer{}
	if err := json.Unmarshal(resp.Body, a); err != nil {
		return nil, fmt.Errorf("bad answer (%d): %w", resp.Status, err)
	}
	return a, nil
}

// linkOp sends a link request without content as the one OP of a new
// channel to o.URL and returns the answer.
func linkOp(ctx context.Context, o Options, method, link, action, metaS string) (*InnerResponse, error) {
	u, err := url.Parse(o.URL)
	if err != nil {
		return nil, err
	}
	c, err := Dial(ctx, DialOptions{URL: u, Pins: o.Pins})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	header := map[string]string{wire.HeaderLink: link, wire.HeaderLinkAction: action}
	req, err := signedOp(o, c, method, metaS, header, func(host, path, ts, nonce string) (string, []byte) {
		return wire.LinkNamespaceV2, wire.LinkCanonicalTextV2(method, host, path, link, action, ts, nonce, metaS, c.H())
	})
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req, nil)
}

// linkReplace replaces the content of o.Link through the channel.
func linkReplace(ctx context.Context, o LinkOptions, method string) (*wire.LinkAnswer, error) {
	if err := o.Meta.Normalize(); err != nil {
		return nil, err
	}
	metaS, err := wire.EncodeMeta(o.Meta)
	if err != nil {
		return nil, err
	}
	header := map[string]string{wire.HeaderLink: o.Link, wire.HeaderLinkAction: o.Action}
	res, err := uploadParts(ctx, o.Options, func(c *Channel) (channel.Request, error) {
		return signedOp(o.Options, c, method, metaS, header, func(host, path, ts, nonce string) (string, []byte) {
			return wire.LinkNamespaceV2, wire.LinkCanonicalTextV2(method, host, path, o.Link, o.Action, ts, nonce, metaS, c.H())
		})
	})
	if err != nil {
		return nil, err
	}
	resp := res.resp
	if resp.Status >= 400 {
		if he := changedSource(o.Options, res, resp.Status); he != nil {
			return nil, he
		}
		return nil, rejection(resp)
	}
	if resp.Status != http.StatusAccepted || !res.parts {
		return nil, fmt.Errorf("unexpected answer %d %s to a link %s", resp.Status, http.StatusText(resp.Status), o.Action)
	}
	a := &wire.LinkAnswer{}
	if err := json.Unmarshal(resp.Body, a); err != nil {
		return nil, fmt.Errorf("bad answer (%d): %w", resp.Status, err)
	}
	if local := sentSum(o.Options, res); a.SHA256 != "" && a.SHA256 != local {
		return a, &HashMismatchError{Local: local, Remote: a.SHA256}
	}
	return a, nil
}

// LinkList asks the endpoint o.URL through the channel for the links of
// the signer there; only URL, Pins and Signer of o count.
func LinkList(ctx context.Context, o Options) (*wire.LinkListAnswer, error) {
	metaS, err := wire.EncodeLinkMeta(wire.LinkMeta{})
	if err != nil {
		return nil, err
	}
	method, _ := wire.LinkMethod(wire.LinkList)
	resp, err := linkOp(ctx, Options{URL: o.URL, Pins: o.Pins, Signer: o.Signer}, method, "", wire.LinkList, metaS)
	if err != nil {
		return nil, err
	}
	if resp.Status >= 400 {
		return nil, rejection(resp)
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("unexpected answer %d %s to a link list", resp.Status, http.StatusText(resp.Status))
	}
	a := &wire.LinkListAnswer{}
	if err := json.Unmarshal(resp.Body, a); err != nil {
		return nil, fmt.Errorf("bad answer (%d): %w", resp.Status, err)
	}
	return a, nil
}

// LinkHost is the host a link mapping is kept under: the lowercase host of
// an http(s) or luk URL, without the port.
func LinkHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != wire.SchemeLuk) || u.Hostname() == "" {
		return "", fmt.Errorf("invalid link URL %q, want http(s)://host/... or luk://host/...", raw)
	}
	return strings.ToLower(u.Hostname()), nil
}

// LinkEndpoint is the endpoint argument for a link request to the link
// URL: flag (a name or a URL) when set, else the endpoint the link mapping
// gives the host of the URL, else the default endpoint.
func (c *Config) LinkEndpoint(link, flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	host, err := LinkHost(link)
	if err != nil {
		return "", err
	}
	if e, ok := c.Link[host]; ok {
		return e, nil
	}
	if c.Default != "" {
		return c.Default, nil
	}
	return "", fmt.Errorf("no endpoint for host %s; add one with luk config link add --url LINK -e NAME", host)
}

// AddLink maps the host of the link URL to the endpoint, which must be one
// of merged.
func (c *Config) AddLink(link, endpoint string, merged *Config) error {
	host, err := LinkHost(link)
	if err != nil {
		return err
	}
	if _, ok := merged.Endpoint[endpoint]; !ok {
		return fmt.Errorf("unknown endpoint %q", endpoint)
	}
	if c.Link == nil {
		c.Link = map[string]string{}
	}
	c.Link[host] = endpoint
	return nil
}

// RemoveLink deletes the mapping of host.
func (c *Config) RemoveLink(host string) error {
	if _, ok := c.Link[host]; !ok {
		return fmt.Errorf("unknown link host %q", host)
	}
	delete(c.Link, host)
	return nil
}

// validLinkHost reports whether host is a lowercase host name as LinkHost
// keeps it.
func validLinkHost(host string) bool {
	h := host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	got, err := LinkHost("https://" + h + "/")
	return err == nil && got == host
}

// ValidateLinks checks the link mappings of one layer: a valid host and an
// endpoint name; with endpoints set, the endpoint must be one of them.
func ValidateLinks(c *Config, endpoints map[string]EndpointConfig) error {
	var errs []error
	for _, host := range slices.Sorted(maps.Keys(c.Link)) {
		e := c.Link[host]
		switch {
		case !validLinkHost(host):
			errs = append(errs, fmt.Errorf("link %q: not a lowercase host name", host))
		case e == "":
			errs = append(errs, fmt.Errorf("link %s: no endpoint", host))
		case endpoints != nil:
			if _, ok := endpoints[e]; !ok {
				errs = append(errs, fmt.Errorf("link %s: endpoint %q is not a defined endpoint", host, e))
			}
		}
	}
	return errors.Join(errs...)
}
