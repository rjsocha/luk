package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"luk/internal/sshsig"
	"luk/internal/wire"
)

// GetOptions is a signed download (luk-get@v1) of a private file: URL is
// its luk:// URL (or the https:// URL of the expose), Pin the SPKI pin of
// the server (empty: system CAs).
type GetOptions struct {
	URL    *url.URL
	Pin    string
	Signer ssh.Signer
	// Progress receives the transfer progress; nil turns it off.
	Progress io.Writer
	// BWLimit caps the download rate in bytes per second; 0 is unlimited.
	BWLimit int64
	// DecisionTimeout bounds the wait for the headers of the answer; 0
	// means 60s.
	DecisionTimeout time.Duration
	// IdleTimeout bounds each wait for the next bytes of the answer; 0
	// means 2m.
	IdleTimeout time.Duration
}

// ParseGetURL reads the URL of luk get: luk:// (always https) or https://,
// with an optional pin fragment "#sha256//..." (or "#pin=sha256//..."). It
// returns the https URL without the fragment and the pin.
func ParseGetURL(raw string) (*url.URL, string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != wire.SchemeLuk && u.Scheme != "https") || u.Host == "" || u.Opaque != "" {
		return nil, "", fmt.Errorf("invalid URL %q, want luk://host/... or https://host/...", raw)
	}
	var pin string
	if u.Fragment != "" {
		pin = strings.TrimPrefix(u.Fragment, "pin=")
		if !validPin(pin) {
			return nil, "", fmt.Errorf("URL fragment must be a pin, sha256//...: %q", raw)
		}
	}
	u.Scheme, u.Fragment, u.RawFragment = "https", "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u, pin, nil
}

// validPin reports whether pin is sha256// plus base64 of 32 bytes.
func validPin(pin string) bool {
	b, ok := strings.CutPrefix(pin, "sha256//")
	raw, err := base64.StdEncoding.DecodeString(b)
	return ok && err == nil && len(raw) == sha256.Size
}

// Download is the answer to a signed get: the content, read through the
// rate limit and the progress, hashed on the way.
type Download struct {
	// Name is the file name of Content-Disposition, empty when the answer
	// names none.
	Name string
	// Size is the Content-Length, -1 when unknown.
	Size int64

	body   io.ReadCloser
	r      io.Reader
	h      hash.Hash
	want   string
	finish func()
	ctx    context.Context
	host   string
	n      int64
}

// Read fails with a TransferError when the answer breaks off.
func (d *Download) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	d.n += int64(n)
	if err != nil && err != io.EOF {
		err = transferError(d.ctx, err, d.host, d.n, d.Size, true)
	}
	return n, err
}

// Close ends the progress and closes the answer.
func (d *Download) Close() error {
	if d.finish != nil {
		d.finish()
		d.finish = nil
	}
	return d.body.Close()
}

// Check compares the sha256 of what was read with the one the server
// announced in its ETag; nil without one. Call it after reading to the
// end.
func (d *Download) Check() error {
	if d.want == "" {
		return nil
	}
	if got := hex.EncodeToString(d.h.Sum(nil)); got != d.want {
		return &HashMismatchError{Local: got, Remote: d.want}
	}
	return nil
}

var etagSHA = regexp.MustCompile(`^"([0-9a-f]{64})"$`)

// Get sends a signed GET of o.URL and returns the content of a 200
// answer; any other answer is an error (RejectedError for 400 and
// above). The caller reads and closes the Download.
func Get(ctx context.Context, o GetOptions) (*Download, error) {
	resp, err := signedGet(ctx, o, http.MethodGet)
	if err != nil {
		return nil, err
	}
	h := headOf(resp)
	d := &Download{Name: h.Name, Size: h.Size, body: resp.Body, h: sha256.New(), want: h.SHA256, ctx: ctx, host: o.URL.Host}
	var src io.Reader = resp.Body
	if o.BWLimit > 0 {
		src = newLimitReader(ctx, src, o.BWLimit)
	}
	if o.Progress != nil {
		pr := newProgress(src, o.Progress, resp.ContentLength, time.Now)
		d.finish = pr.Finish
		src = pr
	}
	d.r = io.TeeReader(src, d.h)
	return d, nil
}

// IsDirURL reports whether the URL of luk get names a directory: its
// path ends with a slash (as in rsync).
func IsDirURL(u *url.URL) bool { return strings.HasSuffix(u.Path, "/") }

// maxListing is the largest signed listing read.
const maxListing = 64 << 20

// List sends a signed GET of the directory URL o.URL, with the query
// recursive=1 when recursive (replacing any query of the URL), and returns
// the listing: one level, or every file below the directory named
// relative to it. Errors as for Get; Progress and BWLimit do not apply.
func List(ctx context.Context, o GetOptions, recursive bool) ([]wire.ListEntry, error) {
	u := *o.URL
	u.RawQuery, u.ForceQuery = "", false
	if recursive {
		u.RawQuery = wire.QueryRecursive
	}
	o.URL = &u
	resp, err := signedGet(ctx, o, http.MethodGet)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxListing+1))
	if err != nil {
		return nil, transferError(ctx, err, u.Host, int64(len(data)), resp.ContentLength, true)
	}
	if len(data) > maxListing {
		return nil, fmt.Errorf("listing larger than %s", HumanBytes(maxListing))
	}
	var ents []wire.ListEntry
	if err := json.Unmarshal(data, &ents); err != nil {
		return nil, fmt.Errorf("listing: not a JSON array of entries: %w", err)
	}
	return ents, nil
}

// ChildURL is the URL of the name rel (relative, elements separated by
// slashes) under the directory URL dir, each element escaped.
func ChildURL(dir *url.URL, rel string) *url.URL {
	u := *dir
	u.RawQuery, u.ForceQuery = "", false
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	u.Path = dir.Path + rel
	u.RawPath = dir.EscapedPath() + strings.Join(parts, "/")
	return &u
}

// ValidListName reports whether a file name of a recursive listing is
// safe to create under a local directory: relative, valid UTF-8, without
// empty, "." or ".." elements and without characters Printable escapes
// (control characters among them).
func ValidListName(name string) error {
	bad := func(why string) error { return fmt.Errorf("unsafe name %q in the listing: %s", name, why) }
	switch {
	case name == "":
		return bad("empty")
	case !utf8.ValidString(name):
		return bad("not UTF-8")
	case strings.HasPrefix(name, "/"):
		return bad("absolute")
	case strings.ContainsFunc(name, unsafeRune):
		return bad("control or formatting characters")
	}
	for _, e := range strings.Split(name, "/") {
		switch e {
		case "":
			return bad("empty path element")
		case ".", "..":
			return bad("path element " + e)
		}
	}
	return nil
}

// Head is what the server announces for a file without sending it.
type Head struct {
	// Name is the file name of Content-Disposition, empty when the answer
	// names none.
	Name string
	// Size is the Content-Length, -1 when unknown.
	Size int64
	// Type is the Content-Type.
	Type string
	// SHA256 is the hex sha256 of the ETag, empty without one.
	SHA256 string
	// Expires is Luk-Expires (RFC 3339), empty without one.
	Expires string
	// Once is Luk-Once: true.
	Once bool
}

// HeadFile sends a signed HEAD of o.URL (which never claims a once file)
// and returns what a 200 answer announces; errors as for Get. Progress
// and BWLimit do not apply.
func HeadFile(ctx context.Context, o GetOptions) (*Head, error) {
	resp, err := signedGet(ctx, o, http.MethodHead)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return headOf(resp), nil
}

// headOf reads the download headers of a 200 answer.
func headOf(resp *http.Response) *Head {
	h := &Head{
		Size: resp.ContentLength, Type: resp.Header.Get("Content-Type"),
		Expires: resp.Header.Get(wire.HeaderExpires), Once: resp.Header.Get(wire.HeaderOnce) == "true",
	}
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil {
		h.Name = params["filename"]
	}
	if m := etagSHA.FindStringSubmatch(resp.Header.Get("ETag")); m != nil {
		h.SHA256 = m[1]
	}
	return h
}

// signedGet sends a signed request (luk-get@v1) of method GET or HEAD to
// o.URL and returns a 200 answer. Without its headers within the decision
// timeout the request ends with NoAnswer; the body of the answer fails
// with Stalled when no byte comes for the idle timeout. Closing the body
// ends the request.
func signedGet(ctx context.Context, o GetOptions, method string) (*http.Response, error) {
	u := o.URL
	wait, err := orDefault(o.DecisionTimeout, defaultDecision, "decision timeout")
	if err != nil {
		return nil, err
	}
	idle, err := orDefault(o.IdleTimeout, defaultIdle, "idle timeout")
	if err != nil {
		return nil, err
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := wire.NewNonce()
	text := wire.GetCanonicalText(method, u.Host, wire.GetTarget(u.EscapedPath(), u.RawQuery), ts, nonce)
	sig, err := sshsig.Sign(o.Signer, wire.GetNamespace, text)
	if err != nil {
		return nil, err
	}
	caller := ctx
	ctx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set(wire.HeaderTimestamp, ts)
	req.Header.Set(wire.HeaderNonce, nonce)
	req.Header.Set(wire.HeaderSignature, base64.StdEncoding.EncodeToString(sig.Marshal()))
	tr, err := transport(u, o.Pin)
	if err != nil {
		cancel()
		return nil, err
	}
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	dec := newDecider(wait, cancel)
	resp, err := c.Do(req)
	at := time.Now()
	dec.stop()
	if !dec.decide() {
		if resp != nil {
			resp.Body.Close()
		}
		cancel()
		return nil, &TransferError{Reason: NoAnswer, Host: u.Host, Total: -1, Wait: wait, Err: context.Canceled}
	}
	if err != nil {
		cancel()
		return nil, transferError(caller, err, u.Host, 0, -1, false)
	}
	resp.Body = &readIdle{r: resp.Body, w: newWatchdog(idle, cancel), done: cancel}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode >= 400 {
			return nil, rejected(resp.StatusCode, data, resp.Header.Get("Date"), at, "")
		}
		return nil, fmt.Errorf("unexpected answer %d %s to a get", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return resp, nil
}
