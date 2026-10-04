package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"luk/internal/config"
	"luk/internal/gpgkeys"
	"luk/internal/gpgkeys/gpgtest"
	"luk/internal/queue"
)

type gpgEnv struct {
	*env
	keys string
	wkd  map[string][]byte
	srv  *httptest.Server
}

// newGPGEnv is a run env with gpg.keys holding keyFiles and a WKD server
// answering the local parts of wkd.
func newGPGEnv(t *testing.T, pipeline string, keyFiles map[string][]byte, wkd map[string][]byte) *gpgEnv {
	t.Helper()
	root := t.TempDir()
	keys := filepath.Join(root, "keys")
	if err := os.MkdirAll(keys, 0o750); err != nil {
		t.Fatal(err)
	}
	for n, b := range keyFiles {
		if err := os.WriteFile(filepath.Join(keys, n), b, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(runTmpl, root, pipeline) + "gpg:\n  keys: " + keys + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"queue/up", "a", "b", "c", "work", "gpg-cache"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	free := func(string) (int64, error) { return 1 << 40, nil }
	g := &gpgEnv{env: &env{root: root, cfg: cfg, q: queue.New(0, free), logs: &syncBuf{}}, keys: keys, wkd: wkd}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := g.wkd[r.URL.Query().Get("l")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *gpgEnv) run(t *testing.T, id string) {
	t.Helper()
	d := g.dispatcher()
	d.keys.Client, d.keys.BaseURL = g.srv.Client(), g.srv.URL
	if err := d.Submit(g.enqueue(t, id, "up", "p")); err != nil {
		t.Fatal(err)
	}
	d.Wait()
}

func (g *gpgEnv) raw(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(g.root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type encMeta struct {
	Kind       string   `json:"kind"`
	Encryption string   `json:"encryption"`
	Recipients []string `json:"recipients"`
	Plain      struct {
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	} `json:"plain"`
}

func TestEncryptRoundTrip(t *testing.T) {
	robert := gpgtest.New(t, "robert@example.net")
	matt := gpgtest.New(t, "Matt@Example.com")
	g := newGPGEnv(t, `    steps:
      - encrypt:
          wkd: [robert@example.net]
          key: [matt@example.com]
      - store: a
`, map[string][]byte{"matt.asc": gpgtest.Armored(t, matt)}, map[string][]byte{"robert": gpgtest.Public(t, robert)})
	g.run(t, "id1")
	if find(g.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", g.logs.records(t))
	}
	msg := g.raw(t, "a/file/robert.socha/f.txt.gpg")
	if bytes.HasPrefix(msg, []byte("-----BEGIN")) {
		t.Fatal("armored output")
	}
	for _, k := range []*openpgp.Entity{robert, matt} {
		if got := string(gpgtest.Decrypt(t, msg, k)); got != "data-id1" {
			t.Fatalf("decrypted %q", got)
		}
	}
	sc := g.sidecar(t, "a/.db/meta/robert.socha/f.txt.gpg.json")
	if sc.Produced != "f.txt.gpg" || sc.Size != int64(len(msg)) || sc.SHA256 != sha(string(msg)) {
		t.Fatalf("sidecar %+v", sc)
	}
	var m encMeta
	if err := json.Unmarshal(sc.Meta, &m); err != nil {
		t.Fatal(err)
	}
	want := []string{gpgkeys.Fingerprint(robert), gpgkeys.Fingerprint(matt)}
	if m.Encryption != "gpg" || strings.Join(m.Recipients, ",") != strings.Join(want, ",") ||
		m.Plain.Name != "f.txt" || m.Plain.Size != 8 || m.Plain.SHA256 != sha("data-id1") {
		t.Fatalf("meta %s", sc.Meta)
	}
	if _, err := os.Stat(filepath.Join(g.root, "gpg-cache", "robert@example.net.pgp")); err != nil {
		t.Errorf("wkd key not cached: %v", err)
	}
	gone(t, filepath.Join(g.root, "work", "id1", "p"))
	gpgDecrypt(t, msg, robert, "data-id1")
}

// gpgDecrypt checks msg with the gpg binary when there is one.
func gpgDecrypt(t *testing.T, msg []byte, key *openpgp.Entity, want string) {
	t.Helper()
	bin, err := exec.LookPath("gpg")
	if err != nil {
		t.Log("no gpg binary, interop not checked")
		return
	}
	home, err := os.MkdirTemp("", "gnupg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
		os.RemoveAll(home)
	})
	env := append(os.Environ(), "GNUPGHOME="+home)
	imp := exec.Command(bin, "--batch", "--import")
	imp.Env, imp.Stdin = env, bytes.NewReader(gpgtest.ArmoredPrivate(t, key))
	if out, err := imp.CombinedOutput(); err != nil {
		t.Fatalf("gpg --import: %v\n%s", err, out)
	}
	dec := exec.Command(bin, "--batch", "--decrypt")
	var stdout, stderr bytes.Buffer
	dec.Env, dec.Stdin, dec.Stdout, dec.Stderr = env, bytes.NewReader(msg), &stdout, &stderr
	if err := dec.Run(); err != nil {
		t.Fatalf("gpg --decrypt: %v\n%s", err, stderr.String())
	}
	if stdout.String() != want {
		t.Fatalf("gpg decrypted %q", stdout.String())
	}
}

func TestEncryptMultiFileSet(t *testing.T) {
	s1 := script(t, `set -e
printf one > "$LUK_OUT/one.txt"
printf two > "$LUK_OUT/two.txt"
printf '{"kind": "dump", "alias": "latest"}' > "$LUK_OUT/one.txt.meta.json"
`)
	s2 := script(t, `set -e
test "$(ls "$LUK_IN" | tr '\n' ' ')" = "one.txt.gpg one.txt.gpg.meta.json two.txt.gpg two.txt.gpg.meta.json "
grep -q '"encryption":"gpg"' "$LUK_IN/two.txt.gpg.meta.json"
for f in one two; do ln "$LUK_IN/$f.txt.gpg" "$LUK_OUT/$f.txt.gpg"; done
`)
	k := gpgtest.New(t, "matt@example.com")
	g := newGPGEnv(t, fmt.Sprintf(`    steps:
      - run: %s
      - encrypt: {key: matt@example.com}
      - run: %s
      - store: b
`, s1, s2), map[string][]byte{"k.asc": gpgtest.Armored(t, k)}, nil)
	g.run(t, "id1")
	if find(g.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", g.logs.records(t))
	}
	for _, n := range []string{"one", "two"} {
		if got := string(gpgtest.Decrypt(t, g.raw(t, "b/file/robert.socha/"+n+".txt.gpg"), k)); got != n {
			t.Fatalf("%s: %q", n, got)
		}
	}
	// A run step drops the meta of a file it passes on by hardlink.
	sc := g.sidecar(t, "b/.db/meta/robert.socha/one.txt.gpg.json")
	if sc.Produced != "one.txt.gpg" {
		t.Fatalf("sidecar %+v", sc)
	}
}

func TestEncryptMetaCarriedOver(t *testing.T) {
	s1 := script(t, `set -e
printf one > "$LUK_OUT/one.txt"
printf '{"kind": "dump"}' > "$LUK_OUT/one.txt.meta.json"
`)
	k := gpgtest.New(t, "matt@example.com")
	g := newGPGEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - encrypt: {key: matt@example.com}\n      - store: a\n", s1),
		map[string][]byte{"k.asc": gpgtest.Armored(t, k)}, nil)
	g.run(t, "id1")
	var m encMeta
	if err := json.Unmarshal(g.sidecar(t, "a/.db/meta/robert.socha/one.txt.gpg.json").Meta, &m); err != nil {
		t.Fatal(err)
	}
	if m.Kind != "dump" || m.Encryption != "gpg" || m.Plain.Name != "one.txt" || m.Plain.Size != 3 || m.Plain.SHA256 != sha("one") {
		t.Fatalf("meta %+v", m)
	}
}

func recipientRecord(t *testing.T, g *gpgEnv, addr string) map[string]any {
	for _, r := range g.logs.records(t) {
		if r["msg"] == "recipient unusable" && r["recipient"] == addr {
			return r
		}
	}
	return nil
}

func TestEncryptUnusableRecipient(t *testing.T) {
	good := gpgtest.New(t, "matt@example.com")
	keys := map[string][]byte{
		"good.asc":    gpgtest.Armored(t, good),
		"expired.asc": gpgtest.Armored(t, gpgtest.Expired(t, "old@example.com")),
		"revoked.asc": gpgtest.Armored(t, gpgtest.Revoked(t, "gone@example.com")),
	}
	steps := func(strict bool) string {
		return fmt.Sprintf(`    steps:
      - encrypt:
          wkd: [nobody@example.net]
          key: [matt@example.com, old@example.com, gone@example.com, missing@example.com]
          strict: %v
      - store: a
`, strict)
	}

	g := newGPGEnv(t, steps(false), keys, nil)
	g.run(t, "id1")
	if find(g.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", g.logs.records(t))
	}
	for _, a := range []string{"nobody@example.net", "old@example.com", "gone@example.com", "missing@example.com"} {
		if recipientRecord(t, g, a) == nil {
			t.Errorf("no warning for %s", a)
		}
	}
	if recipientRecord(t, g, "matt@example.com") != nil {
		t.Error("warning for a usable recipient")
	}
	var m encMeta
	if err := json.Unmarshal(g.sidecar(t, "a/.db/meta/robert.socha/f.txt.gpg.json").Meta, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Recipients) != 1 || m.Recipients[0] != gpgkeys.Fingerprint(good) {
		t.Fatalf("recipients %v", m.Recipients)
	}

	g = newGPGEnv(t, steps(true), keys, nil)
	g.run(t, "id2")
	r := find(g.logs.records(t), "pipeline failed", "p")
	if r == nil || !strings.Contains(fmt.Sprint(r["error"]), "strict") || r["step"] != float64(1) {
		t.Fatalf("strict: %v", g.logs.records(t))
	}
	if exists(filepath.Join(g.root, "a", "file", "robert.socha", "f.txt.gpg")) {
		t.Fatal("stored despite strict failure")
	}
}

func TestEncryptNoUsableRecipient(t *testing.T) {
	g := newGPGEnv(t, "    steps:\n      - encrypt: {key: [old@example.com], wkd: [nobody@example.net]}\n      - store: a\n",
		map[string][]byte{"old.asc": gpgtest.Armored(t, gpgtest.Expired(t, "old@example.com"))}, nil)
	g.run(t, "id1")
	r := find(g.logs.records(t), "pipeline failed", "p")
	if r == nil || !strings.Contains(fmt.Sprint(r["error"]), "no usable recipient") {
		t.Fatalf("logs %v", g.logs.records(t))
	}
	if exists(filepath.Join(g.root, "a", "file", "robert.socha", "f.txt.gpg")) {
		t.Fatal("stored without recipients")
	}
}

func TestEncryptKeyNeverUsesWKD(t *testing.T) {
	k := gpgtest.New(t, "matt@example.com")
	g := newGPGEnv(t, "    steps:\n      - encrypt: {key: [matt@example.com]}\n      - store: a\n", nil,
		map[string][]byte{"matt": gpgtest.Public(t, k)})
	g.run(t, "id1")
	if r := find(g.logs.records(t), "pipeline failed", "p"); r == nil || !strings.Contains(fmt.Sprint(r["error"]), "no key with user id matt@example.com in") {
		t.Fatalf("key recipient resolved without gpg.keys: %v", g.logs.records(t))
	}
}

func TestEncryptWKDNeverUsesKeyDir(t *testing.T) {
	k := gpgtest.New(t, "matt@example.com")
	g := newGPGEnv(t, "    steps:\n      - encrypt: {wkd: [matt@example.com]}\n      - store: a\n",
		map[string][]byte{"k.asc": gpgtest.Armored(t, k)}, nil)
	g.run(t, "id1")
	if r := find(g.logs.records(t), "pipeline failed", "p"); r == nil || !strings.Contains(fmt.Sprint(r["error"]), "404") {
		t.Fatalf("wkd recipient resolved from gpg.keys: %v", g.logs.records(t))
	}
}

func TestEncryptAfterTee(t *testing.T) {
	s1 := script(t, `set -e
printf one > "$LUK_OUT/one.txt"
printf '{"kind": "dump"}' > "$LUK_OUT/one.txt.meta.json"
`)
	tee := script(t, "test -f \"$LUK_IN/one.txt.meta.json\"\n")
	k := gpgtest.New(t, "matt@example.com")
	g := newGPGEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - run: %s\n        tee: true\n      - encrypt: {key: matt@example.com}\n      - store: a\n", s1, tee),
		map[string][]byte{"k.asc": gpgtest.Armored(t, k)}, nil)
	g.run(t, "id1")
	var m encMeta
	if err := json.Unmarshal(g.sidecar(t, "a/.db/meta/robert.socha/one.txt.gpg.json").Meta, &m); err != nil {
		t.Fatal(err)
	}
	if m.Kind != "dump" || m.Plain.Name != "one.txt" || m.Plain.SHA256 != sha("one") {
		t.Fatalf("meta %+v", m)
	}
}
