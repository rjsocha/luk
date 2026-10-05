package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"luk/internal/config"
	"luk/internal/queue"
	"luk/internal/status"
	"luk/internal/store"
)

const runTmpl = `
root: %s
listen:
  main: {addr: 127.0.0.1:8080}
auth:
  keys:
    - name: robert.socha
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILfWnf2l8r4MBD1t4Rnk3fF9BGDtA+LubieHdJSa5e6n Robert Socha"
endpoint:
  up:
    listen: main
    endpoint: /up
    path: queue/up
    allow: [robert.socha]
pipeline:
  p:
    endpoint: [up]
%s
storage:
  a: {type: local, base: a, path: "{{ .Sender }}/{{ .File }}"}
  b: {type: local, base: b, path: "{{ .Sender }}/{{ .File }}"}
  c: {type: local, base: c, path: "{{ .Id }}"}
`

func script(t *testing.T, body string) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	p := filepath.Join(t.TempDir(), "step")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func newRunEnv(t *testing.T, pipeline string) *env {
	t.Helper()
	root := t.TempDir()
	cfg, err := config.Parse([]byte(fmt.Sprintf(runTmpl, root, pipeline)))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"queue/up", "a", "b", "c", "work", "status/process"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	free := func(string) (int64, error) { return 1 << 40, nil }
	return &env{root: root, cfg: cfg, q: queue.New(0, free), logs: &syncBuf{}}
}

func (e *env) runOne(t *testing.T, id string) Job {
	t.Helper()
	d := e.dispatcher()
	j := e.enqueue(t, id, "up", "p")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	return j
}

func (e *env) sidecar(t *testing.T, rel string) store.Sidecar {
	t.Helper()
	var sc store.Sidecar
	if err := json.Unmarshal([]byte(e.read(t, rel)), &sc); err != nil {
		t.Fatal(err)
	}
	return sc
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestRunTwoFilesWithMeta(t *testing.T) {
	s1 := script(t, `set -e
grep -q '"pipeline":"p"' "$LUK_META"
grep -q '"step":1' "$LUK_META"
grep -q '"id":"id1"' "$LUK_META"
test "$(ls "$LUK_IN")" = f.txt
test "$(stat -c %h "$LUK_IN/f.txt")" -ge 2
tr a-z A-Z < "$LUK_IN/f.txt" > "$LUK_OUT/up.txt"
printf x > "$LUK_OUT/x.bin"
printf '{"kind": "upper"}' > "$LUK_OUT/up.txt.meta.json"
`)
	s2 := script(t, `set -e
grep -q '"step":3' "$LUK_META"
test "$(cat "$LUK_IN/up.txt.meta.json")" = '{"kind":"upper"}'
test ! -e "$LUK_IN/x.bin.meta.json"
cat "$LUK_IN/up.txt" "$LUK_IN/x.bin" > "$LUK_OUT/final.txt"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - store: a\n      - run: %s\n      - store: b\n", s1, s2))
	stale := filepath.Join(e.root, "work", "id1", "p", "1", "out")
	if err := os.MkdirAll(stale, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "stale.txt"), []byte("s"), 0o640); err != nil {
		t.Fatal(err)
	}
	j := e.runOne(t, "id1")
	if find(e.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	if got := e.read(t, "a/file/robert.socha/up.txt"); got != "DATA-ID1" {
		t.Fatalf("up.txt %q", got)
	}
	if got := e.read(t, "a/file/robert.socha/x.bin"); got != "x" {
		t.Fatalf("x.bin %q", got)
	}
	if got := e.read(t, "b/file/robert.socha/final.txt"); got != "DATA-ID1x" {
		t.Fatalf("final.txt %q", got)
	}
	gone(t, filepath.Join(e.root, "a/file/robert.socha/stale.txt"))
	gone(t, filepath.Join(e.root, "a/file/robert.socha/up.txt.meta.json"))
	sc := e.sidecar(t, "a/.db/meta/robert.socha/up.txt.json")
	if sc.ID != "id1" || sc.Sender != "robert.socha" || string(sc.Meta) != `{"kind":"upper"}` || sc.Size != 8 || sc.SHA256 != sha("DATA-ID1") || sc.Produced != "up.txt" {
		t.Fatalf("up.txt sidecar %+v meta %s", sc, sc.Meta)
	}
	if sc := e.sidecar(t, "a/.db/meta/robert.socha/x.bin.json"); sc.ID != "id1" || sc.Meta != nil || sc.Size != 1 {
		t.Fatalf("x.bin sidecar %+v", sc)
	}
	gone(t, filepath.Join(e.root, "work", "id1"))
	gone(t, j.Entry.Dir)
}

func TestRunEnv(t *testing.T) {
	t.Setenv("LUK_LEAK_TEST", "leak")
	s := script(t, `env > "$LUK_OUT/env"
printf '%s' "$1" > "$LUK_OUT/arg"
pwd > "$LUK_OUT/pwd"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        env: {FOO: bar}\n      - store: a\n", s))
	e.runOne(t, "id2")
	w := filepath.Join(e.root, "work", "id2", "p", "1")
	env := e.read(t, "a/file/robert.socha/env")
	for _, want := range []string{
		"LUK_ID=id2", "LUK_SENDER=robert.socha", "LUK_ENDPOINT=up", "LUK_PIPELINE=p",
		"LUK_WORK=" + w, "LUK_IN=" + w + "/in", "LUK_OUT=" + w + "/out", "LUK_META=" + w + "/meta.json",
		"LANG=C.UTF-8", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "FOO=bar",
	} {
		if !strings.Contains("\n"+env, "\n"+want+"\n") {
			t.Errorf("env lacks %s:\n%s", want, env)
		}
	}
	if strings.Contains(env, "LUK_LEAK_TEST") || strings.Contains(env, "HOME=") {
		t.Errorf("lukd env leaked:\n%s", env)
	}
	if got := e.read(t, "a/file/robert.socha/arg"); got != w {
		t.Errorf("arg %q", got)
	}
	if got := strings.TrimSpace(e.read(t, "a/file/robert.socha/pwd")); got != w {
		t.Errorf("pwd %q", got)
	}
}

func alive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func waitDead(t *testing.T, pid int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if !alive(pid) {
			return
		}
	}
	t.Fatalf("child %d still alive", pid)
}

func childPid(t *testing.T, e *env, id string) int {
	t.Helper()
	var pid int
	if _, err := fmt.Sscan(e.read(t, "child-"+id), &pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

func TestRunTimeoutTerm(t *testing.T) {
	s := script(t, `sleep 30 &
echo $! > "$LUK_ROOT/child-$LUK_ID"
wait
`)
	e := newRunEnv(t, fmt.Sprintf("    timeout: 300ms\n    steps:\n      - run: %s\n      - store: a\n", s))
	start := time.Now()
	e.runOne(t, "t1")
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("took %v", el)
	}
	r := find(e.logs.records(t), "pipeline failed", "p")
	if r == nil || r["step"] != float64(1) || !strings.Contains(fmt.Sprint(r["error"]), "timeout") {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	waitDead(t, childPid(t, e, "t1"))
}

func TestRunTimeoutKill(t *testing.T) {
	old := killAfter
	killAfter = 200 * time.Millisecond
	t.Cleanup(func() { killAfter = old })
	s := script(t, `trap '' TERM
sleep 30 &
echo $! > "$LUK_ROOT/child-$LUK_ID"
wait
`)
	e := newRunEnv(t, fmt.Sprintf("    timeout: 300ms\n    steps:\n      - run: %s\n      - store: a\n", s))
	e.runOne(t, "t2")
	r := find(e.logs.records(t), "pipeline failed", "p")
	if r == nil || !strings.Contains(fmt.Sprint(r["error"]), "timeout") {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	waitDead(t, childPid(t, e, "t2"))
}

func TestRunOutputCapped(t *testing.T) {
	s := script(t, `dd if=/dev/zero bs=65536 count=32 2>/dev/null
echo tail-marker >&2
exit 3
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n", s))
	e.runOne(t, "c1")
	r := find(e.logs.records(t), "pipeline failed", "p")
	if r == nil || !strings.Contains(fmt.Sprint(r["error"]), "exit status 3") {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	out := fmt.Sprint(r["output"])
	if !strings.HasSuffix(out, "tail-marker\n") || len(out) > 4096 {
		t.Fatalf("output tail %d bytes, ends %q", len(out), out[max(0, len(out)-20):])
	}
}

// The log of a run step is capped at 1 MiB; the next step of the pipeline
// still sees it.
func TestRunLogCapped(t *testing.T) {
	big := script(t, `dd if=/dev/zero bs=65536 count=32 2>/dev/null; echo x > "$LUK_OUT/f"
`)
	size := script(t, `wc -c < "$LUK_WORK/../1/log" | tr -d ' \n' > "$LUK_WORK/fail"; exit 1
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - run: %s\n", big, size))
	e.runOne(t, "c2")
	if r := loadRecord(t, e.recordPath("up", "c2")); len(r.Pipelines) != 1 || r.Pipelines[0].Error != "1048576" {
		t.Fatalf("record %+v", r.Pipelines)
	}
}

func TestRunBadOut(t *testing.T) {
	cases := map[string]string{
		"symlink":      `echo x > "$LUK_OUT/f"; ln -s /etc/passwd "$LUK_OUT/l"`,
		"dir":          `echo x > "$LUK_OUT/f"; mkdir "$LUK_OUT/d"`,
		"dotfile":      `echo x > "$LUK_OUT/f"; echo x > "$LUK_OUT/.h"`,
		"empty":        `true`,
		"meta array":   `echo x > "$LUK_OUT/f"; echo '[1]' > "$LUK_OUT/f.meta.json"`,
		"meta invalid": `echo x > "$LUK_OUT/f"; echo '{' > "$LUK_OUT/f.meta.json"`,
		"meta big":     `echo x > "$LUK_OUT/f"; { printf '{"a":"'; dd if=/dev/zero bs=1024 count=65 2>/dev/null | tr '\0' a; printf '"}'; } > "$LUK_OUT/f.meta.json"`,
		"meta orphan":  `echo x > "$LUK_OUT/f"; echo '{}' > "$LUK_OUT/g.meta.json"`,
		"meta of meta": `echo x > "$LUK_OUT/f"; echo '{}' > "$LUK_OUT/f.meta.json"; echo '{}' > "$LUK_OUT/f.meta.json.meta.json"`,
		"out removed":  `rm -r "$LUK_OUT"`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			s := script(t, body+"\n")
			e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - store: a\n", s))
			e.runOne(t, "b1")
			r := find(e.logs.records(t), "pipeline failed", "p")
			if r == nil || r["step"] != float64(1) {
				t.Fatalf("logs %v", e.logs.records(t))
			}
			gone(t, filepath.Join(e.root, "work", "b1"))
			if ents, _ := os.ReadDir(filepath.Join(e.root, "a", "file")); len(ents) != 0 {
				t.Fatalf("stored %v", ents)
			}
		})
	}
}

func TestRunStoreFailureFailsPipeline(t *testing.T) {
	s := script(t, `echo x > "$LUK_OUT/f"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - store: a\n", s))
	if err := os.MkdirAll(filepath.Join(e.root, "a", "file", "robert.socha"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(e.root, "a", "file", "robert.socha", "f")); err != nil {
		t.Fatal(err)
	}
	e.runOne(t, "sf")
	r := find(e.logs.records(t), "pipeline failed", "p")
	if r == nil || r["step"] != float64(2) || !strings.Contains(fmt.Sprint(r["error"]), "invalid path") {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	gone(t, filepath.Join(e.root, "work", "sf"))
}

func TestRunSetIntoOnePathVersions(t *testing.T) {
	s := script(t, `echo one > "$LUK_OUT/f1"
echo two > "$LUK_OUT/f2"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - store: c\n", s))
	e.runOne(t, "v1")
	ents, err := os.ReadDir(filepath.Join(e.root, "c", "file"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range ents {
		if !d.IsDir() {
			got = append(got, e.read(t, filepath.Join("c/file", d.Name())))
		}
	}
	if len(got) != 2 || got[0] == got[1] {
		t.Fatalf("stored %v", got)
	}
}

func TestRunTimeoutKillsTermTrappingChild(t *testing.T) {
	old := killAfter
	killAfter = 300 * time.Millisecond
	t.Cleanup(func() { killAfter = old })
	s := script(t, `sh -c 'trap "" TERM; while :; do sleep 1; done' >/dev/null 2>&1 &
echo $! > "$LUK_ROOT/child-$LUK_ID"
wait
`)
	e := newRunEnv(t, fmt.Sprintf("    timeout: 300ms\n    steps:\n      - run: %s\n", s))
	e.runOne(t, "t3")
	waitDead(t, childPid(t, e, "t3"))
}

func TestRunKillsStraysAfterExit(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	s := script(t, `echo ok > "$LUK_OUT/f"
(sleep 0.3; chmod u+w "$LUK_OUT/f"; echo mutated > "$LUK_OUT/f") >/dev/null 2>&1 &
echo $! > "$PIDFILE"
exit 0
`)
	slow := script(t, `sleep 1; echo y > "$LUK_OUT/y"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        env: {PIDFILE: %s}\n      - store: a\n      - run: %s\n", s, pidfile, slow))
	start := time.Now()
	e.runOne(t, "k1")
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("took %v", el)
	}
	b, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	fmt.Sscan(string(b), &pid)
	waitDead(t, pid)
	time.Sleep(500 * time.Millisecond)
	if got := e.read(t, "a/file/robert.socha/f"); got != "ok\n" {
		t.Fatalf("stored %q", got)
	}
}

func TestCloseInterruptsRun(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	s := script(t, `echo $$ > "$PIDFILE.tmp"; mv "$PIDFILE.tmp" "$PIDFILE"
sleep 30
echo x > "$LUK_OUT/f"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        env: {PIDFILE: %s}\n      - store: a\n", s, pidfile))
	d := e.dispatcher()
	j := e.enqueue(t, "i1", "up", "p")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	var pid int
	for deadline := time.Now().Add(5 * time.Second); pid == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("step did not start")
		}
		if b, err := os.ReadFile(pidfile); err == nil {
			fmt.Sscan(string(b), &pid)
		}
	}
	start := time.Now()
	d.Close()
	d.Wait()
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("close took %v", el)
	}
	waitDead(t, pid)
	if !exists(filepath.Join(j.Entry.Dir, "meta.json")) || !exists(filepath.Join(j.Entry.Dir, "payload")) {
		t.Fatal("queue entry removed")
	}
	recs := e.logs.records(t)
	if find(recs, "pipeline failed", "p") != nil || find(recs, "pipeline interrupted", "p") == nil {
		t.Fatalf("logs %v", recs)
	}
}

func TestInterruptedEntryKeepsOnlyUnfinishedPipelines(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	s := script(t, `echo $$ > "$PIDFILE.tmp"; mv "$PIDFILE.tmp" "$PIDFILE"
sleep 30
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        env: {PIDFILE: %s}\n  q:\n    endpoint: [up]\n    steps:\n      - store: b\n", s, pidfile))
	d := e.dispatcher()
	j := e.enqueue(t, "n1", "up", "p", "q")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("pipelines did not reach the expected state")
		}
		if exists(pidfile) && find(e.logs.records(t), "pipeline done", "q") != nil {
			break
		}
	}
	d.Close()
	d.Wait()
	got, err := LoadJob(j.Entry)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Pipelines, ",") != "p" {
		t.Fatalf("remaining pipelines %v", got.Pipelines)
	}
	if got.Sidecar.ID != "n1" || got.Vars.Id != "n1" {
		t.Fatalf("meta lost: %+v", got)
	}
}

func TestDispatcherReportsStatus(t *testing.T) {
	bad := script(t, `echo some output
echo boom >&2
exit 2
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - store: a\n      - run: %s\n  q:\n    endpoint: [up]\n    steps:\n      - store: b\n", bad))
	st := status.New(status.Path(e.root))
	d := e.dispatcher()
	d.SetStatus(st)
	j := e.enqueue(t, "st1", "up", "p", "q")
	j.Sidecar.Received = "2026-09-30T10:00:00Z"
	j.Vars.Tags = []string{"prod"}
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	es := st.Entries()
	if len(es) != 2 {
		t.Fatalf("entries %+v", es)
	}
	p, q := es[0], es[1]
	if p.Pipeline != "p" || p.Sender != "robert.socha" || p.LastFailure == "" || p.LastSuccess != "" || p.FailedStep != 2 ||
		!strings.Contains(p.Error, "exit status 2") || !strings.HasSuffix(p.Error, "boom\n") || p.LastID != "st1" ||
		p.Size != int64(len("data-st1")) || p.LastReceived != "2026-09-30T10:00:00Z" || strings.Join(p.Tags, ",") != "prod" {
		t.Fatalf("p %+v", p)
	}
	if q.Pipeline != "q" || q.LastSuccess == "" || q.LastFailure != "" {
		t.Fatalf("q %+v", q)
	}
	if _, err := os.Stat(status.Path(e.root)); err != nil {
		t.Fatal(err)
	}
}

func TestInterruptedNotReported(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	s := script(t, `echo $$ > "$PIDFILE.tmp"; mv "$PIDFILE.tmp" "$PIDFILE"
sleep 30
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        env: {PIDFILE: %s}\n", s, pidfile))
	st := status.New(status.Path(e.root))
	d := e.dispatcher()
	d.SetStatus(st)
	d.Submit(e.enqueue(t, "st2", "up", "p"))
	for deadline := time.Now().Add(5 * time.Second); !exists(pidfile); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("step did not start")
		}
	}
	d.Close()
	d.Wait()
	if es := st.Entries(); len(es) != 0 {
		t.Fatalf("entries %+v", es)
	}
}

func envLines(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

func TestRunEnvFileVars(t *testing.T) {
	s1 := script(t, `env > "$LUK_OUT/env1"
printf x > "$LUK_OUT/x"
`)
	s2 := script(t, `env > "$LUK_OUT/env2"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        env: {LUK_ROOT: /evil, LUK_STEP: 9}\n      - store: a\n      - run: %s\n      - store: b\n", s1, s2))
	d := e.dispatcher()
	j := e.enqueueWith(t, "id7", "up", func(j *Job) {
		j.Vars.Tags = []string{"t1", "t2"}
		j.Vars.Hostname = "host1"
	}, "p")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	w1 := filepath.Join(e.root, "work", "id7", "p", "1")
	m := envLines(e.read(t, "a/file/robert.socha/env1"))
	for k, want := range map[string]string{
		"LUK_FILE": w1 + "/in/f.txt", "LUK_NAME": "f.txt", "LUK_ROOT": e.root, "LUK_STEP": "1",
		"LUK_TAGS": "t1,t2", "LUK_HOSTNAME": "host1", "LUK_ORIGIN": "host1",
	} {
		if m[k] != want {
			t.Errorf("step 1 %s=%q, want %q", k, m[k], want)
		}
	}
	m = envLines(e.read(t, "b/file/robert.socha/env2"))
	if _, ok := m["LUK_FILE"]; ok {
		t.Errorf("LUK_FILE set with two files: %q", m["LUK_FILE"])
	}
	if v, ok := m["LUK_NAME"]; !ok || v != "" {
		t.Errorf("LUK_NAME %q, %v", v, ok)
	}
	if m["LUK_STEP"] != "3" || m["LUK_ROOT"] != e.root {
		t.Errorf("step 3 %q root %q", m["LUK_STEP"], m["LUK_ROOT"])
	}
}

func TestRunEnvOriginWithoutHostname(t *testing.T) {
	s := script(t, `env > "$LUK_OUT/env"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - store: a\n", s))
	d := e.dispatcher()
	j := e.enqueueWith(t, "id8", "up", func(j *Job) { j.Vars.File = "" }, "p")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	m := envLines(e.read(t, "a/file/robert.socha/env"))
	if m["LUK_HOSTNAME"] != "" || m["LUK_ORIGIN"] != "robert.socha" || m["LUK_NAME"] != "" || m["LUK_FILE"] == "" || m["LUK_TAGS"] != "" {
		t.Errorf("env %v", m)
	}
}

func TestRunFailFileIsStepError(t *testing.T) {
	bad := script(t, `echo some output
printf 'disk full\033[2J\n' > "$LUK_WORK/fail"
exit 3
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n", bad))
	st := status.New(status.Path(e.root))
	d := e.dispatcher()
	d.SetStatus(st)
	if err := d.Submit(e.enqueue(t, "f1", "up", "p")); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	es := st.Entries()
	if len(es) != 1 || es[0].Error != "disk full [2J" || es[0].FailedStep != 1 {
		t.Fatalf("entries %+v", es)
	}
	rec := find(e.logs.records(t), "pipeline failed", "p")
	if rec == nil || rec["error"] != "disk full [2J" || rec["output"] != "some output\n" {
		t.Fatalf("log %v", rec)
	}
	if r := loadRecord(t, e.recordPath("up", "f1")); len(r.Pipelines) != 1 || r.Pipelines[0].Error != "disk full [2J" {
		t.Fatalf("failed %+v", r.Pipelines)
	}
}

func TestRunFailFileIgnoredOnSuccessAndWhenEmpty(t *testing.T) {
	ok := script(t, `echo ignored > "$LUK_WORK/fail"
printf x > "$LUK_OUT/x"
`)
	empty := script(t, `echo tail-text
printf ' \n' > "$LUK_WORK/fail"
exit 1
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - run: %s\n", ok, empty))
	st := status.New(status.Path(e.root))
	d := e.dispatcher()
	d.SetStatus(st)
	if err := d.Submit(e.enqueue(t, "f2", "up", "p")); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	es := st.Entries()
	if len(es) != 1 || es[0].FailedStep != 2 || !strings.Contains(es[0].Error, "exit status 1") || !strings.HasSuffix(es[0].Error, "tail-text\n") {
		t.Fatalf("entries %+v", es)
	}
}

func TestRunTeeHandsOnItsInput(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "seen")
	s1 := script(t, `set -e
tr a-z A-Z < "$LUK_IN/f.txt" > "$LUK_OUT/up.txt"
printf x > "$LUK_OUT/x.bin"
printf '{"kind": "upper"}' > "$LUK_OUT/up.txt.meta.json"
`)
	tee := script(t, `set -e
test "$(pwd)" = "$LUK_WORK"
ls "$LUK_IN" > `+seen+`
`)
	s3 := script(t, `set -e
test "$(ls "$LUK_IN" | tr '\n' ' ')" = 'up.txt up.txt.meta.json x.bin '
test "$(cat "$LUK_IN/up.txt.meta.json")" = '{"kind":"upper"}'
cat "$LUK_IN/up.txt" "$LUK_IN/x.bin" > "$LUK_OUT/final.txt"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n      - run: %s\n        tee: true\n      - store: a\n      - run: %s\n      - store: b\n", s1, tee, s3))
	j := e.runOne(t, "id1")
	if find(e.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	if b, err := os.ReadFile(seen); err != nil || string(b) != "up.txt\nup.txt.meta.json\nx.bin\n" {
		t.Fatalf("tee saw %q %v", b, err)
	}
	sc := e.sidecar(t, "a/.db/meta/robert.socha/up.txt.json")
	if string(sc.Meta) != `{"kind":"upper"}` || sc.Produced != "up.txt" || sc.SHA256 != sha("DATA-ID1") {
		t.Fatalf("up.txt sidecar %+v meta %s", sc, sc.Meta)
	}
	if got := e.read(t, "a/file/robert.socha/x.bin"); got != "x" {
		t.Fatalf("x.bin %q", got)
	}
	if got := e.read(t, "b/file/robert.socha/final.txt"); got != "DATA-ID1x" {
		t.Fatalf("final.txt %q", got)
	}
	gone(t, filepath.Join(e.root, "work", "id1"))
	gone(t, j.Entry.Dir)
}

func TestRunTeeOnUploadThenStore(t *testing.T) {
	tee := script(t, `set -e
test "$LUK_NAME" = f.txt
test -f "$LUK_FILE"
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        tee: true\n      - store: a\n", tee))
	e.runOne(t, "id1")
	if find(e.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	if got := e.read(t, "a/file/robert.socha/f.txt"); got != "data-id1" {
		t.Fatalf("f.txt %q", got)
	}
	if sc := e.sidecar(t, "a/.db/meta/robert.socha/f.txt.json"); sc.Produced != "" || sc.SHA256 != sha("data-id1") {
		t.Fatalf("sidecar %+v", sc)
	}
}

func TestRunTeeLastStep(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "seen")
	tee := script(t, `cat "$LUK_IN/f.txt" > `+seen+`
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - store: a\n      - run: %s\n        tee: true\n", tee))
	j := e.runOne(t, "id1")
	if find(e.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	if b, err := os.ReadFile(seen); err != nil || string(b) != "data-id1" {
		t.Fatalf("tee saw %q %v", b, err)
	}
	gone(t, filepath.Join(e.root, "work", "id1"))
	gone(t, j.Entry.Dir)
}

func TestRunTeeWritesOut(t *testing.T) {
	cases := map[string]string{
		"file":     `cp "$LUK_IN/f.txt" "$LUK_OUT/f.txt"`,
		"meta":     `echo '{}' > "$LUK_OUT/f.txt.meta.json"`,
		"dotfile":  `touch "$LUK_OUT/.h"`,
		"rm out":   `rm -r "$LUK_OUT"`,
		"no files": `true`,
	}
	want := map[string]string{
		"file":    "tee step wrote out/f.txt",
		"meta":    "tee step wrote out/f.txt.meta.json",
		"dotfile": "tee step wrote out/.h",
		"rm out":  "out: ",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			s := script(t, body+"\n")
			e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        tee: true\n      - store: a\n", s))
			e.runOne(t, "b1")
			if want[name] == "" {
				if find(e.logs.records(t), "pipeline done", "p") == nil {
					t.Fatalf("logs %v", e.logs.records(t))
				}
				return
			}
			r := find(e.logs.records(t), "pipeline failed", "p")
			if r == nil || r["step"] != float64(1) || !strings.HasPrefix(fmt.Sprint(r["error"]), "run "+s+": "+want[name]) {
				t.Fatalf("logs %v", e.logs.records(t))
			}
			if ents, _ := os.ReadDir(filepath.Join(e.root, "a", "file")); len(ents) != 0 {
				t.Fatalf("stored %v", ents)
			}
		})
	}
}

func TestStoreRecordsSeries(t *testing.T) {
	e := newRunEnv(t, "    steps:\n      - store: a\n")
	d := e.dispatcher()
	for id, host := range map[string]string{"id9": "db1-prod", "id10": ""} {
		j := e.enqueueWith(t, id, "up", func(j *Job) {
			j.Vars.Hostname = host
			j.Vars.File = id
		}, "p")
		if err := d.Submit(j); err != nil {
			t.Fatal(err)
		}
	}
	d.Wait()
	for id, origin := range map[string]string{"id9": "db1-prod", "id10": "robert.socha"} {
		sc := e.sidecar(t, "a/.db/meta/robert.socha/"+id+".json")
		if sc.Pipeline != "p" || sc.Origin != origin {
			t.Errorf("%s: pipeline %q origin %q, want p %q", id, sc.Pipeline, sc.Origin, origin)
		}
	}
}
