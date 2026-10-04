package pipeline

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"luk/internal/status"
)

// lukJob is the luk-job binary built once for the step scripts.
var lukJob string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "luk-job-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	lukJob = filepath.Join(dir, "luk-job")
	build := exec.Command("go", "build", "-o", lukJob, "luk/cmd/luk-job")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build luk-job: %v\n%s", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestJobHelperOutputWithMeta(t *testing.T) {
	s := script(t, `set -e
in=$(luk-job input)
test "$(luk-job meta --field client.file)" = f.txt
tr a-z A-Z < "$in" > "$LUK_WORK/up"
luk-job output --file "$LUK_WORK/up" --name up.txt --meta kind=logical --meta alias=x
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        env: {PATH: %s}\n      - store: a\n",
		s, filepath.Dir(lukJob)+":/usr/bin:/bin"))
	d := e.dispatcher()
	j := e.enqueueWith(t, "j1", "up", func(j *Job) { j.Sidecar.Client.File = "f.txt" }, "p")
	if err := d.Submit(j); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	if find(e.logs.records(t), "pipeline done", "p") == nil {
		t.Fatalf("logs %v", e.logs.records(t))
	}
	if got := e.read(t, "a/file/robert.socha/up.txt"); got != "DATA-J1" {
		t.Fatalf("up.txt %q", got)
	}
	if sc := e.sidecar(t, "a/.db/meta/robert.socha/up.txt.json"); string(sc.Meta) != `{"alias":"x","kind":"logical"}` {
		t.Fatalf("meta %s", sc.Meta)
	}
}

func TestJobHelperFail(t *testing.T) {
	s := script(t, `echo noise
luk-job fail --message boom || exit 1
echo unreachable
`)
	e := newRunEnv(t, fmt.Sprintf("    steps:\n      - run: %s\n        env: {PATH: %s}\n", s, filepath.Dir(lukJob)+":/usr/bin:/bin"))
	st := status.New(status.Path(e.root))
	d := e.dispatcher()
	d.SetStatus(st)
	if err := d.Submit(e.enqueue(t, "j2", "up", "p")); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	if es := st.Entries(); len(es) != 1 || es[0].Error != "boom" || es[0].FailedStep != 1 {
		t.Fatalf("entries %+v", es)
	}
	rec := find(e.logs.records(t), "pipeline failed", "p")
	if out, _ := rec["output"].(string); !strings.Contains(out, "noise") || strings.Contains(out, "unreachable") {
		t.Fatalf("log %v", rec)
	}
}
