package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/pipeline"
	"luk/internal/store"
)

func failedEntry(t *testing.T, root, id string, failures ...pipeline.Failure) string {
	t.Helper()
	dir := filepath.Join(root, "q/backup/failed", id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	m := pipeline.QueueMeta{
		Vars:    store.Vars{Sender: "robert.socha", Endpoint: "backup", Id: id},
		Sidecar: store.Sidecar{ID: id, Sender: "robert.socha", Endpoint: "backup"},
		Failed:  failures,
	}
	for _, f := range failures {
		m.Pipelines = append(m.Pipelines, f.Pipeline)
	}
	b, _ := json.Marshal(m)
	for name, data := range map[string][]byte{"meta.json": b, "payload": []byte("x")} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestQueueLs(t *testing.T) {
	cfg, root := statusConfig(t)
	out, err := runLukd(t, "queue", "ls", "-c", cfg)
	if err != nil || strings.Count(out, "\n") != 1 || !strings.HasPrefix(out, "ID") {
		t.Fatalf("empty: %q %v", out, err)
	}
	at := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	failedEntry(t, root, "id1",
		pipeline.Failure{Pipeline: "archive", Step: 2, Error: "run /x: exit status 1\x1b[2J\nlast line", At: at},
		pipeline.Failure{Pipeline: "extra", Step: 0, Error: "pipeline not in the config", At: at})
	out, err = runLukd(t, "queue", "ls", "-c", cfg)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], "id1") || !strings.Contains(lines[1], "backup") ||
		!strings.Contains(lines[1], "robert.socha") || !strings.Contains(lines[1], "archive") ||
		!strings.Contains(lines[1], `exit status 1\x1b[2J`) || !strings.Contains(lines[1], at) ||
		!strings.Contains(lines[1], "2h") || strings.Contains(out, "last line") || !strings.Contains(lines[2], "extra") {
		t.Fatalf("table:\n%s", out)
	}
	out, err = runLukd(t, "queue", "ls", "--json", "-c", cfg)
	var got []queueItem
	if err != nil || json.Unmarshal([]byte(out), &got) != nil || len(got) != 1 || got[0].ID != "id1" ||
		got[0].Endpoint != "backup" || got[0].Sender != "robert.socha" || len(got[0].Pipelines) != 2 ||
		got[0].Pipelines[0].Step != 2 || !strings.Contains(got[0].Pipelines[0].Error, "last line") || got[0].FailedAt != at {
		t.Fatalf("json %q %v", out, err)
	}
	if _, err := runLukd(t, "queue", "ls", "extra", "-c", cfg); err == nil {
		t.Fatal("positional argument accepted")
	}
}

func TestQueueRm(t *testing.T) {
	cfg, root := statusConfig(t)
	dir := failedEntry(t, root, "id1", pipeline.Failure{Pipeline: "archive", Step: 1, Error: "boom", At: time.Now().UTC().Format(time.RFC3339)})
	work := filepath.Join(root, "work", "id1", "archive")
	if err := os.MkdirAll(work, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := runLukd(t, "queue", "rm", "--id", "nope", "-c", cfg); err == nil {
		t.Fatal("unknown id accepted")
	}
	if _, err := runLukd(t, "queue", "rm", "-c", cfg); err == nil {
		t.Fatal("missing --id accepted")
	}
	out, err := runLukd(t, "queue", "rm", "--id", "id1", "-c", cfg)
	if err != nil || !strings.Contains(out, "id1") {
		t.Fatalf("%q %v", out, err)
	}
	for _, p := range []string{dir, filepath.Join(root, "work", "id1")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s kept", p)
		}
	}
}

func TestQueueRetry(t *testing.T) {
	cfg, root := statusConfig(t)
	at := time.Now().UTC().Format(time.RFC3339)
	failedEntry(t, root, "id1", pipeline.Failure{Pipeline: "archive", Step: 1, Error: "boom", At: at},
		pipeline.Failure{Pipeline: "other", Step: 1, Error: "boom", At: at})
	if _, err := runLukd(t, "queue", "retry", "--id", "nope", "-c", cfg); err == nil {
		t.Fatal("unknown id accepted")
	}
	if _, err := runLukd(t, "queue", "retry", "--id", "id1", "--pipeline", "nope", "-c", cfg); err == nil {
		t.Fatal("unknown pipeline accepted")
	}
	out, err := runLukd(t, "queue", "retry", "--id", "id1", "--pipeline", "archive", "-c", cfg)
	if err != nil || !strings.Contains(out, "id1") || !strings.Contains(out, "archive") || !strings.Contains(out, "within a minute") {
		t.Fatalf("%q %v", out, err)
	}
	b, err := os.ReadFile(filepath.Join(root, "q/backup/id1/meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m pipeline.QueueMeta
	if err := json.Unmarshal(b, &m); err != nil || strings.Join(m.Pipelines, ",") != "archive" || len(m.Failed) != 0 {
		t.Fatalf("meta %s %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(root, "q/backup/failed/id1")); !os.IsNotExist(err) {
		t.Fatal("entry still in failed/")
	}
}
