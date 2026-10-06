package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"luk/internal/pipeline"
)

func failureRecord(t *testing.T, root, id string, outcomes ...pipeline.Outcome) string {
	t.Helper()
	dir := filepath.Join(root, "data", "q/backup/failed")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	r := pipeline.Record{ID: id, Endpoint: "backup", Sender: "robert.socha", Origin: "robert.socha",
		FailedAt: time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339), Pipelines: outcomes}
	b, _ := json.Marshal(r)
	p := filepath.Join(dir, id+".json")
	if err := os.WriteFile(p, b, 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestQueueLs(t *testing.T) {
	cfg, root := statusConfig(t)
	out, err := runLukd(t, "queue", "ls", "-c", cfg)
	if err != nil || strings.Count(out, "\n") != 1 || !strings.HasPrefix(out, "ID") {
		t.Fatalf("empty: %q %v", out, err)
	}
	if out, err := runLukd(t, "queue", "ls", "--json", "-c", cfg); err != nil || strings.TrimSpace(out) != "[]" {
		t.Fatalf("empty json: %q %v", out, err)
	}
	at := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	failureRecord(t, root, "id1",
		pipeline.Outcome{Pipeline: "archive", State: pipeline.StateFailed, Step: 2, Error: "run /x: exit status 1\x1b[2J\nlast line", At: at, Stored: []string{"archive:a"}},
		pipeline.Outcome{Pipeline: "copy", State: pipeline.StateOK, At: at, Stored: []string{"archive:copy/db.sql"}},
		pipeline.Outcome{Pipeline: "extra", State: pipeline.StateNotRun, Error: "not run: archive failed", At: at})
	out, err = runLukd(t, "queue", "ls", "-c", cfg)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 || !strings.Contains(lines[1], "id1") || !strings.Contains(lines[1], "backup") ||
		!strings.Contains(lines[1], "robert.socha") || !strings.Contains(lines[1], "archive") || !strings.Contains(lines[1], "failed") ||
		!strings.Contains(lines[1], `exit status 1\x1b[2J`) || !strings.Contains(lines[1], at) ||
		!strings.Contains(lines[1], "2h") || strings.Contains(out, "last line") ||
		!strings.Contains(lines[2], "copy") || !strings.Contains(lines[2], " ok ") || !strings.Contains(lines[2], "archive:copy/db.sql") ||
		!strings.Contains(lines[3], "extra") || !strings.Contains(lines[3], "not_run") || !strings.Contains(lines[3], "not run: archive failed") {
		t.Fatalf("table:\n%s", out)
	}
	out, err = runLukd(t, "queue", "ls", "--json", "-c", cfg)
	var got []pipeline.Record
	if err != nil || json.Unmarshal([]byte(out), &got) != nil || len(got) != 1 || got[0].ID != "id1" ||
		got[0].Endpoint != "backup" || got[0].Sender != "robert.socha" || len(got[0].Pipelines) != 3 ||
		got[0].Pipelines[0].Step != 2 || !strings.Contains(got[0].Pipelines[0].Error, "last line") ||
		strings.Join(got[0].Pipelines[0].Stored, ",") != "archive:a" || got[0].Pipelines[1].State != "ok" {
		t.Fatalf("json %q %v", out, err)
	}
	if _, err := runLukd(t, "queue", "ls", "extra", "-c", cfg); err == nil {
		t.Fatal("positional argument accepted")
	}
}

func TestQueueRm(t *testing.T) {
	cfg, root := statusConfig(t)
	p := failureRecord(t, root, "id1", pipeline.Outcome{Pipeline: "archive", State: pipeline.StateFailed, Step: 1, Error: "boom", At: time.Now().UTC().Format(time.RFC3339)})
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
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("%s kept", p)
	}
}
