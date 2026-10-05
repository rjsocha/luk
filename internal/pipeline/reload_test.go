package pipeline

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"luk/internal/config"
)

// reloaded parses the env config with concurrency and edit applied.
func (e *env) reloaded(t *testing.T, concurrency int, edit func(string) string) *config.Config {
	t.Helper()
	text := fmt.Sprintf(cfgTmpl, e.root, concurrency)
	if edit != nil {
		text = edit(text)
	}
	return parseCfg(t, text)
}

func withoutTee(s string) string {
	return strings.Replace(s, "  tee:\n    endpoint: [up]\n    steps:\n      - store: [a, b]\n", "", 1)
}

// blockRun makes every pipeline wait in hookRun until release is closed;
// entered gets one value per pipeline that got its slot.
func blockRun(t *testing.T) (entered chan string, release chan struct{}) {
	entered, release = make(chan string, 8), make(chan struct{})
	hookRun = func(j Job, name string) {
		entered <- j.Entry.ID
		<-release
	}
	t.Cleanup(func() { hookRun = func(Job, string) {} })
	return entered, release
}

func TestReloadKeepsRunningPipeline(t *testing.T) {
	e := newEnv(t, 1)
	entered, release := blockRun(t)
	d := e.dispatcher()
	j := e.enqueue(t, "r1", "up", "tee")
	d.Submit(j)
	<-entered
	d.Reload(e.reloaded(t, 1, withoutTee))
	close(release)
	d.Wait()
	gone(t, j.Entry.Dir)
	gone(t, e.recordPath("up", "r1"))
	if e.read(t, "a/file/robert.socha/f.txt") != "data-r1" || e.read(t, "b/file/r-r1") != "data-r1" {
		t.Fatal("not stored")
	}
}

func TestReloadRemovedPipelineFails(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	d.Reload(e.reloaded(t, 1, withoutTee))
	j := e.enqueue(t, "r2", "up", "tee")
	d.Submit(j)
	d.Wait()
	gone(t, j.Entry.Dir)
	r := loadRecord(t, e.recordPath("up", "r2"))
	if len(r.Pipelines) != 1 || r.Pipelines[0].Pipeline != "tee" || r.Pipelines[0].Error != "pipeline not in the config" {
		t.Fatalf("%+v", r.Pipelines)
	}
}

func TestReloadConcurrency(t *testing.T) {
	e := newEnv(t, 1)
	entered, release := blockRun(t)
	d := e.dispatcher()
	d.Submit(e.enqueue(t, "c1", "up", "serial"))
	<-entered
	d.Submit(e.enqueue(t, "c2", "up", "serial"))
	select {
	case id := <-entered:
		t.Fatalf("%s entered while c1 holds the only slot", id)
	case <-time.After(100 * time.Millisecond):
	}
	d.Reload(e.reloaded(t, 2, nil))
	if id := <-entered; id != "c2" {
		t.Fatalf("entered %s", id)
	}
	// Lowering the limit stops neither running pipeline; the next waits.
	d.Reload(e.reloaded(t, 1, nil))
	d.Submit(e.enqueue(t, "c3", "up", "serial"))
	select {
	case id := <-entered:
		t.Fatalf("%s entered over the new limit", id)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	d.Wait()
	for _, id := range []string{"c1", "c2", "c3"} {
		if e.read(t, "b/file/r-"+id) != "data-"+id {
			t.Fatalf("%s not stored", id)
		}
	}
}

func TestReloadRemovedEndpointStillPickedUp(t *testing.T) {
	e := newEnv(t, 1)
	d := e.dispatcher()
	d.Reload(e.reloaded(t, 1, func(s string) string {
		return strings.Replace(s, "  other:\n    listen: main\n    endpoint: /other\n    path: queue/other\n    allow: [robert.socha]\n", "", 1)
	}))
	j := e.enqueue(t, "o1", "other", "serial")
	d.Pickup()
	d.Wait()
	gone(t, j.Entry.Dir)
	if e.read(t, "b/file/r-o1") != "data-o1" {
		t.Fatal("not stored")
	}
}
