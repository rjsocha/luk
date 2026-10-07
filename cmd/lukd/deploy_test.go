package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDeployFilesPackaged(t *testing.T) {
	g, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	units, _ := filepath.Glob("../../deploy/*.service")
	for _, ext := range []string{"socket", "timer"} {
		m, _ := filepath.Glob("../../deploy/*." + ext)
		units = append(units, m...)
	}
	for _, u := range units {
		src := "deploy/" + filepath.Base(u)
		if !bytes.Contains(g, []byte("src: "+src+"\n")) {
			t.Errorf("%s not in .goreleaser.yaml", src)
		}
	}
	for _, want := range []string{"deploy/lukd-run-prune.service", "deploy/lukd-run-prune.timer"} {
		if _, err := os.Stat("../../" + want); err != nil {
			t.Error(err)
		}
	}
	if _, err := os.Stat("../../deploy/lukd-process.service.d/docker.conf.example"); err == nil {
		t.Error("docker drop-in for lukd-process still shipped")
	}
}
