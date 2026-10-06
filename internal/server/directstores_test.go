package server

import (
	"slices"
	"testing"

	"luk/internal/config"
)

// A store after a tee step stores the upload itself; one after another run
// step or an encrypt step stores what that step produced.
func TestDirectStoresAfterTee(t *testing.T) {
	cfg := &config.Config{
		Storage: map[string]*config.Storage{
			"a": {Type: "local", Base: "/a"},
			"b": {Type: "local", Base: "/b"},
			"c": {Type: "local", Base: "/c"},
		},
		Pipeline: map[string]*config.Pipeline{
			"p": {Steps: []config.Step{
				{Store: config.StringList{"a"}},
				{Run: config.RunSpec{Program: "/opt/luk/s3copy"}, Tee: true},
				{Store: config.StringList{"b"}},
				{Run: config.RunSpec{Program: "/opt/luk/zip"}},
				{Store: config.StringList{"c"}},
			}},
		},
	}
	var got []string
	for sn := range directStores(cfg, []string{"p"}, "") {
		got = append(got, sn)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("%v", got)
	}
	if ls := storesOnly(cfg, []string{"p"}, ""); ls != nil {
		t.Fatalf("stores only: %v", ls)
	}
}

// A relay step passes the upload on like a tee step, but a pipeline with
// one is not store-only: the transfer dedup excludes it.
func TestDirectStoresAfterRelay(t *testing.T) {
	cfg := &config.Config{
		Storage: map[string]*config.Storage{
			"a": {Type: "local", Base: "/a"},
			"b": {Type: "local", Base: "/b"},
		},
		Pipeline: map[string]*config.Pipeline{
			"p": {Steps: []config.Step{
				{Store: config.StringList{"a"}},
				{Relay: "s3-upload"},
				{Store: config.StringList{"b"}},
			}},
		},
	}
	var got []string
	for sn := range directStores(cfg, []string{"p"}, "") {
		got = append(got, sn)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("%v", got)
	}
	if ls := storesOnly(cfg, []string{"p"}, ""); ls != nil {
		t.Fatalf("stores only: %v", ls)
	}
}
