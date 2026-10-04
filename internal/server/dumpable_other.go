//go:build !linux

package server

func setNonDumpable() error { return nil }
