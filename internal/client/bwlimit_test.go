package client

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestLimitReaderPaces(t *testing.T) {
	data := make([]byte, 200<<10)
	r := newLimitReader(context.Background(), bytes.NewReader(data), 1<<20)
	start := time.Now()
	b, err := io.ReadAll(r)
	if err != nil || len(b) != len(data) {
		t.Fatalf("%d %v", len(b), err)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("read took %s, want >= 150ms", d)
	}
}

func TestLimitReaderCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := newLimitReader(ctx, bytes.NewReader(make([]byte, 100)), 1)
	buf := make([]byte, 10)
	if _, err := r.Read(buf); err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	_, err := r.Read(buf)
	if err == nil {
		t.Fatal("no error after cancel")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("cancel took %s", d)
	}
}

func TestLimitReaderCapsChunk(t *testing.T) {
	r := newLimitReader(context.Background(), bytes.NewReader(make([]byte, 1000)), 100)
	n, _ := r.Read(make([]byte, 1000))
	if n != 10 {
		t.Fatalf("first chunk %d, want 10", n)
	}
}
