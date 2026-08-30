package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDestroyArgs(t *testing.T) {
	options, err := parseDestroyArgs([]string{"-A", "-q"})
	if err != nil || !options.All || !options.Quiet {
		t.Fatalf("options = %#v, err = %v", options, err)
	}
	if _, err := parseDestroyArgs([]string{"-A", "-p", "alice@TEST"}); err == nil {
		t.Fatal("-A and -p accepted together")
	}
	if _, err := parseDestroyArgs([]string{"-c"}); err == nil {
		t.Fatal("missing -c value accepted")
	}
}

func TestDestroyQuietMissingCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if err := runDestroy([]string{"-c", path}, os.Stderr); err == nil {
		t.Fatal("missing cache unexpectedly succeeded without quiet mode")
	}
	if err := runDestroy([]string{"-q", "-c", path}, os.Stderr); err != nil {
		t.Fatalf("quiet missing cache: %v", err)
	}
}
