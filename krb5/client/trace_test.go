package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientTraceDefaultsFromEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.log")
	t.Setenv("KRB5_TRACE", path)
	var client Client
	client.tracef("default trace")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), ": default trace\n") {
		t.Fatalf("trace file = %q", data)
	}
}
