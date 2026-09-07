package client

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestClientTraceDefaultsFromEnv(t *testing.T) {
	file, err := os.CreateTemp("", "go-kerberos-client-trace-*")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		defer os.Remove(path)
	}
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
