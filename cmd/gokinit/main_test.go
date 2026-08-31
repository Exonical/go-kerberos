package main

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/config"
)

func TestPrincipalFromArgumentUsesDefaultRealm(t *testing.T) {
	cfg := &config.Config{DefaultRealm: "EXAMPLE.COM"}
	value, err := principalFromArgument("alice", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if value.String() != "alice@EXAMPLE.COM" {
		t.Fatalf("principal = %s", value)
	}
}

func TestCachePathResolution(t *testing.T) {
	if got := resolveCachePath("FILE:/tmp/custom", func(string) string { return "" }, 42); got != "/tmp/custom" {
		t.Fatalf("explicit cache = %q", got)
	}
	if got := resolveCachePath("", func(string) string { return "FILE:/tmp/from-env" }, 42); got != "/tmp/from-env" {
		t.Fatalf("environment cache = %q", got)
	}
	if got := resolveCachePath("", func(string) string { return "" }, 42); got != "/tmp/krb5cc_42" {
		t.Fatalf("default cache = %q", got)
	}
}

func TestParseInitArgsErrors(t *testing.T) {
	if _, err := parseInitArgs([]string{"-l"}); err == nil {
		t.Fatal("missing lifetime value accepted")
	}
	if _, err := parseInitArgs([]string{"alice", "extra"}); err == nil {
		t.Fatal("extra principal argument accepted")
	}
	if _, err := parseInitArgs(nil); err == nil {
		t.Fatal("missing principal accepted")
	}
}
