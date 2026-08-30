package main

import (
	"os"
	"testing"
)

func TestGokinitParsingAndConfigBoundaries(t *testing.T) {
	options, err := parseInitArgs([]string{"-c", "FILE:/tmp/cache", "-l", "2h", "alice@EXAMPLE.COM"})
	if err != nil || options.CachePath != "FILE:/tmp/cache" || options.Lifetime != 2*60*60*1e9 {
		t.Fatalf("init options = %#v/%v", options, err)
	}
	if _, err := parseInitArgs([]string{"-x", "alice"}); err == nil {
		t.Fatal("unknown init option accepted")
	}
	if _, err := parseInitArgs([]string{"-c", "", "alice"}); err != nil {
		t.Fatal(err)
	}
	if _, err := principalFromArgument("alice", nil); err == nil {
		t.Fatal("realm-less principal accepted without config")
	}
	if got := resolveCachePath("", func(string) string { return "MEMORY:foo" }, 1); got != "MEMORY:foo" {
		t.Fatalf("memory cache path = %q", got)
	}
	path := t.TempDir() + "/krb5.conf"
	if err := os.WriteFile(path, []byte("[libdefaults]\n default_realm = EXAMPLE.COM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadInitConfig(func(string) string { return path })
	if err != nil || cfg.DefaultRealm != "EXAMPLE.COM" {
		t.Fatalf("loaded config = %#v/%v", cfg, err)
	}
	if _, err := loadInitConfig(func(string) string { return path + ".missing" }); err == nil {
		t.Fatal("missing config accepted")
	}
}
