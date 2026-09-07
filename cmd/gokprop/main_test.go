package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParsePropArgsDefaults(t *testing.T) {
	options, err := parsePropArgs([]string{"replica.example"})
	if err != nil {
		t.Fatal(err)
	}
	if options.ReplicaHost != "replica.example" || options.Port != "754" ||
		options.File != defaultKPropFile || options.Debug {
		t.Fatalf("defaults = %#v", options)
	}
}

func TestParsePropArgsExplicitValues(t *testing.T) {
	options, err := parsePropArgs([]string{"-r", "EXAMPLE.COM", "-f", "dump",
		"-d", "-P", "1754", "-s", "MEMORY:master", "replica"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Realm != "EXAMPLE.COM" || options.File != "dump" ||
		options.Port != "1754" || options.Keytab != "MEMORY:master" ||
		!options.Debug || options.ReplicaHost != "replica" {
		t.Fatalf("options = %#v", options)
	}
}

func TestTouchLastProp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve Unix file permission bits")
	}
	path := filepath.Join(t.TempDir(), "dump")
	if err := touchLastProp(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path + ".last_prop")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("last-prop mode = %o", info.Mode().Perm())
	}
}
