package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
)

func TestCreateAndStash(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "principal")
	stashPath := filepath.Join(dir, "stash")
	var out bytes.Buffer
	if err := run([]string{"-r", "EXAMPLE.COM", "-d", dbPath, "-sf", stashPath, "-P", "password", "create"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	store, err := mitdump.LoadWithMasterPassword(dbPath, "password")
	if err != nil {
		t.Fatal(err)
	}
	records := store.Records()
	for _, name := range []string{"K/M@EXAMPLE.COM", "krbtgt/EXAMPLE.COM@EXAMPLE.COM", "kadmin/admin@EXAMPLE.COM", "kadmin/changepw@EXAMPLE.COM", "kadmin/history@EXAMPLE.COM"} {
		found := false
		for _, record := range records {
			if record.Name.String() == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing bootstrap principal %q", name)
		}
	}
	if _, err := mitdump.LoadWithStash(dbPath, stashPath); err != nil {
		t.Fatal(err)
	}
}

func TestCreatePipePasswordPromptsShareReader(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "principal")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString("password\npassword\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"-r", "EXAMPLE.COM", "-d", dbPath, "create"}, reader, &out, &out); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := mitdump.LoadWithMasterPassword(dbPath, "password"); err != nil {
		t.Fatal(err)
	}
}

func TestDestroyConfirmation(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "principal")
	if err := os.WriteFile(dbPath, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"-d", dbPath, "destroy"}, strings.NewReader("no\n"), &out, &out); err == nil {
		t.Fatal("destroy unexpectedly succeeded")
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatal(err)
	}
}
