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

func TestCreateDoesNotReplaceExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "principal")
	original := []byte("existing")
	if err := os.WriteFile(dbPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-r", "EXAMPLE.COM", "-d", dbPath, "-P", "password", "create"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("create unexpectedly succeeded")
	}
	data, readErr := os.ReadFile(dbPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != string(original) {
		t.Fatalf("database changed to %q", data)
	}
}

func TestLoadReplacesWith0600Atomically(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	target := filepath.Join(dir, "target")
	var out bytes.Buffer
	if err := run([]string{"-r", "EXAMPLE.COM", "-d", source, "-P", "password", "create"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-d", target, "load", source}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("target mode = %o, want 600", got)
	}
	if _, err := mitdump.LoadWithMasterPassword(target, "password"); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordPromptPreservesSpaces(t *testing.T) {
	value, err := readPassword(strings.NewReader(" leading and trailing \r\n"), &bytes.Buffer{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if value != " leading and trailing " {
		t.Fatalf("password = %q", value)
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
