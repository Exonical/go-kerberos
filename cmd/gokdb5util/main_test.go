package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/kdb"
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve Unix file permission bits")
	}
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

func TestMasterKeyLifecycle(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "principal")
	var out bytes.Buffer
	if err := run([]string{"-r", "EXAMPLE.COM", "-d", dbPath, "-P", "old", "create"},
		strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"-d", dbPath, "-P", "old", "add_mkey", "-e", "18"},
		strings.NewReader("new\nnew\n"), &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "version 2") {
		t.Fatalf("add_mkey output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"-d", dbPath, "-P", "new", "use_mkey", "2", "now"},
		strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"-d", dbPath, "-P", "new", "update_princ_encryption", "-f", "-v"},
		strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	store, err := mitdump.LoadWithMasterPassword(dbPath, "new")
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range store.Records() {
		if record.Name.String() == "K/M@EXAMPLE.COM" {
			continue
		}
		kvno, err := kdb.MKVNO(record.TLData)
		if err != nil {
			t.Fatal(err)
		}
		if kvno != 2 {
			t.Fatalf("%s MKVNO = %d", record.Name, kvno)
		}
	}
	out.Reset()
	if err := run([]string{"-d", dbPath, "-P", "new", "purge_mkeys", "-f"},
		strings.NewReader(""), &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "1 key(s) purged.") {
		t.Fatalf("purge_mkeys output = %q", out.String())
	}
}
