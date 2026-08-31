package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/keytab"
)

func TestParseUtilEnctype(t *testing.T) {
	if got, err := parseUtilEnctype("aes256-cts-hmac-sha1-96"); err != nil || got != 18 {
		t.Fatalf("enctype = %d, err = %v", got, err)
	}
	if _, err := parseUtilEnctype("des-cbc-crc"); err == nil {
		t.Fatal("unsupported enctype accepted")
	}
}

func TestParseUtilArgs(t *testing.T) {
	options, err := parseUtilArgs([]string{"-k", "FILE:test.keytab", "-p", "alice@TEST",
		"-kvno", "3", "-e", "18", "-key", "00ff"})
	if err != nil || options.KVNO != 3 || options.Key != "00ff" {
		t.Fatalf("options = %#v, err = %v", options, err)
	}
}

func TestUtilAddPasswordAndDeleteSlot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.keytab")
	args := []string{"addent", "-password", "-k", path, "-p", "alice@TEST",
		"-kvno", "2", "-e", "aes256-cts-hmac-sha1-96"}
	if err := runUtil(args, &bytes.Buffer{}, strings.NewReader("password\n")); err != nil {
		t.Fatal(err)
	}
	kt, err := keytab.Resolve(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := kt.EntriesSnapshot()
	if len(entries) != 1 || entries[0].KVNO != 2 {
		t.Fatalf("entries = %#v", entries)
	}
	etype, err := crypto.NewRegistry().Get(18)
	if err != nil {
		t.Fatal(err)
	}
	want, err := etype.StringToKey([]byte("password"), []byte("TESTalice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entries[0].Key, want) {
		t.Fatalf("password-derived key = %x, want %x", entries[0].Key, want)
	}
	if err := runUtil([]string{"delent", "-k", path, "-slot", "1"},
		&bytes.Buffer{}, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	kt, err = keytab.Resolve(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(kt.EntriesSnapshot()) != 0 {
		t.Fatal("delete did not remove keytab entry")
	}
}

func TestUtilRejectsWrongExplicitKeyLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.keytab")
	err := runUtil([]string{"addent", "-k", path, "-p", "alice@TEST",
		"-kvno", "1", "-e", "18", "-key", "00"}, &bytes.Buffer{}, strings.NewReader(""))
	if err == nil {
		t.Fatal("wrong key length accepted")
	}
}

func TestUtilPasswordReadsOneLineWithoutWaitingForEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.keytab")
	err := runUtil([]string{"addent", "-password", "-k", path, "-p", "alice@TEST",
		"-kvno", "1", "-e", "18"}, &bytes.Buffer{},
		&oneLineReader{value: " pass \n"})
	if err != nil {
		t.Fatal(err)
	}
	kt, err := keytab.Resolve(path)
	if err != nil {
		t.Fatal(err)
	}
	entry := kt.EntriesSnapshot()[0]
	etype, err := crypto.NewRegistry().Get(18)
	if err != nil {
		t.Fatal(err)
	}
	want, err := etype.StringToKey([]byte(" pass "),
		[]byte("TESTalice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entry.Key, want) {
		t.Fatalf("password whitespace was changed: got %x want %x",
			entry.Key, want)
	}
}

func TestUtilRejectsNonFileKeytabs(t *testing.T) {
	for _, command := range [][]string{
		{"list", "-k", "MEMORY:keytab"},
		{"write_kt", "-k", "MEMORY:keytab"},
		{"addent", "-k", "MEMORY:keytab", "-p", "alice@TEST",
			"-kvno", "1", "-e", "18", "-key", strings.Repeat("00", 32)},
		{"delent", "-k", "MEMORY:keytab", "-slot", "1"},
	} {
		if err := runUtil(command, &bytes.Buffer{}, strings.NewReader("")); err == nil {
			t.Fatalf("%v accepted non-FILE keytab", command)
		}
	}
}

func TestUtilWriteFailurePreservesExistingKeytab(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.keytab")
	if err := runUtil([]string{"addent", "-k", path, "-p", "alice@TEST",
		"-kvno", "1", "-e", "18", "-key", strings.Repeat("00", 32)},
		&bytes.Buffer{}, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = writeUtilKeytab(path, &keytab.Keytab{Entries: []keytab.Entry{{
		Timestamp: -1,
	}}})
	if err == nil {
		t.Fatal("invalid keytab unexpectedly written")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed keytab write modified the existing file")
	}
}

type oneLineReader struct {
	value string
	done  bool
}

func (r *oneLineReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	n := copy(p, r.value)
	r.done = true
	return n, errors.New("reader should not be read after newline")
}
