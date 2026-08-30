package main

import (
	"bytes"
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
