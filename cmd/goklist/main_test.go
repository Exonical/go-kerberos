package main

import (
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
)

func TestKlistFormatting(t *testing.T) {
	value := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := formatKlistTime(value); got != "01/02/25 03:04:05" {
		t.Fatalf("formatted time = %q", got)
	}
	if got := enctypeName(crypto.EnctypeAES256SHA1); got != "aes256-cts-hmac-sha1-96" {
		t.Fatalf("enctype name = %q", got)
	}
}

func TestParseListArgs(t *testing.T) {
	options, err := parseListArgs([]string{"-e", "-c", "cache", "-k", "keytab"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.ShowEtypes || options.CachePath != "cache" || options.KeytabPath != "keytab" {
		t.Fatalf("options = %#v", options)
	}
	if _, err := parseListArgs([]string{"-c"}); err == nil {
		t.Fatal("missing cache path accepted")
	}
	if _, err := parseListArgs([]string{"unexpected"}); err == nil {
		t.Fatal("unexpected argument accepted")
	}
}
