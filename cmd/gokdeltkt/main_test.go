package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestDeleteTicketsFromFileCache(t *testing.T) {
	setDeleteTestConfig(t)
	client := mustDeletePrincipal(t, "alice@EXAMPLE.COM")
	first := mustDeletePrincipal(t, "host/one@EXAMPLE.COM")
	second := mustDeletePrincipal(t, "host/two@EXAMPLE.COM")
	path := filepath.Join(t.TempDir(), "cache")
	if err := ccache.WriteName("FILE:"+path, &ccache.Cache{
		DefaultPrincipal: *client,
		Credentials: []ccache.Credential{
			{Client: *client, Server: *first, Enctype: crypto.EnctypeAES256SHA1},
			{Client: *client, Server: *second, Enctype: crypto.EnctypeAES128SHA1},
		},
	}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := runDelete([]string{"-c", "FILE:" + path, first.String()}, &stderr); err != nil {
		t.Fatalf("runDelete: %v (%s)", err, stderr.String())
	}
	value, err := ccache.ReadName("FILE:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.Credentials) != 1 || value.Credentials[0].Server.String() != second.String() {
		t.Fatalf("remaining credentials = %#v", value.Credentials)
	}
}

func TestDeleteMissingTicketReturnsError(t *testing.T) {
	setDeleteTestConfig(t)
	client := mustDeletePrincipal(t, "alice@EXAMPLE.COM")
	path := filepath.Join(t.TempDir(), "cache")
	if err := ccache.WriteName("FILE:"+path, &ccache.Cache{DefaultPrincipal: *client}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := runDelete([]string{"-c", "FILE:" + path, "host/missing@EXAMPLE.COM"}, &stderr); err == nil {
		t.Fatal("runDelete unexpectedly succeeded")
	}
	if stderr.Len() == 0 {
		t.Fatal("missing-ticket error was not reported")
	}
}

func TestDeleteQuietlySuppressesParseErrors(t *testing.T) {
	setDeleteTestConfig(t)
	client := mustDeletePrincipal(t, "alice@EXAMPLE.COM")
	path := filepath.Join(t.TempDir(), "cache")
	if err := ccache.WriteName("FILE:"+path, &ccache.Cache{DefaultPrincipal: *client}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := runDelete([]string{"-q", "-c", "FILE:" + path, "not a principal"}, &stderr); err == nil {
		t.Fatal("runDelete unexpectedly succeeded")
	}
	if stderr.Len() != 0 {
		t.Fatalf("quiet parse stderr = %q", stderr.String())
	}
}

func setDeleteTestConfig(t *testing.T) {
	t.Helper()
	profile := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(profile, []byte("[libdefaults]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", profile)
}

func TestDeleteRejectsEmptyArgument(t *testing.T) {
	if _, err := parseDeleteArgs([]string{""}); err == nil {
		t.Fatal("parseDeleteArgs unexpectedly accepted an empty argument")
	}
}

func mustDeletePrincipal(t *testing.T, value string) *principal.Principal {
	t.Helper()
	result, err := principal.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
