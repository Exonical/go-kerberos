package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestDeleteTicketsFromFileCache(t *testing.T) {
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

func mustDeletePrincipal(t *testing.T, value string) *principal.Principal {
	t.Helper()
	result, err := principal.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
