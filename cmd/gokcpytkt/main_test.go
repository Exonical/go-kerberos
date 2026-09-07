package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestCopyTicketsBetweenFileCaches(t *testing.T) {
	client := mustCopyPrincipal(t, "alice@EXAMPLE.COM")
	first := mustCopyPrincipal(t, "host/one@EXAMPLE.COM")
	second := mustCopyPrincipal(t, "host/two@EXAMPLE.COM")
	unrelated := mustCopyPrincipal(t, "host/unrelated@EXAMPLE.COM")
	source := filepath.Join(t.TempDir(), "source")
	destination := filepath.Join(t.TempDir(), "destination")
	if err := ccache.WriteName("FILE:"+source, &ccache.Cache{
		DefaultPrincipal: *client,
		Credentials: []ccache.Credential{
			{Client: *client, Server: *first, Enctype: crypto.EnctypeAES256SHA1},
			{Client: *client, Server: *second, Enctype: crypto.EnctypeAES128SHA1},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ccache.WriteName("FILE:"+destination, &ccache.Cache{
		DefaultPrincipal: *client,
		Credentials: []ccache.Credential{
			{Client: *client, Server: *unrelated, Enctype: crypto.EnctypeAES128SHA1},
		},
	}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := runCopy([]string{"-c", "FILE:" + source, "FILE:" + destination, first.String()}, &stderr); err != nil {
		t.Fatalf("runCopy: %v (%s)", err, stderr.String())
	}
	value, err := ccache.ReadName("FILE:" + destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.Credentials) != 2 ||
		value.Credentials[0].Server.String() != unrelated.String() ||
		value.Credentials[1].Server.String() != first.String() {
		t.Fatalf("copied credentials = %#v", value.Credentials)
	}
}

func TestCopyTicketErrorsAndQuietParsing(t *testing.T) {
	client := mustCopyPrincipal(t, "alice@EXAMPLE.COM")
	source := filepath.Join(t.TempDir(), "source")
	destination := filepath.Join(t.TempDir(), "destination")
	if err := ccache.WriteName("FILE:"+source, &ccache.Cache{DefaultPrincipal: *client}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := runCopy([]string{"-q", "-c", "FILE:" + source, "FILE:" + destination, "not a principal"}, &stderr); err == nil {
		t.Fatal("runCopy unexpectedly succeeded")
	}
	if stderr.Len() != 0 {
		t.Fatalf("quiet parse stderr = %q", stderr.String())
	}
}

func TestCopySelectsRequestedEnctype(t *testing.T) {
	client := mustCopyPrincipal(t, "alice@EXAMPLE.COM")
	service := mustCopyPrincipal(t, "host/one@EXAMPLE.COM")
	source := filepath.Join(t.TempDir(), "source")
	destination := filepath.Join(t.TempDir(), "destination")
	if err := ccache.WriteName("FILE:"+source, &ccache.Cache{
		DefaultPrincipal: *client,
		Credentials: []ccache.Credential{
			{Client: *client, Server: *service, Enctype: crypto.EnctypeAES256SHA1},
			{Client: *client, Server: *service, Enctype: crypto.EnctypeAES128SHA1},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ccache.WriteName("FILE:"+destination, &ccache.Cache{DefaultPrincipal: *client}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if err := runCopy([]string{"-c", "FILE:" + source, "-e", "17", "FILE:" + destination, service.String()}, &stderr); err != nil {
		t.Fatalf("runCopy: %v (%s)", err, stderr.String())
	}
	value, err := ccache.ReadName("FILE:" + destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.Credentials) != 1 || value.Credentials[0].Enctype != crypto.EnctypeAES128SHA1 {
		t.Fatalf("selected credentials = %#v", value.Credentials)
	}
}

func mustCopyPrincipal(t *testing.T, value string) *principal.Principal {
	t.Helper()
	result, err := principal.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
