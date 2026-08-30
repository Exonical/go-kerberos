package main

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestGokvnoServiceAndCredentialBoundaries(t *testing.T) {
	if _, err := servicePrincipal("host/server", nil); err == nil {
		t.Fatal("service without realm accepted")
	}
	if _, err := servicePrincipal("@EXAMPLE.COM", &config.Config{}); err == nil {
		t.Fatal("malformed service accepted")
	}
	if _, err := parseVNOArgs([]string{"-x", "host/server"}); err == nil {
		t.Fatal("unknown vno option accepted")
	}
	if got := resolveVNOCachePath("", 42); got != "/tmp/krb5cc_42" {
		t.Fatalf("default vno cache = %q", got)
	}
	if got := findTGT(nil); got != -1 {
		t.Fatalf("nil TGT index = %d", got)
	}
}

func TestGokvnoCredentialsAndTicketValidation(t *testing.T) {
	clientName, _ := principal.Parse("alice@EXAMPLE.COM")
	serverName, _ := principal.Parse("krbtgt/EXAMPLE.COM@EXAMPLE.COM")
	value := ccache.Credential{
		Client: *clientName, Server: *serverName, Enctype: crypto.EnctypeAES256SHA1,
		Key: []byte{1, 2}, TicketFlags: uint32(types.TicketForwardable),
		AuthTime: 10, StartTime: 20, EndTime: 30, RenewTill: 40,
		Ticket: []byte{1, 2, 3},
	}
	converted := credentialsFromCCache(value)
	if converted.Client.String() != value.Client.String() || converted.Server.String() != value.Server.String() ||
		len(converted.Key.KeyValue) != 2 || !converted.EndTime.Present ||
		converted.Flags&types.TicketForwardable == 0 || converted.RenewTill == nil {
		t.Fatalf("credentials conversion = %#v", converted)
	}
	if got, err := ticketKVNO([]byte{1}); err == nil || got != 0 {
		t.Fatalf("malformed ticket = %d/%v", got, err)
	}
}
