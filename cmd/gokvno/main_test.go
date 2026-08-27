package main

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestServicePrincipalUsesDefaultRealm(t *testing.T) {
	value, err := servicePrincipal("host/service.test", &config.Config{DefaultRealm: "EXAMPLE.COM"})
	if err != nil {
		t.Fatal(err)
	}
	if value.String() != "host/service.test@EXAMPLE.COM" {
		t.Fatalf("service = %s", value)
	}
}

func TestParseVNOArgsErrors(t *testing.T) {
	if _, err := parseVNOArgs([]string{"-c"}); err == nil {
		t.Fatal("missing cache path accepted")
	}
	if _, err := parseVNOArgs(nil); err == nil {
		t.Fatal("missing service accepted")
	}
}

func TestFindTGT(t *testing.T) {
	client, err := principal.Parse("alice@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := principal.Parse("krbtgt/EXAMPLE.COM@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	service, err := principal.Parse("host/server@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	cache := &ccache.Cache{
		DefaultPrincipal: *client,
		Credentials: []ccache.Credential{
			{Client: *client, Server: *service},
			{Client: *client, Server: *tgt},
		},
	}
	if got := findTGT(cache); got != 1 {
		t.Fatalf("TGT index = %d", got)
	}
}

func TestTicketKVNOAbsentIsZero(t *testing.T) {
	der, err := asn1.Marshal(protocol.Ticket{
		TktVNO: 5,
		Realm:  "EXAMPLE.COM",
		SName:  protocol.PrincipalName{NameType: 2, NameString: []string{"krbtgt", "EXAMPLE.COM"}},
		EncPart: protocol.EncryptedData{
			EType: 18,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ticketKVNO(der); err != nil || got != 0 {
		t.Fatalf("absent KVNO = %d, err = %v", got, err)
	}
	kvno := uint32(7)
	der, err = asn1.Marshal(protocol.Ticket{
		TktVNO:  5,
		Realm:   "EXAMPLE.COM",
		SName:   protocol.PrincipalName{NameType: 2, NameString: []string{"host", "server"}},
		EncPart: protocol.EncryptedData{EType: 18, KVNO: &kvno},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ticketKVNO(der); err != nil || got != kvno {
		t.Fatalf("KVNO = %d, err = %v", got, err)
	}
}
