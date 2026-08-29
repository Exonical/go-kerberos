package kdc

import (
	"context"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestOptInPACIssuanceAndExtraction(t *testing.T) {
	now := time.Unix(2000001900, 0).UTC()
	server, kclient := testServer(t, now)
	server.EnablePAC = true
	server.GeneratePAC = func(client, service principal.Principal) ([]byte, error) {
		return []byte{0xaa, 0xbb, 0xcc}, nil
	}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	creds, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(creds.Ticket, &ticket); err != nil {
		t.Fatal(err)
	}
	record, ok, err := server.DB.Lookup(ticketPrincipal(ticket))
	if err != nil || !ok {
		t.Fatalf("lookup ticket key: %v", err)
	}
	key := record.Keys[ticket.EncPart.EType]
	etype, err := crypto.NewRegistry().Get(key.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(key.Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	p, err := pac.FromTicket(part, pac.Key{EType: etype, Key: key.Key}, &pac.Key{EType: etype, Key: key.Key})
	if err != nil {
		t.Fatal(err)
	}
	data, ok := p.Buffer(pac.LogonInfo)
	if !ok || string(data) != string([]byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("logon-info = %x", data)
	}

	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	serviceCreds, err := kclient.TGSExchange(context.Background(), creds, service)
	if err != nil {
		t.Fatal(err)
	}
	var serviceTicket protocol.Ticket
	if err := asn1.Unmarshal(serviceCreds.Ticket, &serviceTicket); err != nil {
		t.Fatal(err)
	}
	serviceRecord, ok, err := server.DB.Lookup(ticketPrincipal(serviceTicket))
	if err != nil || !ok {
		t.Fatalf("lookup service key: %v", err)
	}
	serviceKDBKey := serviceRecord.Keys[serviceTicket.EncPart.EType]
	serviceEType, err := crypto.NewRegistry().Get(serviceKDBKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	servicePlain, err := serviceEType.Decrypt(serviceKDBKey.Key, 2, serviceTicket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var servicePart protocol.EncTicketPart
	if err := asn1.Unmarshal(servicePlain, &servicePart); err != nil {
		t.Fatal(err)
	}
	servicePAC, err := pac.FromTicket(servicePart,
		pac.Key{EType: serviceEType, Key: serviceKDBKey.Key}, &pac.Key{EType: etype, Key: key.Key})
	if err != nil {
		t.Fatal(err)
	}
	if data, ok := servicePAC.Buffer(pac.LogonInfo); !ok || string(data) != string([]byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("TGS logon-info = %x", data)
	}
}

func ticketPrincipal(ticket protocol.Ticket) principal.Principal {
	return principal.Principal{Realm: ticket.Realm, NameType: principal.NameType(ticket.SName.NameType), Components: ticket.SName.NameString}
}
