package client

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestVerifyInitCredsRejectsExpiredTicket(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	creds, kt, server := verifyInitCredsFixture(t, now, now.Add(-time.Hour), 0)
	err := (&Client{Now: func() time.Time { return now }}).VerifyInitCreds(
		context.Background(), creds, kt,
		VerifyInitCredsOptions{Server: &server, NoFailSet: true, NoFail: true})
	if !errors.Is(err, krberrors.ErrTicketExpired) {
		t.Fatalf("VerifyInitCreds error = %v, want ErrTicketExpired", err)
	}
}

func TestVerifyInitCredsRejectsInvalidTicket(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	creds, kt, server := verifyInitCredsFixture(t, now, now.Add(time.Hour), types.TicketInvalid)
	err := (&Client{Now: func() time.Time { return now }}).VerifyInitCreds(
		context.Background(), creds, kt,
		VerifyInitCredsOptions{Server: &server, NoFailSet: true, NoFail: true})
	if !errors.Is(err, krberrors.ErrTicketInvalid) {
		t.Fatalf("VerifyInitCreds error = %v, want ErrTicketInvalid", err)
	}
}

func TestVerifyInitCredsNoFailUsesRealmOverride(t *testing.T) {
	cfg, err := config.Parse([]byte(`[libdefaults]
verify_ap_req_nofail = false
TEST.REALM = {
    verify_ap_req_nofail = true
}
`))
	if err != nil {
		t.Fatal(err)
	}
	clientPrincipal := principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	creds := &Credentials{
		Client: clientPrincipal,
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: []byte{1}},
		Ticket: []byte{1},
	}
	err = (&Client{Config: cfg}).VerifyInitCreds(
		context.Background(), creds, nil, VerifyInitCredsOptions{})
	if err == nil {
		t.Fatal("VerifyInitCreds unexpectedly ignored realm nofail override")
	}
	if got := err.Error(); got != "verify initial credentials: keytab unavailable" {
		t.Fatalf("VerifyInitCreds error = %q", got)
	}
}

func TestVerifyInitCredsAutomaticSelectionUsesHostPrincipals(t *testing.T) {
	realm := testRealm
	host := principal.Principal{
		Realm: realm, NameType: principal.NTSrvHst, Components: []string{"host", "verify"},
	}
	service := principal.Principal{
		Realm: realm, NameType: principal.NTSrvInstance, Components: []string{"HTTP", "verify", "extra"},
	}
	servers := verifyInitCredsPrincipals(&keytab.Keytab{Entries: []keytab.Entry{
		{Principal: service}, {Principal: host}, {Principal: host},
	}}, nil)
	if len(servers) != 1 || !sameClientPrincipal(servers[0], host) {
		t.Fatalf("automatic server principals = %#v, want only %s", servers, host)
	}
}

func TestVerifyInitCredsNoHostPrincipalsHonorsNoFail(t *testing.T) {
	clientPrincipal := principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	creds := &Credentials{
		Client: clientPrincipal,
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: []byte{1}},
		Ticket: []byte{1},
	}
	kt := &keytab.Keytab{Entries: []keytab.Entry{{Principal: principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvInstance, Components: []string{"HTTP", "verify"},
	}}}}
	client := &Client{}
	if err := client.VerifyInitCreds(context.Background(), creds, kt, VerifyInitCredsOptions{}); err != nil {
		t.Fatalf("VerifyInitCreds without nofail = %v, want success", err)
	}
	err := client.VerifyInitCreds(context.Background(), creds, kt,
		VerifyInitCredsOptions{NoFailSet: true, NoFail: true})
	if err == nil {
		t.Fatal("VerifyInitCreds with nofail unexpectedly succeeded")
	}
	if got := err.Error(); got != "verify initial credentials: no usable keytab entries" {
		t.Fatalf("VerifyInitCreds with nofail error = %q", got)
	}
}

func verifyInitCredsFixture(t *testing.T, now, end time.Time,
	flags types.TicketFlags) (*Credentials, *keytab.Keytab, principal.Principal) {
	t.Helper()
	clientPrincipal := principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	server := principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvHst, Components: []string{"host", "verify"},
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	part := protocol.EncTicketPart{
		Flags: flags,
		Key: protocol.EncryptionKey{
			KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{0x24}, 32),
		},
		CRealm: testRealm,
		CName: protocol.PrincipalName{
			NameType: int32(clientPrincipal.NameType), NameString: clientPrincipal.Components,
		},
		AuthTime:  kerberosTime(now.Add(-time.Minute)),
		StartTime: ptrKerberosTime(kerberosTime(now.Add(-time.Minute))),
		EndTime:   kerberosTime(end),
	}
	plain, err := asn1.Marshal(part)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := etype.Encrypt(key, 2, plain)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := asn1.Marshal(protocol.Ticket{
		TktVNO: 5, Realm: testRealm,
		SName: protocol.PrincipalName{
			NameType: int32(server.NameType), NameString: server.Components,
		},
		EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: cipher},
	})
	if err != nil {
		t.Fatal(err)
	}
	creds := &Credentials{
		Client: clientPrincipal, Server: server,
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: []byte{1}},
		Ticket: ticket,
	}
	return creds, &keytab.Keytab{Entries: []keytab.Entry{{
		Principal: server, Enctype: crypto.EnctypeAES256SHA1, Key: key,
	}}}, server
}
