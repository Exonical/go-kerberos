package cammac

import (
	"bytes"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func cammacFixture(t *testing.T) (protocol.AuthorizationData, protocol.EncTicketPart,
	protocol.EncryptionKey, protocol.EncryptionKey) {
	t.Helper()
	kdcKey := protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1,
		KeyValue: bytes.Repeat([]byte{0x11}, 32)}
	serviceKey := protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1,
		KeyValue: bytes.Repeat([]byte{0x22}, 32)}
	ticket := protocol.EncTicketPart{
		Flags: types.TicketInitial, Key: serviceKey, CRealm: "TEST.REALM",
		CName:    protocol.PrincipalName{NameType: 1, NameString: []string{"alice"}},
		AuthTime: types.KerberosTime{Time: types.KerberosTime{}.Time, Present: true},
		EndTime:  types.KerberosTime{Present: true},
	}
	elements := protocol.AuthorizationData{{
		ADType: protocol.ADAuthIndicator, ADData: []byte("indicator"),
	}}
	return elements, ticket, kdcKey, serviceKey
}

func TestCAMMACRoundTripAndVerification(t *testing.T) {
	elements, ticket, kdcKey, serviceKey := cammacFixture(t)
	data, err := Marshal(elements, ticket, kdcKey, serviceKey, 7)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyService(data, serviceKey)
	if err != nil {
		t.Fatalf("VerifyService: %v", err)
	}
	if !EqualElements(got, elements) {
		t.Fatalf("protected elements = %#v, want %#v", got, elements)
	}
	if err := VerifyKDC(data, ticket, kdcKey); err != nil {
		t.Fatalf("VerifyKDC: %v", err)
	}
	inner, err := ProtectedElements(data)
	if err != nil || !EqualElements(inner, elements) {
		t.Fatalf("ProtectedElements = %#v, %v", inner, err)
	}
}

func TestCAMMACTamperRejected(t *testing.T) {
	elements, ticket, kdcKey, serviceKey := cammacFixture(t)
	data, err := Marshal(elements, ticket, kdcKey, serviceKey, 7)
	if err != nil {
		t.Fatal(err)
	}
	var outer protocol.AuthorizationData
	if err := asn1.Unmarshal(data[0].ADData, &outer); err != nil {
		t.Fatal(err)
	}
	outer[0].ADData[len(outer[0].ADData)-1] ^= 1
	data[0].ADData, err = asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyService(data, serviceKey); err == nil {
		t.Fatal("tampered CAMMAC unexpectedly verified")
	}
}
