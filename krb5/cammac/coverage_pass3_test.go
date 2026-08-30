package cammac

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestCAMMACInvalidInputsAndDiscovery(t *testing.T) {
	elements, ticket, kdcKey, serviceKey := cammacFixture(t)
	if _, err := Marshal(nil, ticket, kdcKey, serviceKey, 1); err == nil {
		t.Fatal("empty CAMMAC accepted")
	}
	if _, err := Marshal(elements, ticket, protocol.EncryptionKey{}, serviceKey, 1); err == nil {
		t.Fatal("empty KDC key accepted")
	}
	if _, err := Marshal(elements, ticket, protocol.EncryptionKey{KeyType: 999, KeyValue: []byte{1}}, serviceKey, 1); err == nil {
		t.Fatal("unknown KDC enctype accepted")
	}
	if _, err := Parse([]byte{1}); err == nil {
		t.Fatal("malformed CAMMAC accepted")
	}
	if _, err := VerifyService(nil, serviceKey); err != ErrNotFound {
		t.Fatalf("missing service CAMMAC = %v", err)
	}
	if _, err := ProtectedElements(protocol.AuthorizationData{{ADType: protocol.ADIfRelevant, ADData: []byte{1}}}); err == nil {
		t.Fatal("malformed IF-RELEVANT accepted")
	}
	if HasCAMMAC(nil) {
		t.Fatal("empty authdata has CAMMAC")
	}
	if EqualElements(elements, protocol.AuthorizationData{{ADType: protocol.ADAuthIndicator, ADData: []byte("other")}}) {
		t.Fatal("different elements compared equal")
	}
	if err := VerifyKDC(nil, ticket, kdcKey); err != ErrNotFound {
		t.Fatalf("missing KDC CAMMAC = %v", err)
	}
	if _, err := VerifyService(protocol.AuthorizationData{{ADType: protocol.ADIfRelevant, ADData: []byte{1}}}, protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: []byte{1}}); err == nil {
		t.Fatal("invalid service wrapper accepted")
	}
}
