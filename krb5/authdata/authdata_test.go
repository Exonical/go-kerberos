package authdata

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestGreetModuleImportsVerifiedKDCIssuedData(t *testing.T) {
	key := protocol.EncryptionKey{
		KeyType:  crypto.EnctypeAES128SHA1,
		KeyValue: []byte("0123456789abcdef"),
	}
	elements := protocol.AuthorizationData{{
		ADType: GreetAuthDataType,
		ADData: []byte("Hello, KDC issued acceptor world!"),
	}}
	encoded, err := asn1.Marshal(elements)
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := etype.Checksum(key.KeyValue, 19, encoded)
	if err != nil {
		t.Fatal(err)
	}
	realm := "EXAMPLE.COM"
	issued, err := asn1.Marshal(protocol.KDCIssued{
		Checksum: protocol.Checksum{
			ChecksumType: crypto.ChecksumHMACSHA196AES128,
			Checksum:     checksum,
		},
		IRealm:   &realm,
		Elements: elements,
	})
	if err != nil {
		t.Fatal(err)
	}
	inner, err := asn1.Marshal(protocol.AuthorizationData{{
		ADType: protocol.ADKDCIssued,
		ADData: issued,
	}})
	if err != nil {
		t.Fatal(err)
	}
	module := &GreetModule{}
	ctx := NewContext(module)
	if err := ctx.Import(protocol.AuthorizationData{{
		ADType: protocol.ADIfRelevant,
		ADData: inner,
	}}, ADUsageAPReq, &protocol.EncTicketPart{}, key); err != nil {
		t.Fatal(err)
	}
	value, display, authenticated, complete, err := ctx.GetAttribute(GreetAttribute)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != string(elements[0].ADData) ||
		string(display) != string(value) ||
		!authenticated || !complete {
		t.Fatalf("unexpected greeting: value=%q display=%q authenticated=%v complete=%v",
			value, display, authenticated, complete)
	}
}

func TestGreetModuleDoesNotAuthenticateWithoutValidChecksum(t *testing.T) {
	module := &GreetModule{}
	ctx := NewContext(module)
	inner, err := asn1.Marshal(protocol.AuthorizationData{{
		ADType: GreetAuthDataType,
		ADData: []byte("hello"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.Import(protocol.AuthorizationData{{
		ADType: protocol.ADIfRelevant,
		ADData: inner,
	}}, ADUsageAPReq, nil, protocol.EncryptionKey{}); err != nil {
		t.Fatal(err)
	}
	_, _, authenticated, _, err := ctx.GetAttribute(GreetAttribute)
	if err != nil {
		t.Fatal(err)
	}
	if authenticated {
		t.Fatal("unprotected greeting was authenticated")
	}
}

func TestGreetModuleIssuer(t *testing.T) {
	module := &GreetModule{}
	if module.Flags(GreetAuthDataType)&ADUsageKDCIssued == 0 {
		t.Fatal("greet module does not advertise KDC-issued usage")
	}
	issuer := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"krbtgt", "EXAMPLE.COM"}}
	if err := module.ImportAuthData(protocol.AuthorizationData{{
		ADType: GreetAuthDataType, ADData: []byte("hello"),
	}}, true, &issuer); err != nil {
		t.Fatal(err)
	}
}
