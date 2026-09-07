package authdata

import (
	"errors"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/cammac"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

type recordingModule struct {
	flags         uint32
	types         []int32
	authenticated []bool
}

func (m *recordingModule) Name() string       { return "recording" }
func (m *recordingModule) Flags(int32) uint32 { return m.flags }
func (m *recordingModule) ImportAuthData(data protocol.AuthorizationData,
	authenticated bool, _ *principal.Principal) error {
	m.types = append(m.types, data[0].ADType)
	m.authenticated = append(m.authenticated, authenticated)
	return nil
}
func (*recordingModule) ExportAuthData(uint32) (protocol.AuthorizationData, error) {
	return nil, nil
}
func (*recordingModule) AttributeTypes() []string { return nil }
func (*recordingModule) GetAttribute(string) ([]byte, []byte, bool, bool, error) {
	return nil, nil, false, false, ErrAttributeNotFound
}

func TestImportUsageTracksVerifiedContainers(t *testing.T) {
	key := protocol.EncryptionKey{KeyType: crypto.EnctypeAES128SHA1, KeyValue: []byte("0123456789abcdef")}
	issued := mustKDCIssued(t, key, protocol.AuthorizationData{{
		ADType: GreetAuthDataType, ADData: []byte("issued"),
	}})
	data := protocol.AuthorizationData{{ADType: protocol.ADIfRelevant,
		ADData: mustAuthData(t, protocol.AuthorizationData{{ADType: protocol.ADKDCIssued, ADData: issued}})}}

	kdcModule := &recordingModule{flags: ADUsageKDCIssued}
	if err := NewContext(kdcModule).Import(data, ADUsageAPReq, nil, key); err != nil {
		t.Fatal(err)
	}
	if len(kdcModule.types) != 1 || !kdcModule.authenticated[0] {
		t.Fatalf("KDC-issued dispatch = %#v authenticated=%v", kdcModule.types, kdcModule.authenticated)
	}

	plainModule := &recordingModule{flags: ADUsageAPReq}
	if err := NewContext(plainModule).Import(data, ADUsageAPReq, nil, key); err != nil {
		t.Fatal(err)
	}
	if len(plainModule.types) != 1 {
		t.Fatalf("plain dispatch count = %d, want 1", len(plainModule.types))
	}
}

func TestImportCAMMACMixedIFRelevantSiblings(t *testing.T) {
	key := protocol.EncryptionKey{KeyType: crypto.EnctypeAES128SHA1, KeyValue: []byte("0123456789abcdef")}
	ticket := protocol.EncTicketPart{Key: key}
	cammacData, err := cammac.Marshal(protocol.AuthorizationData{{
		ADType: 100, ADData: []byte("protected"),
	}}, ticket, key, key, 1)
	if err != nil {
		t.Fatal(err)
	}
	var inner protocol.AuthorizationData
	if err := asn1.Unmarshal(cammacData[0].ADData, &inner); err != nil {
		t.Fatal(err)
	}
	inner = append(inner, protocol.AuthorizationDataEntry{ADType: 101, ADData: []byte("plain")})
	data := protocol.AuthorizationData{{ADType: protocol.ADIfRelevant,
		ADData: mustAuthData(t, inner)}}

	protectedModule := &recordingModule{flags: ADCAMMACProtected}
	if err := NewContext(protectedModule).Import(data, ADUsageAPReq, &ticket, key); err != nil {
		t.Fatal(err)
	}
	if len(protectedModule.types) != 1 || protectedModule.types[0] != 100 ||
		!protectedModule.authenticated[0] {
		t.Fatalf("protected dispatch = %#v authenticated=%v",
			protectedModule.types, protectedModule.authenticated)
	}

	plainModule := &recordingModule{flags: ADUsageAPReq}
	if err := NewContext(plainModule).Import(data, ADUsageAPReq, &ticket, key); err != nil {
		t.Fatal(err)
	}
	if len(plainModule.types) != 2 {
		t.Fatalf("mixed dispatch count = %d, want 2", len(plainModule.types))
	}
	if !plainModule.authenticated[0] || plainModule.authenticated[1] {
		t.Fatalf("mixed authentication = %v, want [true false]", plainModule.authenticated)
	}
}

func TestKDCIssuedUsesDeclaredChecksumType(t *testing.T) {
	key := protocol.EncryptionKey{KeyType: crypto.EnctypeAES128SHA1, KeyValue: []byte("0123456789abcdef")}
	issued := mustKDCIssued(t, key, protocol.AuthorizationData{{
		ADType: GreetAuthDataType, ADData: []byte("issued"),
	}})
	var value protocol.KDCIssued
	if err := asn1.Unmarshal(issued, &value); err != nil {
		t.Fatal(err)
	}
	value.Checksum.ChecksumType = crypto.ChecksumHMACSHA196AES256
	data := protocol.AuthorizationData{{ADType: protocol.ADKDCIssued,
		ADData: mustMarshal(t, value)}}
	if err := NewContext(&recordingModule{flags: ADUsageAPReq}).Import(
		data, ADUsageAPReq, nil, key); err == nil {
		t.Fatal("accepted KDC-issued checksum with mismatched declared type")
	}
}

func TestAttributeErrorsAreNotSwallowed(t *testing.T) {
	want := errors.New("module failure")
	module := &errorAttributeModule{err: want}
	_, _, _, _, err := NewContext(module).GetAttribute("failure")
	if !errors.Is(err, want) {
		t.Fatalf("GetAttribute error = %v, want %v", err, want)
	}
	if err := NewContext(module).SetAttribute("failure", nil, false); !errors.Is(err, want) {
		t.Fatalf("SetAttribute error = %v, want %v", err, want)
	}
	if err := NewContext(module).DeleteAttribute("failure"); !errors.Is(err, want) {
		t.Fatalf("DeleteAttribute error = %v, want %v", err, want)
	}
}

type errorAttributeModule struct{ err error }

func (*errorAttributeModule) Name() string       { return "errors" }
func (*errorAttributeModule) Flags(int32) uint32 { return 0 }
func (*errorAttributeModule) ImportAuthData(protocol.AuthorizationData, bool, *principal.Principal) error {
	return nil
}
func (*errorAttributeModule) ExportAuthData(uint32) (protocol.AuthorizationData, error) {
	return nil, nil
}
func (*errorAttributeModule) AttributeTypes() []string { return nil }
func (m *errorAttributeModule) GetAttribute(string) ([]byte, []byte, bool, bool, error) {
	return nil, nil, false, false, m.err
}
func (m *errorAttributeModule) SetAttribute(string, []byte, bool) error { return m.err }
func (m *errorAttributeModule) DeleteAttribute(string) error            { return m.err }

func mustAuthData(t *testing.T, data protocol.AuthorizationData) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustKDCIssued(t *testing.T, key protocol.EncryptionKey,
	elements protocol.AuthorizationData) []byte {
	t.Helper()
	encoded := mustAuthData(t, elements)
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := etype.Checksum(key.KeyValue, 19, encoded)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := asn1.Marshal(protocol.KDCIssued{
		Checksum: protocol.Checksum{
			ChecksumType: crypto.ChecksumHMACSHA196AES128,
			Checksum:     checksum,
		},
		Elements: elements,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

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
