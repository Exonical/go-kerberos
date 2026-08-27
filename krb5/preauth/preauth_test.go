package preauth

import (
	"bytes"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestSelectETypeInfo2AndBuildEncryptedTimestamp(t *testing.T) {
	name := principal.Principal{Realm: "REALM", Components: []string{"alice"}}
	info, err := asn1.Marshal(protocol.ETypeInfo2{
		{EType: 999},
		{EType: crypto.EnctypeAES256SHA1, S2KParams: []byte{0, 0, 0x10, 0}},
	})
	if err != nil {
		t.Fatal(err)
	}
	methodData, err := asn1.Marshal(protocol.MethodData{
		{PADataType: 19, PADataValue: info},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseMethodData(methodData)
	if err != nil {
		t.Fatalf("ParseMethodData: %v", err)
	}
	etype, salt, params, err := SelectEType(parsed, "REALM", name, crypto.NewRegistry())
	if err != nil {
		t.Fatalf("SelectEType: %v", err)
	}
	if etype != crypto.EnctypeAES256SHA1 || string(salt) != "REALMalice" ||
		!bytes.Equal(params, []byte{0, 0, 0x10, 0}) {
		t.Fatalf("selection = %d, %q, %x", etype, salt, params)
	}
	profile, err := crypto.NewRegistry().Get(etype)
	if err != nil {
		t.Fatal(err)
	}
	key, err := profile.StringToKey([]byte("password"), []byte("REALMalice"), params)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	padata, err := BuildEncryptedTimestamp(profile, key, now, 123456)
	if err != nil {
		t.Fatalf("BuildEncryptedTimestamp: %v", err)
	}
	if padata.PADataType != 2 {
		t.Fatalf("padata type = %d", padata.PADataType)
	}
	plaintext, err := profile.Decrypt(key, 1, padata.PADataValue)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	var timestamp EncTimestamp
	if err := asn1.Unmarshal(plaintext, &timestamp); err != nil {
		t.Fatalf("Unmarshal EncTimestamp: %v", err)
	}
	if !timestamp.PATimestamp.Present || !timestamp.PATimestamp.Time.Equal(now) ||
		timestamp.PAUSec == nil || *timestamp.PAUSec != 123456 {
		t.Fatalf("timestamp = %#v", timestamp)
	}
}

func TestSelectETypeInfoFallsBackToDefaultSalt(t *testing.T) {
	etype, salt, params, err := SelectEType(protocol.MethodData{{PADataType: 11, PADataValue: mustMarshal(t, protocol.ETypeInfo{
		{EType: crypto.EnctypeAES128SHA1},
	})}}, "REALM", principal.Principal{Components: []string{"a", "b"}}, crypto.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if etype != crypto.EnctypeAES128SHA1 || string(salt) != "REALMab" || len(params) != 0 {
		t.Fatalf("selection = %d, %q, %x", etype, salt, params)
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var _ = types.KerberosTime{}
