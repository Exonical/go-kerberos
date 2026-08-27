package asn1

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestPrimitiveGoldenDER(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  []byte
	}{
		// RFC 4120 PrincipalName: SEQUENCE, [0] INTEGER 1, [1] sequence of
		// GeneralString("alice"). Each tag and length is included explicitly.
		{"PrincipalName", protocol.PrincipalName{NameType: 1, NameString: []string{"alice"}}, []byte{
			0x30, 0x10, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x09, 0x30, 0x07,
			0x1b, 0x05, 0x61, 0x6c, 0x69, 0x63, 0x65,
		}},
		// RFC 4120 EncryptedData with etype 17 and a two-octet cipher.
		// The optional kvno [1] field is absent.
		{"EncryptedData", protocol.EncryptedData{EType: 17, Cipher: []byte{1, 2}}, []byte{
			0x30, 0x0b, 0xa0, 0x03, 0x02, 0x01, 0x11, 0xa2, 0x04, 0x04, 0x02, 0x01, 0x02,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Marshal(tt.value)
			if err != nil {
				t.Fatalf("Marshal(%s): %v", tt.name, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Marshal(%s) = %x, want %x", tt.name, got, tt.want)
			}
		})
	}
}

func TestPrimitiveRoundTrip(t *testing.T) {
	value := protocol.PrincipalName{NameType: 1, NameString: []string{"alice"}}
	encoded, err := Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded protocol.PrincipalName
	if err := Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(decoded, value) {
		t.Fatalf("round trip = %#v, want %#v", decoded, value)
	}
}

func TestFieldTGSReqBody(t *testing.T) {
	body := protocol.KDCReqBody{
		KDCOptions: types.KDCOptions(0),
		CName:      &protocol.PrincipalName{NameType: 1, NameString: []string{"alice"}},
		Realm:      "EXAMPLE.COM",
		SName:      &protocol.PrincipalName{NameType: 2, NameString: []string{"krbtgt", "EXAMPLE.COM"}},
		Nonce:      1,
		EType:      []int32{18},
	}
	bodyDER, err := Marshal(body)
	if err != nil {
		t.Fatalf("Marshal body: %v", err)
	}
	requestDER, err := Marshal(protocol.TGSReq{
		PVNO:    5,
		MsgType: 12,
		ReqBody: body,
	})
	if err != nil {
		t.Fatalf("Marshal TGS-REQ: %v", err)
	}
	raw, err := Field(requestDER, 12, 4)
	if err != nil {
		t.Fatalf("Field: %v", err)
	}
	content, err := FieldContent(requestDER, 12, 4)
	if err != nil {
		t.Fatalf("FieldContent: %v", err)
	}
	if !bytes.Equal(content, bodyDER) {
		t.Fatalf("body content = %x, want %x", content, bodyDER)
	}
	if !bytes.HasSuffix(raw, bodyDER) {
		t.Fatalf("raw body field = %x, want field containing %x", raw, bodyDER)
	}
}

func TestMalformedDERReturnsError(t *testing.T) {
	for _, input := range [][]byte{
		{},
		{0x30},
		{0x31, 0x00},
		{0x30, 0x82, 0xff, 0xff, 0x00},
		{0x30, 0x03, 0xa0, 0x01},
	} {
		var value protocol.PrincipalName
		if err := Unmarshal(input, &value); err == nil {
			t.Fatalf("Unmarshal(%x) accepted malformed DER", input)
		}
	}
}

func TestFullMessageFixtures(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(source), "..", "..", "testdata", "packets")
	tests := []struct {
		name string
		dst  any
	}{
		{"PrincipalName", new(protocol.PrincipalName)},
		{"HostAddress", new(protocol.HostAddress)},
		{"HostAddresses", new(protocol.HostAddresses)},
		{"AuthorizationData", new(protocol.AuthorizationData)},
		{"PA-DATA", new(protocol.PAData)},
		{"EncryptedData", new(protocol.EncryptedData)},
		{"EncryptionKey", new(protocol.EncryptionKey)},
		{"Checksum", new(protocol.Checksum)},
		{"EncTicketPart", new(protocol.EncTicketPart)},
		{"Authenticator", new(protocol.Authenticator)},
		{"KDC-REQ", new(protocol.KDCReq)},
		{"KDC-REQ-BODY", new(protocol.KDCReqBody)},
		{"AS-REQ", new(protocol.ASReq)},
		{"TGS-REQ", new(protocol.TGSReq)},
		{"KDC-REP", new(protocol.KDCRep)},
		{"AS-REP", new(protocol.ASRep)},
		{"TGS-REP", new(protocol.TGSRep)},
		{"EncASRepPart", new(protocol.EncASRepPart)},
		{"EncTGSRepPart", new(protocol.EncTGSRepPart)},
		{"Ticket", new(protocol.Ticket)},
		{"AP-REQ", new(protocol.APReq)},
		{"AP-REP", new(protocol.APRep)},
		{"EncAPRepPart", new(protocol.EncAPRepPart)},
		{"KRB-ERROR", new(protocol.KRBError)},
		{"METHOD-DATA", new(protocol.MethodData)},
		{"ETYPE-INFO", new(protocol.ETypeInfo)},
		{"ETYPE-INFO2", new(protocol.ETypeInfo2)},
		{"ETYPE-INFO2-ENTRY", new(protocol.ETypeInfo2Entry)},
		{"LastReq", new(protocol.LastReq)},
		{"TransitedEncoding", new(protocol.TransitedEncoding)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, tt.name+".der"))
			if os.IsNotExist(err) {
				t.Skipf("fixture not yet generated: %s", filepath.Join("testdata", "packets", tt.name+".der"))
			}
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := Unmarshal(data, tt.dst); err != nil {
				t.Fatalf("decode %s fixture: %v", tt.name, err)
			}
		})
	}
}
