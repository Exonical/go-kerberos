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

func TestRawDERAlgorithmIdentifierParameters(t *testing.T) {
	tests := []struct {
		name   string
		value  protocol.AlgorithmIdentifier
		expect []byte
	}{
		{
			name: "NULL",
			value: protocol.AlgorithmIdentifier{
				Algorithm:  types.ObjectIdentifier{0x2a, 0x03},
				Parameters: rawDERPtr([]byte{0x05, 0x00}),
			},
			expect: []byte{0x30, 0x06, 0x06, 0x02, 0x2a, 0x03, 0x05, 0x00},
		},
		{
			name: "SEQUENCE",
			value: protocol.AlgorithmIdentifier{
				Algorithm:  types.ObjectIdentifier{0x2a, 0x03},
				Parameters: rawDERPtr([]byte{0x30, 0x00}),
			},
			expect: []byte{0x30, 0x06, 0x06, 0x02, 0x2a, 0x03, 0x30, 0x00},
		},
		{
			name: "absent",
			value: protocol.AlgorithmIdentifier{
				Algorithm: types.ObjectIdentifier{0x2a, 0x03},
			},
			expect: []byte{0x30, 0x04, 0x06, 0x02, 0x2a, 0x03},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, test.expect) {
				t.Fatalf("encoded = %x, want %x", encoded, test.expect)
			}
			var decoded protocol.AlgorithmIdentifier
			if err := Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			roundTrip, err := Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(roundTrip, encoded) {
				t.Fatalf("round trip = %x, want %x", roundTrip, encoded)
			}
			if (test.value.Parameters == nil) != (decoded.Parameters == nil) {
				t.Fatalf("parameters presence = %v, want %v",
					decoded.Parameters != nil, test.value.Parameters != nil)
			}
			if decoded.Parameters != nil &&
				!bytes.Equal(*decoded.Parameters, *test.value.Parameters) {
				t.Fatalf("parameters = %x, want %x",
					*decoded.Parameters, *test.value.Parameters)
			}
		})
	}
}

func TestRawDEROTPTokenInfoAlgorithmParameters(t *testing.T) {
	value := protocol.OTPTokenInfo{
		Flags: types.OTPFlags(0),
		SupportedHashAlg: []protocol.AlgorithmIdentifier{{
			Algorithm:  types.ObjectIdentifier{0x2a, 0x03},
			Parameters: rawDERPtr([]byte{0x05, 0x00}),
		}},
	}
	encoded, err := Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded protocol.OTPTokenInfo
	if err := Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	roundTrip, err := Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTrip, encoded) {
		t.Fatalf("round trip = %x, want %x", roundTrip, encoded)
	}
	if len(decoded.SupportedHashAlg) != 1 ||
		decoded.SupportedHashAlg[0].Parameters == nil ||
		!bytes.Equal(*decoded.SupportedHashAlg[0].Parameters, []byte{0x05, 0x00}) {
		t.Fatalf("decoded supported hash algorithm = %#v", decoded.SupportedHashAlg)
	}
}

func TestOptionalRawDERDoesNotConsumeFollowingContextField(t *testing.T) {
	type value struct {
		Parameters *types.RawDER `krb5:"tag:1,optional,bare"`
		Count      int32         `krb5:"tag:2"`
	}
	input := []byte{0x30, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x07}
	var decoded value
	if err := Unmarshal(input, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Parameters != nil || decoded.Count != 7 {
		t.Fatalf("decoded value = %#v", decoded)
	}
}

func TestOptionalRawDERContextSpecificValue(t *testing.T) {
	type value struct {
		A *types.RawDER `krb5:"tag:0,optional,bare"`
		B *int32        `krb5:"tag:1,optional"`
	}
	b := int32(7)
	tests := []struct {
		name  string
		input []byte
		check func(t *testing.T, decoded value)
	}{
		{
			name:  "A absent B present",
			input: []byte{0x30, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x07},
			check: func(t *testing.T, decoded value) {
				if decoded.A != nil || decoded.B == nil || *decoded.B != b {
					t.Fatalf("decoded value = %#v", decoded)
				}
			},
		},
		{
			name:  "A context-specific B present",
			input: []byte{0x30, 0x08, 0xa5, 0x01, 0x00, 0xa1, 0x03, 0x02, 0x01, 0x07},
			check: func(t *testing.T, decoded value) {
				if decoded.A == nil || !bytes.Equal(*decoded.A, []byte{0xa5, 0x01, 0x00}) ||
					decoded.B == nil || *decoded.B != b {
					t.Fatalf("decoded value = %#v", decoded)
				}
			},
		},
		{
			name:  "A NULL B absent",
			input: []byte{0x30, 0x02, 0x05, 0x00},
			check: func(t *testing.T, decoded value) {
				if decoded.A == nil || !bytes.Equal(*decoded.A, []byte{0x05, 0x00}) ||
					decoded.B != nil {
					t.Fatalf("decoded value = %#v", decoded)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded value
			if err := Unmarshal(test.input, &decoded); err != nil {
				t.Fatal(err)
			}
			test.check(t, decoded)
			encoded, err := Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, test.input) {
				t.Fatalf("round trip = %x, want %x", encoded, test.input)
			}
		})
	}
}

func TestOptionalRawDERBeforeImplicitConstructedField(t *testing.T) {
	type sequence struct {
		Value int32 `krb5:"tag:0"`
	}
	type value struct {
		A *types.RawDER `krb5:"tag:0,optional,bare"`
		B *sequence     `krb5:"tag:1,optional,implicit"`
	}
	tests := []struct {
		name  string
		input []byte
		check func(t *testing.T, decoded value)
	}{
		{
			name: "A absent B present",
			// B is an implicitly tagged constructed SEQUENCE.
			input: []byte{0x30, 0x07, 0xa1, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x07},
			check: func(t *testing.T, decoded value) {
				if decoded.A != nil || decoded.B == nil || decoded.B.Value != 7 {
					t.Fatalf("decoded value = %#v", decoded)
				}
			},
		},
		{
			name:  "A present B present",
			input: []byte{0x30, 0x0a, 0xa5, 0x01, 0x00, 0xa1, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x07},
			check: func(t *testing.T, decoded value) {
				if decoded.A == nil || !bytes.Equal(*decoded.A, []byte{0xa5, 0x01, 0x00}) ||
					decoded.B == nil || decoded.B.Value != 7 {
					t.Fatalf("decoded value = %#v", decoded)
				}
			},
		},
		{
			name:  "A NULL B absent",
			input: []byte{0x30, 0x02, 0x05, 0x00},
			check: func(t *testing.T, decoded value) {
				if decoded.A == nil || !bytes.Equal(*decoded.A, []byte{0x05, 0x00}) ||
					decoded.B != nil {
					t.Fatalf("decoded value = %#v", decoded)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded value
			if err := Unmarshal(test.input, &decoded); err != nil {
				t.Fatal(err)
			}
			test.check(t, decoded)
			encoded, err := Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, test.input) {
				t.Fatalf("round trip = %x, want %x", encoded, test.input)
			}
		})
	}
}

func TestObjectIdentifierDERValidation(t *testing.T) {
	valid := []types.ObjectIdentifier{
		{0x2a, 0x03},
		{0x2a, 0x81, 0x00},
	}
	for _, value := range valid {
		encoded, err := Marshal(value)
		if err != nil {
			t.Fatalf("Marshal(%x): %v", value, err)
		}
		var decoded types.ObjectIdentifier
		if err := Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("Unmarshal(%x): %v", encoded, err)
		}
		if !bytes.Equal(decoded, value) {
			t.Fatalf("decoded OID = %x, want %x", decoded, value)
		}
	}
	for _, content := range [][]byte{
		{0x2a, 0x80, 0x01},
		{0x2a, 0x80, 0x00},
		{0x2a, 0x81},
	} {
		if _, err := Marshal(types.ObjectIdentifier(content)); err == nil {
			t.Fatalf("Marshal accepted malformed OID content %x", content)
		}
		input := append([]byte{0x06, byte(len(content))}, content...)
		var decoded types.ObjectIdentifier
		if err := Unmarshal(input, &decoded); err == nil {
			t.Fatalf("Unmarshal accepted malformed OID %x", input)
		}
	}
}

func rawDERPtr(value []byte) *types.RawDER {
	raw := types.RawDER(value)
	return &raw
}

func TestChangePasswdDataGoldenDER(t *testing.T) {
	realm := "TEST.REALM"
	value := protocol.ChangePasswdData{
		NewPassword: []byte("new-password"),
		TargetName:  &protocol.PrincipalName{NameType: 1, NameString: []string{"alice"}},
		TargetRealm: &realm,
	}
	got, err := Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x30, 0x32,
		0xa0, 0x0e, 0x04, 0x0c, 0x6e, 0x65, 0x77, 0x2d, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
		0xa1, 0x12, 0x30, 0x10, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x09, 0x30, 0x07, 0x1b, 0x05, 0x61, 0x6c, 0x69, 0x63, 0x65,
		0xa2, 0x0c, 0x1b, 0x0a, 0x54, 0x45, 0x53, 0x54, 0x2e, 0x52, 0x45, 0x41, 0x4c, 0x4d,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ChangePasswdData = %x, want %x", got, want)
	}
	var decoded protocol.ChangePasswdData
	if err := Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.NewPassword, value.NewPassword) ||
		decoded.TargetName == nil || decoded.TargetRealm == nil ||
		*decoded.TargetRealm != realm {
		t.Fatalf("decoded ChangePasswdData = %#v", decoded)
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
