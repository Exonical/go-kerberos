package protocol

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestChangePasswdDataGolden(t *testing.T) {
	realm := "TEST.REALM"
	encoded, err := asn1.Marshal(ChangePasswdData{
		NewPassword: []byte("newpass"),
		TargetName:  &PrincipalName{NameType: 1, NameString: []string{"alice"}},
		TargetRealm: &realm,
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("302da00904076e657770617373a1123010a003020101a10930071b05616c696365a20c1b0a544553542e5245414c4d")
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(want) {
		t.Fatalf("ChangePasswdData DER = %x, want %x", encoded, want)
	}
	var decoded ChangePasswdData
	if err := asn1.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.NewPassword) != "newpass" || decoded.TargetName == nil ||
		decoded.TargetRealm == nil || *decoded.TargetRealm != realm {
		t.Fatalf("decoded ChangePasswdData = %#v", decoded)
	}
}

func TestFASTStructuresRoundTrip(t *testing.T) {
	value := KrbFastReq{
		FastOptions: 0,
		PAData:      MethodData{{PADataType: 2, PADataValue: []byte("timestamp")}},
		ReqBody: KDCReqBody{
			Realm: "TEST.REALM",
			Till:  types.KerberosTime{Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Present: true},
			Nonce: 7,
			EType: []int32{18},
		},
	}
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded KrbFastReq
	if err := asn1.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReqBody.Realm != value.ReqBody.Realm || decoded.ReqBody.Nonce != value.ReqBody.Nonce ||
		len(decoded.PAData) != 1 || decoded.PAData[0].PADataType != 2 {
		t.Fatalf("FAST round trip mismatch: %#v", decoded)
	}
}

func TestFASTChoicesUseExplicitContextTags(t *testing.T) {
	request, err := asn1.Marshal(PAFXFastRequest{ArmoredData: KrbFastArmoredReq{
		ReqChecksum: Checksum{ChecksumType: 16, Checksum: []byte{1}},
		EncFastReq:  EncryptedData{EType: 18, Cipher: []byte{2}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(request) == 0 || request[0] != 0xa0 {
		t.Fatalf("FAST request choice tag = 0x%x, want 0xa0", request[0])
	}
	var decodedRequest PAFXFastRequest
	if err := asn1.Unmarshal(request, &decodedRequest); err != nil {
		t.Fatal(err)
	}

	reply, err := asn1.Marshal(PAFXFastReply{ArmoredData: KrbFastArmoredRep{
		EncFastRep: EncryptedData{EType: 18, Cipher: []byte{3}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) == 0 || reply[0] != 0xa0 {
		t.Fatalf("FAST reply choice tag = 0x%x, want 0xa0", reply[0])
	}
	var decodedReply PAFXFastReply
	if err := asn1.Unmarshal(reply, &decodedReply); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationTagNumbers(t *testing.T) {
	tests := map[string]int{
		"Ticket":        TagTicket,
		"Authenticator": TagAuthenticator,
		"EncTicketPart": TagEncTicketPart,
		"AS-REQ":        TagASReq,
		"TGS-REQ":       TagTGSReq,
		"AS-REP":        TagASRep,
		"TGS-REP":       TagTGSRep,
		"AP-REQ":        TagAPReq,
		"AP-REP":        TagAPRep,
		"EncASRepPart":  TagEncASRepPart,
		"EncTGSRepPart": TagEncTGSRepPart,
		"EncAPRepPart":  TagEncAPRepPart,
		"KRB-ERROR":     TagKRBError,
	}
	want := map[string]int{
		"Ticket": 1, "Authenticator": 2, "EncTicketPart": 3,
		"AS-REQ": 10, "TGS-REQ": 12, "AS-REP": 11, "TGS-REP": 13,
		"AP-REQ": 14, "AP-REP": 15, "EncASRepPart": 25, "EncTGSRepPart": 26,
		"EncAPRepPart": 27, "KRB-ERROR": 30,
	}
	for name, got := range tests {
		if got != want[name] {
			t.Errorf("%s tag = %d, want %d", name, got, want[name])
		}
	}
}

func TestProtocolStructuresHaveEncodingContract(t *testing.T) {
	values := []any{
		PrincipalName{}, HostAddress{}, HostAddresses{}, AuthorizationData{},
		PAData{}, EncryptedData{}, EncryptionKey{}, ChangePasswdData{}, Checksum{}, Ticket{},
		EncTicketPart{}, Authenticator{}, KDCReq{}, KDCReqBody{}, ASReq{},
		TGSReq{}, KDCRep{}, ASRep{}, TGSRep{}, EncASRepPart{}, EncTGSRepPart{},
		APReq{}, APRep{}, EncAPRepPart{}, KRBError{}, MethodData{}, ETypeInfo{},
		ETypeInfo2{}, ETypeInfo2Entry{}, LastReq{}, TransitedEncoding{},
		KrbFastArmor{}, KrbFastArmoredReq{}, PAFXFastRequest{}, KrbFastReq{},
		KrbFastArmoredRep{}, PAFXFastReply{}, KrbFastResponse{}, KrbFastFinished{},
	}
	for _, value := range values {
		if _, err := asn1.Marshal(value); err != nil {
			t.Fatalf("encoding contract for %T: %v", value, err)
		}
	}
}
