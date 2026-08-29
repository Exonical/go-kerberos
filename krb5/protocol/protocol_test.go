package protocol

import (
	"bytes"
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

func TestKRBCredGolden(t *testing.T) {
	realm := "REALM"
	serverName := PrincipalName{NameType: 2, NameString: []string{"krbtgt", "REALM"}}
	encoded, err := asn1.Marshal(KRBCred{
		PVNO: 5, MsgType: 22,
		Tickets: []Ticket{{TktVNO: 5, Realm: realm, SName: serverName,
			EncPart: EncryptedData{EType: 0, Cipher: []byte{1, 2}}}},
		EncPart: EncryptedData{EType: 0, Cipher: []byte{5}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("765b3059a003020105a103020116a23f303d613b3039a003020105a1071b055245414c4da21a3018a003020102a111300f1b066b72627467741b055245414c4da30d300ba003020100a20404020102a30c300aa003020100a203040105")
	if !bytes.Equal(encoded, want) {
		t.Fatalf("KRB-CRED DER = %x, want %x", encoded, want)
	}
	var decoded KRBCred
	if err := asn1.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PVNO != 5 || decoded.MsgType != 22 || len(decoded.Tickets) != 1 ||
		decoded.Tickets[0].Realm != realm || len(decoded.Tickets[0].EncPart.Cipher) != 2 {
		t.Fatalf("decoded KRB-CRED = %#v", decoded)
	}
}

func TestEncKrbCredPartGolden(t *testing.T) {
	realm := "REALM"
	clientName := PrincipalName{NameType: 1, NameString: []string{"alice"}}
	serverName := PrincipalName{NameType: 2, NameString: []string{"krbtgt", "REALM"}}
	encoded, err := asn1.Marshal(EncKrbCredPart{TicketInfo: []KrbCredInfo{{
		Key:    EncryptionKey{KeyType: 18, KeyValue: []byte{3, 4}},
		Prealm: &realm, PName: &clientName, SRealm: &realm, SName: &serverName,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("7d593057a05530533051a00d300ba003020112a10404020304a1071b055245414c4da2123010a003020101a10930071b05616c696365a8071b055245414c4da91a3018a003020102a111300f1b066b72627467741b055245414c4d")
	if !bytes.Equal(encoded, want) {
		t.Fatalf("EncKrbCredPart DER = %x, want %x", encoded, want)
	}
	var decoded EncKrbCredPart
	if err := asn1.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.TicketInfo) != 1 || decoded.TicketInfo[0].PName == nil ||
		decoded.TicketInfo[0].PName.NameString[0] != "alice" {
		t.Fatalf("decoded EncKrbCredPart = %#v", decoded)
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
