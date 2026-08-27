package protocol

import (
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/types"
)

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
		PAData{}, EncryptedData{}, EncryptionKey{}, Checksum{}, Ticket{},
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
