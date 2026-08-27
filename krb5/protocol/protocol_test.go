package protocol

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/asn1"
)

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
	}
	for _, value := range values {
		if _, err := asn1.Marshal(value); err != nil {
			t.Fatalf("encoding contract for %T: %v", value, err)
		}
	}
}
