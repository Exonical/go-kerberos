package kdc

import (
	"fmt"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestGreetAuthDataModuleWrapsTGSData(t *testing.T) {
	reply := &protocol.EncTicketPart{
		Key: protocol.EncryptionKey{KeyType: 17, KeyValue: []byte("0123456789abcdef")},
	}
	server := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"host", "server"}}
	module := greetAuthDataModule{}
	req := &AuthDataRequest{
		Flags:     AuthDataTGSReq,
		Server:    server,
		ServerKey: &kdb.Key{},
		Reply:     reply,
	}
	module.Handle(req)
	if len(reply.AuthorizationData) != 1 ||
		reply.AuthorizationData[0].ADType != protocol.ADIfRelevant {
		t.Fatalf("unexpected authorization data: %#v", reply.AuthorizationData)
	}
	if len(reply.AuthorizationData[0].ADData) == 0 {
		t.Fatal("greeting authorization data is empty")
	}
}

func TestAuthDataModulesSkipAnonymousTickets(t *testing.T) {
	reply := &protocol.EncTicketPart{Flags: types.TicketAnonymous}
	called := false
	module := authDataTestModule{called: &called}
	server := &Server{AuthDataModules: []AuthDataModule{module}}
	server.handleAuthData(&AuthDataRequest{Reply: reply})
	if called {
		t.Fatal("anonymous ticket invoked authdata module")
	}
}

type authDataTestModule struct {
	called *bool
}

type greetAuthDataModule struct{}

func (greetAuthDataModule) Name() string { return "greet" }

func (greetAuthDataModule) Handle(req *AuthDataRequest) error {
	if req == nil || req.Reply == nil || req.Flags&AuthDataTGSReq == 0 {
		return nil
	}
	if len(req.Reply.Key.KeyValue) == 0 {
		return fmt.Errorf("greet: missing ticket session key")
	}
	elements := protocol.AuthorizationData{{
		ADType: -42,
		ADData: []byte("Hello, KDC issued acceptor world!"),
	}}
	encoded, err := asn1.Marshal(elements)
	if err != nil {
		return err
	}
	etype, err := crypto.NewRegistry().Get(req.Reply.Key.KeyType)
	if err != nil {
		return err
	}
	checksum, err := etype.Checksum(req.Reply.Key.KeyValue, 19, encoded)
	if err != nil {
		return err
	}
	checksumType := crypto.ChecksumHMACSHA196AES128
	issuer := protocol.PrincipalName{
		NameType:   int32(req.Server.NameType),
		NameString: append([]string(nil), req.Server.Components...),
	}
	realm := req.Server.Realm
	issued, err := asn1.Marshal(protocol.KDCIssued{
		Checksum: protocol.Checksum{ChecksumType: checksumType, Checksum: checksum},
		IRealm:   &realm,
		IName:    &issuer,
		Elements: elements,
	})
	if err != nil {
		return err
	}
	wrapped, err := asn1.Marshal(protocol.AuthorizationData{{
		ADType: protocol.ADKDCIssued,
		ADData: issued,
	}})
	if err != nil {
		return err
	}
	req.Reply.AuthorizationData = append(req.Reply.AuthorizationData,
		protocol.AuthorizationDataEntry{ADType: protocol.ADIfRelevant, ADData: wrapped})
	return nil
}

func TestHasMandatoryKDCAuthData(t *testing.T) {
	tests := []struct {
		name string
		data protocol.AuthorizationData
	}{
		{
			name: "top-level",
			data: protocol.AuthorizationData{{ADType: protocol.ADMandatoryForKDC}},
		},
		{
			name: "if-relevant",
			data: protocol.AuthorizationData{{ADType: protocol.ADIfRelevant, ADData: mustMarshalAuthData(
				t, protocol.AuthorizationData{{ADType: protocol.ADMandatoryForKDC}},
			)}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !hasMandatoryKDCAuthData(test.data) {
				t.Fatal("mandatory-for-kdc authorization data was not found")
			}
		})
	}
}

func TestDecryptTGSRequestAuthDataFailureIsReturned(t *testing.T) {
	_, err := decryptTGSRequestAuthData(protocol.TGSReq{
		ReqBody: protocol.KDCReqBody{
			EncAuthorizationData: &protocol.EncryptedData{
				EType:  crypto.EnctypeAES128SHA1,
				Cipher: []byte("malformed"),
			},
		},
	}, protocol.EncryptionKey{
		KeyType:  crypto.EnctypeAES128SHA1,
		KeyValue: []byte("0123456789abcdef"),
	}, nil)
	if err == nil {
		t.Fatal("malformed TGS request authorization data was accepted")
	}
}

func mustMarshalAuthData(t *testing.T, data protocol.AuthorizationData) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (m authDataTestModule) Name() string { return "test" }
func (m authDataTestModule) Handle(*AuthDataRequest) error {
	*m.called = true
	return nil
}
