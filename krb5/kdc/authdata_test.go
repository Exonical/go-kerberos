package kdc

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/authdata"
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
	module := GreetAuthDataModule{}
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
	ctx := authdata.NewContext(&authdata.GreetModule{})
	if err := ctx.Import(reply.AuthorizationData, authdata.ADUsageAPReq,
		reply, reply.Key); err != nil {
		t.Fatal(err)
	}
	value, _, authenticated, _, err := ctx.GetAttribute(authdata.GreetAttribute)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "Hello, KDC issued acceptor world!" || !authenticated {
		t.Fatalf("unexpected greeting value=%q authenticated=%v", value, authenticated)
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

func (m authDataTestModule) Name() string { return "test" }
func (m authDataTestModule) Handle(*AuthDataRequest) error {
	*m.called = true
	return nil
}
