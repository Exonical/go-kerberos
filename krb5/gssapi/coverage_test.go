package gssapi

import (
	"context"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestCredentialAPIValidation(t *testing.T) {
	name := principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}}
	if _, err := AcquireInitiatorCredentialWithPassword(context.Background(), nil, name, "password"); err == nil {
		t.Fatal("nil initiator client accepted")
	}
	if _, err := AcquireInitiatorCredentialWithPassword(context.Background(), &client.Client{}, principal.Principal{}, "password"); err == nil {
		t.Fatal("invalid initiator principal accepted")
	}
	if _, err := AcquireInitiatorCredential(context.Background(), &client.Client{}, name, ""); err == nil {
		t.Fatal("empty initiator password accepted")
	}
	if _, err := AcquireAcceptorCredential(nil, nil); err == nil {
		t.Fatal("nil acceptor keytab accepted")
	}
	if _, err := AcquireAcceptorCredential(&keytab.Keytab{}, nil); err == nil {
		t.Fatal("empty acceptor keytab accepted")
	}
	if _, err := AcquireAcceptorCredentialFromFile("", nil); err == nil {
		t.Fatal("empty keytab path accepted")
	}
	if _, err := AcquireAcceptorCredentialFromFile("/does/not/exist", nil); err == nil {
		t.Fatal("missing keytab path accepted")
	}
	if _, err := AcquireImpersonatedCredential(context.Background(), nil, name); err == nil {
		t.Fatal("nil impersonator accepted")
	}
	var empty Credential
	if _, err := empty.NewInitiatorForCredential(0); err == nil {
		t.Fatal("empty credential initiated")
	}
	if _, err := empty.NewInitiatorForService(context.Background(), name, 0); err == nil {
		t.Fatal("empty credential resolved a service")
	}
	if _, err := empty.InitSecContext(context.Background(), name, 0); err == nil {
		t.Fatal("empty credential initialized a context")
	}
	if _, err := empty.Initiator(0); err == nil {
		t.Fatal("empty credential returned an initiator")
	}
	if _, err := empty.NewInitiator(0); err == nil {
		t.Fatal("empty credential returned a new initiator")
	}
	if _, err := empty.NewAcceptorForCredential(); err == nil {
		t.Fatal("empty credential accepted")
	}
	if _, err := empty.Acceptor(); err == nil {
		t.Fatal("empty credential returned an acceptor")
	}
	if _, err := empty.NewAcceptor(); err == nil {
		t.Fatal("empty credential returned a new acceptor")
	}
	if _, err := empty.S4U2Proxy(context.Background(), name); err == nil {
		t.Fatal("empty credential performed S4U2Proxy")
	}
}
