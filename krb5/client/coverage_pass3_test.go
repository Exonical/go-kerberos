package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestClientExchangeValidationPaths(t *testing.T) {
	name := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	service := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"host", "server"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := (&Client{}).ASExchangeFAST(ctx, name, "password", &Credentials{}); err == nil {
		t.Fatal("canceled FAST AS exchange accepted")
	}
	if _, err := (&Client{}).ASExchangeFAST(context.Background(), principal.Principal{}, "password", &Credentials{}); err == nil {
		t.Fatal("invalid FAST principal accepted")
	}
	if _, err := (&Client{}).ASExchangeFASTOTP(context.Background(), name, &Credentials{}, nil); err == nil {
		t.Fatal("nil OTP provider accepted")
	}
	if _, err := (&Client{}).TGSExchange(context.Background(), nil, service); err == nil {
		t.Fatal("nil TGT accepted")
	}
	if _, err := (&Client{}).TGSExchangeU2U(context.Background(), nil, []byte{1}, service); err == nil {
		t.Fatal("nil U2U TGT accepted")
	}
	if _, err := (&Client{}).TGSExchangeForwarded(context.Background(), nil); err == nil {
		t.Fatal("nil forwarded TGT accepted")
	}
	if _, err := (&Client{}).TGSExchangeFAST(context.Background(), nil, service); err == nil {
		t.Fatal("nil FAST TGT accepted")
	}
	if _, _, err := (&Client{}).DecodeTGSResponseForExchange(nil, nil, service, service, true, 1, time.Now()); err == nil {
		t.Fatal("nil TGT response accepted")
	}
	if _, err := (&Client{}).exchangeRawPayload(context.Background(), "EXAMPLE.COM", []byte{1}, "test"); err == nil {
		t.Fatal("unconfigured KDC accepted")
	}
	if _, err := (&Client{Config: &config.Config{Realms: map[string][]string{"EXAMPLE.COM": {"bad host"}}}}).exchangeRawPayload(context.Background(), "EXAMPLE.COM", []byte{1}, "test"); err == nil {
		t.Fatal("invalid KDC address accepted")
	}
	if _, err := (&Client{Exchange: func(context.Context, string, []byte) ([]byte, error) {
		return nil, errors.New("transport")
	}}).exchangeRawPayload(context.Background(), "EXAMPLE.COM", []byte{1}, "test"); err == nil {
		t.Fatal("exchange transport failure suppressed")
	}
}

func TestClientFASTAndForwardedBuilderValidation(t *testing.T) {
	c := &Client{Config: &config.Config{DefaultTKTEnctypes: []int32{crypto.EnctypeAES256SHA1}}}
	name := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	if _, err := c.ASExchangeService(nil, name, "password", principal.Principal{}); err == nil {
		t.Fatal("nil context AS service exchange accepted")
	}
	if _, err := c.ASExchangeService(context.Background(), principal.Principal{}, "password", principal.Principal{Components: []string{"host", "x"}}); err == nil {
		t.Fatal("invalid client principal accepted")
	}
	if _, err := c.DecodeASResponse([]byte{1}, name, 1, crypto.EnctypeAES256SHA1, make([]byte, 32), time.Now()); err == nil {
		t.Fatal("malformed AS response accepted")
	}
	tgt := &Credentials{
		Client: name,
		Server: principal.Principal{Realm: name.Realm, Components: []string{"krbtgt", name.Realm}},
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: make([]byte, 32)},
		Ticket: mustMarshal(t, protocol.Ticket{
			TktVNO: 5, Realm: name.Realm,
			SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", name.Realm}},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}},
		}),
	}
	request, nonce, armor, replyKey, err := c.newTGSReqFAST(tgt,
		principal.Principal{Realm: name.Realm, Components: []string{"host", "server"}},
		name.Realm, time.Unix(100, 0).UTC(), false)
	if err != nil || nonce == 0 || armor == nil || len(replyKey.KeyValue) != 32 ||
		len(request.PAData) < 2 {
		t.Fatalf("FAST TGS request = %#v/%d/%#v/%v", request, nonce, replyKey, err)
	}
}
