package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestClientRequestBuildersAndOptions(t *testing.T) {
	name := principal.Principal{Realm: "EXAMPLE.COM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	client := &Client{Config: &config.Config{
		DefaultTKTEnctypes: []int32{999, 18},
		DefaultTGSEnctypes: []int32{999, 18},
		TicketLifetime:     2 * time.Hour, Forwardable: true,
		Canonicalize: true,
	}}
	asReq, err := client.BuildASRequest(name, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if asReq.MsgType != 10 || asReq.ReqBody.Nonce == 0 ||
		len(asReq.ReqBody.EType) != 1 || asReq.ReqBody.EType[0] != 18 ||
		asReq.ReqBody.KDCOptions == 0 {
		t.Fatalf("AS request = %#v", asReq)
	}
	tgt := &Credentials{Client: name, Server: principal.Principal{
		Realm: "EXAMPLE.COM", Components: []string{"krbtgt", "EXAMPLE.COM"}},
		Key: protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: make([]byte, 32)}}
	tgt.Ticket = mustMarshal(t, protocol.Ticket{TktVNO: 5, Realm: "EXAMPLE.COM",
		SName: protocol.PrincipalName{NameType: int32(principal.NTSrvInstance),
			NameString: []string{"krbtgt", "EXAMPLE.COM"}},
		EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}}})
	service := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"host", "server"}}
	tgsReq, nonce, err := client.BuildTGSRequest(tgt, service, time.Unix(100, 0).UTC())
	if err != nil || tgsReq.MsgType != 12 || nonce == 0 || len(tgsReq.PAData) == 0 {
		t.Fatalf("TGS request = %#v, nonce=%d, err=%v", tgsReq, nonce, err)
	}
	if _, _, err := client.BuildTGSRequest(nil, service, time.Now()); err == nil {
		t.Fatal("nil TGT accepted")
	}
	if _, _, err := client.BuildTGSRequestForRealm(nil, service, "EXAMPLE.COM", false, time.Now()); err == nil {
		t.Fatal("nil TGT accepted by realm builder")
	}
	if _, nonce, err := client.BuildTGSRequestForRealm(tgt, service, "EXAMPLE.COM", true, time.Unix(100, 0).UTC()); err != nil || nonce == 0 {
		t.Fatalf("realm TGS request = %d/%v", nonce, err)
	}
}

func TestClientExchangeRawAndHelpers(t *testing.T) {
	name := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	client := &Client{Exchange: func(ctx context.Context, realm string, payload []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if realm != "EXAMPLE.COM" || string(payload) != "request" {
			t.Fatalf("exchange arguments = %q/%q", realm, payload)
		}
		return []byte("reply"), nil
	}}
	reply, err := client.ExchangeRaw(context.Background(), "EXAMPLE.COM", []byte("request"))
	if err != nil || string(reply) != "reply" {
		t.Fatalf("ExchangeRaw = %q/%v", reply, err)
	}
	if _, err := client.ExchangeRaw(context.Background(), "EXAMPLE.COM", nil); err == nil {
		t.Fatal("empty raw exchange accepted")
	}
	if _, err := client.ExchangeRaw(context.Background(), "EXAMPLE.COM", []byte("request")); err != nil {
		t.Fatal(err)
	}
	if !isUnknownServiceError(&krberrors.KRBError{Code: krberrors.KDCErrSPrincipalUnknown}) {
		t.Fatal("unknown service helper returned false")
	}
	if isUnknownServiceError(errors.New("other")) || isKRBError(errors.New("other")) {
		t.Fatal("error helpers misclassified ordinary error")
	}
	if !isReferralPrincipal(protocol.PrincipalName{NameString: []string{"krbtgt", "OTHER"}},
		principal.Principal{Realm: "EXAMPLE.COM"}) {
		t.Fatal("referral principal not detected")
	}
	if (&Client{}).clockSkew() == 0 {
		t.Fatal("clock skew unexpectedly zero")
	}
	if _, err := (&Client{}).DecodeASResponse(nil, name, 1, crypto.EnctypeAES256SHA1, make([]byte, 32), time.Now()); err == nil {
		t.Fatal("malformed AS response accepted")
	}
	if _, err := (&Client{}).DecodeTGSResponse(nil, nil, principal.Principal{}, 1, time.Now()); err == nil {
		t.Fatal("nil TGT TGS response accepted")
	}
}

func TestClientCredentialAndRealmHelpers(t *testing.T) {
	name := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	end := types.KerberosTime{Time: time.Unix(100, 0).UTC(), Present: true}
	creds := Credentials{
		Client: name, Server: principal.Principal{Realm: name.Realm, Components: []string{"krbtgt", name.Realm}},
		Key:   protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: []byte{1, 2}},
		Flags: 3, IsSKey: true, AuthTime: end, StartTime: &end, EndTime: end,
		RenewTill: &end, Ticket: []byte{4}, SecondTicket: []byte{5},
	}
	cache := creds.ToCCacheCredential()
	if cache.Client.String() != name.String() || cache.Enctype != crypto.EnctypeAES256SHA1 ||
		!cache.IsSKey || len(cache.Ticket) != 1 || len(cache.SecondTicket) != 1 {
		t.Fatalf("ccache conversion = %#v", cache)
	}
	cfg := &config.Config{DefaultRealm: "DEFAULT.TEST",
		DomainRealm: map[string]string{"server.test": "MAPPED.TEST"}}
	if realm, mapped := ServiceRealm(cfg, principal.Principal{Realm: "EXPLICIT.TEST"}); !mapped || realm != "EXPLICIT.TEST" {
		t.Fatalf("explicit service realm = %q/%v", realm, mapped)
	}
	if realm, mapped := ServiceRealm(cfg, principal.Principal{Components: []string{"host", "server.test"}}); !mapped || realm != "MAPPED.TEST" {
		t.Fatalf("mapped service realm = %q/%v", realm, mapped)
	}
	if realm, mapped := ServiceRealm(cfg, principal.Principal{Components: []string{"user"}}); mapped || realm != "DEFAULT.TEST" {
		t.Fatalf("default service realm = %q/%v", realm, mapped)
	}
	if realm, mapped := ServiceRealm(nil, principal.Principal{}); mapped || realm != "" {
		t.Fatalf("empty service realm = %q/%v", realm, mapped)
	}
	if !sameProtocolPrincipal(protocol.PrincipalName{NameType: int32(name.NameType),
		NameString: name.Components}, name) ||
		sameProtocolPrincipal(protocol.PrincipalName{NameType: 99, NameString: name.Components}, name) {
		t.Fatal("protocol principal comparison is incorrect")
	}
}

func TestClientTimeAndEncodingHelpers(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	present := func(at time.Time) *types.KerberosTime {
		return &types.KerberosTime{Time: at, Present: true}
	}
	if !validTimes(*present(now), present(now), *present(now.Add(time.Hour)), now, time.Minute) {
		t.Fatal("valid ticket times rejected")
	}
	if validTimes(types.KerberosTime{}, nil, *present(now), now, time.Minute) ||
		validTimes(*present(now), present(now.Add(time.Hour)), *present(now), now, time.Minute) ||
		validTimes(*present(now.Add(2 * time.Minute)), nil, *present(now), now, time.Minute) {
		t.Fatal("invalid ticket times accepted")
	}
	if unixTime(types.KerberosTime{}) != 0 || unixOptional(nil) != 0 ||
		unixTime(*present(now)) != 100 || unixOptional(present(now)) != 100 {
		t.Fatal("Kerberos time conversion incorrect")
	}
	if checksumType(crypto.EnctypeAES128SHA1) == 0 ||
		checksumType(crypto.EnctypeCamellia256) == 0 ||
		checksumType(999) != 0 {
		t.Fatal("checksum mapping incomplete")
	}
}
