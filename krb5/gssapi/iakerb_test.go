package gssapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestIAKERBHeaderGolden(t *testing.T) {
	header := IAKERBHeader{TargetRealm: "TEST.REALM", Cookie: []byte{1, 2}}
	encoded, err := MarshalIAKERBHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("3014a10c0c0a544553542e5245414c4da20404020102")
	if !bytes.Equal(encoded, want) {
		t.Fatalf("header DER = %x, want %x", encoded, want)
	}
	decoded, err := ParseIAKERBHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.TargetRealm != header.TargetRealm || !bytes.Equal(decoded.Cookie, header.Cookie) {
		t.Fatalf("decoded header = %#v", decoded)
	}
}

func TestIAKERBFinishedGolden(t *testing.T) {
	value, err := asn1.Marshal(IAKERBFinished{
		Checksum: protocol.Checksum{ChecksumType: 12, Checksum: []byte{1, 2, 3, 4, 5, 6}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("3013a111300fa00302010ca1080406010203040506")
	if !bytes.Equal(value, want) {
		t.Fatalf("finished DER = %x, want %x", value, want)
	}
	var decoded IAKERBFinished
	if err := asn1.Unmarshal(value, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Checksum.ChecksumType != 12 || !bytes.Equal(decoded.Checksum.Checksum, []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("decoded finished = %#v", decoded)
	}
}

func TestIAKERBFinishedRoundTripAndFailure(t *testing.T) {
	credentials, _ := syntheticCredentials(t, crypto.EnctypeAES256SHA1)
	conversation := []byte("IAKERB proxy conversation")
	finished, err := MarshalIAKERBFinished(credentials.Key, conversation)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyIAKERBFinished(credentials.Key, conversation, finished); err != nil {
		t.Fatalf("verify finished: %v", err)
	}
	conversation[0] ^= 1
	if err := VerifyIAKERBFinished(credentials.Key, conversation, finished); err == nil {
		t.Fatal("tampered conversation unexpectedly verified")
	}
}

func TestIAKERBProxyTokenRoundTrip(t *testing.T) {
	request := []byte{0x30, 0x03, 0x01, 0x01, 0xff}
	token, err := BuildIAKERBProxyToken("TEST.REALM", []byte("cookie"), request)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := parseIAKERBProxyToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if header.TargetRealm != "TEST.REALM" || !bytes.Equal(header.Cookie, []byte("cookie")) ||
		!bytes.Equal(payload, request) {
		t.Fatalf("parsed token = %#v, %x", header, payload)
	}
}

func TestIAKERBRealmDiscoveryUsesEmptyPayload(t *testing.T) {
	initiator, err := NewIAKERBInitiator(&client.Client{},
		principal.Principal{Components: []string{"alice"}}, principal.Principal{
			Realm: "TEST.REALM", Components: []string{"host", "service"},
		}, "password", 0)
	if err != nil {
		t.Fatal(err)
	}
	token, err := initiator.Step(nil, time.Unix(1700002200, 0))
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := parseIAKERBProxyToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if header.TargetRealm != "" || len(payload) != 0 {
		t.Fatalf("discovery token = %#v, %x", header, payload)
	}
}

func TestIAKERBRejectsDelegation(t *testing.T) {
	_, err := NewIAKERBInitiator(&client.Client{},
		principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}},
		principal.Principal{Realm: "TEST.REALM", Components: []string{"host", "service"}},
		"password", GSSDelegFlag)
	if err == nil || !strings.Contains(err.Error(), "delegation") {
		t.Fatalf("delegation result = %v", err)
	}
}

func TestIAKERBRejectsMalformedProxyTokens(t *testing.T) {
	token, err := BuildIAKERBProxyToken("TEST.REALM", nil, []byte{0x30, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{
		token[:len(token)-1],
		append([]byte(nil), token[:2]...),
		[]byte{0x60, 0x01, 0x00},
	} {
		if _, _, err := parseIAKERBProxyToken(malformed); err == nil {
			t.Fatalf("malformed token %x unexpectedly parsed", malformed)
		}
	}
}

func TestIAKERBProxyRealmDiscoveryAndForwarding(t *testing.T) {
	credentials, kt := syntheticCredentials(t, crypto.EnctypeAES256SHA1)
	var forwardedRealm string
	var forwarded []byte
	kdc := &client.Client{Exchange: func(_ context.Context, realm string, request []byte) ([]byte, error) {
		forwardedRealm, forwarded = realm, append([]byte(nil), request...)
		return []byte{0x30, 0x00}, nil
	}}
	acceptor, err := NewIAKERBAcceptor(kt, kdc, credentials.Server.Realm)
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := BuildIAKERBProxyToken("", []byte("cookie"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, reply, err := acceptor.Accept(context.Background(), discovery, time.Unix(1700002200, 0)); err != nil {
		t.Fatal(err)
	} else {
		header, payload, err := parseIAKERBProxyToken(reply)
		if err != nil {
			t.Fatal(err)
		}
		if string(header.TargetRealm) != credentials.Server.Realm || !bytes.Equal(header.Cookie, []byte("cookie")) ||
			len(payload) != 0 {
			t.Fatalf("discovery reply = %#v, %x", header, payload)
		}
	}
	request := []byte{0x30, 0x01, 0x00}
	proxy, err := BuildIAKERBProxyToken(credentials.Server.Realm, []byte("cookie"), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, reply, err := acceptor.Accept(context.Background(), proxy, time.Unix(1700002200, 0)); err != nil {
		t.Fatal(err)
	} else {
		header, payload, err := parseIAKERBProxyToken(reply)
		if err != nil {
			t.Fatal(err)
		}
		if forwardedRealm != credentials.Server.Realm || !bytes.Equal(forwarded, request) ||
			string(header.TargetRealm) != credentials.Server.Realm || !bytes.Equal(header.Cookie, []byte("cookie")) ||
			!bytes.Equal(payload, []byte{0x30, 0x00}) {
			t.Fatalf("forwarding = %q %x, reply = %#v %x", forwardedRealm, forwarded, header, payload)
		}
	}
}

func TestIAKERBAcceptorRealmAllowlistAndContext(t *testing.T) {
	credentials, kt := syntheticCredentials(t, crypto.EnctypeAES256SHA1)
	type contextKey string
	key := contextKey("seen")
	var seen any
	kdc := &client.Client{Exchange: func(ctx context.Context, realm string, request []byte) ([]byte, error) {
		seen = ctx.Value(key)
		return []byte{0x30, 0x00}, nil
	}}
	acceptor, err := NewIAKERBAcceptor(kt, kdc, credentials.Server.Realm)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte{0x30, 0x01, 0x00}
	proxy, err := BuildIAKERBProxyToken("OTHER.REALM", nil, request)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), key, "passed")
	if _, _, err := acceptor.Accept(ctx, proxy, time.Unix(1700002200, 0)); err == nil {
		t.Fatal("unconfigured realm unexpectedly proxied")
	}
	acceptor.AllowedRealms = []string{"OTHER.REALM"}
	if _, _, err := acceptor.Accept(ctx, proxy, time.Unix(1700002200, 0)); err != nil {
		t.Fatal(err)
	}
	if seen != "passed" {
		t.Fatalf("proxy context = %#v", seen)
	}
}

func TestIAKERBExistingCredentialsHandoff(t *testing.T) {
	credentials, kt := syntheticCredentials(t, crypto.EnctypeAES256SHA1)
	now := time.Unix(1700002200, 0).UTC()
	target := principal.Principal{
		Realm: credentials.Server.Realm, NameType: credentials.Server.NameType,
		Components: append([]string(nil), credentials.Server.Components...),
	}
	initiator, err := NewIAKERBInitiatorWithCredentials(nil, credentials, target, GSSMutualFlag|GSSIntegrityFlag)
	if err != nil {
		t.Fatal(err)
	}
	token, err := initiator.Step(nil, now)
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := NewIAKERBAcceptor(kt, &client.Client{}, credentials.Server.Realm)
	if err != nil {
		t.Fatal(err)
	}
	acceptCtx, reply, err := acceptor.Accept(context.Background(), token, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.Step(reply, now); err != nil {
		t.Fatal(err)
	}
	ctx, err := initiator.Context()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := ctx.Wrap([]byte("hello"), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acceptCtx.Unwrap(wrapped); err != nil {
		t.Fatal(err)
	}
}
