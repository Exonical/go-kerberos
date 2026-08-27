package client

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const testRealm = "TEST.REALM"

func TestASExchangePreauthRetry(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	clientPrincipal := principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.ASReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatalf("request: %v", err)
		}
		calls++
		if calls == 1 {
			return asn1.Marshal(protocol.KRBError{
				PVNO:      5,
				MsgType:   30,
				STime:     kerberosTime(now),
				Susec:     0,
				ErrorCode: 25,
				Realm:     testRealm,
				SName: protocol.PrincipalName{
					NameType:   int32(principal.NTSrvInstance),
					NameString: []string{"krbtgt", testRealm},
				},
				EData: mustMarshal(t, protocol.MethodData{{PADataType: 19, PADataValue: mustMarshal(t, protocol.ETypeInfo2{
					{EType: crypto.EnctypeAES256SHA1},
				})}}),
			})
		}
		if request.PAData == nil || len(request.PAData) != 1 {
			t.Fatalf("preauth data = %#v", request.PAData)
		}
		key, err := profile.StringToKey([]byte("password"), []byte(testRealm+"alice"), nil)
		if err != nil {
			t.Fatal(err)
		}
		encPart := protocol.EncASRepPart{
			Key:       protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key},
			Nonce:     request.ReqBody.Nonce,
			Flags:     types.TicketForwardable,
			AuthTime:  kerberosTime(now),
			StartTime: ptrKerberosTime(kerberosTime(now)),
			EndTime:   kerberosTime(now.Add(10 * time.Hour)),
			SRealm:    testRealm,
			SName: protocol.PrincipalName{
				NameType:   int32(principal.NTSrvInstance),
				NameString: []string{"krbtgt", testRealm},
			},
		}
		encodedPart := mustMarshal(t, encPart)
		cipher, err := profile.Encrypt(key, 3, encodedPart)
		if err != nil {
			t.Fatal(err)
		}
		return asn1.Marshal(protocol.ASRep{
			PVNO: 5, MsgType: 11, CRealm: testRealm,
			CName: protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: []string{"alice"}},
			Ticket: protocol.Ticket{
				TktVNO: 5, Realm: testRealm,
				SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
				EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}},
			},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: cipher},
		})
	}
	result, err := (&Client{Now: func() time.Time { return now }, Exchange: exchange}).ASExchange(context.Background(), clientPrincipal, "password")
	if err != nil {
		t.Fatalf("ASExchange: %v", err)
	}
	if calls != 2 || result.Client.Realm != clientPrincipal.Realm ||
		result.Client.NameType != clientPrincipal.NameType ||
		len(result.Client.Components) != len(clientPrincipal.Components) ||
		result.Client.Components[0] != clientPrincipal.Components[0] ||
		result.Key.KeyType != crypto.EnctypeAES256SHA1 {
		t.Fatalf("result = %#v, calls = %d", result, calls)
	}
}

func TestASExchangeRejectsWrongNonce(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.ASReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatal(err)
		}
		calls++
		if calls == 1 {
			return asn1.Marshal(protocol.KRBError{
				PVNO: 5, MsgType: 30, STime: kerberosTime(now), ErrorCode: 25,
				Realm: testRealm, SName: protocol.PrincipalName{NameType: 2, NameString: []string{"krbtgt", testRealm}},
				EData: mustMarshal(t, protocol.MethodData{{PADataType: 19, PADataValue: mustMarshal(t, protocol.ETypeInfo2{{EType: crypto.EnctypeAES256SHA1}})}}),
			})
		}
		key, err := profile.StringToKey([]byte("password"), []byte(testRealm+"alice"), nil)
		if err != nil {
			t.Fatal(err)
		}
		encodedPart := mustMarshal(t, protocol.EncASRepPart{
			Key:      protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key},
			Nonce:    request.ReqBody.Nonce + 1,
			AuthTime: kerberosTime(now),
			EndTime:  kerberosTime(now.Add(time.Hour)),
			SRealm:   testRealm,
			SName:    protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
		})
		cipher, err := profile.Encrypt(key, 3, encodedPart)
		if err != nil {
			t.Fatal(err)
		}
		return asn1.Marshal(protocol.ASRep{
			PVNO: 5, MsgType: 11, CRealm: testRealm,
			CName: protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: []string{"alice"}},
			Ticket: protocol.Ticket{
				TktVNO: 5, Realm: testRealm,
				SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
				EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}},
			},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: cipher},
		})
	}
	_, err = (&Client{Now: func() time.Time { return now }, Exchange: exchange}).ASExchange(context.Background(), principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}}, "password")
	if err == nil {
		t.Fatal("wrong nonce unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("error = %v", err)
	}
}

func TestKRBErrorMapsClockSkew(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload := mustMarshal(t, protocol.KRBError{
		PVNO: 5, MsgType: 30, STime: kerberosTime(now), ErrorCode: 37,
		Realm: testRealm, SName: protocol.PrincipalName{NameType: 2, NameString: []string{"krbtgt", testRealm}},
	})
	client := &Client{Now: func() time.Time { return now }, Exchange: func(context.Context, string, []byte) ([]byte, error) {
		return payload, nil
	}}
	_, err := client.ASExchange(context.Background(), principal.Principal{Realm: testRealm, Components: []string{"alice"}}, "password")
	if !errors.Is(err, krberrors.ErrClockSkew) {
		t.Fatalf("error = %v, want clock skew", err)
	}
}

func TestTGSExchangeBuildsAPReqAndValidatesReply(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	clientPrincipal := principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	servicePrincipal := principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvHst, Components: []string{"host", "service.test"},
	}
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey := bytes.Repeat([]byte{0x42}, profile.KeySize())
	ticket := protocol.Ticket{
		TktVNO: 5, Realm: testRealm,
		SName: protocol.PrincipalName{
			NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm},
		},
		EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}},
	}
	ticketDER := mustMarshal(t, ticket)
	tgt := &Credentials{
		Client: clientPrincipal,
		Server: principal.Principal{
			Realm: testRealm, NameType: principal.NTSrvInstance,
			Components: []string{"krbtgt", testRealm},
		},
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: sessionKey},
		Ticket: ticketDER,
	}
	var calls int
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.TGSReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatalf("TGS-REQ: %v", err)
		}
		if request.MsgType != 12 || len(request.PAData) != 1 || request.PAData[0].PADataType != 1 {
			t.Fatalf("request = %#v", request)
		}
		var apReq protocol.APReq
		if err := asn1.Unmarshal(request.PAData[0].PADataValue, &apReq); err != nil {
			t.Fatalf("AP-REQ: %v", err)
		}
		if apReq.MsgType != 14 || apReq.Ticket.Realm != testRealm {
			t.Fatalf("AP-REQ = %#v", apReq)
		}
		authenticatorDER, err := profile.Decrypt(sessionKey, 7, apReq.Authenticator.Cipher)
		if err != nil {
			t.Fatalf("decrypt authenticator: %v", err)
		}
		var authenticator protocol.Authenticator
		if err := asn1.Unmarshal(authenticatorDER, &authenticator); err != nil {
			t.Fatalf("authenticator: %v", err)
		}
		if authenticator.CRealm != testRealm || authenticator.CName.NameString[0] != "alice" {
			t.Fatalf("authenticator = %#v", authenticator)
		}
		bodyDER := mustMarshal(t, request.ReqBody)
		if err := profile.VerifyChecksum(sessionKey, 6, bodyDER, authenticator.Checksum.Checksum); err != nil {
			t.Fatalf("request checksum: %v", err)
		}
		if authenticator.Checksum.ChecksumType != crypto.ChecksumHMACSHA196AES256 {
			t.Fatalf("checksum type = %d", authenticator.Checksum.ChecksumType)
		}
		calls++
		partDER := mustMarshal(t, protocol.EncTGSRepPart{
			Key:      protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{0x24}, profile.KeySize())},
			Nonce:    request.ReqBody.Nonce,
			AuthTime: kerberosTime(now),
			EndTime:  kerberosTime(now.Add(time.Hour)),
			SRealm:   testRealm,
			SName: protocol.PrincipalName{
				NameType: int32(servicePrincipal.NameType), NameString: servicePrincipal.Components,
			},
		})
		cipher, err := profile.Encrypt(sessionKey, 8, partDER)
		if err != nil {
			t.Fatal(err)
		}
		return asn1.Marshal(protocol.TGSRep{
			PVNO: 5, MsgType: 13, CRealm: testRealm,
			CName: protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: []string{"alice"}},
			Ticket: protocol.Ticket{
				TktVNO: 5, Realm: testRealm,
				SName: protocol.PrincipalName{
					NameType: int32(servicePrincipal.NameType), NameString: servicePrincipal.Components,
				},
				EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{2}},
			},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: cipher},
		})
	}
	result, err := (&Client{
		Now: func() time.Time { return now }, Exchange: exchange,
	}).TGSExchange(context.Background(), tgt, servicePrincipal)
	if err != nil {
		t.Fatalf("TGSExchange: %v", err)
	}
	if calls != 1 || result.Server.Realm != testRealm ||
		len(result.Server.Components) != 2 ||
		result.Server.Components[0] != "host" ||
		result.Server.Components[1] != "service.test" {
		t.Fatalf("result = %#v, calls = %d", result, calls)
	}
}

func TestTGSExchangeRejectsTamperedReply(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	tgt := &Credentials{
		Client: principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}},
		Server: principal.Principal{Realm: testRealm, NameType: principal.NTSrvInstance, Components: []string{"krbtgt", testRealm}},
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{0x42}, profile.KeySize())},
		Ticket: mustMarshal(t, protocol.Ticket{TktVNO: 5, Realm: testRealm, SName: protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}}, EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}}}),
	}
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.TGSReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatal(err)
		}
		return asn1.Marshal(protocol.TGSRep{
			PVNO: 5, MsgType: 13, CRealm: testRealm,
			CName: protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: []string{"alice"}},
			Ticket: protocol.Ticket{
				TktVNO: 5, Realm: testRealm,
				SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvHst), NameString: []string{"host", "service.test"}},
				EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{2}},
			},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: append([]byte(nil), request.PAData[0].PADataValue...)},
		})
	}
	_, err = (&Client{Now: func() time.Time { return now }, Exchange: exchange}).TGSExchange(
		context.Background(), tgt,
		principal.Principal{Realm: testRealm, NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}},
	)
	if !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("error = %v, want integrity", err)
	}
}

func TestRequestNonceFitsKerberosInteger(t *testing.T) {
	restore := crypto.SetRandomSource(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff}))
	defer restore()
	request, err := (&Client{}).newASReq(
		principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}},
		time.Unix(0, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.ReqBody.Nonce > 0x7fffffff {
		t.Fatalf("nonce = %#x exceeds positive INTEGER range", request.ReqBody.Nonce)
	}
}

func kerberosTime(value time.Time) types.KerberosTime {
	return types.KerberosTime{Time: value, Present: true}
}

func ptrKerberosTime(value types.KerberosTime) *types.KerberosTime {
	return &value
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
