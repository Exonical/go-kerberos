package client

import (
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
