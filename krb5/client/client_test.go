package client

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/spake"
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
				EData: mustMarshal(t, protocol.MethodData{
					{PADataType: preauth.PADataSPAKE},
					{PADataType: 19, PADataValue: mustMarshal(t, protocol.ETypeInfo2{
						{EType: crypto.EnctypeAES256SHA1},
					})},
				}),
			})
		}
		if request.PAData == nil || len(request.PAData) != 1 ||
			request.PAData[0].PADataType != preauth.PADataEncryptedTimestamp {
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

func TestASExchangeFASTEchoesKDCookie(t *testing.T) {
	for _, encryptedChallenge := range []bool{false, true} {
		name := "encrypted-timestamp"
		if encryptedChallenge {
			name = "encrypted-challenge"
		}
		t.Run(name, func(t *testing.T) {
			testASExchangeFASTEchoesKDCookie(t, encryptedChallenge)
		})
	}
}

func testASExchangeFASTEchoesKDCookie(t *testing.T, encryptedChallenge bool) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	user := principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := asn1.Marshal(protocol.Ticket{
		TktVNO: 5, Realm: testRealm,
		SName: protocol.PrincipalName{NameType: int32(principal.NTSrvInstance),
			NameString: []string{"krbtgt", testRealm}},
		EncPart: protocol.EncryptedData{EType: etype.ID(), Cipher: []byte{1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	armorTGT := &Credentials{
		Ticket: ticket, Client: user,
		Key: protocol.EncryptionKey{KeyType: etype.ID(), KeyValue: bytes.Repeat([]byte{0x11}, etype.KeySize())},
	}
	cookie := []byte("kdc-cookie")
	var retryPA protocol.MethodData
	var calls int
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.ASReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatalf("AS-REQ: %v", err)
		}
		if len(request.PAData) != 1 || request.PAData[0].PADataType != fast.PAFXFast {
			t.Fatalf("AS-REQ padata = %#v", request.PAData)
		}
		var wrapped protocol.PAFXFastRequest
		if err := asn1.Unmarshal(request.PAData[0].PADataValue, &wrapped); err != nil {
			t.Fatalf("FAST request: %v", err)
		}
		var apReq protocol.APReq
		if err := asn1.Unmarshal(wrapped.ArmoredData.Armor.ArmorValue, &apReq); err != nil {
			t.Fatalf("FAST armor AP-REQ: %v", err)
		}
		authPlain, err := etype.Decrypt(armorTGT.Key.KeyValue, 11, apReq.Authenticator.Cipher)
		if err != nil {
			t.Fatalf("FAST armor authenticator: %v", err)
		}
		var authenticator protocol.Authenticator
		if err := asn1.Unmarshal(authPlain, &authenticator); err != nil {
			t.Fatalf("FAST authenticator: %v", err)
		}
		armorKey, err := crypto.CF2(etype, authenticator.SubKey.KeyValue, armorTGT.Key.KeyValue,
			[]byte("subkeyarmor"), []byte("ticketarmor"))
		if err != nil {
			t.Fatalf("FAST armor key: %v", err)
		}
		plain, err := etype.Decrypt(armorKey, fast.UsageReq, wrapped.ArmoredData.EncFastReq.Cipher)
		if err != nil {
			t.Fatalf("FAST request decrypt: %v", err)
		}
		var inner protocol.KrbFastReq
		if err := asn1.Unmarshal(plain, &inner); err != nil {
			t.Fatalf("FAST request body: %v", err)
		}
		if calls > 0 {
			retryPA = inner.PAData
			return asn1.Marshal(protocol.KRBError{
				PVNO: 5, MsgType: 30, STime: kerberosTime(now), Susec: 0,
				ErrorCode: 24, Realm: testRealm,
				SName: protocol.PrincipalName{NameType: int32(principal.NTSrvInstance),
					NameString: []string{"krbtgt", testRealm}},
			})
		}
		calls++
		salt := testRealm + "alice"
		etypeInfo, err := asn1.Marshal(protocol.ETypeInfo2{{EType: etype.ID(), Salt: &salt}})
		if err != nil {
			t.Fatalf("ETYPE-INFO2: %v", err)
		}
		fastPAData := protocol.MethodData{
			{PADataType: preauth.PADataETypeInfo2, PADataValue: etypeInfo},
			{PADataType: preauth.PADataCookie, PADataValue: cookie},
		}
		if encryptedChallenge {
			fastPAData = append(fastPAData, protocol.PAData{
				PADataType: preauth.PADataEncryptedChallenge,
			})
		}
		fastResponse, err := asn1.Marshal(protocol.KrbFastResponse{
			PAData: fastPAData,
			Nonce:  request.ReqBody.Nonce,
		})
		if err != nil {
			t.Fatalf("FAST response: %v", err)
		}
		cipher, err := etype.Encrypt(armorKey, fast.UsageRep, fastResponse)
		if err != nil {
			t.Fatalf("FAST response encryption: %v", err)
		}
		fastPA, err := asn1.Marshal(protocol.PAFXFastReply{ArmoredData: protocol.KrbFastArmoredRep{
			EncFastRep: protocol.EncryptedData{EType: etype.ID(), Cipher: cipher},
		}})
		if err != nil {
			t.Fatalf("FAST reply: %v", err)
		}
		errorData, err := asn1.Marshal(protocol.MethodData{{PADataType: fast.PAFXFast, PADataValue: fastPA}})
		if err != nil {
			t.Fatalf("FAST error data: %v", err)
		}
		return asn1.Marshal(protocol.KRBError{
			PVNO: 5, MsgType: 30, STime: kerberosTime(now), Susec: 0,
			ErrorCode: 25, Realm: testRealm,
			SName: protocol.PrincipalName{NameType: int32(principal.NTSrvInstance),
				NameString: []string{"krbtgt", testRealm}},
			EData: errorData,
		})
	}
	kclient := &Client{
		Now:      func() time.Time { return now },
		Config:   &config.Config{DefaultTKTEnctypes: []int32{etype.ID()}},
		Exchange: exchange,
	}
	_, _ = kclient.ASExchangeFAST(context.Background(), user, "alice-password", armorTGT)
	if len(retryPA) != 2 {
		t.Fatalf("FAST retry padata = %#v, want preauth and cookie", retryPA)
	}
	retryCookie := preauth.FindPAData(retryPA, preauth.PADataCookie)
	if retryCookie == nil || !bytes.Equal(retryCookie.PADataValue, cookie) {
		t.Fatalf("FAST retry cookie = %#v, want %q", retryCookie, cookie)
	}
}

func TestAnonymousASExchangeRejectsMissingTicketFlag(t *testing.T) {
	err := requireAnonymousTicketFlag(&Credentials{})
	if err == nil || !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("missing anonymous ticket flag error = %v, want integrity", err)
	}
}

func TestASExchangeAcceptsMixedSPAKEFactors(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	clientPrincipal := principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := profile.StringToKey([]byte("password"), []byte(testRealm+"alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	support, err := spake.EncodeSupport([]int32{spake.GroupEdwards25519})
	if err != nil {
		t.Fatal(err)
	}
	w, err := spake.DeriveW(profile, key, spake.GroupEdwards25519)
	if err != nil {
		t.Fatal(err)
	}
	serverPrivate, serverPublic, err := spake.Keygen(spake.GroupEdwards25519, w, true)
	if err != nil {
		t.Fatal(err)
	}
	challengeDER, err := asn1.Marshal(protocol.PASPAKE{Challenge: &protocol.SPAKEChallenge{
		Group: spake.GroupEdwards25519, PubKey: serverPublic,
		Factors: []protocol.SPAKESecondFactor{{Type: 99}, {Type: spake.FactorNone}},
	}})
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
				PVNO: 5, MsgType: 30, STime: kerberosTime(now), ErrorCode: 25,
				Realm: testRealm,
				SName: protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
				EData: mustMarshal(t, protocol.MethodData{
					{PADataType: preauth.PADataSPAKE, PADataValue: challengeDER},
					{PADataType: 19, PADataValue: mustMarshal(t, protocol.ETypeInfo2{{EType: crypto.EnctypeAES256SHA1}})},
				}),
			})
		}
		if len(request.PAData) != 1 || request.PAData[0].PADataType != preauth.PADataSPAKE {
			t.Fatalf("response PA-DATA = %#v", request.PAData)
		}
		response, err := spake.Decode(request.PAData[0].PADataValue)
		if err != nil || response.Response == nil {
			t.Fatalf("SPAKE response = %#v, %v", response, err)
		}
		result, err := spake.Result(spake.GroupEdwards25519, w, serverPrivate, response.Response.PubKey, false)
		if err != nil {
			t.Fatal(err)
		}
		transcript := spake.Transcript(nil, support, challengeDER)
		transcript = spake.Transcript(transcript, response.Response.PubKey, nil)
		bodyDER, err := asn1.Marshal(request.ReqBody)
		if err != nil {
			t.Fatal(err)
		}
		k0, err := spake.DeriveKey(profile, key, w, result, transcript, bodyDER, spake.GroupEdwards25519, 0)
		if err != nil {
			t.Fatal(err)
		}
		sessionKey := bytes.Repeat([]byte{0x42}, profile.KeySize())
		encPart := mustMarshal(t, protocol.EncASRepPart{
			Key:      protocol.EncryptionKey{KeyType: profile.ID(), KeyValue: sessionKey},
			Nonce:    request.ReqBody.Nonce,
			AuthTime: kerberosTime(now), EndTime: kerberosTime(now.Add(time.Hour)),
			SRealm: testRealm,
			SName:  protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
		})
		cipher, err := profile.Encrypt(k0, 3, encPart)
		if err != nil {
			t.Fatal(err)
		}
		return asn1.Marshal(protocol.ASRep{
			PVNO: 5, MsgType: 11, CRealm: testRealm,
			CName: protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: []string{"alice"}},
			Ticket: protocol.Ticket{
				TktVNO: 5, Realm: testRealm,
				SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
				EncPart: protocol.EncryptedData{EType: profile.ID(), Cipher: []byte{1}},
			},
			EncPart: protocol.EncryptedData{EType: profile.ID(), Cipher: cipher},
		})
	}
	credentials, err := (&Client{Now: func() time.Time { return now }, Exchange: exchange}).ASExchange(
		context.Background(), clientPrincipal, "password")
	if err != nil {
		t.Fatalf("ASExchange: %v", err)
	}
	if calls != 2 || credentials.Key.KeyType != profile.ID() {
		t.Fatalf("credentials = %#v, calls = %d", credentials, calls)
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

func TestASExchangeCanonicalizeOption(t *testing.T) {
	request, err := (&Client{Canonicalize: true}).newASReq(
		principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}},
		time.Unix(0, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.ReqBody.KDCOptions&types.KDCCanonicalize == 0 {
		t.Fatalf("KDC options = %#x, canonicalize is not set", request.ReqBody.KDCOptions)
	}
}

func TestRequestEnctypeSelectionMatchesMIT(t *testing.T) {
	camellia := []int32{crypto.EnctypeCamellia128}
	aes := []int32{crypto.EnctypeAES128SHA1}
	client := &Client{Config: &config.Config{
		DefaultTKTEnctypes: aes,
		DefaultTGSEnctypes: camellia,
	}}
	asRequest, err := client.newASReq(
		principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}},
		time.Unix(0, 0).UTC(),
	)
	if err != nil {
		t.Fatalf("AS request: %v", err)
	}
	if !reflect.DeepEqual(asRequest.ReqBody.EType, aes) {
		t.Fatalf("AS request enctypes = %v, want %v", asRequest.ReqBody.EType, aes)
	}
	tgt := &Credentials{
		Client: principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}},
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES128SHA1, KeyValue: bytes.Repeat([]byte{0x42}, 16)},
		Ticket: mustMarshal(t, protocol.Ticket{
			TktVNO: 5, Realm: testRealm,
			SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES128SHA1, Cipher: []byte{1}},
		}),
	}
	tgsRequest, _, err := client.newTGSReq(tgt,
		principal.Principal{Realm: testRealm, NameType: principal.NTSrvHst, Components: []string{"host", "service"}},
		testRealm, time.Unix(0, 0).UTC(), false)
	if err != nil {
		t.Fatalf("TGS request: %v", err)
	}
	if !reflect.DeepEqual(tgsRequest.ReqBody.EType, camellia) {
		t.Fatalf("TGS request enctypes = %v, want %v", tgsRequest.ReqBody.EType, camellia)
	}

	permitted := []int32{crypto.EnctypeCamellia256, crypto.EnctypeAES256SHA1}
	client = &Client{Config: &config.Config{PermittedEnctypes: permitted}}
	if got := client.asRequestEnctypes(); !reflect.DeepEqual(got, permitted) {
		t.Fatalf("permitted-only AS enctypes = %v, want %v", got, permitted)
	}
	if got := client.tgsRequestEnctypes(); !reflect.DeepEqual(got, permitted) {
		t.Fatalf("permitted-only TGS enctypes = %v, want %v", got, permitted)
	}

	wantDefault := []int32{
		crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA1,
		crypto.EnctypeAES256SHA384,
		crypto.EnctypeAES128SHA256,
		crypto.EnctypeCamellia128,
		crypto.EnctypeCamellia256,
	}
	client = &Client{}
	if got := client.asRequestEnctypes(); !reflect.DeepEqual(got, wantDefault) {
		t.Fatalf("default AS enctypes = %v, want %v", got, wantDefault)
	}
	if got := client.tgsRequestEnctypes(); !reflect.DeepEqual(got, wantDefault) {
		t.Fatalf("default TGS enctypes = %v, want %v", got, wantDefault)
	}
}

func TestASExchangeCanonicalizeAcceptsReturnedName(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	requested := principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	returned := principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice-alias"}}
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := profile.StringToKey([]byte("password"), []byte(testRealm+"alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.ASReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatal(err)
		}
		partDER := mustMarshal(t, protocol.EncASRepPart{
			Key:   protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key},
			Nonce: request.ReqBody.Nonce, AuthTime: kerberosTime(now),
			EndTime: kerberosTime(now.Add(time.Hour)), SRealm: testRealm,
			SName: protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
		})
		cipher, err := profile.Encrypt(key, 3, partDER)
		if err != nil {
			t.Fatal(err)
		}
		return asn1.Marshal(protocol.ASRep{
			PVNO: 5, MsgType: 11, CRealm: testRealm,
			CName: protocol.PrincipalName{NameType: int32(returned.NameType), NameString: returned.Components},
			Ticket: protocol.Ticket{
				TktVNO: 5, Realm: testRealm,
				SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
				EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}},
			},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: cipher},
		})
	}
	if _, err := (&Client{Now: func() time.Time { return now }, Exchange: exchange}).ASExchange(context.Background(), requested, "password"); err == nil {
		t.Fatal("non-canonicalized name change unexpectedly accepted")
	}
	result, err := (&Client{Canonicalize: true, Now: func() time.Time { return now }, Exchange: exchange}).ASExchange(context.Background(), requested, "password")
	if err != nil {
		t.Fatalf("canonicalized AS exchange: %v", err)
	}
	if result.Client.String() != returned.String() {
		t.Fatalf("returned client = %s, want %s", result.Client, returned)
	}
}

func TestTGSExchangeFollowsReferral(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey := bytes.Repeat([]byte{0x42}, profile.KeySize())
	referralKey := bytes.Repeat([]byte{0x24}, profile.KeySize())
	clientPrincipal := principal.Principal{Realm: "HOME", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt := &Credentials{
		Client: clientPrincipal,
		Server: principal.Principal{Realm: "HOME", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "HOME"}},
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: sessionKey},
		Ticket: mustMarshal(t, protocol.Ticket{
			TktVNO: 5, Realm: "HOME",
			SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", "HOME"}},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}},
		}),
	}
	service := principal.Principal{NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	var realms []string
	exchange := func(_ context.Context, realm string, payload []byte) ([]byte, error) {
		realms = append(realms, realm)
		var request protocol.TGSReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatal(err)
		}
		if len(realms) == 1 {
			return makeTGSReply(t, profile, sessionKey, request.ReqBody.Nonce, now, referralKey,
				"HOME", principal.Principal{Realm: "HOME", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "OTHER"}}), nil
		}
		if request.ReqBody.KDCOptions&types.KDCCanonicalize == 0 {
			t.Fatalf("referral request options = %#x, canonicalize is not set", request.ReqBody.KDCOptions)
		}
		return makeTGSReply(t, profile, referralKey, request.ReqBody.Nonce, now, bytes.Repeat([]byte{0x33}, profile.KeySize()),
			"OTHER", principal.Principal{Realm: "OTHER", NameType: principal.NTSrvHst, Components: service.Components}), nil
	}
	result, err := (&Client{Config: &config.Config{DefaultRealm: "HOME"}, Now: func() time.Time { return now }, Exchange: exchange}).TGSExchange(context.Background(), tgt, service)
	if err != nil {
		t.Fatalf("TGS referral: %v", err)
	}
	if len(realms) != 2 || realms[0] != "HOME" || realms[1] != "OTHER" {
		t.Fatalf("KDC realms = %#v", realms)
	}
	if result.Server.Realm != "OTHER" || result.Server.Components[0] != "host" {
		t.Fatalf("result server = %s", result.Server)
	}
}

func TestServiceRealmUsesHostMapping(t *testing.T) {
	cfg := &config.Config{
		DefaultRealm: "HOME",
		DomainRealm:  map[string]string{".other.test": "OTHER"},
	}
	service := principal.Principal{Components: []string{"host", "api.other.test"}}
	realm, mapped := ServiceRealm(cfg, service)
	if realm != "OTHER" || !mapped {
		t.Fatalf("service realm = %q, mapped = %v", realm, mapped)
	}
	service.Realm = "EXPLICIT"
	realm, mapped = ServiceRealm(cfg, service)
	if realm != "EXPLICIT" || !mapped {
		t.Fatalf("explicit service realm = %q, mapped = %v", realm, mapped)
	}
}

func TestTGSExchangeFollowsConfiguredCapath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x42}, profile.KeySize())
	tgt := &Credentials{
		Client: principal.Principal{Realm: "HOME", NameType: principal.NTPrincipal, Components: []string{"alice"}},
		Server: principal.Principal{Realm: "HOME", Components: []string{"krbtgt", "HOME"}},
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key},
		Ticket: mustMarshal(t, protocol.Ticket{TktVNO: 5, Realm: "HOME",
			SName:   protocol.PrincipalName{NameType: 2, NameString: []string{"krbtgt", "HOME"}},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}}}),
	}
	var requests []string
	cfg := &config.Config{
		CapathOptions: map[string]map[string][]string{"HOME": {"OTHER": {"MIDDLE"}}},
	}
	c := &Client{
		Config: cfg, Now: func() time.Time { return now },
		Exchange: func(_ context.Context, realm string, payload []byte) ([]byte, error) {
			var request protocol.TGSReq
			if err := asn1.Unmarshal(payload, &request); err != nil {
				t.Fatal(err)
			}
			requests = append(requests, realm+":"+strings.Join(request.ReqBody.SName.NameString, "/"))
			var server principal.Principal
			if realm == "HOME" {
				server = principal.Principal{Realm: "HOME", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "MIDDLE"}}
			} else if realm == "MIDDLE" {
				server = principal.Principal{Realm: "MIDDLE", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "OTHER"}}
			} else {
				server = principal.Principal{Realm: "OTHER", NameType: principal.NTSrvHst, Components: []string{"host", "service"}}
			}
			return makeTGSReply(t, profile, key, request.ReqBody.Nonce, now, key, realm, server), nil
		},
	}
	result, err := c.TGSExchange(context.Background(), tgt, principal.Principal{
		Realm: "OTHER", NameType: principal.NTSrvHst, Components: []string{"host", "service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"HOME:krbtgt/MIDDLE", "MIDDLE:krbtgt/OTHER", "OTHER:host/service"}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("requests = %#v, want %#v", requests, want)
	}
	if result.Server.Realm != "OTHER" {
		t.Fatalf("result realm = %q", result.Server.Realm)
	}
}

func TestTGSExchangeRejectsReferralLoopAndHopCap(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x42}, profile.KeySize())
	tgt := &Credentials{
		Client: principal.Principal{Realm: "HOME", NameType: principal.NTPrincipal, Components: []string{"alice"}},
		Server: principal.Principal{Realm: "HOME", Components: []string{"krbtgt", "HOME"}},
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key},
		Ticket: mustMarshal(t, protocol.Ticket{TktVNO: 5, Realm: "HOME",
			SName:   protocol.PrincipalName{NameType: 2, NameString: []string{"krbtgt", "HOME"}},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}}}),
	}
	makeClient := func(responseRealm func(string) string) *Client {
		return &Client{Now: func() time.Time { return now }, Config: &config.Config{DefaultRealm: "HOME"},
			Exchange: func(_ context.Context, realm string, payload []byte) ([]byte, error) {
				var request protocol.TGSReq
				if err := asn1.Unmarshal(payload, &request); err != nil {
					t.Fatal(err)
				}
				next := responseRealm(realm)
				return makeTGSReply(t, profile, key, request.ReqBody.Nonce, now, key,
					realm, principal.Principal{Realm: realm, NameType: principal.NTSrvInstance, Components: []string{"krbtgt", next}}), nil
			}}
	}
	loop := makeClient(func(realm string) string {
		if realm == "HOME" {
			return "OTHER"
		}
		return "HOME"
	})
	if _, err := loop.TGSExchange(context.Background(), tgt, principal.Principal{Components: []string{"host", "service.test"}}); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("loop error = %v", err)
	}
	hop := 0
	hops := makeClient(func(realm string) string {
		hop++
		return "R" + strconv.Itoa(hop)
	})
	if _, err := hops.TGSExchange(context.Background(), tgt, principal.Principal{Components: []string{"host", "service.test"}}); err == nil || !strings.Contains(err.Error(), "hop") {
		t.Fatalf("hop cap error = %v", err)
	}
}

func TestTGSExchangeU2UAddsSecondTicketAndMarksCredentials(t *testing.T) {
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x42}, profile.KeySize())
	tgt := &Credentials{
		Client: principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"bob"}},
		Server: principal.Principal{Realm: testRealm, NameType: principal.NTSrvInstance, Components: []string{"krbtgt", testRealm}},
		Key:    protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key},
		Ticket: mustMarshal(t, protocol.Ticket{
			TktVNO: 5, Realm: testRealm,
			SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}},
		}),
	}
	secondTicket := mustMarshal(t, protocol.Ticket{
		TktVNO: 5, Realm: testRealm,
		SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm}},
		EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{2}},
	})
	service := principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.TGSReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatal(err)
		}
		if request.ReqBody.KDCOptions&types.KDCEncTktInSkey == 0 ||
			len(request.ReqBody.AdditionalTickets) != 1 {
			t.Fatalf("U2U request = %#v", request.ReqBody)
		}
		partDER := mustMarshal(t, protocol.EncTGSRepPart{
			Key:      protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key},
			Nonce:    request.ReqBody.Nonce,
			AuthTime: kerberosTime(now),
			EndTime:  kerberosTime(now.Add(time.Hour)),
			SRealm:   service.Realm,
			SName:    protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
		})
		cipher, err := profile.Encrypt(key, 8, partDER)
		if err != nil {
			t.Fatal(err)
		}
		return mustMarshal(t, protocol.TGSRep{
			PVNO: 5, MsgType: 13, CRealm: testRealm,
			CName: protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: []string{"bob"}},
			Ticket: protocol.Ticket{
				TktVNO: 5, Realm: testRealm,
				SName:   protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
				EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{2}},
			},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: cipher},
		}), nil
	}
	credentials, err := (&Client{Now: func() time.Time { return now }, Exchange: exchange}).
		TGSExchangeU2U(context.Background(), tgt, secondTicket, service)
	if err != nil {
		t.Fatal(err)
	}
	if !credentials.IsSKey || !bytes.Equal(credentials.SecondTicket, secondTicket) {
		t.Fatalf("U2U credentials = %#v", credentials)
	}
}

func makeTGSReply(t *testing.T, profile crypto.EType, decryptKey []byte, nonce uint32, now time.Time, sessionKey []byte, realm string, server principal.Principal) []byte {
	t.Helper()
	partDER := mustMarshal(t, protocol.EncTGSRepPart{
		Key:   protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: sessionKey},
		Nonce: nonce, AuthTime: kerberosTime(now), EndTime: kerberosTime(now.Add(time.Hour)),
		SRealm: server.Realm, SName: protocol.PrincipalName{NameType: int32(server.NameType), NameString: server.Components},
	})
	cipher, err := profile.Encrypt(decryptKey, 8, partDER)
	if err != nil {
		t.Fatal(err)
	}
	ticketDER := mustMarshal(t, protocol.Ticket{
		TktVNO: 5, Realm: realm,
		SName:   protocol.PrincipalName{NameType: int32(server.NameType), NameString: server.Components},
		EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{2}},
	})
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(ticketDER, &ticket); err != nil {
		t.Fatal(err)
	}
	return mustMarshal(t, protocol.TGSRep{
		PVNO: 5, MsgType: 13, CRealm: "HOME",
		CName:  protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: []string{"alice"}},
		Ticket: ticket, EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: cipher},
	})
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
