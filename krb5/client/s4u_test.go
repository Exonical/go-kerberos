package client

import (
	"bytes"
	"context"
	"encoding/hex"
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

// goldenPAS4UX509User is hand-derived from [MS-SFU] section 2.2.1:
//
//	30 45                                  PA-S4U-X509-USER SEQUENCE
//	   a0 33 30 31                         [0] user-id S4UUserID SEQUENCE
//	      a0 03 02 01 2a                   [0] nonce INTEGER 42
//	      a1 12 30 10                      [1] cname PrincipalName SEQUENCE
//	         a0 03 02 01 01                [0] name-type INTEGER 1
//	         a1 09 30 07 1b 05 "alice"     [1] name-string SEQUENCE OF GeneralString
//	      a2 0d 1b 0b "EXAMPLE.COM"        [2] crealm Realm
//	      a4 07 03 05 00 20 00 00 00       [4] options BIT STRING (reply key usage)
//	   a1 0e 30 0c                         [1] checksum Checksum SEQUENCE
//	      a0 03 02 01 13                   [0] cksumtype INTEGER 19
//	      a1 05 04 03 01 02 03             [1] checksum OCTET STRING
const goldenPAS4UX509User = "3045" +
	"a0333031" +
	"a00302012a" +
	"a1123010a003020101a10930071b05616c696365" +
	"a20d1b0b4558414d504c452e434f4d" +
	"a40703050020000000" +
	"a10e300ca003020113a1050403010203"

func TestPAS4UX509UserGoldenDER(t *testing.T) {
	options := protocol.S4UOptionsUseReplyKeyUsage
	value := protocol.PAS4UX509User{
		UserID: protocol.S4UUserID{
			Nonce: 42,
			CName: &protocol.PrincipalName{
				NameType: int32(principal.NTPrincipal), NameString: []string{"alice"},
			},
			CRealm:  "EXAMPLE.COM",
			Options: &options,
		},
		Checksum: protocol.Checksum{ChecksumType: 19, Checksum: []byte{1, 2, 3}},
	}
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("marshal PA-S4U-X509-USER: %v", err)
	}
	if got := hex.EncodeToString(encoded); got != goldenPAS4UX509User {
		t.Fatalf("PA-S4U-X509-USER DER =\n%s\nwant\n%s", got, goldenPAS4UX509User)
	}
	var decoded protocol.PAS4UX509User
	if err := asn1.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal PA-S4U-X509-USER: %v", err)
	}
	if decoded.UserID.Nonce != 42 || decoded.UserID.CRealm != "EXAMPLE.COM" ||
		decoded.UserID.CName == nil || decoded.UserID.CName.NameString[0] != "alice" ||
		decoded.UserID.Options == nil || *decoded.UserID.Options != options {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func s4uFixture(t *testing.T) (crypto.EType, []byte, *Credentials, principal.Principal, principal.Principal) {
	t.Helper()
	profile, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvHst, Components: []string{"host", "service.test"},
	}
	user := principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	sessionKey := bytes.Repeat([]byte{0x42}, profile.KeySize())
	tgt := &Credentials{
		Client: service,
		Server: principal.Principal{
			Realm: testRealm, NameType: principal.NTSrvInstance,
			Components: []string{"krbtgt", testRealm},
		},
		Key: protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: sessionKey},
		Ticket: mustMarshal(t, protocol.Ticket{
			TktVNO: 5, Realm: testRealm,
			SName: protocol.PrincipalName{
				NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", testRealm},
			},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{1}},
		}),
	}
	return profile, sessionKey, tgt, service, user
}

func makeS4UReply(t *testing.T, profile crypto.EType, key []byte, nonce uint32, now time.Time,
	user, service principal.Principal, tamperChecksum bool) []byte {
	t.Helper()
	partDER := mustMarshal(t, protocol.EncTGSRepPart{
		Key:      protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{0x24}, profile.KeySize())},
		Nonce:    nonce,
		AuthTime: kerberosTime(now), EndTime: kerberosTime(now.Add(time.Hour)),
		SRealm: service.Realm,
		SName:  protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
	})
	cipher, err := profile.Encrypt(key, 8, partDER)
	if err != nil {
		t.Fatal(err)
	}
	options := protocol.S4UOptionsUseReplyKeyUsage
	userID := protocol.S4UUserID{
		Nonce:  nonce,
		CName:  &protocol.PrincipalName{NameType: int32(user.NameType), NameString: user.Components},
		CRealm: user.Realm, Options: &options,
	}
	checksum, err := profile.Checksum(key, 27, mustMarshal(t, userID))
	if err != nil {
		t.Fatal(err)
	}
	if tamperChecksum {
		checksum[0] ^= 0xff
	}
	padata := mustMarshal(t, protocol.PAS4UX509User{
		UserID: userID,
		Checksum: protocol.Checksum{
			ChecksumType: checksumType(crypto.EnctypeAES256SHA1), Checksum: checksum,
		},
	})
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(mustMarshal(t, protocol.Ticket{
		TktVNO: 5, Realm: service.Realm,
		SName:   protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
		EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{2}},
	}), &ticket); err != nil {
		t.Fatal(err)
	}
	return mustMarshal(t, protocol.TGSRep{
		PVNO: 5, MsgType: 13,
		PAData:  protocol.MethodData{{PADataType: protocol.PADataS4UX509User, PADataValue: padata}},
		CRealm:  user.Realm,
		CName:   protocol.PrincipalName{NameType: int32(user.NameType), NameString: user.Components},
		Ticket:  ticket,
		EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: cipher},
	})
}

func TestS4U2SelfBuildsProtocolTransitionRequest(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	profile, sessionKey, tgt, service, user := s4uFixture(t)
	var calls int
	exchange := func(_ context.Context, realm string, payload []byte) ([]byte, error) {
		calls++
		if realm != testRealm {
			t.Fatalf("request realm = %q", realm)
		}
		var request protocol.TGSReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatalf("TGS-REQ: %v", err)
		}
		if !sameProtocolPrincipal(*request.ReqBody.SName, service) {
			t.Fatalf("request sname = %#v, want the requesting service", request.ReqBody.SName)
		}
		var found bool
		for _, pa := range request.PAData {
			if pa.PADataType != protocol.PADataS4UX509User {
				continue
			}
			found = true
			var value protocol.PAS4UX509User
			if err := asn1.Unmarshal(pa.PADataValue, &value); err != nil {
				t.Fatalf("PA-S4U-X509-USER: %v", err)
			}
			if value.UserID.Nonce != request.ReqBody.Nonce {
				t.Fatalf("user-id nonce = %d, request nonce = %d", value.UserID.Nonce, request.ReqBody.Nonce)
			}
			if value.UserID.CRealm != user.Realm || value.UserID.CName == nil ||
				!sameProtocolPrincipal(*value.UserID.CName, user) {
				t.Fatalf("user-id = %#v, want %s", value.UserID, user)
			}
			if value.UserID.Options == nil || *value.UserID.Options != protocol.S4UOptionsUseReplyKeyUsage {
				t.Fatalf("user-id options = %#v", value.UserID.Options)
			}
			if want := checksumType(crypto.EnctypeAES256SHA1); value.Checksum.ChecksumType != want {
				t.Fatalf("checksum type = %d, want mandatory type %d", value.Checksum.ChecksumType, want)
			}
			userIDDER, err := asn1.Field(pa.PADataValue, 0)
			if err != nil {
				t.Fatalf("raw user-id: %v", err)
			}
			content, err := asn1.FieldContent(pa.PADataValue, 0)
			if err != nil {
				t.Fatalf("raw user-id content: %v", err)
			}
			_ = userIDDER
			if err := profile.VerifyChecksum(sessionKey, 26, content, value.Checksum.Checksum); err != nil {
				t.Fatalf("request checksum is not keyed by the TGT session key at usage 26: %v", err)
			}
			if err := profile.VerifyChecksum(sessionKey, 27, content, value.Checksum.Checksum); err == nil {
				t.Fatal("request checksum verified at reply usage 27")
			}
		}
		if !found {
			t.Fatal("request carries no PA-S4U-X509-USER padata")
		}
		for _, pa := range request.PAData {
			if pa.PADataType == protocol.PADataForUser {
				t.Fatal("request carries PA-FOR-USER, which needs an RC4 checksum")
			}
		}
		return makeS4UReply(t, profile, sessionKey, request.ReqBody.Nonce, now, user, service, false), nil
	}
	result, err := (&Client{Now: func() time.Time { return now }, Exchange: exchange}).
		S4U2Self(context.Background(), tgt, user)
	if err != nil {
		t.Fatalf("S4U2Self: %v", err)
	}
	if calls != 1 {
		t.Fatalf("exchange calls = %d", calls)
	}
	if result.Client.String() != user.String() {
		t.Fatalf("credential client = %s, want %s", result.Client, user)
	}
	if result.Server.String() != service.String() {
		t.Fatalf("credential server = %s, want %s", result.Server, service)
	}
}

func TestS4U2SelfRejectsTamperedReplyChecksum(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	profile, sessionKey, tgt, service, user := s4uFixture(t)
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.TGSReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatalf("TGS-REQ: %v", err)
		}
		return makeS4UReply(t, profile, sessionKey, request.ReqBody.Nonce, now, user, service, true), nil
	}
	_, err := (&Client{Now: func() time.Time { return now }, Exchange: exchange}).
		S4U2Self(context.Background(), tgt, user)
	if !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("tampered S4U reply checksum error = %v, want integrity failure", err)
	}
}

func TestS4U2SelfRejectsMismatchedReplyUser(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	profile, sessionKey, tgt, service, user := s4uFixture(t)
	other := principal.Principal{Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"bob"}}
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.TGSReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatalf("TGS-REQ: %v", err)
		}
		return makeS4UReply(t, profile, sessionKey, request.ReqBody.Nonce, now, other, service, false), nil
	}
	_, err := (&Client{Now: func() time.Time { return now }, Exchange: exchange}).
		S4U2Self(context.Background(), tgt, user)
	if err == nil {
		t.Fatal("S4U2Self accepted a reply for a different user")
	}
}

func TestS4U2ProxySendsEvidenceTicketAndOption(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	profile, sessionKey, tgt, service, user := s4uFixture(t)
	backend := principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvHst, Components: []string{"HTTP", "backend.test"},
	}
	evidence := &Credentials{
		Client: user, Server: service,
		Key: protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{0x11}, profile.KeySize())},
		Ticket: mustMarshal(t, protocol.Ticket{
			TktVNO: 5, Realm: testRealm,
			SName: protocol.PrincipalName{
				NameType: int32(service.NameType), NameString: service.Components,
			},
			EncPart: protocol.EncryptedData{EType: crypto.EnctypeAES256SHA1, Cipher: []byte{9}},
		}),
	}
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.TGSReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatalf("TGS-REQ: %v", err)
		}
		if request.ReqBody.KDCOptions&types.KDCCNameInAddlTkt == 0 {
			t.Fatalf("kdc-options = %#x, want cname-in-addl-tkt", uint32(request.ReqBody.KDCOptions))
		}
		if len(request.ReqBody.AdditionalTickets) != 1 ||
			!sameProtocolPrincipal(request.ReqBody.AdditionalTickets[0].SName, service) {
			t.Fatalf("additional tickets = %#v", request.ReqBody.AdditionalTickets)
		}
		if !sameProtocolPrincipal(*request.ReqBody.SName, backend) {
			t.Fatalf("request sname = %#v, want %s", request.ReqBody.SName, backend)
		}
		return makeS4UReply(t, profile, sessionKey, request.ReqBody.Nonce, now, user, backend, false), nil
	}
	client := &Client{Now: func() time.Time { return now }, Exchange: exchange}
	result, err := client.S4U2Proxy(context.Background(), tgt, evidence, backend)
	if err != nil {
		t.Fatalf("S4U2Proxy: %v", err)
	}
	if result.Server.String() != backend.String() {
		t.Fatalf("credential server = %s, want %s", result.Server, backend)
	}
	if result.Client.String() != user.String() {
		t.Fatalf("credential client = %s, want the impersonated user %s", result.Client, user)
	}
}

func TestS4URejectsIncompleteArguments(t *testing.T) {
	_, _, tgt, service, user := s4uFixture(t)
	client := &Client{Exchange: func(context.Context, string, []byte) ([]byte, error) {
		t.Fatal("exchange called for an invalid request")
		return nil, nil
	}}
	if _, err := client.S4U2Self(context.Background(), nil, user); err == nil {
		t.Fatal("S4U2Self accepted a nil TGT")
	}
	if _, err := client.S4U2Self(context.Background(), tgt, principal.Principal{}); err == nil {
		t.Fatal("S4U2Self accepted an empty user principal")
	}
	if _, err := client.S4U2Proxy(context.Background(), tgt, nil, service); err == nil {
		t.Fatal("S4U2Proxy accepted missing evidence")
	}
	_, err := client.S4U2Self(context.Background(), tgt, principal.Principal{Components: []string{"alice"}})
	if err == nil || !strings.Contains(err.Error(), "S4U2Self") {
		t.Fatalf("realmless user error = %v", err)
	}
}
