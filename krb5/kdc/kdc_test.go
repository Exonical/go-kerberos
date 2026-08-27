package kdc

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestServerASAndTGSExchange(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	_, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("ASExchange: %v", err)
	}
	if tgt.Server.Components[0] != "krbtgt" || tgt.Server.Components[1] != "TEST.REALM" {
		t.Fatalf("TGT server = %v", tgt.Server)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	credentials, err := kclient.TGSExchange(context.Background(), tgt, service)
	if err != nil {
		t.Fatalf("TGSExchange: %v", err)
	}
	if !samePrincipal(credentials.Server, service) {
		t.Fatalf("service server = %v, want %v", credentials.Server, service)
	}
}

func TestASRequiresPreauthenticationAndMapsFailures(t *testing.T) {
	now := time.Unix(2000000100, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"},
	}, 1)
	response := server.HandleMessage(mustMarshal(t, request))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("preauth response: %v", err)
	}
	if kerberosError.ErrorCode != 25 || len(kerberosError.EData) == 0 {
		t.Fatalf("preauth error = code %d, e-data %d bytes", kerberosError.ErrorCode, len(kerberosError.EData))
	}
	var methodData protocol.MethodData
	if err := asn1.Unmarshal(kerberosError.EData, &methodData); err != nil {
		t.Fatalf("ETYPE-INFO2: %v", err)
	}
	var hasETypeInfo2, hasEncTimestampHint bool
	for _, pa := range methodData {
		switch pa.PADataType {
		case 19:
			hasETypeInfo2 = true
		case 2:
			hasEncTimestampHint = true
		}
	}
	if !hasETypeInfo2 || !hasEncTimestampHint {
		t.Fatalf("preauth method data = %#v", methodData)
	}

	badClient := &client.Client{
		Now: func() time.Time { return now },
		Exchange: func(_ context.Context, _ string, payload []byte) ([]byte, error) {
			return server.HandleMessage(payload), nil
		},
	}
	_, err := badClient.ASExchange(context.Background(), user, "wrong-password")
	if err == nil || !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("wrong password error = %v, want integrity", err)
	}
	unknown := user
	unknown.Components = []string{"nobody"}
	_, err = badClient.ASExchange(context.Background(), unknown, "password")
	if err == nil || !hasKRBCode(err, 6) {
		t.Fatalf("unknown client error = %v, want code 6", err)
	}
}

func TestASDirectServiceRequestEchoesSName(t *testing.T) {
	now := time.Unix(2000000200, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := etype.StringToKey([]byte("alice-password"), []byte("TEST.REALMalice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := asRequest(user, service, 2)
	timestamp := types.KerberosTime{Time: now, Present: true}
	timestampDER := mustMarshal(t, preauth.EncTimestamp{PATimestamp: timestamp})
	timestampCipher, err := etype.Encrypt(key, 1, timestampDER)
	if err != nil {
		t.Fatal(err)
	}
	request.PAData = protocol.MethodData{{PADataType: 2, PADataValue: timestampCipher}}
	response := server.HandleMessage(mustMarshal(t, request))
	var reply protocol.ASRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("AS-REP: %v", err)
	}
	if reply.Ticket.SName.NameType != int32(service.NameType) ||
		!bytes.Equal([]byte(reply.Ticket.SName.NameString[0]), []byte(service.Components[0])) ||
		reply.Ticket.SName.NameString[1] != service.Components[1] {
		t.Fatalf("ticket sname = %#v, want %#v", reply.Ticket.SName, service)
	}
}

func TestTGSRejectsTamperedAuthenticatorChecksum(t *testing.T) {
	now := time.Unix(2000000300, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		var request protocol.TGSReq
		if err := asn1.Unmarshal(payload, &request); err != nil {
			t.Fatal(err)
		}
		var apReq protocol.APReq
		if err := asn1.Unmarshal(request.PAData[0].PADataValue, &apReq); err != nil {
			t.Fatal(err)
		}
		etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := etype.Decrypt(tgt.Key.KeyValue, 7, apReq.Authenticator.Cipher)
		if err != nil {
			t.Fatal(err)
		}
		var authenticator protocol.Authenticator
		if err := asn1.Unmarshal(plain, &authenticator); err != nil {
			t.Fatal(err)
		}
		authenticator.Checksum.Checksum[0] ^= 1
		plain = mustMarshal(t, authenticator)
		apReq.Authenticator.Cipher, err = etype.Encrypt(tgt.Key.KeyValue, 7, plain)
		if err != nil {
			t.Fatal(err)
		}
		request.PAData[0].PADataValue = mustMarshal(t, apReq)
		return server.HandleMessage(mustMarshal(t, request)), nil
	}
	_, err = (&client.Client{Now: func() time.Time { return now }, Exchange: exchange}).TGSExchange(
		context.Background(), tgt, service)
	if err == nil || !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("tampered checksum error = %v, want integrity", err)
	}
}

func testServer(t *testing.T, now time.Time) (*Server, *client.Client) {
	t.Helper()
	db := kdb.NewDatabase("TEST.REALM")
	for _, item := range []struct {
		name, password string
	}{
		{"alice", "alice-password"},
		{"krbtgt/TEST.REALM", "krbtgt-password"},
		{"host/service.test", "host-password"},
	} {
		if err := db.AddPrincipal(item.name, item.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	server := &Server{
		Realm:            "TEST.REALM",
		DB:               db,
		Now:              func() time.Time { return now },
		ClockSkew:        5 * time.Minute,
		MaxTicketLife:    10 * time.Hour,
		MaxRenewableLife: 24 * time.Hour,
	}
	return server, &client.Client{
		Now: func() time.Time { return now },
		Exchange: func(_ context.Context, _ string, payload []byte) ([]byte, error) {
			return server.HandleMessage(payload), nil
		},
	}
}

func asRequest(user, service principal.Principal, nonce uint32) protocol.ASReq {
	return protocol.ASReq{
		PVNO: 5, MsgType: 10,
		ReqBody: protocol.KDCReqBody{
			KDCOptions: types.KDCRenewableOK,
			CName:      &protocol.PrincipalName{NameType: int32(user.NameType), NameString: user.Components},
			Realm:      user.Realm,
			SName:      &protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
			Till:       types.KerberosTime{Time: time.Unix(2000000000, 0).UTC().Add(10 * time.Hour), Present: true},
			Nonce:      nonce,
			EType:      []int32{crypto.EnctypeAES256SHA1, crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA384, crypto.EnctypeAES128SHA256},
		},
	}
}

func samePrincipal(left, right principal.Principal) bool {
	return left.Realm == right.Realm && left.NameType == right.NameType &&
		bytes.Equal([]byte(stringsJoin(left.Components)), []byte(stringsJoin(right.Components)))
}

func stringsJoin(values []string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += "/" + value
	}
	return result
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func hasKRBCode(err error, code int32) bool {
	var kerberosError *krberrors.KRBError
	if !errors.As(err, &kerberosError) {
		return false
	}
	return int32(kerberosError.Code) == code
}

func TestASUnknownServiceReturnsCode7(t *testing.T) {
	now := time.Unix(2000000400, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	unknown := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "missing.test"}}
	response := server.HandleMessage(mustMarshal(t, asRequest(user, unknown, 3)))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("unknown service response: %v", err)
	}
	if kerberosError.ErrorCode != 7 {
		t.Fatalf("unknown service code = %d, want 7", kerberosError.ErrorCode)
	}
}

func TestASNoSharedEnctypeReturnsCode14(t *testing.T) {
	now := time.Unix(2000000450, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgtService := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	request := asRequest(user, tgtService, 4)
	request.ReqBody.EType = []int32{1, 3, 23}
	response := server.HandleMessage(mustMarshal(t, request))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("no shared enctype response: %v", err)
	}
	if kerberosError.ErrorCode != 14 {
		t.Fatalf("no shared enctype code = %d, want 14", kerberosError.ErrorCode)
	}
}

func TestASRejectsSkewedTimestamp(t *testing.T) {
	now := time.Unix(2000000500, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgtService := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := etype.StringToKey([]byte("alice-password"), []byte("TEST.REALMalice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := asRequest(user, tgtService, 5)
	skewed := types.KerberosTime{Time: now.Add(-time.Hour), Present: true}
	timestampDER := mustMarshal(t, preauth.EncTimestamp{PATimestamp: skewed})
	timestampCipher, err := etype.Encrypt(key, 1, timestampDER)
	if err != nil {
		t.Fatal(err)
	}
	request.PAData = protocol.MethodData{{PADataType: 2, PADataValue: timestampCipher}}
	response := server.HandleMessage(mustMarshal(t, request))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("skewed timestamp response: %v", err)
	}
	if kerberosError.ErrorCode != 37 {
		t.Fatalf("skewed timestamp code = %d, want 37", kerberosError.ErrorCode)
	}
}

func TestTGSUsesAuthenticatorSubkeyAtUsage9(t *testing.T) {
	now := time.Unix(2000000600, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	body := protocol.KDCReqBody{
		KDCOptions: types.KDCRenewableOK,
		Realm:      "TEST.REALM",
		SName:      &protocol.PrincipalName{NameType: int32(principal.NTSrvHst), NameString: []string{"host", "service.test"}},
		Till:       types.KerberosTime{Time: now.Add(8 * time.Hour), Present: true},
		Nonce:      42,
		EType:      []int32{tgt.Key.KeyType},
	}
	bodyDER := mustMarshal(t, body)
	checksum, err := etype.Checksum(tgt.Key.KeyValue, 6, bodyDER)
	if err != nil {
		t.Fatal(err)
	}
	subkeyValue := bytes.Repeat([]byte{0x42}, etype.KeySize())
	subkey := protocol.EncryptionKey{KeyType: tgt.Key.KeyType, KeyValue: subkeyValue}
	authenticator := protocol.Authenticator{
		AuthenticatorVNO: 5,
		CRealm:           "TEST.REALM",
		CName:            protocol.PrincipalName{NameType: int32(user.NameType), NameString: user.Components},
		Checksum:         &protocol.Checksum{ChecksumType: mandatoryChecksumType(tgt.Key.KeyType), Checksum: checksum},
		Ctime:            types.KerberosTime{Time: now, Present: true},
		SubKey:           &subkey,
	}
	authCipher, err := etype.Encrypt(tgt.Key.KeyValue, 7, mustMarshal(t, authenticator))
	if err != nil {
		t.Fatal(err)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(tgt.Ticket, &ticket); err != nil {
		t.Fatal(err)
	}
	apReq := protocol.APReq{
		PVNO: 5, MsgType: 14, Ticket: ticket,
		Authenticator: protocol.EncryptedData{EType: tgt.Key.KeyType, Cipher: authCipher},
	}
	request := protocol.TGSReq{
		PVNO: 5, MsgType: 12,
		PAData:  protocol.MethodData{{PADataType: 1, PADataValue: mustMarshal(t, apReq)}},
		ReqBody: body,
	}
	response := server.HandleMessage(mustMarshal(t, request))
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("TGS-REP: %v", err)
	}
	if _, err := etype.Decrypt(tgt.Key.KeyValue, 8, reply.EncPart.Cipher); err == nil {
		t.Fatal("reply decrypted with session key at usage 8, want subkey usage 9")
	}
	plain, err := etype.Decrypt(subkeyValue, 9, reply.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt with subkey usage 9: %v", err)
	}
	var part protocol.EncTGSRepPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatalf("EncTGSRepPart: %v", err)
	}
	if part.Nonce != 42 {
		t.Fatalf("nonce = %d, want 42", part.Nonce)
	}
}

func TestTGSRejectsExpiredAndPostdatedTickets(t *testing.T) {
	now := time.Unix(2000000900, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}

	for _, testCase := range []struct {
		name  string
		shift time.Duration
		code  int32
	}{
		{"expired", 11 * time.Hour, 32},
		{"not yet valid", -24 * time.Hour, 33},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			later := now.Add(testCase.shift)
			server.Now = func() time.Time { return later }
			defer func() { server.Now = func() time.Time { return now } }()
			shifted := &client.Client{
				Now: func() time.Time { return later },
				Exchange: func(_ context.Context, _ string, payload []byte) ([]byte, error) {
					return server.HandleMessage(payload), nil
				},
			}
			_, err := shifted.TGSExchange(context.Background(), tgt, service)
			if err == nil || !hasKRBCode(err, testCase.code) {
				t.Fatalf("TGS error = %v, want code %d", err, testCase.code)
			}
		})
	}
}

type stubStore struct {
	db  *kdb.Database
	err error
}

func (s *stubStore) Lookup(name principal.Principal) (kdb.PrincipalRecord, bool, error) {
	if s.err != nil {
		return kdb.PrincipalRecord{}, false, s.err
	}
	record, ok, err := s.db.Lookup(name)
	if err != nil || !ok {
		return record, ok, err
	}
	for enctype, key := range record.Keys {
		key.Salt = "custom-salt"
		record.Keys[enctype] = key
	}
	return record, true, nil
}

func TestASAdvertisesPerKeySalt(t *testing.T) {
	now := time.Unix(2000000100, 0).UTC()
	server, _ := testServer(t, now)
	server.DB = &stubStore{db: server.DB.(*kdb.Database)}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"},
	}, 1)
	response := server.HandleMessage(mustMarshal(t, request))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("preauth response: %v", err)
	}
	if kerberosError.ErrorCode != 25 {
		t.Fatalf("error code = %d, want 25", kerberosError.ErrorCode)
	}
	var methodData protocol.MethodData
	if err := asn1.Unmarshal(kerberosError.EData, &methodData); err != nil {
		t.Fatalf("METHOD-DATA: %v", err)
	}
	var salt string
	for _, pa := range methodData {
		if pa.PADataType != 19 {
			continue
		}
		var info protocol.ETypeInfo2
		if err := asn1.Unmarshal(pa.PADataValue, &info); err != nil {
			t.Fatalf("ETYPE-INFO2: %v", err)
		}
		if len(info) == 0 || info[0].Salt == nil {
			t.Fatalf("ETYPE-INFO2 = %#v", info)
		}
		salt = *info[0].Salt
	}
	if salt != "custom-salt" {
		t.Fatalf("advertised salt = %q, want custom-salt", salt)
	}
}

func TestStoreErrorMapsToGeneric(t *testing.T) {
	now := time.Unix(2000000100, 0).UTC()
	server, _ := testServer(t, now)
	server.DB = &stubStore{err: errors.New("backend unavailable")}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"},
	}, 1)
	response := server.HandleMessage(mustMarshal(t, request))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("error response: %v", err)
	}
	if kerberosError.ErrorCode != 60 {
		t.Fatalf("error code = %d, want KRB_ERR_GENERIC (60)", kerberosError.ErrorCode)
	}
}

func TestStubStoreServesASEndToEnd(t *testing.T) {
	now := time.Unix(2000000100, 0).UTC()
	server, kclient := testServer(t, now)
	db := kdb.NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("carol", "carol-password", 1); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("krbtgt/TEST.REALM", "krbtgt-password", 1); err != nil {
		t.Fatal(err)
	}
	server.DB = delegatingStore{db}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"carol"}}
	credentials, err := kclient.ASExchange(context.Background(), user, "carol-password")
	if err != nil {
		t.Fatalf("AS exchange through stub store: %v", err)
	}
	if credentials.Client.String() != "carol@TEST.REALM" {
		t.Fatalf("client = %s", credentials.Client)
	}
}

type delegatingStore struct{ db *kdb.Database }

func (d delegatingStore) Lookup(name principal.Principal) (kdb.PrincipalRecord, bool, error) {
	return d.db.Lookup(name)
}

func TestTGSRejectsAuthenticatorReplay(t *testing.T) {
	now := time.Unix(2000001000, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	request := rawTGSRequest(t, tgt, service, now, 0)
	response := server.HandleMessage(request)
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("first TGS response: %v", err)
	}
	response = server.HandleMessage(request)
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("replay response: %v", err)
	}
	if kerberosError.ErrorCode != 34 {
		t.Fatalf("replay error code = %d, want 34", kerberosError.ErrorCode)
	}
}

func TestASIssuesRenewableTicketAndTGSRenewsIt(t *testing.T) {
	now := time.Unix(2000001100, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt := issueASTicket(t, server, user, now, types.KDCRenewable, now.Add(2*time.Hour))
	if tgt.Flags&types.TicketRenewable == 0 || tgt.RenewTill == nil {
		t.Fatalf("TGT flags=%#x renew-till=%v, want renewable", tgt.Flags, tgt.RenewTill)
	}
	if !tgt.RenewTill.Time.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("renew-till = %v, want %v", tgt.RenewTill.Time, now.Add(2*time.Hour))
	}
	renewNow := now.Add(time.Hour)
	server.Now = func() time.Time { return renewNow }
	request := rawTGSRequest(t, tgt, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"},
	}, renewNow, types.KDCRenew)
	response := server.HandleMessage(request)
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("renew response: %v", err)
	}
	var part protocol.EncTGSRepPart
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(tgt.Key.KeyValue, 8, reply.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt renew reply: %v", err)
	}
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatalf("renew reply part: %v", err)
	}
	if part.RenewTill == nil || !part.RenewTill.Time.Equal(tgt.RenewTill.Time) {
		t.Fatalf("renew reply renew-till = %v, want %v", part.RenewTill, tgt.RenewTill)
	}
	if part.EndTime.Time.Before(now) || part.EndTime.Time.After(tgt.RenewTill.Time) {
		t.Fatalf("renew reply end-time = %v, outside renewable interval", part.EndTime.Time)
	}
}

func TestASPostdatedTicketRequiresValidation(t *testing.T) {
	now := time.Unix(2000001200, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	start := now.Add(time.Hour)
	tgt := issueASTicket(t, server, user, now,
		types.KDCAllowPostdate|types.KDCPostdated, start)
	if tgt.Flags&types.TicketInvalid == 0 || tgt.StartTime == nil || !tgt.StartTime.Time.Equal(start) {
		t.Fatalf("postdated TGT flags=%#x start=%v", tgt.Flags, tgt.StartTime)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	response := server.HandleMessage(rawTGSRequest(t, tgt, service, now, 0))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("pre-validation response: %v", err)
	}
	if kerberosError.ErrorCode != 33 {
		t.Fatalf("pre-validation code = %d, want 33", kerberosError.ErrorCode)
	}
	server.Now = func() time.Time { return start.Add(time.Minute) }
	response = server.HandleMessage(rawTGSRequest(t, tgt, service, start.Add(time.Minute), types.KDCValidate))
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("validation response: %v", err)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(tgt.Ticket, &ticket); err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(tgt.Key.KeyValue, 8, reply.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt validation reply: %v", err)
	}
	var part protocol.EncTGSRepPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	if part.Flags&types.TicketInvalid != 0 {
		t.Fatalf("validated reply retains invalid flag: %#x", part.Flags)
	}
}

func issueASTicket(t *testing.T, server *Server, user principal.Principal, now time.Time, options types.KDCOptions, rtime time.Time) *client.Credentials {
	t.Helper()
	service := principal.Principal{Realm: user.Realm, NameType: principal.NTSrvInstance, Components: []string{"krbtgt", user.Realm}}
	request := asRequest(user, service, 77)
	request.ReqBody.KDCOptions = options
	request.ReqBody.From = nil
	if options&types.KDCPostdated != 0 {
		start := kerberosTime(rtime)
		request.ReqBody.From = &start
		request.ReqBody.Till = kerberosTime(rtime.Add(time.Hour))
	} else {
		request.ReqBody.Till = kerberosTime(now.Add(time.Hour))
		request.ReqBody.RTime = &types.KerberosTime{Time: rtime, Present: true}
	}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := etype.StringToKey([]byte("alice-password"), []byte("TEST.REALMalice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	timestampDER := mustMarshal(t, preauth.EncTimestamp{PATimestamp: types.KerberosTime{Time: now, Present: true}})
	timestampCipher, err := etype.Encrypt(key, 1, timestampDER)
	if err != nil {
		t.Fatal(err)
	}
	request.PAData = protocol.MethodData{{PADataType: paEncTimestamp, PADataValue: timestampCipher}}
	response := server.HandleMessage(mustMarshal(t, request))
	var reply protocol.ASRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("AS response: %v", err)
	}
	plain, err := etype.Decrypt(key, 3, reply.EncPart.Cipher)
	if err != nil {
		t.Fatalf("AS reply decrypt: %v", err)
	}
	var part protocol.EncASRepPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatalf("AS reply part: %v", err)
	}
	ticketDER := mustMarshal(t, reply.Ticket)
	return &client.Credentials{
		Client: user, Server: service, Key: part.Key, Flags: part.Flags,
		AuthTime: part.AuthTime, StartTime: part.StartTime, EndTime: part.EndTime,
		RenewTill: part.RenewTill, Ticket: ticketDER,
	}
}

func rawTGSRequest(t *testing.T, tgt *client.Credentials, service principal.Principal, now time.Time, options types.KDCOptions) []byte {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	body := protocol.KDCReqBody{
		KDCOptions: options,
		Realm:      service.Realm,
		SName:      &protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
		Till:       types.KerberosTime{Time: now.Add(time.Hour), Present: true},
		Nonce:      101,
		EType:      []int32{tgt.Key.KeyType},
	}
	bodyDER := mustMarshal(t, body)
	checksum, err := etype.Checksum(tgt.Key.KeyValue, 6, bodyDER)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := protocol.Authenticator{
		AuthenticatorVNO: 5,
		CRealm:           tgt.Client.Realm,
		CName:            *protocolPrincipalForTest(tgt.Client),
		Checksum:         &protocol.Checksum{ChecksumType: mandatoryChecksumType(tgt.Key.KeyType), Checksum: checksum},
		Ctime:            types.KerberosTime{Time: now, Present: true},
		Cusec:            int32(now.Nanosecond() / 1000),
	}
	authCipher, err := etype.Encrypt(tgt.Key.KeyValue, 7, mustMarshal(t, authenticator))
	if err != nil {
		t.Fatal(err)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(tgt.Ticket, &ticket); err != nil {
		t.Fatal(err)
	}
	apReq := protocol.APReq{
		PVNO: 5, MsgType: 14, Ticket: ticket,
		Authenticator: protocol.EncryptedData{EType: tgt.Key.KeyType, Cipher: authCipher},
	}
	return mustMarshal(t, protocol.TGSReq{
		PVNO: 5, MsgType: 12,
		PAData:  protocol.MethodData{{PADataType: paTGSReq, PADataValue: mustMarshal(t, apReq)}},
		ReqBody: body,
	})
}

func protocolPrincipalForTest(value principal.Principal) *protocol.PrincipalName {
	return &protocol.PrincipalName{NameType: int32(value.NameType), NameString: append([]string(nil), value.Components...)}
}

func kerberosTime(value time.Time) types.KerberosTime {
	return types.KerberosTime{Time: value, Present: true}
}
