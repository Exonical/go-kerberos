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
	server, kclient := testServer(t, now)
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
	if len(methodData) != 1 || methodData[0].PADataType != 19 {
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
