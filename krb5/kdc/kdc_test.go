package kdc

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/fast"
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

func TestServerFASTASExchange(t *testing.T) {
	now := time.Unix(2000000050, 0).UTC()
	_, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	armorTGT, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("armor ASExchange: %v", err)
	}
	credentials, err := kclient.ASExchangeFAST(context.Background(), user, "alice-password", armorTGT)
	if err != nil {
		t.Fatalf("FAST ASExchange: %v", err)
	}
	if !samePrincipal(credentials.Client, user) || credentials.Server.Components[0] != "krbtgt" {
		t.Fatalf("FAST credentials = %#v", credentials)
	}
}

func TestServerFASTRejectsMalformedArmor(t *testing.T) {
	now := time.Unix(2000000060, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	armorTGT, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("armor ASExchange: %v", err)
	}
	armor, err := fast.NewArmor(fast.TGT{
		Ticket: armorTGT.Ticket, Client: armorTGT.Client, Key: armorTGT.Key,
	}, now)
	if err != nil {
		t.Fatalf("new armor: %v", err)
	}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"},
	}, 7)
	fastData, err := armor.WrapASReq(request.ReqBody, nil)
	if err != nil {
		t.Fatalf("wrap FAST request: %v", err)
	}
	fastData.PADataValue[len(fastData.PADataValue)-1] ^= 0xff
	request.PAData = protocol.MethodData{fastData}
	response := server.HandleMessage(mustMarshal(t, request))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("malformed FAST response: %v", err)
	}
	if kerberosError.ErrorCode == 0 {
		t.Fatal("malformed FAST request unexpectedly succeeded")
	}
}

func TestServerFASTRejectsBadChecksumAndGarbage(t *testing.T) {
	now := time.Unix(2000000070, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	armorTGT, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("armor ASExchange: %v", err)
	}
	armor, err := fast.NewArmor(fast.TGT{
		Ticket: armorTGT.Ticket, Client: armorTGT.Client, Key: armorTGT.Key,
	}, now)
	if err != nil {
		t.Fatalf("new armor: %v", err)
	}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"},
	}, 8)
	fastData, err := armor.WrapASReq(request.ReqBody, nil)
	if err != nil {
		t.Fatalf("wrap FAST request: %v", err)
	}
	var wrapper protocol.PAFXFastRequest
	if err := asn1.Unmarshal(fastData.PADataValue, &wrapper); err != nil {
		t.Fatalf("decode FAST request: %v", err)
	}
	wrapper.ArmoredData.ReqChecksum.Checksum[0] ^= 0xff
	fastData.PADataValue = mustMarshal(t, wrapper)
	request.PAData = protocol.MethodData{fastData}
	assertKRBError(t, server.HandleMessage(mustMarshal(t, request)))

	fastData, err = armor.WrapASReq(request.ReqBody, nil)
	if err != nil {
		t.Fatalf("rewrap FAST request: %v", err)
	}
	if err := asn1.Unmarshal(fastData.PADataValue, &wrapper); err != nil {
		t.Fatalf("decode fresh FAST request: %v", err)
	}
	wrapper.ArmoredData.Armor.ArmorValue[len(wrapper.ArmoredData.Armor.ArmorValue)-1] ^= 0xff
	request.PAData[0].PADataValue = mustMarshal(t, wrapper)
	assertKRBError(t, server.HandleMessage(mustMarshal(t, request)))

	fastData, err = armor.WrapASReq(request.ReqBody, nil)
	if err != nil {
		t.Fatalf("rewrap FAST request: %v", err)
	}
	fastData.PADataValue[len(fastData.PADataValue)-1] ^= 0xff
	request.PAData[0].PADataValue = fastData.PADataValue
	assertKRBError(t, server.HandleMessage(mustMarshal(t, request)))

	request.PAData[0].PADataValue = []byte{0x01, 0x02, 0x03}
	assertKRBError(t, server.HandleMessage(mustMarshal(t, request)))
}

func assertKRBError(t *testing.T, response []byte) {
	t.Helper()
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("FAST error response: %v", err)
	}
	if kerberosError.ErrorCode == 0 {
		t.Fatal("FAST request unexpectedly succeeded")
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

func TestASDisablePreauth(t *testing.T) {
	now := time.Unix(2000000150, 0).UTC()
	server, _ := testServer(t, now)
	server.DisablePreauth = true
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}

	request := asRequest(user, service, 150)
	request.PAData = nil
	part := asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if part.Flags&types.TicketPreAuthent != 0 {
		t.Fatalf("unpreauthenticated AS reply flags = %#x, has preauthenticated flag", part.Flags)
	}

	request = asRequest(user, service, 151)
	addPreauth(t, &request, now)
	part = asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if part.Flags&types.TicketPreAuthent == 0 {
		t.Fatalf("preauthenticated AS reply flags = %#x, missing preauthenticated flag", part.Flags)
	}
}

func TestASAndTGSApplyDefaultTicketLife(t *testing.T) {
	now := time.Unix(2000000175, 0).UTC()
	server, kclient := testServer(t, now)
	server.DefaultTicketLife = 4 * time.Hour
	server.MaxTicketLife = 10 * time.Hour
	if got := server.ticketEndFrom(kerberosTime(now.Add(8*time.Hour)), now); !got.Time.Equal(now.Add(8 * time.Hour)) {
		t.Fatalf("explicit-till end-time = %v, want %v", got.Time, now.Add(8*time.Hour))
	}
	server.DefaultTicketLife = 2 * time.Hour
	server.MaxTicketLife = 3 * time.Hour
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}

	if got := server.ticketEndFrom(types.KerberosTime{}, now); !got.Time.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("zero-till end-time = %v, want %v", got.Time, now.Add(2*time.Hour))
	}

	request := asRequest(user, service, 175)
	request.ReqBody.Till = kerberosTime(time.Unix(0, 0).UTC())
	addPreauth(t, &request, now)
	part := asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if !part.EndTime.Time.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("AS end-time = %v, want %v", part.EndTime.Time, now.Add(2*time.Hour))
	}

	request = asRequest(user, service, 176)
	request.ReqBody.Till = kerberosTime(time.Unix(0, 0).UTC())
	addPreauth(t, &request, now)
	part = asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if !part.EndTime.Time.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("AS epoch-till end-time = %v, want %v", part.EndTime.Time, now.Add(2*time.Hour))
	}

	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	tgsResponse := server.HandleMessage(rawTGSRequestWithTill(t, tgt, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"},
	}, now, kerberosTime(time.Unix(0, 0).UTC()), 0))
	tgsPart := tgsReplyPart(t, tgsResponse, tgt.Key)
	if !tgsPart.EndTime.Time.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("TGS end-time = %v, want %v", tgsPart.EndTime.Time, now.Add(2*time.Hour))
	}
	server.DefaultTicketLife = 4 * time.Hour
	tgsResponse = server.HandleMessage(rawTGSRequestWithTill(t, tgt, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"},
	}, now.Add(time.Second), kerberosTime(time.Unix(0, 0).UTC()), 0))
	tgsPart = tgsReplyPart(t, tgsResponse, tgt.Key)
	if !tgsPart.EndTime.Time.Equal(now.Add(3 * time.Hour)) {
		t.Fatalf("TGS max-capped end-time = %v, want %v", tgsPart.EndTime.Time, now.Add(3*time.Hour))
	}
}

func TestServerPolicyClearsDisallowedFlags(t *testing.T) {
	now := time.Unix(2000000180, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt := issueASTicket(t, server, user, now,
		types.KDCForwardable|types.KDCProxiable|types.KDCRenewable, now.Add(2*time.Hour))
	server.Policy = &Policy{}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	for i, option := range []types.KDCOptions{types.KDCForwardable, types.KDCProxiable, types.KDCRenewable} {
		request := asRequest(user, service, uint32(180+i))
		request.ReqBody.KDCOptions = option
		addPreauth(t, &request, now)
		part := asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
		var flag types.TicketFlags
		switch option {
		case types.KDCForwardable:
			flag = types.TicketForwardable
		case types.KDCProxiable:
			flag = types.TicketProxiable
		case types.KDCRenewable:
			flag = types.TicketRenewable
		}
		if part.Flags&flag != 0 {
			t.Fatalf("AS option %#x granted disallowed flag %#x", option, flag)
		}
	}

	service = principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	for _, option := range []types.KDCOptions{types.KDCForwardable, types.KDCProxiable, types.KDCRenewable} {
		response := server.HandleMessage(rawTGSRequest(t, tgt, service, now, option))
		part := tgsReplyPart(t, response, tgt.Key)
		var flag types.TicketFlags
		switch option {
		case types.KDCForwardable:
			flag = types.TicketForwardable
		case types.KDCProxiable:
			flag = types.TicketProxiable
		case types.KDCRenewable:
			flag = types.TicketRenewable
		}
		if part.Flags&flag != 0 {
			t.Fatalf("TGS option %#x granted disallowed flag %#x", option, flag)
		}
	}
}

func TestASAndTGSIssueAndPropagateProxiable(t *testing.T) {
	now := time.Unix(2000000190, 0).UTC()
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}

	server, _ := testServer(t, now)
	request := asRequest(user, service, 190)
	request.ReqBody.KDCOptions = types.KDCProxiable
	addPreauth(t, &request, now)
	part := asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if part.Flags&types.TicketProxiable == 0 {
		t.Fatalf("nil-policy AS flags = %#x, missing proxiable", part.Flags)
	}
	tgt := issueASTicket(t, server, user, now, types.KDCProxiable, now.Add(time.Hour))
	service = principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	tgsPart := tgsReplyPart(t, server.HandleMessage(rawTGSRequest(t, tgt, service, now, 0)), tgt.Key)
	if tgsPart.Flags&types.TicketProxiable == 0 {
		t.Fatalf("propagated TGS flags = %#x, missing proxiable", tgsPart.Flags)
	}

	server, _ = testServer(t, now)
	server.Policy = &Policy{AllowProxiable: true}
	request = asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"},
	}, 191)
	request.ReqBody.KDCOptions = types.KDCProxiable
	addPreauth(t, &request, now)
	part = asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if part.Flags&types.TicketProxiable == 0 {
		t.Fatalf("allowed-policy AS flags = %#x, missing proxiable", part.Flags)
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

func TestCrossRealmTGSExchange(t *testing.T) {
	now := time.Unix(2000001200, 0).UTC()
	realmA, realmB := "REALM.A", "REALM.B"
	dbA := kdb.NewDatabase(realmA)
	for _, entry := range []struct {
		name, password string
	}{
		{"alice@" + realmA, "alice-password"},
		{"krbtgt/" + realmA, "realm-a-tgt"},
		{"krbtgt/" + realmB + "@" + realmA, "shared-password"},
	} {
		if err := dbA.AddPrincipal(entry.name, entry.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	dbB := kdb.NewDatabase(realmB)
	for _, entry := range []struct {
		name, password string
	}{
		{"krbtgt/" + realmB, "realm-b-tgt"},
		{"krbtgt/" + realmB + "@" + realmA, "shared-password"},
		{"host/backend@" + realmB, "backend-password"},
	} {
		if err := dbB.AddPrincipal(entry.name, entry.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	serverA := &Server{Realm: realmA, DB: dbA, Now: func() time.Time { return now }}
	serverB := &Server{Realm: realmB, DB: dbB, Now: func() time.Time { return now }}
	kclient := &client.Client{
		Now: func() time.Time { return now },
		Exchange: func(ctx context.Context, realm string, payload []byte) ([]byte, error) {
			switch realm {
			case realmA:
				return serverA.HandleMessage(payload), nil
			case realmB:
				return serverB.HandleMessage(payload), nil
			default:
				t.Fatalf("unexpected exchange realm %q", realm)
				return nil, errors.New("unexpected realm")
			}
		},
	}
	user := principal.Principal{Realm: realmA, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("AS exchange: %v", err)
	}
	service := principal.Principal{
		Realm: realmB, NameType: principal.NTSrvHst, Components: []string{"host", "backend"},
	}
	credentials, err := kclient.TGSExchange(context.Background(), tgt, service)
	if err != nil {
		t.Fatalf("cross-realm TGS exchange: %v", err)
	}
	if credentials.Server.Realm != realmB || credentials.Server.Components[0] != "host" ||
		credentials.Server.Components[1] != "backend" {
		t.Fatalf("service credentials = %#v", credentials)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(credentials.Ticket, &ticket); err != nil {
		t.Fatalf("ticket: %v", err)
	}
	record, ok, err := dbB.Lookup(principal.Principal{
		Realm: realmB, NameType: principal.NTSrvHst, Components: []string{"host", "backend"},
	})
	if err != nil || !ok {
		t.Fatalf("service lookup: %v %v", err, ok)
	}
	key, ok := record.Keys[credentials.Key.KeyType]
	if !ok {
		t.Fatalf("service key enctype %d missing", credentials.Key.KeyType)
	}
	etype, err := crypto.NewRegistry().Get(key.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := etype.Decrypt(key.Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt service ticket: %v", err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plaintext, &part); err != nil {
		t.Fatalf("service ticket part: %v", err)
	}
	if part.CRealm != realmA || len(part.CName.NameString) != 1 || part.CName.NameString[0] != "alice" {
		t.Fatalf("foreign client = %s/%#v", part.CRealm, part.CName)
	}
	if part.Transited.TrType != 1 {
		t.Fatalf("transited type = %d, want DOMAIN-X500-COMPRESS (1)", part.Transited.TrType)
	}
	if got := string(part.Transited.Contents); got != realmA {
		t.Fatalf("transited contents = %q, want %q", got, realmA)
	}
}

func TestCapathMultiHopTGSExchange(t *testing.T) {
	now := time.Unix(2000001300, 0).UTC()
	realmA, realmB, realmC := "REALM.A", "REALM.B", "REALM.C"
	dbA := kdb.NewDatabase(realmA)
	for _, entry := range []struct{ name, password string }{
		{"alice@" + realmA, "alice-password"},
		{"krbtgt/" + realmA, "realm-a-tgt"},
		{"krbtgt/" + realmB + "@" + realmA, "a-b-shared"},
	} {
		if err := dbA.AddPrincipal(entry.name, entry.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	dbB := kdb.NewDatabase(realmB)
	for _, entry := range []struct{ name, password string }{
		{"krbtgt/" + realmB, "realm-b-tgt"},
		{"krbtgt/" + realmB + "@" + realmA, "a-b-shared"},
		{"krbtgt/" + realmC + "@" + realmB, "b-c-shared"},
	} {
		if err := dbB.AddPrincipal(entry.name, entry.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	dbC := kdb.NewDatabase(realmC)
	for _, entry := range []struct{ name, password string }{
		{"krbtgt/" + realmC, "realm-c-tgt"},
		{"krbtgt/" + realmC + "@" + realmB, "b-c-shared"},
		{"host/backend@" + realmC, "backend-password"},
	} {
		if err := dbC.AddPrincipal(entry.name, entry.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	serverA := &Server{Realm: realmA, DB: dbA, Now: func() time.Time { return now }}
	serverB := &Server{Realm: realmB, DB: dbB, Now: func() time.Time { return now }}
	serverC := &Server{
		Realm: realmC, DB: dbC, Now: func() time.Time { return now },
		Capaths: map[string]map[string][]string{realmA: {realmC: {realmB}}},
	}
	clientConfig := &config.Config{
		CapathOptions: map[string]map[string][]string{realmA: {realmC: {realmB}}},
	}
	var bTransit string
	kclient := &client.Client{
		Config: clientConfig,
		Now:    func() time.Time { return now },
		Exchange: func(ctx context.Context, realm string, payload []byte) ([]byte, error) {
			var response []byte
			switch realm {
			case realmA:
				response = serverA.HandleMessage(payload)
			case realmB:
				response = serverB.HandleMessage(payload)
				var rep protocol.TGSRep
				if err := asn1.Unmarshal(response, &rep); err == nil {
					keyRecord, ok, err := dbC.Lookup(principal.Principal{
						Realm: realmB, NameType: principal.NTSrvInstance,
						Components: []string{"krbtgt", realmC},
					})
					if err != nil || !ok {
						t.Fatalf("B/C key lookup: %v %v", err, ok)
					}
					key := keyRecord.Keys[rep.Ticket.EncPart.EType]
					etype, err := crypto.NewRegistry().Get(key.Enctype)
					if err != nil {
						t.Fatal(err)
					}
					plain, err := etype.Decrypt(key.Key, 2, rep.Ticket.EncPart.Cipher)
					if err != nil {
						t.Fatalf("decrypt B-issued TGT: %v", err)
					}
					var part protocol.EncTicketPart
					if err := asn1.Unmarshal(plain, &part); err != nil {
						t.Fatal(err)
					}
					bTransit = string(part.Transited.Contents)
				}
			case realmC:
				response = serverC.HandleMessage(payload)
			default:
				return nil, errors.New("unexpected realm")
			}
			return response, nil
		},
	}
	user := principal.Principal{Realm: realmA, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("AS exchange: %v", err)
	}
	serverC.Capaths = nil
	_, err = kclient.TGSExchange(context.Background(), tgt, principal.Principal{
		Realm: realmC, NameType: principal.NTSrvHst, Components: []string{"host", "backend"},
	})
	if err == nil || !hasKRBCode(err, kdcErrPolicy) {
		t.Fatalf("unconfigured transited path error = %v, want KDC_ERR_POLICY", err)
	}
	serverC.Capaths = map[string]map[string][]string{realmA: {realmC: {realmB}}}
	credentials, err := kclient.TGSExchange(context.Background(), tgt, principal.Principal{
		Realm: realmC, NameType: principal.NTSrvHst, Components: []string{"host", "backend"},
	})
	if err != nil {
		t.Fatalf("multi-hop TGS exchange: %v", err)
	}
	if bTransit != realmA {
		t.Fatalf("B-issued TGT transited = %q, want %q", bTransit, realmA)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(credentials.Ticket, &ticket); err != nil {
		t.Fatal(err)
	}
	record, ok, err := dbC.Lookup(principal.Principal{
		Realm: realmC, NameType: principal.NTSrvHst, Components: []string{"host", "backend"},
	})
	if err != nil || !ok {
		t.Fatalf("service lookup: %v %v", err, ok)
	}
	key := record.Keys[ticket.EncPart.EType]
	etype, err := crypto.NewRegistry().Get(key.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(key.Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	if got := string(part.Transited.Contents); got != realmA+","+realmB {
		t.Fatalf("C service ticket transited = %q, want %q", got, realmA+","+realmB)
	}
	if part.Flags&types.TicketTransited == 0 {
		t.Fatal("C service ticket lacks TRANSITED-POLICY-CHECKED")
	}
}

func TestCrossRealmTGSRequiresSharedTGTKey(t *testing.T) {
	now := time.Unix(2000001210, 0).UTC()
	realmA, realmB := "REALM.A", "REALM.B"
	dbA := kdb.NewDatabase(realmA)
	for _, entry := range []struct{ name, password string }{
		{"alice@" + realmA, "alice-password"},
		{"krbtgt/" + realmA, "realm-a-tgt"},
	} {
		if err := dbA.AddPrincipal(entry.name, entry.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	dbB := kdb.NewDatabase(realmB)
	for _, entry := range []struct{ name, password string }{
		{"krbtgt/" + realmB, "realm-b-tgt"},
		{"host/backend@" + realmB, "backend-password"},
	} {
		if err := dbB.AddPrincipal(entry.name, entry.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	serverA := &Server{Realm: realmA, DB: dbA, Now: func() time.Time { return now }}
	serverB := &Server{Realm: realmB, DB: dbB, Now: func() time.Time { return now }}
	kclient := &client.Client{
		Now: func() time.Time { return now },
		Exchange: func(ctx context.Context, realm string, payload []byte) ([]byte, error) {
			if realm == realmA {
				return serverA.HandleMessage(payload), nil
			}
			return serverB.HandleMessage(payload), nil
		},
	}
	user := principal.Principal{Realm: realmA, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	_, err = kclient.TGSExchange(context.Background(), tgt, principal.Principal{
		Realm: realmB, NameType: principal.NTSrvHst, Components: []string{"host", "backend"},
	})
	if err == nil || !hasKRBCode(err, 7) {
		t.Fatalf("missing cross-realm key error = %v, want code 7", err)
	}
	if err := dbA.AddPrincipal("krbtgt/"+realmB+"@"+realmA, "shared-password", 1); err != nil {
		t.Fatal(err)
	}
	if err := dbB.AddPrincipal("krbtgt/"+realmB+"@"+realmA, "wrong-password", 1); err != nil {
		t.Fatal(err)
	}
	_, err = kclient.TGSExchange(context.Background(), tgt, principal.Principal{
		Realm: realmB, NameType: principal.NTSrvHst, Components: []string{"host", "backend"},
	})
	if err == nil || !hasKRBCode(err, 31) {
		t.Fatalf("wrong cross-realm key error = %v, want code 31", err)
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

func TestTGSRejectsRenewalOfNonrenewableTicket(t *testing.T) {
	now := time.Unix(2000001300, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	response := server.HandleMessage(rawTGSRequest(t, tgt, service, now, types.KDCRenew))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("renew response: %v", err)
	}
	if kerberosError.ErrorCode != kdcErrBadOption {
		t.Fatalf("renew error code = %d, want %d", kerberosError.ErrorCode, kdcErrBadOption)
	}
}

func TestTGSRejectsExpiredRenewal(t *testing.T) {
	now := time.Unix(2000001400, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt := issueASTicket(t, server, user, now, types.KDCRenewable, now.Add(30*time.Minute))
	expired := now.Add(31 * time.Minute)
	server.Now = func() time.Time { return expired }
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	response := server.HandleMessage(rawTGSRequest(t, tgt, service, expired, types.KDCRenew))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("expired renew response: %v", err)
	}
	if kerberosError.ErrorCode != krbAPErrTktExpired {
		t.Fatalf("expired renew error code = %d, want %d", kerberosError.ErrorCode, krbAPErrTktExpired)
	}
}

func TestTGSRejectsRenewalAfterTicketEndTime(t *testing.T) {
	now := time.Unix(2000001450, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt := issueASTicket(t, server, user, now, types.KDCRenewable, now.Add(3*time.Hour))
	expired := now.Add(2 * time.Hour)
	server.Now = func() time.Time { return expired }
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	response := server.HandleMessage(rawTGSRequest(t, tgt, service, expired, types.KDCRenew))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("expired-ticket renew response: %v", err)
	}
	if kerberosError.ErrorCode != krbAPErrTktExpired {
		t.Fatalf("expired-ticket renew error code = %d, want %d", kerberosError.ErrorCode, krbAPErrTktExpired)
	}
}

func TestTGSRejectsRenewalOfInvalidTicket(t *testing.T) {
	now := time.Unix(2000001475, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	start := now.Add(time.Hour)
	tgt := issueASTicket(t, server, user, now,
		types.KDCAllowPostdate|types.KDCPostdated|types.KDCRenewable, start)
	renewNow := start.Add(time.Minute)
	server.Now = func() time.Time { return renewNow }
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	response := server.HandleMessage(rawTGSRequest(t, tgt, service, renewNow, types.KDCRenew))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("invalid-ticket renew response: %v", err)
	}
	if kerberosError.ErrorCode != krbAPErrTktNYV {
		t.Fatalf("invalid-ticket renew error code = %d, want %d", kerberosError.ErrorCode, krbAPErrTktNYV)
	}
}

func TestTGSValidateRejectsExpiredTicket(t *testing.T) {
	now := time.Unix(2000001500, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	start := now.Add(time.Hour)
	tgt := issueASTicket(t, server, user, now, types.KDCAllowPostdate|types.KDCPostdated, start)
	expired := start.Add(2 * time.Hour)
	server.Now = func() time.Time { return expired }
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"krbtgt", "TEST.REALM"}}
	response := server.HandleMessage(rawTGSRequest(t, tgt, service, expired, types.KDCValidate))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("expired-ticket validate response: %v", err)
	}
	if kerberosError.ErrorCode != krbAPErrTktExpired {
		t.Fatalf("expired-ticket validate error code = %d, want %d", kerberosError.ErrorCode, krbAPErrTktExpired)
	}
}

func TestTGSValidateRequiresInvalidTicket(t *testing.T) {
	now := time.Unix(2000001500, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	response := server.HandleMessage(rawTGSRequest(t, tgt, service, now, types.KDCValidate))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("validate response: %v", err)
	}
	if kerberosError.ErrorCode != kdcErrBadOption {
		t.Fatalf("validate error code = %d, want %d", kerberosError.ErrorCode, kdcErrBadOption)
	}
}

func TestASRejectsUnauthorizedPostdate(t *testing.T) {
	now := time.Unix(2000001600, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	request := asRequest(user, service, 1)
	request.ReqBody.KDCOptions = types.KDCPostdated
	from := kerberosTime(now.Add(time.Hour))
	request.ReqBody.From = &from
	request.ReqBody.Till = kerberosTime(now.Add(2 * time.Hour))
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := etype.StringToKey([]byte("alice-password"), []byte("TEST.REALMalice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := mustMarshal(t, preauth.EncTimestamp{PATimestamp: kerberosTime(now)})
	timestampCipher, err := etype.Encrypt(key, 1, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	request.PAData = protocol.MethodData{{PADataType: paEncTimestamp, PADataValue: timestampCipher}}
	response := server.HandleMessage(mustMarshal(t, request))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("postdate response: %v", err)
	}
	if kerberosError.ErrorCode != kdcErrCannotPostdate {
		t.Fatalf("postdate error code = %d, want %d", kerberosError.ErrorCode, kdcErrCannotPostdate)
	}
}

func TestReplayCacheExpiresEntries(t *testing.T) {
	now := time.Unix(2000001700, 0).UTC()
	server, _ := testServer(t, now)
	authenticator := protocol.Authenticator{
		Ctime:    kerberosTime(now),
		Cusec:    7,
		Checksum: &protocol.Checksum{ChecksumType: 15, Checksum: []byte{1, 2, 3}},
	}
	name := protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: []string{"alice"}}
	if server.replayed("TEST.REALM", name, authenticator) {
		t.Fatal("first authenticator incorrectly classified as replay")
	}
	if !server.replayed("TEST.REALM", name, authenticator) {
		t.Fatal("duplicate authenticator was not classified as replay")
	}
	server.Now = func() time.Time { return now.Add(server.skew() + time.Second) }
	if server.replayed("TEST.REALM", name, authenticator) {
		t.Fatal("expired authenticator incorrectly classified as replay")
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
	return rawTGSRequestWithTill(t, tgt, service, now, kerberosTime(now.Add(time.Hour)), options)
}

func rawTGSRequestWithTill(t *testing.T, tgt *client.Credentials, service principal.Principal, now time.Time, till types.KerberosTime, options types.KDCOptions) []byte {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	body := protocol.KDCReqBody{
		KDCOptions: options,
		Realm:      service.Realm,
		SName:      &protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
		Till:       till,
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

func addPreauth(t *testing.T, request *protocol.ASReq, now time.Time) {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := etype.StringToKey([]byte("alice-password"), []byte("TEST.REALMalice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := mustMarshal(t, preauth.EncTimestamp{PATimestamp: kerberosTime(now)})
	cipher, err := etype.Encrypt(key, 1, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	request.PAData = protocol.MethodData{{PADataType: paEncTimestamp, PADataValue: cipher}}
}

func asReplyPart(t *testing.T, response []byte) protocol.EncASRepPart {
	t.Helper()
	var reply protocol.ASRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("AS response: %v", err)
	}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := etype.StringToKey([]byte("alice-password"), []byte("TEST.REALMalice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(key, 3, reply.EncPart.Cipher)
	if err != nil {
		t.Fatalf("AS reply decrypt: %v", err)
	}
	var part protocol.EncASRepPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatalf("AS reply part: %v", err)
	}
	return part
}

func tgsReplyPart(t *testing.T, response []byte, key protocol.EncryptionKey) protocol.EncTGSRepPart {
	t.Helper()
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		var kerberosError protocol.KRBError
		if decodeErr := asn1.Unmarshal(response, &kerberosError); decodeErr == nil {
			t.Fatalf("TGS error code %d", kerberosError.ErrorCode)
		}
		t.Fatalf("TGS response: %v", err)
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(key.KeyValue, 8, reply.EncPart.Cipher)
	if err != nil {
		t.Fatalf("TGS reply decrypt: %v", err)
	}
	var part protocol.EncTGSRepPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatalf("TGS reply part: %v", err)
	}
	return part
}
