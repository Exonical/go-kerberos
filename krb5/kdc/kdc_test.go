package kdc

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/otp"
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/spake"
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

func TestServerUserToUserExchangeAndAPVerification(t *testing.T) {
	now := time.Unix(2000000010, 0).UTC()
	server, kclient := testServer(t, now)
	db := server.DB.(*kdb.Database)
	if err := db.AddPrincipal("bob", "bob-password", 1); err != nil {
		t.Fatal(err)
	}
	alice := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	bob := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"bob"}}
	aliceTGT, err := kclient.ASExchange(context.Background(), alice, "alice-password")
	if err != nil {
		t.Fatalf("alice ASExchange: %v", err)
	}
	bobTGT, err := kclient.ASExchange(context.Background(), bob, "bob-password")
	if err != nil {
		t.Fatalf("bob ASExchange: %v", err)
	}
	credentials, err := kclient.TGSExchangeU2U(context.Background(), bobTGT, aliceTGT.Ticket, alice)
	if err != nil {
		t.Fatalf("TGSExchangeU2U: %v", err)
	}
	if !credentials.IsSKey || !bytes.Equal(credentials.SecondTicket, aliceTGT.Ticket) {
		t.Fatalf("U2U credentials metadata = %#v", credentials)
	}
	if !samePrincipal(credentials.Server, alice) {
		t.Fatalf("U2U server = %v, want %v", credentials.Server, alice)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(credentials.Ticket, &ticket); err != nil {
		t.Fatalf("U2U ticket: %v", err)
	}
	peerEType, err := crypto.NewRegistry().Get(aliceTGT.Key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	alicePlain, err := peerEType.Decrypt(aliceTGT.Key.KeyValue, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt U2U ticket: %v", err)
	}
	var aliceTicketPart protocol.EncTicketPart
	if err := asn1.Unmarshal(alicePlain, &aliceTicketPart); err != nil {
		t.Fatalf("U2U ticket part: %v", err)
	}
	if !bytes.Equal(aliceTicketPart.Key.KeyValue, credentials.Key.KeyValue) {
		t.Fatal("U2U ticket could not be decrypted with peer TGT session key")
	}
	_, apDER, err := ap.BuildAPReq(credentials, types.APUseSessionKey, now)
	if err != nil {
		t.Fatalf("BuildAPReq U2U: %v", err)
	}
	verified, err := ap.VerifyAPReqWithSessionKey(aliceTGT.Key, apDER, now, 5*time.Minute)
	if err != nil {
		t.Fatalf("VerifyAPReqWithSessionKey: %v", err)
	}
	if !samePrincipal(verified.Client, bob) || !samePrincipal(verified.Server, alice) {
		t.Fatalf("verified U2U AP-REQ = %#v", verified)
	}
}

func TestServerUserToUserRejectsInvalidSecondTickets(t *testing.T) {
	now := time.Unix(2000000015, 0).UTC()
	server, kclient := testServer(t, now)
	db := server.DB.(*kdb.Database)
	if err := db.AddPrincipal("bob", "bob-password", 1); err != nil {
		t.Fatal(err)
	}
	alice := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	bob := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"bob"}}
	aliceTGT, err := kclient.ASExchange(context.Background(), alice, "alice-password")
	if err != nil {
		t.Fatalf("alice ASExchange: %v", err)
	}
	bobTGT, err := kclient.ASExchange(context.Background(), bob, "bob-password")
	if err != nil {
		t.Fatalf("bob ASExchange: %v", err)
	}
	tests := []struct {
		name       string
		additional []protocol.Ticket
		want       int32
	}{
		{name: "missing", want: kdcErrBadOption},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := server.HandleMessage(rawTGSRequestWithPadata(t, bobTGT, alice, now,
				types.KDCEncTktInSkey, nil, test.additional))
			var kerberosError protocol.KRBError
			if err := asn1.Unmarshal(response, &kerberosError); err != nil {
				t.Fatalf("KRB-ERROR: %v", err)
			}
			if kerberosError.ErrorCode != test.want {
				t.Fatalf("error code = %d, want %d", kerberosError.ErrorCode, test.want)
			}
		})
	}
	ordinary, err := kclient.TGSExchange(context.Background(), aliceTGT,
		principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}})
	if err != nil {
		t.Fatalf("ordinary TGSExchange: %v", err)
	}
	var nonTGT protocol.Ticket
	if err := asn1.Unmarshal(ordinary.Ticket, &nonTGT); err != nil {
		t.Fatal(err)
	}
	var second protocol.Ticket
	if err := asn1.Unmarshal(aliceTGT.Ticket, &second); err != nil {
		t.Fatal(err)
	}
	second.Realm = "FOREIGN.REALM"
	for _, test := range []struct {
		name string
		tkt  protocol.Ticket
		want int32
	}{
		{name: "non-tgt", tkt: nonTGT, want: kdcErrPolicy},
		{name: "wrong-realm", tkt: second, want: kdcErrPolicy},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := server.HandleMessage(rawTGSRequestWithPadata(t, bobTGT, alice, now,
				types.KDCEncTktInSkey, nil, []protocol.Ticket{test.tkt}))
			var kerberosError protocol.KRBError
			if err := asn1.Unmarshal(response, &kerberosError); err != nil {
				t.Fatalf("KRB-ERROR: %v", err)
			}
			if kerberosError.ErrorCode != test.want {
				t.Fatalf("error code = %d, want %d", kerberosError.ErrorCode, test.want)
			}
		})
	}
	second.Realm = "TEST.REALM"
	t.Run("multiple", func(t *testing.T) {
		response := server.HandleMessage(rawTGSRequestWithPadata(t, bobTGT, alice, now,
			types.KDCEncTktInSkey, nil, []protocol.Ticket{second, second}))
		var kerberosError protocol.KRBError
		if err := asn1.Unmarshal(response, &kerberosError); err != nil {
			t.Fatalf("KRB-ERROR: %v", err)
		}
		if kerberosError.ErrorCode != kdcErrBadOption {
			t.Fatalf("error code = %d, want %d", kerberosError.ErrorCode, kdcErrBadOption)
		}
	})
}

func TestServerAuthorizationHookASAndTGS(t *testing.T) {
	now := time.Unix(2000000020, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	var gotClient, gotService principal.Principal
	var gotAS bool
	server.Authorize = func(client, requestedService principal.Principal, asExchange bool) error {
		gotClient, gotService, gotAS = client, requestedService, asExchange
		return errors.New("authorization denied")
	}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"},
	}, 1)
	asService := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"},
	}
	addPreauthPassword(t, &request, "alice-password", now)
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &kerberosError); err != nil {
		t.Fatalf("AS authorization response: %v", err)
	}
	if kerberosError.ErrorCode != kdcErrPolicy {
		t.Fatalf("AS authorization code = %d, want %d", kerberosError.ErrorCode, kdcErrPolicy)
	}
	if kerberosError.EText == nil || *kerberosError.EText != "authorization denied" {
		t.Fatalf("AS authorization text = %v, want authorization denied", kerberosError.EText)
	}
	if !samePrincipal(gotClient, user) || !samePrincipal(gotService, asService) || !gotAS {
		t.Fatalf("AS authorization arguments = %v, %v, %v", gotClient, gotService, gotAS)
	}

	server.Authorize = func(principal.Principal, principal.Principal, bool) error { return nil }
	if _, err := kclient.ASExchange(context.Background(), user, "alice-password"); err != nil {
		t.Fatalf("allowed AS exchange: %v", err)
	}

	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("TGS setup AS exchange: %v", err)
	}
	server.Authorize = func(client, requestedService principal.Principal, asExchange bool) error {
		if asExchange {
			t.Fatal("TGS authorization unexpectedly marked as AS exchange")
		}
		if !samePrincipal(client, user) || !samePrincipal(requestedService, service) {
			t.Fatalf("TGS authorization arguments = %v, %v", client, requestedService)
		}
		return errors.New("TGS authorization denied")
	}
	if err := asn1.Unmarshal(server.HandleMessage(rawTGSRequest(t, tgt, service, now, 0)), &kerberosError); err != nil {
		t.Fatalf("TGS authorization response: %v", err)
	}
	if kerberosError.ErrorCode != kdcErrPolicy {
		t.Fatalf("TGS authorization code = %d, want %d", kerberosError.ErrorCode, kdcErrPolicy)
	}
	if kerberosError.EText == nil || *kerberosError.EText != "TGS authorization denied" {
		t.Fatalf("TGS authorization text = %v, want TGS authorization denied", kerberosError.EText)
	}

	server.Authorize = nil
	if _, err := kclient.TGSExchange(context.Background(), tgt, service); err != nil {
		t.Fatalf("nil authorization hook TGS exchange: %v", err)
	}
}

func TestServerAuthorizationHookMapsKRBErrorCodes(t *testing.T) {
	now := time.Unix(2000000025, 0).UTC()
	tests := []struct {
		name string
		err  error
		want int32
	}{
		{
			name: "wrapped policy",
			err:  fmt.Errorf("wrapped: %w", krberrors.NewKRBError(12, "", "TEST.REALM", now, 0, nil)),
			want: kdcErrPolicy,
		},
		{
			name: "wrapped client revoked",
			err:  fmt.Errorf("wrapped: %w", krberrors.NewKRBError(18, "", "TEST.REALM", now, 0, nil)),
			want: kdcErrClientRevoked,
		},
		{name: "plain error", err: errors.New("plain authorization denial"), want: kdcErrPolicy},
		{
			name: "out of range",
			err:  krberrors.NewKRBError(129, "", "TEST.REALM", now, 0, nil),
			want: kdcErrGeneric,
		},
	}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, _ := testServer(t, now)
			server.Authorize = func(principal.Principal, principal.Principal, bool) error {
				return test.err
			}
			request := asRequest(user, service, 1)
			addPreauthPassword(t, &request, "alice-password", now)
			var kerberosError protocol.KRBError
			if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &kerberosError); err != nil {
				t.Fatalf("authorization response: %v", err)
			}
			if kerberosError.ErrorCode != test.want {
				t.Fatalf("authorization code = %d, want %d", kerberosError.ErrorCode, test.want)
			}
			if kerberosError.EText == nil || *kerberosError.EText != test.err.Error() {
				t.Fatalf("authorization text = %v, want %q", kerberosError.EText, test.err.Error())
			}
		})
	}
}

func TestServerFASTAuthorizationDenial(t *testing.T) {
	now := time.Unix(2000000030, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	armorTGT, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("armor AS exchange: %v", err)
	}
	server.Authorize = func(principal.Principal, principal.Principal, bool) error {
		return errors.New("FAST authorization denied")
	}
	if _, err := kclient.ASExchangeFAST(context.Background(), user, "alice-password", armorTGT); err == nil ||
		!hasKRBCode(err, kdcErrPolicy) {
		t.Fatalf("FAST authorization error = %v, want KDC_ERR_POLICY", err)
	}
}

func TestASAccountLockout(t *testing.T) {
	now := time.Unix(2000000100, 0).UTC()
	server, _ := testServer(t, now)
	db := server.DB.(*kdb.Database)
	if err := db.CreatePolicy(kdb.PolicyRecord{
		Name: "locked", MaxFailure: 2, FailureCountInterval: 60,
		LockoutDuration: 0,
	}); err != nil {
		t.Fatal(err)
	}
	user, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := db.Lookup(*user)
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v", err, ok)
	}
	record.Policy = "locked"
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"}}
	request := asRequest(*user, service, 1)
	addPreauthPassword(t, &request, "wrong-password", now)
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &kerberosError); err != nil {
		t.Fatal(err)
	}
	if kerberosError.ErrorCode != kdcErrPreauthFailed {
		t.Fatalf("first failure code = %d", kerberosError.ErrorCode)
	}
	record, _, _ = db.Lookup(*user)
	if record.FailAuthCount != 1 || !record.LastFailed.Equal(now) {
		t.Fatalf("first failure state = %#v", record)
	}
	request.ReqBody.Nonce++
	addPreauthPassword(t, &request, "wrong-password", now)
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &kerberosError); err != nil {
		t.Fatal(err)
	}
	record, _, _ = db.Lookup(*user)
	if record.FailAuthCount != 2 {
		t.Fatalf("second failure count = %d", record.FailAuthCount)
	}
	request.ReqBody.Nonce++
	addPreauthPassword(t, &request, "alice-password", now)
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &kerberosError); err != nil {
		t.Fatal(err)
	}
	if kerberosError.ErrorCode != kdcErrClientRevoked {
		t.Fatalf("locked account code = %d, want %d", kerberosError.ErrorCode, kdcErrClientRevoked)
	}
	server.Now = func() time.Time { return now.Add(61 * time.Second) }
	request.ReqBody.Nonce++
	addPreauthPassword(t, &request, "alice-password", now.Add(61*time.Second))
	var reply protocol.ASRep
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &reply); err != nil {
		t.Fatalf("post-interval AS reply: %v", err)
	}
	record, _, _ = db.Lookup(*user)
	if record.FailAuthCount != 0 || !record.LastSuccess.Equal(now.Add(61*time.Second)) {
		t.Fatalf("successful authentication state = %#v", record)
	}
}

func TestASSPAKEAccountLockout(t *testing.T) {
	now := time.Unix(2000000125, 0).UTC()
	server, kclient := testServer(t, now)
	server.EnableSPAKE = true
	db := server.DB.(*kdb.Database)
	if err := db.CreatePolicy(kdb.PolicyRecord{Name: "spake-locked", MaxFailure: 2}); err != nil {
		t.Fatal(err)
	}
	user, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := db.Lookup(*user)
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v", err, ok)
	}
	record.Policy = "spake-locked"
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := kclient.ASExchange(context.Background(), *user, "wrong-password"); err == nil ||
			!hasKRBCode(err, kdcErrPreauthFailed) {
			t.Fatalf("SPAKE attempt %d error = %v, want preauth failure", attempt, err)
		}
		record, _, err = db.Lookup(*user)
		if err != nil {
			t.Fatal(err)
		}
		if record.FailAuthCount != uint32(attempt) {
			t.Fatalf("SPAKE attempt %d failure count = %d", attempt, record.FailAuthCount)
		}
	}
	if _, err := kclient.ASExchange(context.Background(), *user, "alice-password"); err == nil ||
		!hasKRBCode(err, kdcErrClientRevoked) {
		t.Fatalf("SPAKE locked account error = %v, want client revoked", err)
	}
}

func TestASSPAKEExpiredCookie(t *testing.T) {
	now := time.Unix(2000000150, 0).UTC()
	server, _ := testServer(t, now)
	server.EnableSPAKE = true
	var calls int
	exchange := func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		calls++
		if calls == 2 {
			server.Now = func() time.Time { return now.Add(spakeCookieLifetime + time.Second) }
		}
		return server.HandleMessage(payload), nil
	}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	_, err := (&client.Client{Now: func() time.Time { return now }, Exchange: exchange}).ASExchange(
		context.Background(), user, "alice-password")
	if err == nil || !hasKRBCode(err, kdcErrPreauthFailed) {
		t.Fatalf("expired SPAKE cookie error = %v, want preauth failure", err)
	}
	if calls != 2 {
		t.Fatalf("AS exchange calls = %d, want 2", calls)
	}
}

func TestASAccountLockoutConcurrentFailuresAreAtomic(t *testing.T) {
	const attempts = 16
	now := time.Unix(2000000150, 0).UTC()
	server, _ := testServer(t, now)
	db := server.DB.(*kdb.Database)
	if err := db.CreatePolicy(kdb.PolicyRecord{
		Name: "concurrent", MaxFailure: attempts, LockoutDuration: 0,
	}); err != nil {
		t.Fatal(err)
	}
	user, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := db.Lookup(*user)
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v", err, ok)
	}
	record.Policy = "concurrent"
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"},
	}
	requests := make([][]byte, attempts)
	for i := range requests {
		request := asRequest(*user, service, uint32(i+1))
		addPreauthPassword(t, &request, "wrong-password", now)
		requests[i] = mustMarshal(t, request)
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(attempts)
	for _, request := range requests {
		request := request
		go func() {
			defer wait.Done()
			<-start
			server.HandleMessage(request)
		}()
	}
	close(start)
	wait.Wait()

	record, _, err = db.Lookup(*user)
	if err != nil {
		t.Fatal(err)
	}
	if record.FailAuthCount != attempts {
		t.Fatalf("concurrent failure count = %d, want %d", record.FailAuthCount, attempts)
	}

	request := asRequest(*user, service, attempts+1)
	addPreauthPassword(t, &request, "alice-password", now)
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &kerberosError); err != nil {
		t.Fatal(err)
	}
	if kerberosError.ErrorCode != kdcErrClientRevoked {
		t.Fatalf("post-threshold error = %d, want %d", kerberosError.ErrorCode, kdcErrClientRevoked)
	}
}

func TestASAccountLockoutDurationAndPasswordExpiration(t *testing.T) {
	now := time.Unix(2000000200, 0).UTC()
	server, _ := testServer(t, now)
	db := server.DB.(*kdb.Database)
	if err := db.CreatePolicy(kdb.PolicyRecord{Name: "temporary", MaxFailure: 1, LockoutDuration: 30}); err != nil {
		t.Fatal(err)
	}
	user, _ := principal.Parse("alice@TEST.REALM")
	record, _, _ := db.Lookup(*user)
	record.Policy = "temporary"
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"}}
	request := asRequest(*user, service, 1)
	addPreauthPassword(t, &request, "wrong-password", now)
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &kerberosError); err != nil {
		t.Fatal(err)
	}
	server.Now = func() time.Time { return now.Add(31 * time.Second) }
	request.ReqBody.Nonce++
	addPreauthPassword(t, &request, "alice-password", now.Add(31*time.Second))
	var reply protocol.ASRep
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &reply); err != nil {
		t.Fatalf("post-duration AS reply: %v", err)
	}
	record.PasswordExpiration = now.Add(30 * time.Second)
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	request.ReqBody.Nonce++
	addPreauthPassword(t, &request, "alice-password", now.Add(31*time.Second))
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &kerberosError); err != nil {
		t.Fatal(err)
	}
	if kerberosError.ErrorCode != kdcErrKeyExpired {
		t.Fatalf("expired password code = %d, want %d", kerberosError.ErrorCode, kdcErrKeyExpired)
	}
}

func TestServerPrincipalAliases(t *testing.T) {
	now := time.Unix(2000000050, 0).UTC()
	server, kclient := testServer(t, now)
	db := server.DB.(*kdb.Database)
	if err := db.AddAlias("alice-alias", "alice"); err != nil {
		t.Fatalf("client alias: %v", err)
	}
	if err := db.AddAlias("host/alias.test", "host/service.test"); err != nil {
		t.Fatalf("service alias: %v", err)
	}
	aliasUser := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice-alias"},
	}
	canonicalUser := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"},
	}
	withoutCanonicalize := kclient
	if _, err := withoutCanonicalize.ASExchange(context.Background(), aliasUser, "alice-password"); err == nil || !hasKRBCode(err, 6) {
		t.Fatalf("alias AS without canonicalization = %v, want client unknown", err)
	}
	withCanonicalize := *kclient
	withCanonicalize.Canonicalize = true
	tgt, err := withCanonicalize.ASExchange(context.Background(), aliasUser, "alice-password")
	if err != nil {
		t.Fatalf("alias AS with canonicalization: %v", err)
	}
	if !samePrincipal(tgt.Client, canonicalUser) {
		t.Fatalf("canonicalized AS client = %v, want %v", tgt.Client, canonicalUser)
	}
	var issuedTicket protocol.Ticket
	if err := asn1.Unmarshal(tgt.Ticket, &issuedTicket); err != nil {
		t.Fatalf("decode canonicalized AS ticket: %v", err)
	}
	tgtName := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"},
	}
	tgtRecord, ok, err := server.DB.Lookup(tgtName)
	if err != nil || !ok {
		t.Fatalf("lookup TGT record: %v, %v", err, ok)
	}
	tgtKey, ok := selectKVNO(tgtRecord, issuedTicket.EncPart.EType, issuedTicket.EncPart.KVNO)
	if !ok {
		t.Fatal("missing TGT encryption key")
	}
	tgtEType, err := crypto.NewRegistry().Get(tgtKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	tgtPlain, err := tgtEType.Decrypt(tgtKey.Key, 2, issuedTicket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt canonicalized AS ticket: %v", err)
	}
	var issuedPart protocol.EncTicketPart
	if err := asn1.Unmarshal(tgtPlain, &issuedPart); err != nil {
		t.Fatalf("decode canonicalized AS ticket: %v", err)
	}
	if !samePrincipal(principalFromProtocol(issuedPart.CName, issuedPart.CRealm), canonicalUser) {
		t.Fatalf("ticket client = %v, want %v",
			principalFromProtocol(issuedPart.CName, issuedPart.CRealm), canonicalUser)
	}
	aliasService := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvHst,
		Components: []string{"host", "alias.test"},
	}
	withoutCanonicalizeTGS, err := withoutCanonicalize.TGSExchange(context.Background(), tgt, aliasService)
	if err != nil {
		t.Fatalf("alias TGS without canonicalization: %v", err)
	}
	if !samePrincipal(withoutCanonicalizeTGS.Server, aliasService) {
		t.Fatalf("echoed alias service = %v, want %v", withoutCanonicalizeTGS.Server, aliasService)
	}
	withCanonicalizeTGS, err := withCanonicalize.TGSExchange(context.Background(), tgt, aliasService)
	if err != nil {
		t.Fatalf("alias TGS with canonicalization: %v", err)
	}
	canonicalService := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"host", "service.test"},
	}
	if !samePrincipal(withCanonicalizeTGS.Server, canonicalService) {
		t.Fatalf("canonicalized TGS service = %v, want %v", withCanonicalizeTGS.Server, canonicalService)
	}
}

func TestServerS4U2SelfPolicyAndProxy(t *testing.T) {
	now := time.Unix(2000001800, 0).UTC()
	server, kclient := testServer(t, now)
	server.EnablePAC = true
	current := now
	server.Now = func() time.Time { return current }
	kclient.Now = func() time.Time { return current }
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	backend := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"HTTP", "backend.test"}}
	db := server.DB.(*kdb.Database)
	if err := db.AddPrincipal("HTTP/backend.test", "backend-password", 1); err != nil {
		t.Fatal(err)
	}
	tgt, err := kclient.ASExchange(context.Background(), service, "host-password")
	if err != nil {
		t.Fatalf("service AS exchange: %v", err)
	}
	self, err := kclient.S4U2Self(context.Background(), tgt, user)
	if err != nil {
		t.Fatalf("S4U2Self without policy: %v", err)
	}
	if !samePrincipal(self.Client, user) || !samePrincipal(self.Server, service) {
		t.Fatalf("S4U2Self credentials = %#v", self)
	}
	if self.Flags&types.TicketForwardable != 0 {
		t.Fatalf("S4U2Self without policy is forwardable: %#x", self.Flags)
	}
	if _, err := kclient.S4U2Proxy(context.Background(), tgt, self, backend); err == nil {
		t.Fatal("S4U2Proxy without policy unexpectedly succeeded")
	}
	current = current.Add(time.Second)
	server.CheckAllowedToDelegate = func(impersonated *principal.Principal, requester principal.Principal, target *principal.Principal) error {
		if impersonated != nil || target != nil {
			t.Fatalf("S4U2Self delegation arguments = %v, %v", impersonated, target)
		}
		return errors.New("S4U2Self delegation denied")
	}
	deniedSelf, err := kclient.S4U2Self(context.Background(), tgt, user)
	if err != nil {
		t.Fatalf("S4U2Self with denied delegation hook: %v", err)
	}
	if deniedSelf.Flags&types.TicketForwardable != 0 {
		t.Fatalf("denied S4U2Self delegation is forwardable: %#x", deniedSelf.Flags)
	}
	current = current.Add(time.Second)
	server.CheckAllowedToDelegate = func(impersonated *principal.Principal, requester principal.Principal, target *principal.Principal) error {
		if !samePrincipal(requester, service) {
			t.Fatalf("delegation requester = %v, want %v", requester, service)
		}
		if impersonated != nil && target != nil {
			if !samePrincipal(*impersonated, user) {
				t.Fatalf("delegation impersonated = %v, want %v", *impersonated, user)
			}
			if !samePrincipal(*target, backend) {
				return errors.New("S4U2Proxy target denied")
			}
		}
		return nil
	}
	nonForwardable, err := kclient.TGSExchange(context.Background(), tgt, service)
	if err != nil {
		t.Fatalf("evidence TGS exchange: %v", err)
	}
	var evidenceTicket protocol.Ticket
	if err := asn1.Unmarshal(nonForwardable.Ticket, &evidenceTicket); err != nil {
		t.Fatal(err)
	}
	serviceRecord, ok, err := server.DB.Lookup(service)
	if err != nil || !ok {
		t.Fatal("missing service record")
	}
	evidenceKey, ok := selectKVNO(serviceRecord, evidenceTicket.EncPart.EType, evidenceTicket.EncPart.KVNO)
	if !ok {
		t.Fatal("missing evidence ticket key")
	}
	evidenceEType, err := crypto.NewRegistry().Get(evidenceKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	evidencePlain, err := evidenceEType.Decrypt(evidenceKey.Key, 2, evidenceTicket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var evidencePart protocol.EncTicketPart
	if err := asn1.Unmarshal(evidencePlain, &evidencePart); err != nil {
		t.Fatal(err)
	}
	evidencePart.Flags &^= types.TicketForwardable
	evidenceTicket.EncPart.Cipher, err = evidenceEType.Encrypt(evidenceKey.Key, 2, mustMarshal(t, evidencePart))
	if err != nil {
		t.Fatal(err)
	}
	nonForwardable.Ticket = mustMarshal(t, evidenceTicket)
	current = current.Add(time.Second)
	if _, err := kclient.S4U2Proxy(context.Background(), tgt, nonForwardable, backend); err == nil {
		t.Fatal("S4U2Proxy accepted non-forwardable evidence")
	}
	self, err = kclient.S4U2Self(context.Background(), tgt, user)
	if err != nil {
		t.Fatalf("S4U2Self with policy: %v", err)
	}
	if self.Flags&types.TicketForwardable == 0 {
		t.Fatalf("S4U2Self with policy is not forwardable: %#x", self.Flags)
	}
	current = current.Add(time.Second)
	proxy, err := kclient.S4U2Proxy(context.Background(), tgt, self, backend)
	if err != nil {
		t.Fatalf("S4U2Proxy: %v", err)
	}
	if !samePrincipal(proxy.Client, user) || !samePrincipal(proxy.Server, backend) {
		t.Fatalf("S4U2Proxy credentials = %#v", proxy)
	}
	var proxyTicket protocol.Ticket
	if err := asn1.Unmarshal(proxy.Ticket, &proxyTicket); err != nil {
		t.Fatal(err)
	}
	backendRecord, ok, err := server.DB.Lookup(backend)
	if err != nil || !ok {
		t.Fatal("missing backend record")
	}
	backendKey, ok := selectKVNO(backendRecord, proxyTicket.EncPart.EType, proxyTicket.EncPart.KVNO)
	if !ok {
		t.Fatal("missing backend ticket key")
	}
	backendEType, err := crypto.NewRegistry().Get(backendKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	proxyPlain, err := backendEType.Decrypt(backendKey.Key, 2, proxyTicket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var proxyPart protocol.EncTicketPart
	if err := asn1.Unmarshal(proxyPlain, &proxyPart); err != nil {
		t.Fatal(err)
	}
	privKey, ok := server.pacPrivsvrKey()
	if !ok {
		t.Fatal("privileged-server key unavailable")
	}
	privEType, err := crypto.NewRegistry().Get(privKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pac.FromTicket(proxyPart,
		pac.Key{EType: backendEType, Key: backendKey.Key},
		&pac.Key{EType: privEType, Key: privKey.Key}); err != nil {
		t.Fatalf("S4U2Proxy PAC verification: %v", err)
	}
	disallowed := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "other.test"}}
	if err := db.AddPrincipal("host/other.test", "other-password", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := kclient.S4U2Proxy(context.Background(), tgt, self, disallowed); err == nil {
		t.Fatal("S4U2Proxy to disallowed target unexpectedly succeeded")
	} else if !hasKRBCode(err, kdcErrBadOption) {
		t.Fatalf("disallowed S4U2Proxy error = %v, want KDC_ERR_BADOPTION", err)
	}
}

func TestPAForUserChecksum(t *testing.T) {
	key := []byte("0123456789abcdef")
	data := []byte("S4U checksum input")
	var usage [4]byte
	binary.LittleEndian.PutUint32(usage[:], 17)
	digest := md5.Sum(append(append([]byte(nil), usage[:]...), data...))
	signing := hmac.New(md5.New, key)
	_, _ = signing.Write([]byte("signaturekey\x00"))
	mac := hmac.New(md5.New, signing.Sum(nil))
	_, _ = mac.Write(digest[:])
	checksum := mac.Sum(nil)
	if !verifyPAForUserChecksum(key, 17, data, checksum) {
		t.Fatal("valid PA-FOR-USER checksum rejected")
	}
	checksum[0] ^= 0xff
	if verifyPAForUserChecksum(key, 17, data, checksum) {
		t.Fatal("bad PA-FOR-USER checksum accepted")
	}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA1)
	if err != nil {
		t.Fatal(err)
	}
	aesKey := bytes.Repeat([]byte{0x31}, etype.KeySize())
	aesChecksum, err := etype.Checksum(aesKey, 17, data)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPAForUserChecksumForEType(etype, aesKey, crypto.ChecksumHMACSHA196AES128, data, aesChecksum) {
		t.Fatal("valid AES PA-FOR-USER checksum rejected")
	}
	sha2, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sha2Key := bytes.Repeat([]byte{0x32}, sha2.KeySize())
	sha2Checksum, err := sha2.Checksum(sha2Key, 17, data)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPAForUserChecksumForEType(etype, sha2Key, crypto.ChecksumHMACSHA256128AES128, data, sha2Checksum) {
		t.Fatal("valid AES-SHA2 PA-FOR-USER checksum rejected")
	}
}

func TestServerS4UX509UsesAuthenticatorSubkey(t *testing.T) {
	now := time.Unix(2000001817, 0).UTC()
	server, kclient := testServer(t, now)
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), service, "host-password")
	if err != nil {
		t.Fatal(err)
	}
	subkey := protocol.EncryptionKey{KeyType: tgt.Key.KeyType, KeyValue: bytes.Repeat([]byte{0x53}, len(tgt.Key.KeyValue))}
	options := protocol.S4UOptionsUseReplyKeyUsage
	userID := protocol.S4UUserID{
		Nonce: 202, CName: protocolPrincipalForTest(user), CRealm: user.Realm, Options: &options,
	}
	placeholder := mustMarshal(t, protocol.PAS4UX509User{
		UserID:   userID,
		Checksum: protocol.Checksum{ChecksumType: mandatoryChecksumType(tgt.Key.KeyType), Checksum: make([]byte, 32)},
	})
	userIDDER, err := asn1.FieldContent(placeholder, 0)
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := etype.Checksum(subkey.KeyValue, 26, userIDDER)
	if err != nil {
		t.Fatal(err)
	}
	padata := protocol.MethodData{{PADataType: protocol.PADataS4UX509User, PADataValue: mustMarshal(t, protocol.PAS4UX509User{
		UserID:   userID,
		Checksum: protocol.Checksum{ChecksumType: mandatoryChecksumType(tgt.Key.KeyType), Checksum: checksum},
	})}}
	response := server.HandleMessage(rawTGSRequestWithPadataAndSubkey(t, tgt, service, now, 0, padata, nil, &subkey))
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("TGS-REP: %v", err)
	}
	if len(reply.PAData) != 1 {
		t.Fatalf("reply padata = %#v", reply.PAData)
	}
	var replyPA protocol.PAS4UX509User
	if err := asn1.Unmarshal(reply.PAData[0].PADataValue, &replyPA); err != nil {
		t.Fatal(err)
	}
	replyUserIDDER, err := asn1.FieldContent(reply.PAData[0].PADataValue, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := etype.VerifyChecksum(subkey.KeyValue, 27, replyUserIDDER, replyPA.Checksum.Checksum); err != nil {
		t.Fatalf("reply checksum did not use authenticator subkey: %v", err)
	}
	if err := etype.VerifyChecksum(tgt.Key.KeyValue, 27, replyUserIDDER, replyPA.Checksum.Checksum); err == nil {
		t.Fatal("reply checksum unexpectedly verified with TGT session key")
	}
}

func TestS4UX509ChecksumKeySelection(t *testing.T) {
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey := bytes.Repeat([]byte{0x55}, etype.KeySize())
	subkey := bytes.Repeat([]byte{0x56}, etype.KeySize())
	data := []byte("S4U-X509 checksum data")
	checksum, err := etype.Checksum(subkey, 26, data)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyS4UChecksum(subkey, crypto.ChecksumHMACSHA196AES256, 26, data, checksum) {
		t.Fatal("authenticator subkey checksum rejected")
	}
	if verifyS4UChecksum(sessionKey, crypto.ChecksumHMACSHA196AES256, 26, data, checksum) {
		t.Fatal("checksum verified with wrong session key")
	}
	fallback, err := etype.Checksum(sessionKey, 26, data)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyS4UChecksum(sessionKey, crypto.ChecksumHMACSHA196AES256, 26, data, fallback) {
		t.Fatal("session-key fallback checksum rejected")
	}
	if verifyS4UChecksum(subkey, crypto.ChecksumHMACSHA196AES256, 26, data, fallback) {
		t.Fatal("fallback checksum verified with wrong subkey")
	}
}

func TestServerFASTErrorContainsFXError(t *testing.T) {
	now := time.Unix(2000001818, 0).UTC()
	server, kclient := testServer(t, now)
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	tgt, err := kclient.ASExchange(context.Background(), service, "host-password")
	if err != nil {
		t.Fatal(err)
	}
	subkey := protocol.EncryptionKey{KeyType: tgt.Key.KeyType, KeyValue: bytes.Repeat([]byte{0x54}, len(tgt.Key.KeyValue))}
	armor, err := fast.NewTGSArmor(fast.TGT{Key: tgt.Key}, subkey)
	if err != nil {
		t.Fatal(err)
	}
	armorContext := &fastContext{etype: armor.EType, key: armor.Key, nonce: 77}
	response := server.fastErrorResponseWithText(kdcErrPolicy, protocolPrincipal(service), nil, 77, armorContext, "policy denied")
	var outer protocol.KRBError
	if err := asn1.Unmarshal(response, &outer); err != nil {
		t.Fatalf("outer KRB-ERROR: %v", err)
	}
	var outerPA protocol.MethodData
	if err := asn1.Unmarshal(outer.EData, &outerPA); err != nil {
		t.Fatalf("outer error padata: %v", err)
	}
	var wrapper protocol.PAFXFastReply
	var fastPA *protocol.PAData
	for i := range outerPA {
		if outerPA[i].PADataType == fast.PAFXFast {
			fastPA = &outerPA[i]
			break
		}
	}
	if fastPA == nil {
		t.Fatal("outer error missing PA-FX-FAST")
	}
	if err := asn1.Unmarshal(fastPA.PADataValue, &wrapper); err != nil {
		t.Fatal(err)
	}
	plain, err := armor.EType.Decrypt(armor.Key, fast.UsageRep, wrapper.ArmoredData.EncFastRep.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var fastResponse protocol.KrbFastResponse
	if err := asn1.Unmarshal(plain, &fastResponse); err != nil {
		t.Fatal(err)
	}
	var fxError *protocol.PAData
	for i := range fastResponse.PAData {
		if fastResponse.PAData[i].PADataType == fast.PAFXError {
			fxError = &fastResponse.PAData[i]
			break
		}
	}
	if fxError == nil {
		t.Fatal("FAST response missing PA-FX-ERROR")
	}
	var inner protocol.KRBError
	if err := asn1.Unmarshal(fxError.PADataValue, &inner); err != nil {
		t.Fatalf("inner KRB-ERROR: %v", err)
	}
	if inner.ErrorCode != kdcErrPolicy || inner.EData != nil ||
		inner.EText == nil || *inner.EText != "policy denied" {
		t.Fatalf("inner KRB-ERROR = %#v, want code %d, text, and absent e-data", inner, kdcErrPolicy)
	}
}

func TestServerS4U2SelfLegacyPAForUser(t *testing.T) {
	now := time.Unix(2000001810, 0).UTC()
	server, kclient := testServer(t, now)
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), service, "host-password")
	if err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 4)
	binary.LittleEndian.PutUint32(input, uint32(user.NameType))
	for _, component := range user.Components {
		input = append(input, component...)
	}
	input = append(input, user.Realm...)
	input = append(input, "Kerberos"...)
	checksum := makePAForUserChecksum(tgt.Key.KeyValue, input)
	request := rawTGSRequestWithPadata(t, tgt, service, now, 0,
		protocol.MethodData{{PADataType: protocol.PADataForUser, PADataValue: mustMarshal(t, protocol.PAForUser{
			UserName: *protocolPrincipalForTest(user), UserRealm: user.Realm,
			Checksum: protocol.Checksum{ChecksumType: -138, Checksum: checksum}, AuthPackage: "Kerberos",
		})}}, nil)
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(server.HandleMessage(request), &reply); err != nil {
		t.Fatal(err)
	}
	if !sameProtocolPrincipal(reply.CName, *protocolPrincipalForTest(user)) || reply.CRealm != user.Realm {
		t.Fatalf("legacy S4U reply client = %#v@%s", reply.CName, reply.CRealm)
	}
}

func TestServerRejectsMalformedPAForUser(t *testing.T) {
	now := time.Unix(2000001815, 0).UTC()
	server, kclient := testServer(t, now)
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	tgt, err := kclient.ASExchange(context.Background(), service, "host-password")
	if err != nil {
		t.Fatal(err)
	}
	request := rawTGSRequestWithPadata(t, tgt, service, now, 0,
		protocol.MethodData{{PADataType: protocol.PADataForUser, PADataValue: []byte{0x30, 0x01, 0x00}}}, nil)
	var reply protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(request), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.ErrorCode != krbAPErrBadIntegrity {
		t.Fatalf("malformed PA-FOR-USER code = %d, want %d", reply.ErrorCode, krbAPErrBadIntegrity)
	}
}

func TestServerIssuesForwardedTGT(t *testing.T) {
	now := time.Unix(2000001820, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgtService := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	addresses := protocol.HostAddresses{{AddrType: 2, Address: []byte{192, 0, 2, 10}}}
	response := server.HandleMessage(rawTGSRequestWithPadata(t, tgt, tgtService, now,
		types.KDCForwarded, nil, nil, addresses))
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatal(err)
	}
	part := tgsReplyPart(t, response, tgt.Key)
	if part.Flags&types.TicketForwarded == 0 {
		t.Fatalf("forwarded TGT flags = %#x, missing FORWARDED", part.Flags)
	}
	record, ok, err := server.DB.Lookup(tgtService)
	if err != nil || !ok {
		t.Fatal("missing krbtgt record")
	}
	key, ok := selectKVNO(record, reply.Ticket.EncPart.EType, reply.Ticket.EncPart.KVNO)
	if !ok {
		t.Fatal("missing krbtgt ticket key")
	}
	etype, err := crypto.NewRegistry().Get(key.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(key.Key, 2, reply.Ticket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var ticketPart protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &ticketPart); err != nil {
		t.Fatal(err)
	}
	if len(ticketPart.CAddr) != 1 || !bytes.Equal(ticketPart.CAddr[0].Address, addresses[0].Address) {
		t.Fatalf("forwarded TGT addresses = %#v, want %#v", ticketPart.CAddr, addresses)
	}
}

func makePAForUserChecksum(key, data []byte) []byte {
	var usage [4]byte
	binary.LittleEndian.PutUint32(usage[:], 17)
	digest := md5.Sum(append(append([]byte(nil), usage[:]...), data...))
	signing := hmac.New(md5.New, key)
	_, _ = signing.Write([]byte("signaturekey\x00"))
	mac := hmac.New(md5.New, signing.Sum(nil))
	_, _ = mac.Write(digest[:])
	return mac.Sum(nil)
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

func TestServerOTPFASTASExchange(t *testing.T) {
	now := time.Unix(2000000060, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	armorTGT, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("armor ASExchange: %v", err)
	}
	server.OTPValidator = func(name principal.Principal, value string) error {
		if name.Components[0] != "alice" || value != "123456" {
			return errors.New("invalid OTP")
		}
		return nil
	}
	server.OTPTokenInfo = func(principal.Principal) []otp.TokenInfo {
		length, format := int32(6), otp.FormatHexadecimal
		vendor := types.UTF8String("test")
		return []otp.TokenInfo{{Vendor: &vendor, Length: &length, Format: &format}}
	}
	credentials, err := kclient.ASExchangeFASTOTP(context.Background(), user, armorTGT,
		func(challenge otp.Challenge) (string, string, error) {
			if len(challenge.TokenInfo) != 1 || challenge.TokenInfo[0].Vendor == nil ||
				string(*challenge.TokenInfo[0].Vendor) != "test" {
				t.Fatalf("unexpected OTP challenge: %#v", challenge)
			}
			return "123456", "", nil
		})
	if err != nil {
		t.Fatalf("OTP FAST ASExchange: %v", err)
	}
	if !samePrincipal(credentials.Client, user) || credentials.Server.Components[0] != "krbtgt" {
		t.Fatalf("OTP credentials = %#v", credentials)
	}
}

func TestServerOTPRequiresFAST(t *testing.T) {
	now := time.Unix(2000000061, 0).UTC()
	server, kclient := testServer(t, now)
	server.OTPValidator = func(principal.Principal, string) error { return nil }
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	_, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err == nil || !hasKRBCode(err, 24) {
		t.Fatalf("non-FAST OTP exchange error = %v, want KDC_ERR_PREAUTH_FAILED", err)
	}
}

func TestServerOTPWrongValueRecordsFailure(t *testing.T) {
	now := time.Unix(2000000062, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	armorTGT, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("armor ASExchange: %v", err)
	}
	server.OTPValidator = func(principal.Principal, string) error { return errors.New("invalid OTP") }
	_, err = kclient.ASExchangeFASTOTP(context.Background(), user, armorTGT,
		func(otp.Challenge) (string, string, error) { return "wrong", "", nil })
	if err == nil || !hasKRBCode(err, 24) {
		t.Fatalf("wrong OTP error = %v, want KDC_ERR_PREAUTH_FAILED", err)
	}
	record, ok, lookupErr := server.DB.Lookup(user)
	if lookupErr != nil || !ok || record.FailAuthCount != 1 {
		t.Fatalf("OTP failure record = %#v, ok=%v, err=%v", record, ok, lookupErr)
	}
}

func TestServerFASTTGSExchange(t *testing.T) {
	now := time.Unix(2000000055, 0).UTC()
	_, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("ASExchange: %v", err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	credentials, err := kclient.TGSExchangeFAST(context.Background(), tgt, service)
	if err != nil {
		t.Fatalf("FAST TGSExchange: %v", err)
	}
	if !samePrincipal(credentials.Client, user) || !samePrincipal(credentials.Server, service) {
		t.Fatalf("FAST TGS credentials = %#v", credentials)
	}
}

func TestServerFASTS4U2SelfReplyCarriesReplyChecksum(t *testing.T) {
	now := time.Unix(2000000058, 0).UTC()
	server, kclient := testServer(t, now)
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), service, "host-password")
	if err != nil {
		t.Fatalf("service AS exchange: %v", err)
	}
	var response []byte
	s4uClient := &client.Client{
		Now: func() time.Time { return now },
		Exchange: func(_ context.Context, _ string, payload []byte) ([]byte, error) {
			response = server.HandleMessage(payload)
			return response, nil
		},
	}
	if _, err := s4uClient.S4U2Self(context.Background(), tgt, user); err != nil {
		t.Fatalf("S4U2Self: %v", err)
	}
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("TGS-REP: %v", err)
	}
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(tgt.Key.KeyValue, 8, reply.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt TGS-REP: %v", err)
	}
	var replyPart protocol.EncTGSRepPart
	if err := asn1.Unmarshal(plain, &replyPart); err != nil {
		t.Fatalf("EncTGSRepPart: %v", err)
	}
	subkey := protocol.EncryptionKey{
		KeyType: tgt.Key.KeyType, KeyValue: bytes.Repeat([]byte{0x5a}, etype.KeySize()),
	}
	armor, err := fast.NewTGSArmor(fast.TGT{Key: tgt.Key}, subkey)
	if err != nil {
		t.Fatalf("TGS armor: %v", err)
	}
	armorContext := &fastContext{
		etype: armor.EType,
		key:   armor.Key,
		nonce: replyPart.Nonce,
	}
	wrappedDER := server.wrapFASTTGSRep(reply, tgt.Key, 8, armorContext)
	var wrapped protocol.TGSRep
	if err := asn1.Unmarshal(wrappedDER, &wrapped); err != nil {
		t.Fatalf("FAST TGS-REP: %v", err)
	}
	fastReply, err := armor.UnwrapReply(wrapped.PAData, mustMarshal(t, wrapped.Ticket), replyPart.Nonce)
	if err != nil {
		t.Fatalf("unwrap FAST TGS-REP: %v", err)
	}
	var replyPA *protocol.PAData
	for i := range fastReply.PAData {
		if fastReply.PAData[i].PADataType == protocol.PADataS4UX509User {
			replyPA = &fastReply.PAData[i]
			break
		}
	}
	if replyPA == nil {
		t.Fatal("FAST response dropped PA-S4U-X509-USER")
	}
	var value protocol.PAS4UX509User
	if err := asn1.Unmarshal(replyPA.PADataValue, &value); err != nil {
		t.Fatalf("FAST S4U reply padata: %v", err)
	}
	userIDDER, err := asn1.FieldContent(replyPA.PADataValue, 0)
	if err != nil {
		t.Fatalf("FAST S4U reply user identity: %v", err)
	}
	if value.UserID.Nonce != replyPart.Nonce || value.UserID.CName == nil ||
		value.UserID.CRealm != user.Realm || !sameProtocolPrincipal(*value.UserID.CName, *protocolPrincipal(user)) {
		t.Fatalf("FAST S4U reply user ID = %#v", value.UserID)
	}
	if err := etype.VerifyChecksum(tgt.Key.KeyValue, 27, userIDDER, value.Checksum.Checksum); err != nil {
		t.Fatalf("FAST S4U reply checksum: %v", err)
	}
}

func TestServerFASTTGSRejectsBadChecksumAndGarbage(t *testing.T) {
	now := time.Unix(2000000056, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("ASExchange: %v", err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	for _, mutate := range []func(protocol.TGSReq) protocol.TGSReq{
		func(request protocol.TGSReq) protocol.TGSReq {
			var wrapper protocol.PAFXFastRequest
			if err := asn1.Unmarshal(request.PAData[1].PADataValue, &wrapper); err != nil {
				t.Fatalf("decode FAST request: %v", err)
			}
			wrapper.ArmoredData.ReqChecksum.Checksum[0] ^= 0xff
			request.PAData[1].PADataValue = mustMarshal(t, wrapper)
			return request
		},
		func(request protocol.TGSReq) protocol.TGSReq {
			request.PAData[1].PADataValue = []byte{0x01, 0x02, 0x03}
			return request
		},
	} {
		badClient := &client.Client{
			Now: func() time.Time { return now },
			Exchange: func(_ context.Context, _ string, payload []byte) ([]byte, error) {
				var request protocol.TGSReq
				if err := asn1.Unmarshal(payload, &request); err != nil {
					t.Fatalf("decode TGS request: %v", err)
				}
				request = mutate(request)
				return server.HandleMessage(mustMarshal(t, request)), nil
			},
		}
		if _, err := badClient.TGSExchangeFAST(context.Background(), tgt, service); err == nil {
			t.Fatal("malformed FAST TGS request unexpectedly succeeded")
		}
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

func TestASEncryptedTimestampWithSPAKEAdvertisement(t *testing.T) {
	now := time.Unix(2000000100, 0).UTC()
	server, _ := testServer(t, now)
	server.EnableSPAKE = true
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	request := asRequest(user, service, 1)

	var hint protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &hint); err != nil {
		t.Fatalf("preauthentication hint: %v", err)
	}
	if hint.ErrorCode != kdcErrPreauthRequired {
		t.Fatalf("hint error code = %d, want %d", hint.ErrorCode, kdcErrPreauthRequired)
	}
	methodData, err := preauth.ParseMethodData(hint.EData)
	if err != nil {
		t.Fatalf("parse method data: %v", err)
	}
	timestampHint := preauth.FindPAData(methodData, paEncTimestamp)
	if timestampHint == nil || len(timestampHint.PADataValue) != 0 {
		t.Fatalf("PA-ENC-TIMESTAMP hint = %#v, want empty padata", timestampHint)
	}
	if preauth.FindPAData(methodData, paSPAKE) == nil {
		t.Fatal("PA-SPAKE hint missing")
	}

	addPreauthPassword(t, &request, "alice-password", now)
	response := server.HandleMessage(mustMarshal(t, request))
	part := asReplyPart(t, response)
	if part.Key.KeyType == 0 || len(part.Key.KeyValue) == 0 {
		t.Fatalf("encrypted-timestamp AS reply has no session key: %#v", part.Key)
	}
}

func TestASP256SPAKE(t *testing.T) {
	now := time.Unix(2000000125, 0).UTC()
	server, c := testServer(t, now)
	server.EnableSPAKE = true
	server.SPAKEGroups = []int32{spake.GroupP256}
	c.SPAKEGroups = []int32{spake.GroupP256}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	credentials, err := c.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("P-256 SPAKE AS exchange: %v", err)
	}
	if credentials == nil || credentials.Key.KeyType == 0 || len(credentials.Key.KeyValue) == 0 {
		t.Fatalf("P-256 SPAKE AS reply has no session key: %#v", credentials)
	}
}

func TestASUnsupportedSPAKESupportFallsBackToTimestamp(t *testing.T) {
	now := time.Unix(2000000135, 0).UTC()
	server, c := testServer(t, now)
	server.EnableSPAKE = true
	server.SPAKEGroups = []int32{spake.GroupP256}
	c.SPAKEGroups = []int32{spake.GroupEdwards25519}

	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	credentials, err := c.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("unsupported SPAKE support AS exchange: %v", err)
	}
	if credentials == nil || credentials.Key.KeyType == 0 || len(credentials.Key.KeyValue) == 0 {
		t.Fatalf("timestamp fallback AS reply has no session key: %#v", credentials)
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

func TestASDisablePreauthAuthorizationHook(t *testing.T) {
	now := time.Unix(2000000160, 0).UTC()
	server, _ := testServer(t, now)
	server.DisablePreauth = true
	server.Authorize = func(principal.Principal, principal.Principal, bool) error {
		return errors.New("preauth-disabled authorization denied")
	}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"},
	}
	request := asRequest(user, service, 160)
	request.PAData = nil
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &kerberosError); err != nil {
		t.Fatalf("preauth-disabled authorization response: %v", err)
	}
	if kerberosError.ErrorCode != kdcErrPolicy {
		t.Fatalf("preauth-disabled authorization code = %d, want %d", kerberosError.ErrorCode, kdcErrPolicy)
	}
	if kerberosError.EText == nil || *kerberosError.EText != "preauth-disabled authorization denied" {
		t.Fatalf("preauth-disabled authorization text = %v", kerberosError.EText)
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

func TestASDefaultRenewableLife(t *testing.T) {
	now := time.Unix(2000001150, 0).UTC()
	server, _ := testServer(t, now)
	server.DefaultRenewableLife = 4 * time.Hour
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"},
	}, 78)
	request.ReqBody.KDCOptions = types.KDCRenewable
	request.ReqBody.Till = kerberosTime(time.Unix(0, 0).UTC())
	request.ReqBody.RTime = &types.KerberosTime{Time: time.Unix(0, 0).UTC(), Present: true}
	addPreauth(t, &request, now)
	part := asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if part.RenewTill == nil || !part.RenewTill.Time.Equal(now.Add(4*time.Hour)) {
		t.Fatalf("renew-till = %v, want %v", part.RenewTill, now.Add(4*time.Hour))
	}
}

func TestASExplicitRenewableLifeHonorsRequestedRTime(t *testing.T) {
	now := time.Unix(2000001175, 0).UTC()
	server, _ := testServer(t, now)
	server.DefaultRenewableLife = 4 * time.Hour
	server.MaxRenewableLife = 10 * time.Hour
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"},
	}, 79)
	request.ReqBody.KDCOptions = types.KDCRenewable
	request.ReqBody.Till = kerberosTime(time.Unix(0, 0).UTC())
	request.ReqBody.RTime = &types.KerberosTime{Time: now.Add(8 * time.Hour), Present: true}
	addPreauth(t, &request, now)
	part := asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if part.RenewTill == nil || !part.RenewTill.Time.Equal(now.Add(8*time.Hour)) {
		t.Fatalf("renew-till = %v, want %v", part.RenewTill, now.Add(8*time.Hour))
	}
}

func TestASDefaultRenewableLifeCappedByMaximum(t *testing.T) {
	now := time.Unix(2000001200, 0).UTC()
	server, _ := testServer(t, now)
	server.DefaultRenewableLife = 20 * time.Hour
	server.MaxRenewableLife = 10 * time.Hour
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"},
	}, 80)
	request.ReqBody.KDCOptions = types.KDCRenewable
	request.ReqBody.Till = kerberosTime(time.Unix(0, 0).UTC())
	request.ReqBody.RTime = nil
	addPreauth(t, &request, now)
	part := asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if part.RenewTill == nil || !part.RenewTill.Time.Equal(now.Add(10*time.Hour)) {
		t.Fatalf("renew-till = %v, want %v", part.RenewTill, now.Add(10*time.Hour))
	}
}

func TestASZeroDefaultRenewableLifePreservesTillBehavior(t *testing.T) {
	now := time.Unix(2000001225, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"},
	}, 81)
	request.ReqBody.KDCOptions = types.KDCRenewable
	request.ReqBody.Till = kerberosTime(now.Add(6 * time.Hour))
	request.ReqBody.RTime = nil
	addPreauth(t, &request, now)
	part := asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if part.RenewTill == nil || !part.RenewTill.Time.Equal(now.Add(6*time.Hour)) {
		t.Fatalf("renew-till = %v, want %v", part.RenewTill, now.Add(6*time.Hour))
	}
}

func TestASDefaultRenewableLifeAppliesToRenewableOK(t *testing.T) {
	now := time.Unix(2000001250, 0).UTC()
	server, _ := testServer(t, now)
	server.DefaultTicketLife = time.Hour
	server.DefaultRenewableLife = 4 * time.Hour
	server.MaxRenewableLife = 10 * time.Hour
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"},
	}, 82)
	request.ReqBody.KDCOptions = types.KDCRenewableOK
	request.ReqBody.Till = kerberosTime(time.Unix(0, 0).UTC())
	request.ReqBody.RTime = nil
	addPreauth(t, &request, now)
	part := asReplyPart(t, server.HandleMessage(mustMarshal(t, request)))
	if part.RenewTill == nil || !part.RenewTill.Time.Equal(now.Add(4*time.Hour)) {
		t.Fatalf("renew-till = %v, want %v", part.RenewTill, now.Add(4*time.Hour))
	}
}

func TestTGSDefaultRenewableLife(t *testing.T) {
	now := time.Unix(2000001275, 0).UTC()
	server, _ := testServer(t, now)
	server.DefaultRenewableLife = 4 * time.Hour
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt := issueASTicket(t, server, user, now, types.KDCRenewable, now.Add(8*time.Hour))
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	response := server.HandleMessage(rawTGSRequestWithTill(t, tgt, service, now, kerberosTime(time.Unix(0, 0).UTC()), types.KDCRenewable))
	part := tgsReplyPart(t, response, tgt.Key)
	if part.RenewTill == nil || !part.RenewTill.Time.Equal(now.Add(4*time.Hour)) {
		t.Fatalf("TGS renew-till = %v, want %v", part.RenewTill, now.Add(4*time.Hour))
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

func rawTGSRequestWithPadata(t *testing.T, tgt *client.Credentials, service principal.Principal, now time.Time, options types.KDCOptions, padata protocol.MethodData, additional []protocol.Ticket, addresses ...protocol.HostAddresses) []byte {
	return rawTGSRequestWithPadataAndSubkey(t, tgt, service, now, options, padata, additional, nil, addresses...)
}

func rawTGSRequestWithPadataAndSubkey(t *testing.T, tgt *client.Credentials, service principal.Principal, now time.Time, options types.KDCOptions, padata protocol.MethodData, additional []protocol.Ticket, subkey *protocol.EncryptionKey, addresses ...protocol.HostAddresses) []byte {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	body := protocol.KDCReqBody{
		KDCOptions: options, Realm: service.Realm,
		SName: &protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
		Till:  types.KerberosTime{Time: now.Add(time.Hour), Present: true},
		Nonce: 202, EType: []int32{tgt.Key.KeyType}, AdditionalTickets: additional,
	}
	if len(addresses) != 0 {
		body.Addresses = addresses[0]
	}
	bodyDER := mustMarshal(t, body)
	checksum, err := etype.Checksum(tgt.Key.KeyValue, 6, bodyDER)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := protocol.Authenticator{
		AuthenticatorVNO: 5, CRealm: tgt.Client.Realm,
		CName:    *protocolPrincipalForTest(tgt.Client),
		Checksum: &protocol.Checksum{ChecksumType: mandatoryChecksumType(tgt.Key.KeyType), Checksum: checksum},
		SubKey:   subkey,
		Ctime:    types.KerberosTime{Time: now, Present: true},
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
		PVNO: 5, MsgType: 12, PAData: append(protocol.MethodData{{PADataType: paTGSReq, PADataValue: mustMarshal(t, apReq)}}, padata...),
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

func addPreauthPassword(t *testing.T, request *protocol.ASReq, password string, now time.Time) {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := etype.StringToKey([]byte(password), []byte("TEST.REALMalice"), nil)
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
