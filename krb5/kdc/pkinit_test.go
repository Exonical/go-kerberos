package kdc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	krb5asn1 "github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/pkinit"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestServerPKINITASExchange(t *testing.T) {
	now := time.Unix(2000001000, 0).UTC()
	server, kclient := testServer(t, now)
	ca, caKey, clientCert, clientKey := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	server.PKINITClientCAs = roots
	server.PKINITIndicators = []string{"pkinit", "hardware"}
	server.CertAuthModules = []CertAuthModule{
		certAuthTestModule{decision: CertAuthPass, indicators: []string{"certauth"}},
	}

	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	credentials, err := kclient.ASExchangePKINIT(context.Background(), user, clientCert, clientKey, roots)
	if err != nil {
		t.Fatalf("PKINIT AS exchange: %v", err)
	}
	if !samePrincipal(credentials.Client, user) {
		t.Fatalf("PKINIT client = %v, want %v", credentials.Client, user)
	}
	assertTicketIndicators(t, server, credentials.Ticket, "krbtgt/TEST.REALM",
		"pkinit", "hardware", "certauth")
}

func TestServerPKINITDBMatchCertAuth(t *testing.T) {
	now := time.Unix(2000001000, 0).UTC()
	server, kclient := testServer(t, now)
	ca, caKey, clientCert, clientKey := makePKINITTestCertificate(
		t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(
		t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	server.PKINITClientCAs = roots

	user := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"},
	}
	record, ok, err := server.DB.Lookup(user)
	if err != nil || !ok {
		t.Fatalf("client lookup: %v", err)
	}
	record.Strings["pkinit_cert_match"] = "<SUBJECT>CN=alice"
	if err := server.DB.(*kdb.Database).UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	if _, err := kclient.ASExchangePKINIT(
		context.Background(), user, clientCert, clientKey, roots); err != nil {
		t.Fatalf("dbmatch PKINIT success: %v", err)
	}

	record.Strings["pkinit_cert_match"] = "<SUBJECT>CN=wrong"
	if err := server.DB.(*kdb.Database).UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	if _, err := kclient.ASExchangePKINIT(
		context.Background(), user, clientCert, clientKey, roots); err == nil ||
		!hasKRBCode(err, 89) {
		t.Fatalf("dbmatch mismatch error = %v, want KDC error 89", err)
	}
}

func TestServerPKINITFreshnessRequired(t *testing.T) {
	now := time.Unix(2000001001, 0).UTC()
	server, kclient := testServer(t, now)
	server.PKINITRequireFreshness = true
	ca, caKey, clientCert, clientKey := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	server.PKINITClientCAs = roots
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	if _, err := kclient.ASExchangePKINIT(context.Background(), user, clientCert, clientKey, roots); err != nil {
		t.Fatalf("freshness-required PKINIT exchange: %v", err)
	}
}

func TestFreshnessKeySkipsUnsupportedEnctype(t *testing.T) {
	now := time.Unix(2000001200, 0).UTC()
	server, _ := testServer(t, now)
	tgt := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	record, ok, err := server.DB.Lookup(tgt)
	if err != nil || !ok {
		t.Fatalf("krbtgt lookup: ok=%v err=%v", ok, err)
	}
	const unsupportedEnctype int32 = 1
	record.Keys[unsupportedEnctype] = kdb.Key{Enctype: unsupportedEnctype, KVNO: 1, Key: make([]byte, 8)}
	if err := server.DB.(*kdb.Database).UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	key, ok := server.freshnessKey([]int32{unsupportedEnctype})
	if !ok {
		t.Fatal("freshnessKey failed with an unsupported requested enctype present")
	}
	if key.Enctype == unsupportedEnctype {
		t.Fatalf("freshnessKey selected unsupported enctype %d", key.Enctype)
	}
	token, ok := server.makeFreshnessToken([]int32{unsupportedEnctype})
	if !ok {
		t.Fatal("makeFreshnessToken failed with an unsupported requested enctype present")
	}
	if !server.verifyFreshnessToken(token) {
		t.Fatal("token from fallback key did not verify")
	}
}

func TestServerPKINITFreshnessMissingAndExpired(t *testing.T) {
	now := time.Unix(2000001100, 0).UTC()
	server, _ := testServer(t, now)
	server.PKINITRequireFreshness = true
	ca, caKey, clientCert, clientKey := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	server.PKINITClientCAs = roots
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	request := asRequest(user, service, 88)
	bodyDER := mustMarshal(t, request.ReqBody)
	pa, pkClient, err := pkinit.BuildPAASReq(bodyDER, now, request.ReqBody.Nonce, clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	request.PAData = protocol.MethodData{pa}
	var missing protocol.KRBError
	if err := krb5asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &missing); err != nil {
		t.Fatalf("missing freshness response: %v", err)
	}
	if missing.ErrorCode != kdcErrPreauthFailed {
		t.Fatalf("missing freshness code = %d, want %d", missing.ErrorCode, kdcErrPreauthFailed)
	}
	methodData := errorMethodDataForTest(t, missing.EData)
	freshness := findPA(methodData, protocol.PADataASFreshness)
	if freshness == nil || len(freshness.PADataValue) == 0 {
		t.Fatal("missing freshness response omitted replacement token")
	}
	server.Now = func() time.Time { return now.Add(-11 * time.Minute) }
	oldToken, ok := server.makeFreshnessToken(request.ReqBody.EType)
	if !ok {
		t.Fatal("could not create freshness token")
	}
	server.Now = func() time.Time { return now }
	pa, err = pkClient.BuildPAASReqWithFreshness(bodyDER, now, request.ReqBody.Nonce, oldToken)
	if err != nil {
		t.Fatal(err)
	}
	request.PAData = protocol.MethodData{pa}
	var expired protocol.KRBError
	if err := krb5asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &expired); err != nil {
		t.Fatalf("expired freshness response: %v", err)
	}
	if expired.ErrorCode != kdcErrPreauthExpired {
		t.Fatalf("expired freshness code = %d, want %d", expired.ErrorCode, kdcErrPreauthExpired)
	}
}

func errorMethodDataForTest(t *testing.T, data []byte) protocol.MethodData {
	t.Helper()
	var methodData protocol.MethodData
	if err := krb5asn1.Unmarshal(data, &methodData); err != nil {
		t.Fatal(err)
	}
	return methodData
}

func TestServerLegacyPKINITASExchangeWithAgilityKDC(t *testing.T) {
	now := time.Unix(2000001002, 0).UTC()
	server, _ := testServer(t, now)
	ca, caKey, clientCert, clientKey := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	server.PKINITClientCAs = roots

	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	request := asRequest(user, service, 12)
	bodyDER := mustMarshal(t, request.ReqBody)
	pkClient, err := pkinit.NewClient(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pa, err := pkClient.BuildPAASReq(bodyDER, now, request.ReqBody.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	request.PAData = protocol.MethodData{pa}
	requestDER := mustMarshal(t, request)
	var reply protocol.ASRep
	if err := krb5asn1.Unmarshal(server.HandleMessage(requestDER), &reply); err != nil {
		t.Fatalf("legacy PKINIT AS response: %v", err)
	}
	for _, item := range reply.PAData {
		if item.PADataType == pkinit.PADataASRep {
			if _, err := pkClient.VerifyPAASRep(item.PADataValue, roots, reply.EncPart.EType, request.ReqBody.Nonce); err != nil {
				t.Fatalf("legacy PKINIT reply verification: %v", err)
			}
			return
		}
	}
	t.Fatal("legacy PKINIT response omitted PA-PK-AS-REP")
}

func TestServerCanonicalizedAliasPKINITASExchange(t *testing.T) {
	now := time.Unix(2000001003, 0).UTC()
	server, kclient := testServer(t, now)
	db := server.DB.(*kdb.Database)
	if err := db.AddAlias("alice-alias", "alice"); err != nil {
		t.Fatal(err)
	}
	ca, caKey, clientCert, clientKey := makePKINITTestCertificate(t, "alice-alias", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	server.PKINITClientCAs = roots

	alias := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice-alias"}}
	withCanonicalize := *kclient
	withCanonicalize.Canonicalize = true
	credentials, err := withCanonicalize.ASExchangePKINIT(context.Background(), alias, clientCert, clientKey, roots)
	if err != nil {
		t.Fatalf("canonicalized alias PKINIT AS exchange: %v", err)
	}
	canonical := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	if !samePrincipal(credentials.Client, canonical) {
		t.Fatalf("canonicalized PKINIT client = %v, want %v", credentials.Client, canonical)
	}
}

func TestServerAnonymousPKINITASExchange(t *testing.T) {
	now := time.Unix(2000001005, 0).UTC()
	server, kclient := testServer(t, now)
	ca, caKey, _, _ := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	credentials, err := kclient.AnonymousASExchange(context.Background(), "TEST.REALM", roots)
	if err != nil {
		t.Fatalf("anonymous client exchange: %v", err)
	}
	if credentials.Client.Realm != "WELLKNOWN:ANONYMOUS" ||
		credentials.Flags&types.TicketAnonymous == 0 {
		t.Fatalf("anonymous credentials = %+v", credentials)
	}
	assertTicketIndicators(t, server, credentials.Ticket, "krbtgt/TEST.REALM")
	service := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"host", "service.test"},
	}
	if _, err := kclient.TGSExchange(context.Background(), credentials, service); err != nil {
		t.Fatalf("anonymous TGS exchange: %v", err)
	}
}

func TestServerAnonymousRequiresPKINIT(t *testing.T) {
	now := time.Unix(2000001007, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTWellKnown,
		Components: []string{"WELLKNOWN", "ANONYMOUS"},
	}
	service := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"},
	}
	request := asRequest(user, service, 12)
	request.ReqBody.KDCOptions |= types.KDCRequestAnonymous
	var kerberosError protocol.KRBError
	if err := krb5asn1.Unmarshal(
		server.HandleMessage(mustMarshal(t, request)), &kerberosError,
	); err != nil {
		t.Fatalf("anonymous request response: %v", err)
	}
	if kerberosError.ErrorCode != kdcErrBadOption {
		t.Fatalf("anonymous request error = %d, want %d",
			kerberosError.ErrorCode, kdcErrBadOption)
	}
}

func TestClientAnonymousRejectsMissingPKINITKX(t *testing.T) {
	now := time.Unix(2000001008, 0).UTC()
	server, kclient := testServer(t, now)
	ca, caKey, _, _ := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	originalExchange := kclient.Exchange
	kclient.Exchange = func(ctx context.Context, realm string, payload []byte) ([]byte, error) {
		response, err := originalExchange(ctx, realm, payload)
		if err != nil {
			return nil, err
		}
		var reply protocol.ASRep
		if asnErr := krb5asn1.Unmarshal(response, &reply); asnErr != nil || reply.MsgType != 11 {
			return response, nil
		}
		filtered := reply.PAData[:0]
		for _, item := range reply.PAData {
			if item.PADataType != 147 {
				filtered = append(filtered, item)
			}
		}
		reply.PAData = filtered
		return krb5asn1.Marshal(reply)
	}
	_, err := kclient.AnonymousASExchange(context.Background(), "TEST.REALM", roots)
	if err == nil || !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("missing PA-PKINIT-KX error = %v, want integrity", err)
	}
}

func TestServerPKINITRejectsUntrustedClient(t *testing.T) {
	now := time.Unix(2000001010, 0).UTC()
	server, kclient := testServer(t, now)
	ca, caKey, _, _ := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITClientCAs = roots
	_, _, clientCert, clientKey := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)

	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	_, err := kclient.ASExchangePKINIT(context.Background(), user, clientCert, clientKey, roots)
	if err == nil || !hasKRBCode(err, kdcErrClientNotTrusted) {
		t.Fatalf("untrusted PKINIT client error = %v, want KDC error %d", err, kdcErrClientNotTrusted)
	}
}

func TestServerPKINITRejectsMissingCTime(t *testing.T) {
	now := time.Unix(2000001020, 0).UTC()
	server, _ := testServer(t, now)
	ca, caKey, clientCert, clientKey := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	server.PKINITClientCAs = roots

	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	request := asRequest(user, service, 12)
	bodyDER := mustMarshal(t, request.ReqBody)
	pa, _, err := pkinit.BuildPAASReq(bodyDER, time.Time{}, request.ReqBody.Nonce, clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	request.PAData = protocol.MethodData{pa}
	var kerberosError protocol.KRBError
	if err := krb5asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &kerberosError); err != nil {
		t.Fatalf("missing ctime response: %v", err)
	}
	if kerberosError.ErrorCode != kdcErrPreauthFailed {
		t.Fatalf("missing ctime code = %d, want %d", kerberosError.ErrorCode, kdcErrPreauthFailed)
	}
}

func TestServerPKINITFASTASExchange(t *testing.T) {
	now := time.Unix(2000001030, 0).UTC()
	server, kclient := testServer(t, now)
	ca, caKey, clientCert, clientKey := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	server.PKINITClientCAs = roots

	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	armorTGT, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("armor AS exchange: %v", err)
	}
	armor, err := fast.NewArmor(fast.TGT{
		Ticket: armorTGT.Ticket, Client: armorTGT.Client, Key: armorTGT.Key,
	}, now)
	if err != nil {
		t.Fatalf("new armor: %v", err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "TEST.REALM"}}
	request := asRequest(user, service, 13)
	bodyDER := mustMarshal(t, request.ReqBody)
	pa, pkClient, err := pkinit.BuildPAASReq(bodyDER, now, request.ReqBody.Nonce, clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	fastData, err := armor.WrapASReq(request.ReqBody, protocol.MethodData{pa})
	if err != nil {
		t.Fatalf("wrap FAST PKINIT request: %v", err)
	}
	innerRequest := request
	innerRequest.PAData = protocol.MethodData{pa}
	requestDER := mustMarshal(t, innerRequest)
	request.PAData = protocol.MethodData{fastData}
	var reply protocol.ASRep
	if err := krb5asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &reply); err != nil {
		t.Fatalf("FAST PKINIT response: %v", err)
	}
	ticketDER := mustMarshal(t, reply.Ticket)
	fastReply, err := armor.UnwrapReply(reply.PAData, ticketDER, request.ReqBody.Nonce)
	if err != nil {
		t.Fatalf("unwrap FAST PKINIT response: %v", err)
	}
	var pkReply []byte
	for _, item := range fastReply.PAData {
		if item.PADataType == pkinit.PADataASRep {
			pkReply = item.PADataValue
			break
		}
	}
	if len(pkReply) == 0 {
		t.Fatal("FAST response omitted PA-PK-AS-REP")
	}
	dhKey, err := pkClient.VerifyPAASRepWithContext(pkReply, roots, reply.EncPart.EType,
		request.ReqBody.Nonce, user, service, requestDER)
	if err != nil {
		t.Fatalf("verify FAST PKINIT reply: %v", err)
	}
	effectiveKey, err := armor.ReplyKey(protocol.EncryptionKey{
		KeyType: reply.EncPart.EType, KeyValue: dhKey,
	}, fastReply.StrengthenKey)
	if err != nil {
		t.Fatalf("derive FAST PKINIT reply key: %v", err)
	}
	etype, err := crypto.NewRegistry().Get(reply.EncPart.EType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := etype.Decrypt(effectiveKey.KeyValue, 3, reply.EncPart.Cipher); err != nil {
		t.Fatalf("decrypt FAST PKINIT AS-REP: %v", err)
	}
}

func TestServerPKINITKeylessPrincipal(t *testing.T) {
	now := time.Unix(2000001040, 0).UTC()
	server, kclient := testServer(t, now)
	ca, caKey, clientCert, clientKey := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	server.PKINITClientCAs = roots
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	server.DB = keylessPKINITStore{base: server.DB, client: user}

	credentials, err := kclient.ASExchangePKINIT(context.Background(), user, clientCert, clientKey, roots)
	if err != nil {
		t.Fatalf("keyless PKINIT AS exchange: %v", err)
	}
	if !samePrincipal(credentials.Client, user) {
		t.Fatalf("keyless PKINIT client = %v, want %v", credentials.Client, user)
	}
}

type keylessPKINITStore struct {
	base   kdb.Store
	client principal.Principal
}

func (s keylessPKINITStore) Lookup(name principal.Principal) (kdb.PrincipalRecord, bool, error) {
	if samePrincipal(name, s.client) {
		return kdb.PrincipalRecord{Name: s.client, Keys: map[int32]kdb.Key{}}, true, nil
	}
	return s.base.Lookup(name)
}

func makePKINITTestCertificate(t *testing.T, component, realm string, kdc bool) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "PKINIT CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := makePKINITTestCertificateWithCA(t, ca, caKey, component, realm, kdc)
	return ca, caKey, cert, key
}

func makePKINITTestCertificateWithCA(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, component, realm string, kdc bool) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	components := []string{component}
	nameType := int64(1)
	eku := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4}
	if kdc {
		components = append(components, realm)
		nameType = 2
		eku = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5}
	}
	nameParts := make([][]byte, 0, len(components))
	for _, value := range components {
		nameParts = append(nameParts, testGeneralString(value))
	}
	principalDER := testSequence(
		testExplicit(0, testGeneralString(realm)),
		testExplicit(1, testSequence(
			testExplicit(0, testInteger(nameType)),
			testExplicit(1, testSequence(nameParts...)),
		)),
	)
	otherName := testContext(0, append(
		testOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}),
		testContext(0, principalDER)...,
	))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: component},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{eku},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: testSequence(otherName)}},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func testTLV(tag byte, content []byte) []byte {
	return append(append([]byte{tag, byte(len(content))}, content...), nil...)
}

func testSequence(values ...[]byte) []byte {
	var content []byte
	for _, value := range values {
		content = append(content, value...)
	}
	return testTLV(0x30, content)
}

func testExplicit(tag int, value []byte) []byte { return testTLV(0xa0|byte(tag), value) }
func testContext(tag int, value []byte) []byte  { return testTLV(0xa0|byte(tag), value) }
func testGeneralString(value string) []byte     { return testTLV(0x1b, []byte(value)) }
func testInteger(value int64) []byte            { return testTLV(0x02, []byte{byte(value)}) }
func testOID(value asn1.ObjectIdentifier) []byte {
	encoded, _ := asn1.Marshal(value)
	return encoded
}
