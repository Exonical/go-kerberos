package kdc

import (
	"bytes"
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const testPluginPAType int32 = 2000

type testClientPreauthModule struct{}

func (testClientPreauthModule) Name() string     { return "test-client" }
func (testClientPreauthModule) PATypes() []int32 { return []int32{testPluginPAType} }
func (testClientPreauthModule) Flags(int32) int  { return preauth.PAReal }
func (testClientPreauthModule) Process(_ *preauth.ClientRequestContext, pa preauth.PAData, _ preauth.ASReqInfo) ([]preauth.PAData, error) {
	if string(pa.PADataValue) != "hint" {
		return nil, stderrors.New("unexpected preauth hint")
	}
	return []preauth.PAData{{PADataType: testPluginPAType, PADataValue: []byte("answer")}}, nil
}

type testKDCPreauthModule struct {
	flags    int
	fail     bool
	authData bool
}

func (m testKDCPreauthModule) Name() string     { return "test-kdc" }
func (m testKDCPreauthModule) PATypes() []int32 { return []int32{testPluginPAType} }
func (m testKDCPreauthModule) Flags(int32) int  { return m.flags }
func (testKDCPreauthModule) Edata(*PreauthRock, int32) (protocol.PAData, error) {
	return protocol.PAData{PADataType: testPluginPAType, PADataValue: []byte("hint")}, nil
}
func (m testKDCPreauthModule) Verify(_ *PreauthRock, pa protocol.PAData) (*VerifyResult, error) {
	if m.fail || !bytes.Equal(pa.PADataValue, []byte("answer")) {
		return nil, stderrors.New("preauth verification failed")
	}
	result := &VerifyResult{
		Authenticated:  true,
		AuthIndicators: []string{"test-indicator"},
		PreauthType:    "test-kdc",
	}
	if m.authData {
		result.AuthorizationData = protocol.AuthorizationData{{
			ADType: 2999,
			ADData: []byte("module-authdata"),
		}}
	}
	return result, nil
}

type multiKDCPreauthModule struct {
	name      string
	paType    int32
	indicator string
	authType  int32
	flags     int
	hasFlags  bool
	count     *int
}

type replacementKDCPreauthModule struct{}

func (replacementKDCPreauthModule) Name() string     { return "replacement" }
func (replacementKDCPreauthModule) PATypes() []int32 { return []int32{2003} }
func (replacementKDCPreauthModule) Flags(int32) int  { return PARequired | PAReplacesKey }
func (replacementKDCPreauthModule) Edata(*PreauthRock, int32) (protocol.PAData, error) {
	return protocol.PAData{PADataType: 2003, PADataValue: []byte("hint")}, nil
}
func (replacementKDCPreauthModule) Verify(*PreauthRock, protocol.PAData) (*VerifyResult, error) {
	return &VerifyResult{
		Authenticated: true,
		ReplacedReplyKey: &kdb.Key{
			Enctype: crypto.EnctypeAES128SHA1,
			Key:     bytes.Repeat([]byte{0x5a}, 16),
		},
	}, nil
}

type keySettingClientModule struct {
	key protocol.EncryptionKey
}

func (keySettingClientModule) Name() string     { return "key-setting-info" }
func (keySettingClientModule) PATypes() []int32 { return []int32{2004} }
func (keySettingClientModule) Flags(int32) int  { return preauth.PAInfo }
func (m keySettingClientModule) Process(ctx *preauth.ClientRequestContext,
	_ preauth.PAData, _ preauth.ASReqInfo) ([]preauth.PAData, error) {
	return nil, ctx.SetASKey(m.key)
}

type keySettingKDCPreauthModule struct{}

func (keySettingKDCPreauthModule) Name() string     { return "key-setting-info" }
func (keySettingKDCPreauthModule) PATypes() []int32 { return []int32{2004} }
func (keySettingKDCPreauthModule) Flags(int32) int  { return 0 }
func (keySettingKDCPreauthModule) Edata(*PreauthRock, int32) (protocol.PAData, error) {
	return protocol.PAData{PADataType: 2004, PADataValue: []byte("hint")}, nil
}
func (keySettingKDCPreauthModule) Verify(*PreauthRock, protocol.PAData) (*VerifyResult, error) {
	return nil, nil
}

func (m multiKDCPreauthModule) Name() string     { return m.name }
func (m multiKDCPreauthModule) PATypes() []int32 { return []int32{m.paType} }
func (m multiKDCPreauthModule) Flags(int32) int {
	if m.hasFlags {
		return m.flags
	}
	return PARequired
}
func (m multiKDCPreauthModule) Edata(*PreauthRock, int32) (protocol.PAData, error) {
	return protocol.PAData{PADataType: m.paType, PADataValue: []byte("hint")}, nil
}
func (m multiKDCPreauthModule) Verify(_ *PreauthRock, pa protocol.PAData) (*VerifyResult, error) {
	if m.count != nil {
		(*m.count)++
	}
	if string(pa.PADataValue) != "answer" {
		return nil, stderrors.New("unexpected module answer")
	}
	return &VerifyResult{
		Authenticated:  true,
		AuthIndicators: []string{m.indicator},
		AuthorizationData: protocol.AuthorizationData{{
			ADType: m.authType, ADData: []byte(m.name),
		}},
	}, nil
}

func TestRegisteredPreauthModuleRoundTrip(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, kclient := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{testKDCPreauthModule{flags: PARequired, authData: true}}
	kclient.PreauthModules = []preauth.ClientPreauthModule{testClientPreauthModule{}}
	var audited AuditState
	server.AuditModules = []AuditModule{NewFuncAuditModule("test", func(event string, success bool, state AuditState) {
		if event == "as_req" && success {
			audited = state
		}
	})}
	var finalResponse []byte
	kclient.Exchange = func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		finalResponse = server.HandleMessage(payload)
		return finalResponse, nil
	}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	credential, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("ASExchange: %v", err)
	}
	if credential == nil || credential.Key.KeyType == 0 {
		t.Fatal("module exchange returned no credentials")
	}
	part := asReplyPart(t, finalResponse)
	if part.Flags&types.TicketPreAuthent == 0 {
		t.Fatal("module AS reply lacks preauth flag")
	}
	if audited.PreauthType != "test-kdc" ||
		len(audited.AuthIndicators) != 1 || audited.AuthIndicators[0] != "test-indicator" {
		t.Fatalf("audit state = %#v", audited)
	}
	var reply protocol.ASRep
	if err := asn1.Unmarshal(finalResponse, &reply); err != nil {
		t.Fatal(err)
	}
	serviceName := principal.Principal{Realm: server.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", server.Realm}}
	serviceRecord, ok, err := server.DB.Lookup(serviceName)
	if err != nil || !ok {
		t.Fatalf("service lookup: %v, %v", err, ok)
	}
	serviceKey := serviceRecord.Keys[crypto.EnctypeAES256SHA1]
	serviceKey.Enctype = crypto.EnctypeAES256SHA1
	etype, err := crypto.NewRegistry().Get(serviceKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(serviceKey.Key, 2, reply.Ticket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var ticket protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &ticket); err != nil {
		t.Fatal(err)
	}
	foundAuthData := false
	for _, entry := range ticket.AuthorizationData {
		if entry.ADType == 2999 && bytes.Equal(entry.ADData, []byte("module-authdata")) {
			foundAuthData = true
			break
		}
	}
	if !foundAuthData {
		t.Fatal("module authorization data missing from AS ticket")
	}
}

func TestRequiredPreauthModuleMissing(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{testKDCPreauthModule{flags: PARequired}}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{Realm: server.Realm,
		NameType: principal.NTSrvInstance, Components: []string{"krbtgt", server.Realm}}, 8)
	var response protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &response); err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != kdcErrPreauthRequired {
		t.Fatalf("error code = %d, want %d", response.ErrorCode, kdcErrPreauthRequired)
	}
	var methodData protocol.MethodData
	if err := asn1.Unmarshal(response.EData, &methodData); err != nil {
		t.Fatal(err)
	}
	if findPA(methodData, testPluginPAType) == nil {
		t.Fatal("required module hint missing")
	}
}

func TestRequiredPreauthModuleRejectsBuiltinOnly(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{testKDCPreauthModule{flags: PARequired}}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{Realm: server.Realm,
		NameType: principal.NTSrvInstance, Components: []string{"krbtgt", server.Realm}}, 8)
	addPreauthPassword(t, &request, "alice-password", now)
	var response protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &response); err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != int32(krberrors.KDCErrPreauthFailed) {
		t.Fatalf("error code = %d, want %d", response.ErrorCode, krberrors.KDCErrPreauthFailed)
	}
}

func TestRequiredPreauthModulesAggregateResults(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{
		multiKDCPreauthModule{name: "first", paType: 2001, indicator: "one", authType: 3001},
		multiKDCPreauthModule{name: "second", paType: 2002, indicator: "two", authType: 3002},
	}
	var audited AuditState
	server.AuditModules = []AuditModule{NewFuncAuditModule("aggregate", func(event string, success bool, state AuditState) {
		if event == "as_req" && success {
			audited = state
		}
	})}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{Realm: server.Realm,
		NameType: principal.NTSrvInstance, Components: []string{"krbtgt", server.Realm}}, 10)
	request.PAData = protocol.MethodData{
		{PADataType: 2001, PADataValue: []byte("answer")},
		{PADataType: 2002, PADataValue: []byte("answer")},
	}
	response := server.HandleMessage(mustMarshal(t, request))
	var reply protocol.ASRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("AS response: %v", err)
	}
	if reply.MsgType != 11 {
		t.Fatalf("message type = %d, want AS-REP", reply.MsgType)
	}
	if len(audited.AuthIndicators) != 2 || audited.AuthIndicators[0] != "one" ||
		audited.AuthIndicators[1] != "two" {
		t.Fatalf("audit indicators = %#v", audited.AuthIndicators)
	}
	service := principal.Principal{Realm: server.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", server.Realm}}
	record, ok, err := server.DB.Lookup(service)
	if err != nil || !ok {
		t.Fatalf("service lookup: %v, %v", err, ok)
	}
	key := record.Keys[crypto.EnctypeAES256SHA1]
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(key.Key, 2, reply.Ticket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var ticket protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &ticket); err != nil {
		t.Fatal(err)
	}
	found := map[int32]bool{}
	for _, entry := range ticket.AuthorizationData {
		if entry.ADType == 3001 || entry.ADType == 3002 {
			found[entry.ADType] = true
		}
	}
	if !found[3001] || !found[3002] {
		t.Fatalf("authorization data = %#v", ticket.AuthorizationData)
	}
}

func TestRequiredPreauthModulesMissingAnswerRejects(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{
		multiKDCPreauthModule{name: "first", paType: 2001, indicator: "one", authType: 3001},
		multiKDCPreauthModule{name: "second", paType: 2002, indicator: "two", authType: 3002},
	}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{Realm: server.Realm,
		NameType: principal.NTSrvInstance, Components: []string{"krbtgt", server.Realm}}, 11)
	request.PAData = protocol.MethodData{{PADataType: 2001, PADataValue: []byte("answer")}}
	var response protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &response); err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != int32(krberrors.KDCErrPreauthFailed) {
		t.Fatalf("error code = %d, want %d", response.ErrorCode, krberrors.KDCErrPreauthFailed)
	}
}

func TestCustomPreauthAuthorizationDenial(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{testKDCPreauthModule{}}
	server.Authorize = func(principal.Principal, principal.Principal, bool) error {
		return stderrors.New("denied")
	}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{Realm: server.Realm,
		NameType: principal.NTSrvInstance, Components: []string{"krbtgt", server.Realm}}, 12)
	request.PAData = protocol.MethodData{{PADataType: testPluginPAType, PADataValue: []byte("answer")}}
	var response protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &response); err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != kdcErrPolicy {
		t.Fatalf("error code = %d, want %d", response.ErrorCode, kdcErrPolicy)
	}
}

func TestCustomPreauthReplacementReplyKey(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, kclient := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{replacementKDCPreauthModule{}}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	kclient.PreauthModules = []preauth.ClientPreauthModule{
		replacementClientPreauthModule{},
	}
	credentials, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("ASExchange: %v", err)
	}
	if credentials == nil {
		t.Fatal("replacement-key exchange returned no credentials")
	}
}

type replacementClientPreauthModule struct{}

func (replacementClientPreauthModule) Name() string     { return "replacement-client" }
func (replacementClientPreauthModule) PATypes() []int32 { return []int32{2003} }
func (replacementClientPreauthModule) Flags(int32) int  { return preauth.PAReal }
func (replacementClientPreauthModule) Process(ctx *preauth.ClientRequestContext,
	_ preauth.PAData, _ preauth.ASReqInfo) ([]preauth.PAData, error) {
	if err := ctx.SetASKey(protocol.EncryptionKey{
		KeyType:  crypto.EnctypeAES128SHA1,
		KeyValue: bytes.Repeat([]byte{0x5a}, 16),
	}); err != nil {
		return nil, err
	}
	return []preauth.PAData{{PADataType: 2003, PADataValue: []byte("answer")}}, nil
}

func TestKeylessCustomPreauthRequiresReplacementKey(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	server.OTPValidator = func(principal.Principal, string) error { return nil }
	server.PreauthModules = []KDCPreauthModule{testKDCPreauthModule{flags: PARequired}}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{Realm: server.Realm,
		NameType: principal.NTSrvInstance, Components: []string{"krbtgt", server.Realm}}, 13)
	request.PAData = protocol.MethodData{{PADataType: testPluginPAType, PADataValue: []byte("answer")}}
	var response protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &response); err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != int32(krberrors.KDCErrPreauthFailed) {
		t.Fatalf("error code = %d, want %d", response.ErrorCode, krberrors.KDCErrPreauthFailed)
	}
}

func TestClientInfoModuleUpdatesBuiltinReplyKey(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, kclient := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{keySettingKDCPreauthModule{}}
	kclient.Config = &config.Config{DefaultTKTEnctypes: []int32{crypto.EnctypeAES128SHA1}}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := etype.StringToKey([]byte("alice-password"), []byte("TEST.REALMalice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	kclient.PreauthModules = []preauth.ClientPreauthModule{keySettingClientModule{
		key: protocol.EncryptionKey{
			KeyType:  crypto.EnctypeAES128SHA1,
			KeyValue: key,
		},
	}}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	if _, err := kclient.ASExchange(context.Background(), user, "alice-password"); err != nil {
		t.Fatalf("ASExchange: %v", err)
	}
}

func TestFASTCustomPreauthModuleRoundTrip(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, kclient := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{testKDCPreauthModule{flags: PARequired}}
	kclient.PreauthModules = []preauth.ClientPreauthModule{testClientPreauthModule{}}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	armorTGT, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("armor ASExchange: %v", err)
	}
	if _, err := kclient.ASExchangeFAST(context.Background(), user, "alice-password", armorTGT); err != nil {
		t.Fatalf("FAST ASExchange: %v", err)
	}
}

func TestHardwarePreauthModuleSetsTicketFlag(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, kclient := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{testKDCPreauthModule{flags: PARequired | PAHardware}}
	kclient.PreauthModules = []preauth.ClientPreauthModule{testClientPreauthModule{}}
	var finalResponse []byte
	kclient.Exchange = func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		finalResponse = server.HandleMessage(payload)
		return finalResponse, nil
	}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	if _, err := kclient.ASExchange(context.Background(), user, "alice-password"); err != nil {
		t.Fatal(err)
	}
	part := asReplyPart(t, finalResponse)
	if part.Flags&types.TicketHWAuthent == 0 {
		t.Fatal("module AS reply lacks hardware-authenticated flag")
	}
}

func TestRequiresHardwareAuthRejectsNonHardwareCustomPreauth(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	db := server.DB.(*kdb.Database)
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	record, ok, err := db.Lookup(user)
	if err != nil || !ok {
		t.Fatal(err)
	}
	record.Flags |= kdb.RequiresHWAuth
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	server.PreauthModules = []KDCPreauthModule{testKDCPreauthModule{flags: PARequired}}
	service := principal.Principal{Realm: server.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", server.Realm}}
	request := asRequest(user, service, 14)
	request.PAData = protocol.MethodData{{PADataType: testPluginPAType, PADataValue: []byte("answer")}}
	var failure protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.ErrorCode != int32(krberrors.KDCErrPreauthFailed) {
		t.Fatalf("error code = %d, want preauth failed", failure.ErrorCode)
	}
}

func TestRequiresHardwareAuthAcceptsHardwareCustomPreauth(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, kclient := testServer(t, now)
	db := server.DB.(*kdb.Database)
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	record, ok, err := db.Lookup(user)
	if err != nil || !ok {
		t.Fatal(err)
	}
	record.Flags |= kdb.RequiresHWAuth
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	server.PreauthModules = []KDCPreauthModule{
		testKDCPreauthModule{flags: PARequired | PAHardware},
	}
	kclient.PreauthModules = []preauth.ClientPreauthModule{testClientPreauthModule{}}
	var finalResponse []byte
	kclient.Exchange = func(_ context.Context, _ string, payload []byte) ([]byte, error) {
		finalResponse = server.HandleMessage(payload)
		return finalResponse, nil
	}
	if _, err := kclient.ASExchange(context.Background(), user, "alice-password"); err != nil {
		t.Fatal(err)
	}
	part := asReplyPart(t, finalResponse)
	if part.Flags&types.TicketHWAuthent == 0 {
		t.Fatal("custom hardware preauth did not set HW-AUTHENT")
	}
}

func TestKeylessCustomPreauthReplacementKey(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	server.DB = keylessPKINITStore{base: server.DB, client: user}
	server.PreauthModules = []KDCPreauthModule{replacementKDCPreauthModule{}}
	service := principal.Principal{Realm: server.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", server.Realm}}
	request := asRequest(user, service, 16)
	request.PAData = protocol.MethodData{{PADataType: 2003, PADataValue: []byte("answer")}}
	var reply protocol.ASRep
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &reply); err != nil {
		t.Fatalf("keyless replacement exchange: %v", err)
	}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := etype.Decrypt(bytes.Repeat([]byte{0x5a}, 16), 3, reply.EncPart.Cipher); err != nil {
		t.Fatalf("replacement-key AS-REP decrypt: %v", err)
	}
}

func TestKeylessCustomPreauthHintsAdvertiseModule(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	server.DB = keylessPKINITStore{base: server.DB, client: user}
	server.PreauthModules = []KDCPreauthModule{replacementKDCPreauthModule{}}
	service := principal.Principal{Realm: server.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", server.Realm}}
	request := asRequest(user, service, 18)
	var failure protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.ErrorCode != int32(25) {
		t.Fatalf("keyless hint error = %d, want preauth required", failure.ErrorCode)
	}
	var methodData protocol.MethodData
	if err := asn1.Unmarshal(failure.EData, &methodData); err != nil {
		t.Fatal(err)
	}
	if findPA(methodData, 2003) == nil {
		t.Fatalf("keyless hints = %#v, missing replacement module", methodData)
	}
}

func TestKeylessCustomPreauthWithoutReplacementKeyFailsPreauth(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	server.DB = keylessPKINITStore{base: server.DB, client: user}
	server.PreauthModules = []KDCPreauthModule{testKDCPreauthModule{flags: PARequired}}
	service := principal.Principal{Realm: server.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", server.Realm}}
	request := asRequest(user, service, 17)
	request.PAData = protocol.MethodData{{PADataType: testPluginPAType, PADataValue: []byte("answer")}}
	var failure protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.ErrorCode != int32(krberrors.KDCErrPreauthFailed) {
		t.Fatalf("keyless non-replacement error = %d, want preauth failed", failure.ErrorCode)
	}
}

func TestSufficientCustomPreauthStopsFurtherModules(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	firstCount, secondCount := 0, 0
	server.PreauthModules = []KDCPreauthModule{
		multiKDCPreauthModule{name: "first", paType: 2001, indicator: "one",
			authType: 3001, flags: PASufficient, hasFlags: true, count: &firstCount},
		multiKDCPreauthModule{name: "second", paType: 2002, indicator: "two",
			authType: 3002, flags: 0, hasFlags: true, count: &secondCount},
	}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: server.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", server.Realm}}
	request := asRequest(user, service, 15)
	request.PAData = protocol.MethodData{
		{PADataType: 2001, PADataValue: []byte("answer")},
		{PADataType: 2002, PADataValue: []byte("answer")},
	}
	var reply protocol.ASRep
	raw := server.HandleMessage(mustMarshal(t, request))
	if err := asn1.Unmarshal(raw, &reply); err != nil {
		t.Fatalf("AS response: %v", err)
	}
	if reply.MsgType != 11 || firstCount != 1 || secondCount != 0 {
		t.Fatalf("reply/counts = %d/%d/%d", reply.MsgType, firstCount, secondCount)
	}
}

func TestPreauthModuleVerifyFailure(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	server.PreauthModules = []KDCPreauthModule{testKDCPreauthModule{flags: PARequired, fail: true}}
	user := principal.Principal{Realm: server.Realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	request := asRequest(user, principal.Principal{Realm: server.Realm,
		NameType: principal.NTSrvInstance, Components: []string{"krbtgt", server.Realm}}, 9)
	request.PAData = protocol.MethodData{{PADataType: testPluginPAType, PADataValue: []byte("answer")}}
	var response protocol.KRBError
	if err := asn1.Unmarshal(server.HandleMessage(mustMarshal(t, request)), &response); err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != int32(krberrors.KDCErrPreauthFailed) {
		t.Fatalf("error code = %d, want %d", response.ErrorCode, krberrors.KDCErrPreauthFailed)
	}
}
