package kdc

import (
	"bytes"
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
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
func (testKDCPreauthModule) Edata(*PreauthRock) (protocol.PAData, error) {
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
