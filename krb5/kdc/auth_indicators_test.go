package kdc

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/cammac"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/spake"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestAuthenticationIndicatorsSPAKEAndTGSPropagation(t *testing.T) {
	now := time.Unix(2000003000, 0).UTC()
	server, kclient := testServer(t, now)
	server.EnableSPAKE = true
	server.SPAKEGroups = []int32{spake.GroupEdwards25519}
	server.SPAKEPreauthIndicators = []string{"password", "spake"}
	kclient.SPAKEGroups = []int32{spake.GroupEdwards25519}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"}}

	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("SPAKE AS exchange: %v", err)
	}
	assertTicketIndicators(t, server, tgt.Ticket, "krbtgt/TEST.REALM", "password", "spake")

	serviceRequirement := "otp spake"
	if err := server.DB.(*kdb.Database).SetString(service, "require_auth", &serviceRequirement); err != nil {
		t.Fatalf("set service require_auth: %v", err)
	}
	issued, err := kclient.TGSExchange(context.Background(), tgt, service)
	if err != nil {
		t.Fatalf("TGS exchange with matching indicator: %v", err)
	}
	assertTicketIndicators(t, server, issued.Ticket, "host/service.test", "password", "spake")

	serviceRequirement = "otp"
	if err := server.DB.(*kdb.Database).SetString(service, "require_auth", &serviceRequirement); err != nil {
		t.Fatalf("set rejecting require_auth: %v", err)
	}
	if _, err := kclient.TGSExchange(context.Background(), tgt, service); err == nil ||
		!hasKRBCode(err, kdcErrPolicy) {
		t.Fatalf("TGS require_auth error = %v, want KDC_ERR_POLICY", err)
	}
}

func TestAuthenticationIndicatorsASRequireAuthAnyMatch(t *testing.T) {
	now := time.Unix(2000003001, 0).UTC()
	server, kclient := testServer(t, now)
	server.EnableSPAKE = true
	server.SPAKEGroups = []int32{spake.GroupEdwards25519}
	server.SPAKEPreauthIndicators = []string{"password"}
	kclient.SPAKEGroups = []int32{spake.GroupEdwards25519}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	krbtgt := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"}}
	required := "otp password"
	if err := server.DB.(*kdb.Database).SetString(krbtgt, "require_auth", &required); err != nil {
		t.Fatalf("set AS require_auth: %v", err)
	}
	if _, err := kclient.ASExchange(context.Background(), user, "alice-password"); err != nil {
		t.Fatalf("AS require_auth any-match: %v", err)
	}
	required = "otp"
	if err := server.DB.(*kdb.Database).SetString(krbtgt, "require_auth", &required); err != nil {
		t.Fatalf("set rejecting AS require_auth: %v", err)
	}
	if _, err := kclient.ASExchange(context.Background(), user, "alice-password"); err == nil ||
		!hasKRBCode(err, kdcErrPolicy) {
		t.Fatalf("AS require_auth error = %v, want KDC_ERR_POLICY", err)
	}
}

func TestRequireAuthErrorText(t *testing.T) {
	server, _ := testServer(t, time.Unix(2000003003, 0).UTC())
	record := kdb.PrincipalRecord{Strings: map[string]string{"require_auth": "otp password"}}
	service := &protocol.PrincipalName{NameType: int32(principal.NTSrvHst),
		NameString: []string{"host", "service.test"}}
	response := server.requireAuthError(record, []string{"spake"}, nil, service)
	if response == nil {
		t.Fatal("require_auth unexpectedly passed")
	}
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("decode require_auth error: %v", err)
	}
	if kerberosError.ErrorCode != kdcErrPolicy || kerberosError.EText == nil ||
		*kerberosError.EText != "Required auth indicators not present in ticket: otp password" {
		t.Fatalf("require_auth error = %#v", kerberosError)
	}
}

func TestAuthenticationIndicatorEncryptedChallenge(t *testing.T) {
	now := time.Unix(2000003002, 0).UTC()
	server, kclient := testServer(t, now)
	server.EncryptedChallengeIndicator = "encrypted-challenge"
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	armorTGT, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("armor AS exchange: %v", err)
	}
	ticket, err := kclient.ASExchangeFAST(context.Background(), user, "alice-password", armorTGT)
	if err != nil {
		t.Fatalf("encrypted challenge FAST exchange: %v", err)
	}
	assertTicketIndicators(t, server, ticket.Ticket, "krbtgt/TEST.REALM", "encrypted-challenge")
}

func TestAuthenticationIndicatorEncryptedTimestampNone(t *testing.T) {
	now := time.Unix(2000003004, 0).UTC()
	server, kclient := testServer(t, now)
	server.EncryptedChallengeIndicator = "encrypted-challenge"
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	ticket, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("encrypted timestamp AS exchange: %v", err)
	}
	assertTicketIndicators(t, server, ticket.Ticket, "krbtgt/TEST.REALM")
}

func TestRequireAuthFASTErrorText(t *testing.T) {
	now := time.Unix(2000003005, 0).UTC()
	server, kclient := testServer(t, now)
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	armorTGT, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("armor AS exchange: %v", err)
	}
	armor, err := fast.NewTGSArmor(fast.TGT{Key: armorTGT.Key}, armorTGT.Key)
	if err != nil {
		t.Fatalf("FAST armor: %v", err)
	}
	service := &protocol.PrincipalName{NameType: int32(principal.NTSrvHst),
		NameString: []string{"host", "service.test"}}
	record := kdb.PrincipalRecord{Strings: map[string]string{"require_auth": "otp"}}
	response := server.requireAuthError(record, nil,
		&fastContext{etype: armor.EType, key: armor.Key, nonce: 77}, service)
	if response == nil {
		t.Fatal("require_auth unexpectedly passed")
	}
	var outer protocol.KRBError
	if err := asn1.Unmarshal(response, &outer); err != nil {
		t.Fatalf("decode FAST error: %v", err)
	}
	var outerPA protocol.MethodData
	if err := asn1.Unmarshal(outer.EData, &outerPA); err != nil {
		t.Fatalf("decode FAST error padata: %v", err)
	}
	var fastPA *protocol.PAData
	for i := range outerPA {
		if outerPA[i].PADataType == fast.PAFXFast {
			fastPA = &outerPA[i]
			break
		}
	}
	if fastPA == nil {
		t.Fatal("FAST error missing PA-FX-FAST")
	}
	var wrapper protocol.PAFXFastReply
	if err := asn1.Unmarshal(fastPA.PADataValue, &wrapper); err != nil {
		t.Fatalf("decode FAST wrapper: %v", err)
	}
	plain, err := armor.EType.Decrypt(armor.Key, fast.UsageRep,
		wrapper.ArmoredData.EncFastRep.Cipher)
	if err != nil {
		t.Fatalf("decrypt FAST error: %v", err)
	}
	var fastReply protocol.KrbFastResponse
	if err := asn1.Unmarshal(plain, &fastReply); err != nil {
		t.Fatalf("decode FAST response: %v", err)
	}
	for _, data := range fastReply.PAData {
		if data.PADataType != fast.PAFXError {
			continue
		}
		var inner protocol.KRBError
		if err := asn1.Unmarshal(data.PADataValue, &inner); err != nil {
			t.Fatalf("decode inner policy error: %v", err)
		}
		if inner.ErrorCode != kdcErrPolicy || inner.EText == nil ||
			*inner.EText != "Required auth indicators not present in ticket: otp" {
			t.Fatalf("inner policy error = %#v", inner)
		}
		return
	}
	t.Fatal("FAST error missing PA-FX-ERROR")
}

func TestAuthenticationIndicatorsRenewValidateAndUseLocalKDCKey(t *testing.T) {
	now := time.Unix(2000003006, 0).UTC()
	server, kclient := testServer(t, now)
	server.EnableSPAKE = true
	server.SPAKEGroups = []int32{spake.GroupEdwards25519}
	server.SPAKEPreauthIndicators = []string{"password"}
	kclient.SPAKEGroups = []int32{spake.GroupEdwards25519}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("SPAKE AS exchange: %v", err)
	}
	tgt = cloneAndSetRenewable(t, server, tgt, now.Add(4*time.Hour))
	issuedResponse := server.HandleMessage(rawTGSRequest(t, tgt, service, now,
		types.KDCRenewable))
	issued := credentialsFromTGSReply(t, issuedResponse, tgt, service)
	if issued.Flags&types.TicketRenewable == 0 || issued.RenewTill == nil {
		t.Fatalf("issued service ticket is not renewable: flags=%#x renewTill=%v",
			issued.Flags, issued.RenewTill)
	}
	assertTicketIndicators(t, server, issued.Ticket, "host/service.test", "password")

	server.Now = func() time.Time { return now.Add(time.Hour) }
	renewedResponse := server.HandleMessage(rawTGSRequest(t, issued, service,
		now.Add(time.Hour), types.KDCRenew))
	renewed := credentialsFromTGSReply(t, renewedResponse, issued, service)
	assertTicketIndicators(t, server, renewed.Ticket, "host/service.test", "password")

	invalid := cloneAndMarkTicketInvalid(t, server, issued)
	validatedResponse := server.HandleMessage(rawTGSRequest(t, invalid, service,
		now.Add(time.Hour), types.KDCValidate))
	validated := credentialsFromTGSReply(t, validatedResponse, invalid, service)
	assertTicketIndicators(t, server, validated.Ticket, "host/service.test", "password")
}

func TestAuthenticationIndicatorsUnverifiableHeaderCAMMACIsDropped(t *testing.T) {
	now := time.Unix(2000003007, 0).UTC()
	server, kclient := testServer(t, now)
	server.EnableSPAKE = true
	server.SPAKEGroups = []int32{spake.GroupEdwards25519}
	server.SPAKEPreauthIndicators = []string{"password"}
	kclient.SPAKEGroups = []int32{spake.GroupEdwards25519}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("SPAKE AS exchange: %v", err)
	}
	tgt = cloneWithUnverifiableCAMMAC(t, server, tgt)
	required := "password"
	if err := server.DB.(*kdb.Database).SetString(service, "require_auth", &required); err != nil {
		t.Fatalf("set service require_auth: %v", err)
	}
	response := server.HandleMessage(rawTGSRequest(t, tgt, service, now, 0))
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("decode policy response: %v", err)
	}
	if kerberosError.ErrorCode != kdcErrPolicy {
		t.Fatalf("policy response code = %d, want %d", kerberosError.ErrorCode, kdcErrPolicy)
	}
	if err := server.DB.(*kdb.Database).SetString(service, "require_auth", nil); err != nil {
		t.Fatalf("clear service require_auth: %v", err)
	}
	server.Now = func() time.Time { return now.Add(time.Second) }
	response = server.HandleMessage(rawTGSRequest(t, tgt, service, now.Add(time.Second), 0))
	issued := credentialsFromTGSReply(t, response, tgt, service)
	assertTicketIndicators(t, server, issued.Ticket, "host/service.test")
}

func assertTicketIndicators(t *testing.T, server *Server, ticketDER []byte, serviceName string, want ...string) {
	t.Helper()
	ticket, err := decodeTicket(ticketDER)
	if err != nil {
		t.Fatal(err)
	}
	service, err := principal.Parse(serviceName + "@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := server.DB.Lookup(*service)
	if err != nil || !ok {
		t.Fatalf("service lookup: %v, %v", err, ok)
	}
	key, ok := record.Keys[ticket.EncPart.EType]
	if !ok {
		t.Fatalf("missing service key for enctype %d", ticket.EncPart.EType)
	}
	etype, err := crypto.NewRegistry().Get(ticket.EncPart.EType)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(key.Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt ticket: %v", err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatalf("decode ticket part: %v", err)
	}
	protected, err := cammac.VerifyService(part.AuthorizationData,
		protocol.EncryptionKey{KeyType: key.Enctype, KeyValue: key.Key})
	if err != nil {
		if errors.Is(err, cammac.ErrNotFound) && len(want) == 0 {
			return
		}
		t.Fatalf("verify ticket CAMMAC: %v", err)
	}
	var got []string
	for _, element := range protected {
		if element.ADType != protocol.ADAuthIndicator {
			continue
		}
		var values []types.UTF8String
		if err := asn1.Unmarshal(element.ADData, &values); err != nil {
			t.Fatalf("decode ticket indicators: %v", err)
		}
		for _, value := range values {
			got = append(got, string(value))
		}
	}
	if len(got) != len(want) {
		t.Fatalf("ticket indicators = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ticket indicators = %v, want %v", got, want)
		}
	}
}

func credentialsFromTGSReply(t *testing.T, response []byte, source *client.Credentials,
	service principal.Principal) *client.Credentials {
	t.Helper()
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		var kerberosError protocol.KRBError
		if decodeErr := asn1.Unmarshal(response, &kerberosError); decodeErr == nil {
			t.Fatalf("TGS error code %d", kerberosError.ErrorCode)
		}
		t.Fatalf("decode TGS reply: %v", err)
	}
	part := tgsReplyPart(t, response, source.Key)
	return &client.Credentials{
		Client: source.Client, Server: service, Key: part.Key, Flags: part.Flags,
		AuthTime: part.AuthTime, StartTime: part.StartTime, EndTime: part.EndTime,
		RenewTill: part.RenewTill, Ticket: mustMarshal(t, reply.Ticket),
	}
}

func cloneAndMarkTicketInvalid(t *testing.T, server *Server, source *client.Credentials) *client.Credentials {
	t.Helper()
	ticket, err := decodeTicket(source.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	service := source.Server
	record, ok, err := server.DB.Lookup(service)
	if err != nil || !ok {
		t.Fatalf("service lookup: %v, %v", err, ok)
	}
	serviceKey, ok := record.Keys[ticket.EncPart.EType]
	if !ok {
		t.Fatalf("missing service key for enctype %d", ticket.EncPart.EType)
	}
	etype, err := crypto.NewRegistry().Get(serviceKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(serviceKey.Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt service ticket: %v", err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	part.Flags |= types.TicketInvalid
	elements, err := cammac.ProtectedElements(part.AuthorizationData)
	if err != nil {
		t.Fatalf("extract service CAMMAC: %v", err)
	}
	localKey, ok := server.freshnessKey(nil)
	if !ok {
		t.Fatal("missing local KDC key")
	}
	protected, err := cammac.Marshal(elements, part,
		protocol.EncryptionKey{KeyType: localKey.Enctype, KeyValue: localKey.Key},
		protocol.EncryptionKey{KeyType: serviceKey.Enctype, KeyValue: serviceKey.Key},
		localKey.KVNO)
	if err != nil {
		t.Fatalf("reissue service CAMMAC: %v", err)
	}
	part.AuthorizationData = protected
	ticket.EncPart.Cipher, err = etype.Encrypt(serviceKey.Key, 2, mustMarshal(t, part))
	if err != nil {
		t.Fatalf("encrypt invalid service ticket: %v", err)
	}
	copy := *source
	copy.Ticket = mustMarshal(t, ticket)
	copy.Flags = part.Flags
	return &copy
}

func cloneAndSetRenewable(t *testing.T, server *Server, source *client.Credentials,
	renewTill time.Time) *client.Credentials {
	t.Helper()
	ticket, err := decodeTicket(source.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	tgt := principal.Principal{Realm: ticket.Realm, NameType: principal.NTSrvInstance,
		Components: ticket.SName.NameString}
	record, ok, err := server.DB.Lookup(tgt)
	if err != nil || !ok {
		t.Fatalf("TGT lookup: %v, %v", err, ok)
	}
	tgtKey, ok := record.Keys[ticket.EncPart.EType]
	if !ok {
		t.Fatalf("missing TGT key for enctype %d", ticket.EncPart.EType)
	}
	etype, err := crypto.NewRegistry().Get(tgtKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(tgtKey.Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt TGT: %v", err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	part.Flags |= types.TicketRenewable
	part.RenewTill = &types.KerberosTime{Time: renewTill, Present: true}
	elements, err := cammac.ProtectedElements(part.AuthorizationData)
	if err != nil {
		t.Fatalf("extract TGT CAMMAC: %v", err)
	}
	localKey, ok := server.freshnessKey(nil)
	if !ok {
		t.Fatal("missing local KDC key")
	}
	protected, err := cammac.Marshal(elements, part,
		protocol.EncryptionKey{KeyType: localKey.Enctype, KeyValue: localKey.Key},
		protocol.EncryptionKey{KeyType: tgtKey.Enctype, KeyValue: tgtKey.Key},
		localKey.KVNO)
	if err != nil {
		t.Fatalf("reissue TGT CAMMAC: %v", err)
	}
	part.AuthorizationData = protected
	ticket.EncPart.Cipher, err = etype.Encrypt(tgtKey.Key, 2, mustMarshal(t, part))
	if err != nil {
		t.Fatalf("encrypt renewable TGT: %v", err)
	}
	copy := *source
	copy.Ticket = mustMarshal(t, ticket)
	copy.Flags = part.Flags
	copy.RenewTill = part.RenewTill
	return &copy
}

func cloneWithUnverifiableCAMMAC(t *testing.T, server *Server, source *client.Credentials) *client.Credentials {
	t.Helper()
	ticket, err := decodeTicket(source.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: ticket.Realm, NameType: principal.NTSrvInstance,
		Components: ticket.SName.NameString}
	record, ok, err := server.DB.Lookup(service)
	if err != nil || !ok {
		t.Fatalf("ticket service lookup: %v, %v", err, ok)
	}
	serviceKey, ok := record.Keys[ticket.EncPart.EType]
	if !ok {
		t.Fatalf("missing ticket key for enctype %d", ticket.EncPart.EType)
	}
	etype, err := crypto.NewRegistry().Get(serviceKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(serviceKey.Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt ticket: %v", err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	elements, err := cammac.ProtectedElements(part.AuthorizationData)
	if err != nil {
		t.Fatalf("extract ticket CAMMAC: %v", err)
	}
	localKey, ok := server.freshnessKey(nil)
	if !ok {
		t.Fatal("missing local KDC key")
	}
	remoteKey := protocol.EncryptionKey{KeyType: localKey.Enctype,
		KeyValue: bytes.Repeat([]byte{0x77}, len(localKey.Key))}
	replacement, err := cammac.Marshal(elements, part, remoteKey,
		protocol.EncryptionKey{KeyType: serviceKey.Enctype, KeyValue: serviceKey.Key},
		localKey.KVNO)
	if err != nil {
		t.Fatalf("reissue remote CAMMAC: %v", err)
	}
	part.AuthorizationData = replacement
	ticket.EncPart.Cipher, err = etype.Encrypt(serviceKey.Key, 2, mustMarshal(t, part))
	if err != nil {
		t.Fatalf("encrypt remote CAMMAC ticket: %v", err)
	}
	copy := *source
	copy.Ticket = mustMarshal(t, ticket)
	return &copy
}

func decodeTicket(data []byte) (protocol.Ticket, error) {
	var ticket protocol.Ticket
	err := asn1.Unmarshal(data, &ticket)
	return ticket, err
}
