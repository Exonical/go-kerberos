package kdc

import (
	"context"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestOptInPACIssuanceAndExtraction(t *testing.T) {
	now := time.Unix(2000001900, 0).UTC()
	server, kclient := testServer(t, now)
	server.EnablePAC = true
	server.GeneratePAC = func(client, service principal.Principal) ([]byte, error) {
		return []byte{0xaa, 0xbb, 0xcc}, nil
	}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	creds, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(creds.Ticket, &ticket); err != nil {
		t.Fatal(err)
	}
	record, ok, err := server.DB.Lookup(ticketPrincipal(ticket))
	if err != nil || !ok {
		t.Fatalf("lookup ticket key: %v", err)
	}
	key := record.Keys[ticket.EncPart.EType]
	etype, err := crypto.NewRegistry().Get(key.Enctype)
	if err != nil {
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
	plain, err := etype.Decrypt(key.Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	p, err := pac.FromTicket(part, pac.Key{EType: etype, Key: key.Key},
		&pac.Key{EType: privEType, Key: privKey.Key})
	if err != nil {
		t.Fatal(err)
	}
	data, ok := p.Buffer(pac.LogonInfoBuffer)
	if !ok || string(data) != string([]byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("logon-info = %x", data)
	}

	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	serviceCreds, err := kclient.TGSExchange(context.Background(), creds, service)
	if err != nil {
		t.Fatal(err)
	}
	var serviceTicket protocol.Ticket
	if err := asn1.Unmarshal(serviceCreds.Ticket, &serviceTicket); err != nil {
		t.Fatal(err)
	}
	serviceRecord, ok, err := server.DB.Lookup(ticketPrincipal(serviceTicket))
	if err != nil || !ok {
		t.Fatalf("lookup service key: %v", err)
	}
	serviceKDBKey := serviceRecord.Keys[serviceTicket.EncPart.EType]
	serviceEType, err := crypto.NewRegistry().Get(serviceKDBKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	servicePlain, err := serviceEType.Decrypt(serviceKDBKey.Key, 2, serviceTicket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var servicePart protocol.EncTicketPart
	if err := asn1.Unmarshal(servicePlain, &servicePart); err != nil {
		t.Fatal(err)
	}
	servicePAC, err := pac.FromTicket(servicePart,
		pac.Key{EType: serviceEType, Key: serviceKDBKey.Key},
		&pac.Key{EType: privEType, Key: privKey.Key})
	if err != nil {
		t.Fatal(err)
	}
	if data, ok := servicePAC.Buffer(pac.LogonInfoBuffer); !ok || string(data) != string([]byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("TGS logon-info = %x", data)
	}
	ticketPAC, ok := servicePAC.Buffer(pac.TicketChecksum)
	if !ok || len(ticketPAC) < 4 {
		t.Fatal("TGS PAC is missing ticket checksum")
	}
	dummyPart := servicePart
	dummyPart.AuthorizationData, err = pac.AddDummyAuthorizationData(part.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	if err := servicePAC.VerifyTicketSignature(marshalDER(dummyPart),
		pac.Key{EType: privEType, Key: privKey.Key}); err != nil {
		t.Fatal(err)
	}
}

func TestStructuredPACIssuance(t *testing.T) {
	now := time.Unix(2000001900, 0).UTC()
	server, kclient := testServer(t, now)
	server.EnablePAC = true
	sid, err := pac.ParseSID("S-1-5-21-1-2-3")
	if err != nil {
		t.Fatal(err)
	}
	server.GeneratePACIdentity = func(client, service principal.Principal) (*PACIdentity, error) {
		return &PACIdentity{
			LogonInfo: &pac.LogonInfo{EffectiveName: "alice", UserID: 1000},
			UPN:       "alice@test.realm", DNSDomainName: "test.realm",
			SAMName: "alice", SID: sid, Flags: pac.UPNDNSInfoHasSAMNameAndSID,
		}, nil
	}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	creds, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(creds.Ticket, &ticket); err != nil {
		t.Fatal(err)
	}
	record, ok, err := server.DB.Lookup(ticketPrincipal(ticket))
	if err != nil || !ok {
		t.Fatalf("lookup ticket key: %v", err)
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
	p, err := pac.FromAuthorizationData(part.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	logon, ok := p.Buffer(pac.LogonInfoBuffer)
	if !ok {
		t.Fatal("structured PAC is missing logon-info")
	}
	parsedLogon, err := pac.ParseLogonInfo(logon)
	if err != nil || parsedLogon.EffectiveName != "alice" {
		t.Fatalf("logon-info = %#v, %v", parsedLogon, err)
	}
	upnData, ok := p.Buffer(pac.UPNDNSInfo)
	if !ok {
		t.Fatal("structured PAC is missing UPN_DNS_INFO")
	}
	upn, err := pac.ParseUPNDNSInfo(upnData)
	if err != nil || upn.UPN != "alice@test.realm" || upn.SID == nil ||
		upn.SID.String() != sid.String() {
		t.Fatalf("UPN_DNS_INFO = %#v, %v", upn, err)
	}
}

func TestPACCredentialsHookUsesReplacedReplyKey(t *testing.T) {
	now := time.Unix(2000001900, 0).UTC()
	server, _ := testServer(t, now)
	server.EnablePAC = true
	client := principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", Components: []string{"krbtgt", "TEST.REALM"}}
	record, ok, err := server.DB.Lookup(service)
	if err != nil || !ok {
		t.Fatal("krbtgt principal lookup failed")
	}
	key := record.Keys[crypto.EnctypeAES256SHA1]
	calls := 0
	plaintext := []byte("opaque credential data")
	server.GeneratePACCredentials = func(gotClient, gotService principal.Principal,
		replaced kdb.Key) ([]byte, int32, error) {
		calls++
		if gotClient.String() != client.String() || gotService.String() != service.String() {
			t.Fatalf("hook principals = %s, %s", gotClient, gotService)
		}
		return plaintext, replaced.Enctype, nil
	}
	part := protocol.EncTicketPart{AuthTime: types.KerberosTime{Time: now, Present: true}}
	replyKey := key
	if err := server.issuePACWithOptions(&part, client, service, key, key, false, false, &replyKey, nil, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("hook calls = %d, want 1", calls)
	}
	p, err := pac.FromAuthorizationData(part.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	data, ok := p.Buffer(pac.CredentialInfoBuffer)
	if !ok {
		t.Fatal("credentials-info buffer missing")
	}
	info, err := pac.ParseCredentialInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := info.Decrypt(key.Key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("decrypted credentials = %q, want %q", got, plaintext)
	}
	originalAuthData := append(protocol.AuthorizationData(nil), part.AuthorizationData...)

	part = protocol.EncTicketPart{AuthTime: types.KerberosTime{Time: now, Present: true}}
	if err := server.issuePACWithOptions(&part, client, service, key, key, false, false, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("hook calls after ordinary issuance = %d, want 1", calls)
	}
	carryPart := protocol.EncTicketPart{
		AuthTime:          types.KerberosTime{Time: now, Present: true},
		AuthorizationData: originalAuthData,
	}
	if err := server.issuePAC(&carryPart, client, service, key, key, false, false); err != nil {
		t.Fatal(err)
	}
	carryPAC, err := pac.FromAuthorizationData(carryPart.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	carryData, ok := carryPAC.Buffer(pac.CredentialInfoBuffer)
	if !ok {
		t.Fatal("credentials-info missing after TGS carry-over")
	}
	if string(carryData) != string(data) {
		t.Fatalf("credentials-info changed during carry-over")
	}
}

func TestPACDelegationInfoUpdateAndCarryOver(t *testing.T) {
	now := time.Unix(2000001900, 0).UTC()
	server, _ := testServer(t, now)
	server.EnablePAC = true
	client := principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", Components: []string{"host", "service.test"}}
	record, ok, err := server.DB.Lookup(service)
	if err != nil || !ok {
		t.Fatal("service principal lookup failed")
	}
	key := record.Keys[crypto.EnctypeAES256SHA1]
	evidence := principal.Principal{Realm: "TEST.REALM", Components: []string{"host", "evidence.test"}}
	part := protocol.EncTicketPart{AuthTime: types.KerberosTime{Time: now, Present: true}}
	if err := server.issuePACWithOptions(&part, client, service, key, key, false, false, nil, &evidence, nil); err != nil {
		t.Fatal(err)
	}
	p, err := pac.FromAuthorizationData(part.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	wire, ok := p.Buffer(pac.DelegationInfoBuffer)
	if !ok {
		t.Fatal("delegation-info buffer missing")
	}
	info, err := pac.ParseDelegationInfo(wire)
	if err != nil {
		t.Fatal(err)
	}
	if info.ProxyTarget != "host/service.test" || !sameStringList(info.TransitedServices, []string{evidence.String()}) {
		t.Fatalf("delegation-info = %#v", info)
	}
	firstWire := append([]byte(nil), wire...)
	firstAuthData := append(protocol.AuthorizationData(nil), part.AuthorizationData...)

	nextEvidence := principal.Principal{Realm: "TEST.REALM", Components: []string{"host", "next.test"}}
	if err := server.issuePACWithOptions(&part, client, service, key, key, false, false, nil, &nextEvidence, nil); err != nil {
		t.Fatal(err)
	}
	p, err = pac.FromAuthorizationData(part.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	wire, ok = p.Buffer(pac.DelegationInfoBuffer)
	if !ok {
		t.Fatal("extended delegation-info buffer missing")
	}
	info, err = pac.ParseDelegationInfo(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !sameStringList(info.TransitedServices, []string{evidence.String(), nextEvidence.String()}) {
		t.Fatalf("extended delegation-info = %#v", info)
	}

	ordinaryPart := protocol.EncTicketPart{AuthTime: types.KerberosTime{Time: now, Present: true}}
	ordinaryPart.AuthorizationData = firstAuthData
	if err := server.issuePAC(&ordinaryPart, client, service, key, key, false, false); err != nil {
		t.Fatal(err)
	}
	p, err = pac.FromAuthorizationData(ordinaryPart.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	gotWire, ok := p.Buffer(pac.DelegationInfoBuffer)
	if !ok || string(gotWire) != string(firstWire) {
		t.Fatalf("ordinary carry-over = %x, want %x", gotWire, firstWire)
	}
}

func sameStringList(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func TestPACRenewValidateUsesHeaderKeyAndMixedPrivsvrEnctype(t *testing.T) {
	now := time.Unix(2000001900, 0).UTC()
	server, _ := testServer(t, now)
	server.EnablePAC = true
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	record, ok, err := server.DB.Lookup(service)
	if err != nil || !ok {
		t.Fatal("service principal lookup failed")
	}
	header := record.Keys[crypto.EnctypeAES128SHA1]
	output := record.Keys[crypto.EnctypeAES256SHA1]
	priv, ok := server.pacPrivsvrKey()
	if !ok {
		t.Fatal("privileged-server key unavailable")
	}
	if priv.Enctype == output.Enctype {
		t.Fatalf("privileged-server key unexpectedly uses output enctype %d", output.Enctype)
	}
	headerEType, err := crypto.NewRegistry().Get(header.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	outputEType, err := crypto.NewRegistry().Get(output.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	privEType, err := crypto.NewRegistry().Get(priv.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	incoming := pac.New()
	incomingData, err := incoming.Sign(now, nil,
		pac.Key{EType: headerEType, Key: header.Key},
		pac.Key{EType: privEType, Key: priv.Key}, true)
	if err != nil {
		t.Fatal(err)
	}
	authdata, err := pac.AuthorizationData(incomingData)
	if err != nil {
		t.Fatal(err)
	}
	part := protocol.EncTicketPart{
		AuthTime:          types.KerberosTime{Time: now, Present: true},
		AuthorizationData: authdata,
	}
	if err := server.issuePAC(&part, principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}},
		service, header, output, true, false); err != nil {
		t.Fatalf("renew PAC re-sign: %v", err)
	}
	renewed, err := pac.FromTicket(part,
		pac.Key{EType: outputEType, Key: output.Key},
		&pac.Key{EType: privEType, Key: priv.Key})
	if err != nil {
		t.Fatalf("renewed PAC verification: %v", err)
	}
	if _, ok := renewed.Buffer(pac.TicketChecksum); !ok {
		t.Fatal("renewed PAC missing ticket checksum")
	}
	if err := server.issuePAC(&part, principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}},
		service, output, output, true, false); err != nil {
		t.Fatalf("validate PAC re-sign: %v", err)
	}
	if _, err := pac.FromTicket(part,
		pac.Key{EType: outputEType, Key: output.Key},
		&pac.Key{EType: privEType, Key: priv.Key}); err != nil {
		t.Fatalf("validated PAC verification: %v", err)
	}
}

func TestPACTicketChecksumMatchesAuthorizationPlacement(t *testing.T) {
	now := time.Unix(2000001950, 0).UTC()
	server, _ := testServer(t, now)
	server.EnablePAC = true
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	record, ok, err := server.DB.Lookup(service)
	if err != nil || !ok {
		t.Fatal("service principal lookup failed")
	}
	serviceKey := record.Keys[crypto.EnctypeAES256SHA1]
	serviceEType, err := crypto.NewRegistry().Get(serviceKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	priv, ok := server.pacPrivsvrKey()
	if !ok {
		t.Fatal("privileged-server key unavailable")
	}
	privEType, err := crypto.NewRegistry().Get(priv.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ad   func(t *testing.T) protocol.AuthorizationData
	}{
		{
			name: "existing PAC before unrelated data",
			ad: func(t *testing.T) protocol.AuthorizationData {
				t.Helper()
				existing := pac.New()
				raw, err := existing.Sign(now, nil,
					pac.Key{EType: serviceEType, Key: serviceKey.Key},
					pac.Key{EType: privEType, Key: priv.Key}, true)
				if err != nil {
					t.Fatal(err)
				}
				inner, err := asn1.Marshal(protocol.AuthorizationData{
					{ADType: pac.ADWin2KPac, ADData: raw},
					{ADType: 77, ADData: []byte("unrelated-inner")},
				})
				if err != nil {
					t.Fatal(err)
				}
				return protocol.AuthorizationData{
					{ADType: pac.ADIfRelevant, ADData: inner},
					{ADType: 78, ADData: []byte("unrelated-outer")},
				}
			},
		},
		{
			name: "no PAC after unrelated data",
			ad: func(t *testing.T) protocol.AuthorizationData {
				t.Helper()
				inner, err := asn1.Marshal(protocol.AuthorizationData{
					{ADType: 79, ADData: []byte("unrelated-inner")},
				})
				if err != nil {
					t.Fatal(err)
				}
				return protocol.AuthorizationData{
					{ADType: 80, ADData: []byte("unrelated-outer")},
					{ADType: pac.ADIfRelevant, ADData: inner},
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.ad(t)
			part := protocol.EncTicketPart{
				AuthTime:          types.KerberosTime{Time: now, Present: true},
				AuthorizationData: original,
			}
			if err := server.issuePAC(&part, user, service, serviceKey, serviceKey, true, false); err != nil {
				t.Fatalf("issue PAC: %v", err)
			}
			signed, err := pac.FromTicket(part,
				pac.Key{EType: serviceEType, Key: serviceKey.Key},
				&pac.Key{EType: privEType, Key: priv.Key})
			if err != nil {
				t.Fatalf("verify signed PAC: %v", err)
			}
			dummy, err := pac.AddDummyAuthorizationData(original)
			if err != nil {
				t.Fatal(err)
			}
			dummyPart := part
			dummyPart.AuthorizationData = dummy
			if err := signed.VerifyTicketSignature(marshalDER(dummyPart),
				pac.Key{EType: privEType, Key: priv.Key}); err != nil {
				t.Fatalf("verify ticket checksum: %v", err)
			}
		})
	}
}

func ticketPrincipal(ticket protocol.Ticket) principal.Principal {
	return principal.Principal{Realm: ticket.Realm, NameType: principal.NameType(ticket.SName.NameType), Components: ticket.SName.NameString}
}
