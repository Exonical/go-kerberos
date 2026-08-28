package kpasswd

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/transport"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestParsePasswordRequest(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		code uint16
	}{
		{"truncated", []byte{0, 6}, ResultMalformed},
		{"inconsistent length", []byte{0, 7, 0, 1, 0, 1, 0}, ResultMalformed},
		{"bad version", []byte{0, 7, 0, 2, 0, 1, 0}, ResultBadVersion},
		{"missing AP-REQ", []byte{0, 6, 0, 1, 0, 0}, ResultMalformed},
		{"missing KRB-PRIV", []byte{0, 7, 0, 1, 0, 1, 0}, ResultMalformed},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{Realm: "TEST.REALM", DB: kdb.NewDatabase("TEST.REALM")}
			response := server.HandleMessage(test.data)
			value := parseFramedKRBError(t, response)
			if len(value.EData) < 2 || binary.BigEndian.Uint16(value.EData[:2]) != test.code {
				t.Fatalf("error data = %x, want result %d", value.EData, test.code)
			}
		})
	}
}

func TestKpasswdServerRejectsMissingOrInvalidServiceKey(t *testing.T) {
	now := time.Unix(1900000050, 0).UTC()
	source := kdb.NewDatabase("TEST.REALM")
	for _, value := range []string{"alice", "kadmin/changepw"} {
		if err := source.AddPrincipal(value, "password"); err != nil {
			t.Fatal(err)
		}
	}
	alice, _ := principal.Parse("alice@TEST.REALM")
	state, packet := passwordRequestFixture(t, source, now, types.TicketInitial, *alice, []byte("new-password"))
	_ = state

	missing := kdb.NewDatabase("TEST.REALM")
	missing.AddPrincipal("alice", "password")
	response := (&Server{Realm: "TEST.REALM", DB: missing, Now: func() time.Time { return now }}).HandleMessage(packet)
	errorValue := parseFramedKRBError(t, response)
	if len(errorValue.EData) < 2 || binary.BigEndian.Uint16(errorValue.EData[:2]) != ResultAuthError {
		t.Fatalf("missing service key error data = %x", errorValue.EData)
	}

	invalid := kdb.NewDatabase("TEST.REALM")
	for _, value := range []string{"alice", "kadmin/changepw"} {
		if err := invalid.AddPrincipal(value, "password"); err != nil {
			t.Fatal(err)
		}
	}
	service, _ := principal.Parse("kadmin/changepw@TEST.REALM")
	record, ok, err := invalid.Lookup(*service)
	if err != nil || !ok {
		t.Fatalf("lookup invalid service: %v, %t", err, ok)
	}
	record.Keys[crypto.EnctypeAES256SHA1] = kdb.Key{
		Enctype: crypto.EnctypeAES256SHA1, KVNO: 1, Key: []byte("bad"),
	}
	if err := invalid.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	response = (&Server{Realm: "TEST.REALM", DB: invalid, Now: func() time.Time { return now }}).HandleMessage(packet)
	errorValue = parseFramedKRBError(t, response)
	if len(errorValue.EData) < 2 || binary.BigEndian.Uint16(errorValue.EData[:2]) != ResultAuthError {
		t.Fatalf("invalid service key error data = %x", errorValue.EData)
	}
}

func TestKpasswdServerAcceptsMITKRBPrivWithoutReplayFields(t *testing.T) {
	now := time.Unix(1900000060, 0).UTC()
	key := protocol.EncryptionKey{
		KeyType:  crypto.EnctypeAES256SHA1,
		KeyValue: bytes.Repeat([]byte{0x44}, 32),
	}
	plain, err := asn1.Marshal(protocol.EncKRBPrivPart{UserData: []byte("password")})
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := etype.Encrypt(key.KeyValue, kpasswdPrivUsage, plain)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := asn1.Marshal(protocol.KRBPriv{
		PVNO: 5, MsgType: 21,
		EncPart: protocol.EncryptedData{EType: key.KeyType, Cipher: cipher},
	})
	if err != nil {
		t.Fatal(err)
	}
	userData, err := (&Server{Now: func() time.Time { return now }}).decryptUserData(
		&ap.VerifiedAPReq{SessionKey: key}, priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(userData) != "password" {
		t.Fatalf("user data = %q", userData)
	}
}

func TestKpasswdServerPasswordChangeAndPolicyResult(t *testing.T) {
	now := time.Unix(1900000000, 0).UTC()
	db := kdb.NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice", "old-password"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("kadmin/changepw", "service-password"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePolicy(kdb.PolicyRecord{Name: "strong", MinLength: 12}); err != nil {
		t.Fatal(err)
	}
	alice, _ := principal.Parse("alice@TEST.REALM")
	record, ok, err := db.Lookup(*alice)
	if err != nil || !ok {
		t.Fatalf("lookup alice: %v, %t", err, ok)
	}
	record.Policy = "strong"
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	server := &Server{Realm: "TEST.REALM", DB: db, Now: func() time.Time { return now }}
	state, packet := passwordRequestFixture(t, db, now, types.TicketInitial, *alice, []byte("short"))
	response := server.HandleMessage(packet)
	result, err := parsePasswordReply(response, state, now, time.Minute, kpasswdVersion)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != ResultSoftError || !strings.Contains(result.Message, "too short") {
		t.Fatalf("result = %#v", result)
	}

	now = now.Add(time.Second)
	state, packet = passwordRequestFixture(t, db, now, types.TicketInitial, *alice, []byte("long-enough-password"))
	response = server.HandleMessage(packet)
	result, err = parsePasswordReply(response, state, now, time.Minute, kpasswdVersion)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != ResultSuccess || result.Message != "" {
		t.Fatalf("result = %#v", result)
	}
}

func TestKpasswdServerSetPasswordAuthorization(t *testing.T) {
	now := time.Unix(1900000100, 0).UTC()
	db := kdb.NewDatabase("TEST.REALM")
	for _, value := range []struct{ name, password string }{
		{"admin", "admin-password"}, {"alice", "alice-password"},
		{"bob", "bob-password"}, {"kadmin/changepw", "service-password"},
	} {
		if err := db.AddPrincipal(value.name, value.password); err != nil {
			t.Fatal(err)
		}
	}
	admin, _ := principal.Parse("admin@TEST.REALM")
	bob, _ := principal.Parse("bob@TEST.REALM")
	allowed := &Server{
		Realm: "TEST.REALM", DB: db, Now: func() time.Time { return now },
		ACL: func(client principal.Principal, operation string, target principal.Principal) bool {
			return operation == "set-password" && client.String() == admin.String() &&
				target.String() == bob.String()
		},
	}
	userData, err := asn1.Marshal(protocol.ChangePasswdData{
		NewPassword: []byte("new-bob-password"),
		TargetName: &protocol.PrincipalName{
			NameType: int32(bob.NameType), NameString: bob.Components,
		},
		TargetRealm: &bob.Realm,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, packet := passwordRequestFixtureWithData(t, db, now, types.TicketForwardable, *admin, setPasswordVersion, userData)
	result, err := serverResult(t, allowed, state, packet, now, setPasswordVersion)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != ResultSuccess {
		t.Fatalf("allowed result = %#v", result)
	}
	denied := *allowed
	denied.ACL = func(principal.Principal, string, principal.Principal) bool { return false }
	now = now.Add(time.Second)
	state, packet = passwordRequestFixtureWithData(t, db, now, types.TicketForwardable, *admin, setPasswordVersion, userData)
	result, err = serverResult(t, &denied, state, packet, now, setPasswordVersion)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != ResultAccessDenied {
		t.Fatalf("denied result = %#v", result)
	}
}

func TestKpasswdServerRequiresInitialTicketForSelfChange(t *testing.T) {
	now := time.Unix(1900000200, 0).UTC()
	db := kdb.NewDatabase("TEST.REALM")
	for _, value := range []string{"alice", "kadmin/changepw"} {
		if err := db.AddPrincipal(value, "password"); err != nil {
			t.Fatal(err)
		}
	}
	alice, _ := principal.Parse("alice@TEST.REALM")
	server := &Server{Realm: "TEST.REALM", DB: db, Now: func() time.Time { return now }}
	state, packet := passwordRequestFixture(t, db, now, 0, *alice, []byte("new-password"))
	result, err := serverResult(t, server, state, packet, now, kpasswdVersion)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != ResultInitialNeeded {
		t.Fatalf("result = %#v", result)
	}
}

func TestKpasswdServerTCPFraming(t *testing.T) {
	now := time.Unix(1900000300, 0).UTC()
	db := kdb.NewDatabase("TEST.REALM")
	for _, value := range []string{"alice", "kadmin/changepw"} {
		if err := db.AddPrincipal(value, "password"); err != nil {
			t.Fatal(err)
		}
	}
	alice, _ := principal.Parse("alice@TEST.REALM")
	state, request := passwordRequestFixture(t, db, now, types.TicketInitial, *alice, []byte("new-password"))
	server := &Server{Realm: "TEST.REALM", DB: db, Now: func() time.Time { return now }}
	left, right := net.Pipe()
	defer left.Close()
	go server.handleTCP(context.Background(), right)
	if err := transport.WriteTCPFrame(left, request); err != nil {
		t.Fatal(err)
	}
	response, err := transport.ReadTCPFrame(left, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	result, err := parsePasswordReply(response, state, now, time.Minute, kpasswdVersion)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != ResultSuccess {
		t.Fatalf("result = %#v", result)
	}
}

func TestKpasswdServerUDPLookasideReplaysResponse(t *testing.T) {
	now := time.Unix(1900000400, 0).UTC()
	db := kdb.NewDatabase("TEST.REALM")
	for _, value := range []string{"alice", "kadmin/changepw"} {
		if err := db.AddPrincipal(value, "password"); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.CreatePolicy(kdb.PolicyRecord{Name: "history", HistoryNum: 3}); err != nil {
		t.Fatal(err)
	}
	alice, _ := principal.Parse("alice@TEST.REALM")
	record, ok, err := db.Lookup(*alice)
	if err != nil || !ok {
		t.Fatalf("lookup alice: %v, %t", err, ok)
	}
	record.Policy = "history"
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	server := &Server{Realm: "TEST.REALM", DB: db, Now: func() time.Time { return now }}
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- server.ListenAndServe(ctx, udpConn, nil)
	}()
	clientConn, err := net.DialUDP("udp", nil, udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	state, request := passwordRequestFixture(t, db, now, types.TicketInitial, *alice, []byte("new-password"))
	readResponse := func() []byte {
		t.Helper()
		if _, err := clientConn.Write(request); err != nil {
			t.Fatal(err)
		}
		if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, kpasswdMaxPacket)
		n, _, err := clientConn.ReadFromUDP(response)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), response[:n]...)
	}
	first := readResponse()
	second := readResponse()
	if !bytes.Equal(first, second) {
		t.Fatalf("duplicate response differs:\nfirst:  %x\nsecond: %x", first, second)
	}
	result, err := parsePasswordReply(first, state, now, time.Minute, kpasswdVersion)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != ResultSuccess {
		t.Fatalf("first result = %#v", result)
	}
	record, ok, err = db.Lookup(*alice)
	if err != nil || !ok {
		t.Fatalf("lookup changed alice: %v, %t", err, ok)
	}
	if record.KVNO != 2 {
		t.Fatalf("alice KVNO = %d, want exactly one change to KVNO 2", record.KVNO)
	}
	if len(record.PasswordHistory) != 1 {
		t.Fatalf("password history length = %d, want exactly one entry", len(record.PasswordHistory))
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("kpasswd server did not stop")
	}
}

func serverResult(t *testing.T, server *Server, state *ap.APReq, packet []byte, now time.Time, version uint16) (passwordChangeResult, error) {
	t.Helper()
	if version == setPasswordVersion {
		return parsePasswordReply(server.HandleMessage(packet), state, now, time.Minute, kpasswdVersion, setPasswordVersion)
	}
	return parsePasswordReply(server.HandleMessage(packet), state, now, time.Minute, version)
}

func parseFramedKRBError(t *testing.T, response []byte) protocol.KRBError {
	t.Helper()
	if len(response) < 6 {
		t.Fatalf("framed error response length = %d, want at least 6", len(response))
	}
	if got := int(binary.BigEndian.Uint16(response[:2])); got != len(response) {
		t.Fatalf("framed error length = %d, want %d", got, len(response))
	}
	if got := binary.BigEndian.Uint16(response[2:4]); got != kpasswdVersion {
		t.Fatalf("framed error version = %d, want %d", got, kpasswdVersion)
	}
	if got := binary.BigEndian.Uint16(response[4:6]); got != 0 {
		t.Fatalf("framed error AP-REP length = %d, want 0", got)
	}
	var value protocol.KRBError
	if err := asn1.Unmarshal(response[6:], &value); err != nil {
		t.Fatalf("decode framed KRB-ERROR: %v", err)
	}
	return value
}

func passwordRequestFixture(t *testing.T, db *kdb.Database, now time.Time, flags types.TicketFlags, clientName principal.Principal, password []byte) (*ap.APReq, []byte) {
	return passwordRequestFixtureWithData(t, db, now, flags, clientName, kpasswdVersion, password)
}

func passwordRequestFixtureWithData(t *testing.T, db *kdb.Database, now time.Time, flags types.TicketFlags, clientName principal.Principal, version uint16, userData []byte) (*ap.APReq, []byte) {
	t.Helper()
	service, _ := principal.Parse("kadmin/changepw@TEST.REALM")
	serviceRecord, ok, err := db.Lookup(*service)
	if err != nil || !ok {
		t.Fatalf("lookup service: %v, %t", err, ok)
	}
	serviceKey := serviceRecord.Keys[crypto.EnctypeAES256SHA1]
	sessionKey := protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{0x33}, 32)}
	encPart, err := asn1.Marshal(protocol.EncTicketPart{
		Flags: flags, Key: sessionKey, CRealm: clientName.Realm,
		CName:     protocol.PrincipalName{NameType: int32(clientName.NameType), NameString: clientName.Components},
		Transited: protocol.TransitedEncoding{TrType: 0, Contents: []byte{}},
		AuthTime:  types.KerberosTime{Time: now, Present: true},
		EndTime:   types.KerberosTime{Time: now.Add(time.Hour), Present: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(serviceKey.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	ticketCipher, err := etype.Encrypt(serviceKey.Key, 2, encPart)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := asn1.Marshal(protocol.Ticket{
		TktVNO: 5, Realm: service.Realm,
		SName:   protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
		EncPart: protocol.EncryptedData{EType: serviceKey.Enctype, KVNO: uint32Pointer(serviceKey.KVNO), Cipher: ticketCipher},
	})
	if err != nil {
		t.Fatal(err)
	}
	creds := &client.Credentials{
		Client: clientName, Server: *service, Key: sessionKey, Ticket: ticket,
	}
	state, apDER, err := ap.BuildAPReq(creds, types.APMutualRequired, now)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := buildKRBPriv(state, userData, now)
	if version == setPasswordVersion {
		priv, err = buildKRBPriv(state, userData, now)
	}
	if err != nil {
		t.Fatal(err)
	}
	packet, err := buildPasswordPacket(version, apDER, priv)
	if err != nil {
		t.Fatal(err)
	}
	return state, packet
}

func uint32Pointer(value uint32) *uint32 { return &value }
