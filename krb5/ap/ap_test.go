package ap

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	apRealm = "TEST.GOKRB5.LOCAL"
	apEtype = crypto.EnctypeAES256SHA1
)

func TestAPReqRoundTripAndMutualAuth(t *testing.T) {
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	creds, kt := apFixture(t, now, now.Add(time.Hour))
	restore := crypto.SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0x33}, 256)))
	defer restore()

	request, der, err := BuildAPReq(creds, types.APMutualRequired, now)
	if err != nil {
		t.Fatal(err)
	}
	if request == nil || len(der) == 0 {
		t.Fatal("BuildAPReq returned empty state or DER")
	}
	verified, err := VerifyAPReq(kt, der, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !principalEqual(verified.Client, creds.Client) {
		t.Fatalf("client = %#v, want %#v", verified.Client, creds.Client)
	}
	if !bytes.Equal(verified.SessionKey.KeyValue, creds.Key.KeyValue) {
		t.Fatal("acceptor returned a different session key")
	}
	if verified.SubKey == nil || verified.SeqNumber == nil {
		t.Fatal("authenticator did not carry generated subkey and sequence number")
	}

	apRep, err := BuildAPRep(verified)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAPRep(request, apRep); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAPReqWithSessionKeyRequiresOption(t *testing.T) {
	now := time.Date(2025, 1, 3, 3, 4, 5, 0, time.UTC)
	creds, kt := apFixture(t, now, now.Add(time.Hour))
	ticket := decodeTicket(t, creds.Ticket)
	part := decryptTicket(t, kt.Entries[0].Key, ticket)
	ticket.EncPart.KVNO = nil
	ticket.EncPart.Cipher = encryptTicket(t, creds.Key.KeyValue, part)
	creds.Ticket = mustMarshalAP(t, ticket)
	_, der, err := BuildAPReq(creds, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReqWithSessionKey(creds.Key, der, now, 5*time.Minute); err == nil {
		t.Fatal("VerifyAPReqWithSessionKey accepted AP-REQ without APUseSessionKey")
	}
	_, der, err = BuildAPReq(creds, types.APUseSessionKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReqWithSessionKey(creds.Key, der, now, 5*time.Minute); err != nil {
		t.Fatalf("VerifyAPReqWithSessionKey: %v", err)
	}
}

func TestVerifyAPReqRejectsWrongKey(t *testing.T) {
	now := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	creds, kt := apFixture(t, now, now.Add(time.Hour))
	restore := crypto.SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0x44}, 256)))
	defer restore()
	_, der, err := BuildAPReq(creds, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	kt.Entries[0].Key = bytes.Repeat([]byte{0x99}, 32)
	if _, err := VerifyAPReq(kt, der, now, 5*time.Minute); !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("VerifyAPReq error = %v, want ErrIntegrity", err)
	}
}

func TestVerifyAPReqRejectsExpiredTicket(t *testing.T) {
	now := time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)
	creds, kt := apFixture(t, now, now.Add(-time.Minute))
	restore := crypto.SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0x55}, 256)))
	defer restore()
	_, der, err := BuildAPReq(creds, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, der, now, 5*time.Minute); !errors.Is(err, krberrors.ErrTicketExpired) {
		t.Fatalf("VerifyAPReq error = %v, want ErrTicketExpired", err)
	}
}

func TestVerifyAPReqRejectsClockSkew(t *testing.T) {
	now := time.Date(2025, 4, 5, 6, 7, 8, 0, time.UTC)
	creds, kt := apFixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	restore := crypto.SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0x66}, 256)))
	defer restore()
	_, der, err := BuildAPReq(creds, 0, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, der, now, 5*time.Minute); !errors.Is(err, krberrors.ErrClockSkew) {
		t.Fatalf("VerifyAPReq error = %v, want ErrClockSkew", err)
	}
}

func TestVerifyAPReqRejectsClientMismatchAndReplay(t *testing.T) {
	now := time.Date(2025, 5, 6, 7, 8, 9, 0, time.UTC)
	creds, kt := apFixture(t, now, now.Add(time.Hour))
	restore := crypto.SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0x77}, 256)))
	defer restore()
	_, der, err := BuildAPReq(creds, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	ticket := decodeTicket(t, creds.Ticket)
	part := decryptTicket(t, kt.Entries[0].Key, ticket)
	part.CName.NameString[0] = "bob"
	ticket.EncPart.Cipher = encryptTicket(t, kt.Entries[0].Key, part)
	creds.Ticket = mustMarshalAP(t, ticket)
	_, mismatchDER, err := BuildAPReq(creds, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, mismatchDER, now, 5*time.Minute); err == nil {
		t.Fatal("VerifyAPReq accepted mismatched client")
	}

	creds, kt = apFixture(t, now.Add(time.Minute), now.Add(61*time.Minute))
	_, der, err = BuildAPReq(creds, 0, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, der, now.Add(time.Minute), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, der, now.Add(time.Minute), 5*time.Minute); err == nil {
		t.Fatal("VerifyAPReq accepted replayed authenticator")
	}
}

func TestVerifyAPReqReplayIdentityIncludesAuthenticatorCiphertext(t *testing.T) {
	resetReplayCache()
	defer resetReplayCache()
	now := time.Date(2025, 5, 6, 7, 8, 9, 0, time.UTC)
	creds, kt := apFixture(t, now, now.Add(time.Hour))
	otherService := principal.Principal{
		Realm: apRealm, NameType: principal.NTSrvHst,
		Components: []string{"host", "other.test"},
	}
	kt.Entries = append(kt.Entries, keytab.Entry{
		Principal: otherService, KVNO: 1, Enctype: apEtype,
		Key: append([]byte(nil), kt.Entries[0].Key...),
	})
	other := *creds
	other.Server = otherService
	ticket := decodeTicket(t, other.Ticket)
	ticket.SName = protocol.PrincipalName{
		NameType: int32(otherService.NameType), NameString: otherService.Components,
	}
	other.Ticket = mustMarshalAP(t, ticket)
	_, first, err := BuildAPReq(creds, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := BuildAPReq(&other, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, first, now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, second, now, 5*time.Minute); err != nil {
		t.Fatalf("different service AP-REQ rejected as replay: %v", err)
	}
	if _, err := VerifyAPReq(kt, first, now, 5*time.Minute); err == nil {
		t.Fatal("exact AP-REQ replay unexpectedly accepted")
	}
}

func TestVerifyAPReqRejectsInvalidTicket(t *testing.T) {
	now := time.Date(2025, 5, 10, 7, 8, 9, 0, time.UTC)
	creds, kt := apFixture(t, now, now.Add(time.Hour))
	ticket := decodeTicket(t, creds.Ticket)
	part := decryptTicket(t, kt.Entries[0].Key, ticket)
	part.Flags |= types.TicketInvalid
	ticket.EncPart.Cipher = encryptTicket(t, kt.Entries[0].Key, part)
	creds.Ticket = mustMarshalAP(t, ticket)
	_, der, err := BuildAPReq(creds, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, der, now, 5*time.Minute); !errors.Is(err, krberrors.ErrTicketInvalid) {
		t.Fatalf("VerifyAPReq error = %v, want ErrTicketInvalid", err)
	}
}

func TestVerifyAPReqExpiresReplayEntries(t *testing.T) {
	resetReplayCache()
	defer resetReplayCache()
	now := time.Date(2025, 5, 7, 7, 8, 9, 0, time.UTC)
	creds, kt := apFixture(t, now, now.Add(time.Hour))
	_, der, err := BuildAPReq(creds, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, der, now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	replayCache.Lock()
	if len(replayCache.entries) != 1 {
		t.Fatalf("replay cache size = %d, want 1", len(replayCache.entries))
	}
	replayCache.Unlock()

	expiredAt := now.Add(10 * time.Minute)
	if _, err := VerifyAPReq(kt, der, expiredAt, 5*time.Minute); !errors.Is(err, krberrors.ErrClockSkew) {
		t.Fatalf("expired authenticator error = %v, want ErrClockSkew", err)
	}
	replayCache.Lock()
	defer replayCache.Unlock()
	if len(replayCache.entries) != 0 {
		t.Fatalf("replay cache retained expired entry: %d entries", len(replayCache.entries))
	}
}

func TestVerifyAPReqReplayWithinSkewRemainsDetected(t *testing.T) {
	resetReplayCache()
	defer resetReplayCache()
	now := time.Date(2025, 5, 8, 7, 8, 9, 0, time.UTC)
	creds, kt := apFixture(t, now, now.Add(time.Hour))
	_, der, err := BuildAPReq(creds, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, der, now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAPReq(kt, der, now.Add(time.Minute), 5*time.Minute); err == nil {
		t.Fatal("VerifyAPReq accepted replay within skew")
	}
	replayCache.Lock()
	defer replayCache.Unlock()
	if len(replayCache.entries) != 1 {
		t.Fatalf("replay cache size = %d, want 1", len(replayCache.entries))
	}
}

func TestVerifyAPReqReplayCacheRemainsBounded(t *testing.T) {
	resetReplayCache()
	defer resetReplayCache()
	start := time.Date(2025, 5, 9, 7, 8, 9, 0, time.UTC)
	creds, kt := apFixture(t, start, start.Add(10*time.Minute))
	const (
		skew  = time.Second
		count = 120
	)
	for i := 0; i < count; i++ {
		now := start.Add(time.Duration(i) * 2 * time.Second)
		_, der, err := BuildAPReq(creds, 0, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyAPReq(kt, der, now, skew); err != nil {
			t.Fatalf("VerifyAPReq at %s: %v", now, err)
		}
		replayCache.Lock()
		size := len(replayCache.entries)
		replayCache.Unlock()
		if size > 1 {
			t.Fatalf("replay cache size = %d after request %d, want at most 1", size, i)
		}
	}
}

func TestVerifyAPRepRejectsCTimeMismatch(t *testing.T) {
	now := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
	creds, kt := apFixture(t, now, now.Add(time.Hour))
	restore := crypto.SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0x88}, 256)))
	defer restore()
	request, der, err := BuildAPReq(creds, types.APMutualRequired, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAPReq(kt, der, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	apRepDER, err := buildAPRepWithTime(verified, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAPRep(request, apRepDER); err == nil {
		t.Fatal("VerifyAPRep accepted mismatched ctime")
	}
}

func resetReplayCache() {
	replayCache.Lock()
	defer replayCache.Unlock()
	replayCache.entries = make(map[string]time.Time)
	replayCache.lastSweep = time.Time{}
	replayCache.sweepCount = 0
}

func apFixture(t *testing.T, start, end time.Time) (*client.Credentials, *keytab.Keytab) {
	t.Helper()
	service := principal.Principal{
		Realm: apRealm, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	}
	clientPrincipal := principal.Principal{
		Realm: apRealm, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	serviceKey := bytes.Repeat([]byte{0x11}, 32)
	sessionKey := bytes.Repeat([]byte{0x22}, 32)
	ticketPart := protocol.EncTicketPart{
		Flags:     types.TicketForwardable,
		Key:       protocol.EncryptionKey{KeyType: apEtype, KeyValue: sessionKey},
		CRealm:    clientPrincipal.Realm,
		CName:     protocol.PrincipalName{NameType: int32(clientPrincipal.NameType), NameString: clientPrincipal.Components},
		Transited: protocol.TransitedEncoding{},
		AuthTime:  types.KerberosTime{Time: start, Present: true},
		StartTime: kerberosTime(start),
		EndTime:   types.KerberosTime{Time: end, Present: true},
	}
	ticketCipher := encryptTicket(t, serviceKey, ticketPart)
	kvno := uint32(1)
	ticket := protocol.Ticket{
		TktVNO: 5, Realm: service.Realm,
		SName:   protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
		EncPart: protocol.EncryptedData{EType: apEtype, KVNO: &kvno, Cipher: ticketCipher},
	}
	return &client.Credentials{
		Client: clientPrincipal, Server: service,
		Key:   protocol.EncryptionKey{KeyType: apEtype, KeyValue: sessionKey},
		Flags: types.TicketForwardable, AuthTime: ticketPart.AuthTime,
		StartTime: ticketPart.StartTime, EndTime: ticketPart.EndTime,
		Ticket: mustMarshalAP(t, ticket),
	}, &keytab.Keytab{Entries: []keytab.Entry{{
		Principal: service, KVNO: 1, Enctype: apEtype, Key: serviceKey,
	}}}
}

func encryptTicket(t *testing.T, key []byte, part protocol.EncTicketPart) []byte {
	t.Helper()
	der := mustMarshalAP(t, part)
	etype, err := crypto.NewRegistry().Get(apEtype)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := etype.Encrypt(key, 2, der)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func decryptTicket(t *testing.T, key []byte, ticket protocol.Ticket) protocol.EncTicketPart {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(apEtype)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	return part
}

func decodeTicket(t *testing.T, der []byte) protocol.Ticket {
	t.Helper()
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(der, &ticket); err != nil {
		t.Fatal(err)
	}
	return ticket
}

func mustMarshalAP(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func kerberosTime(value time.Time) *types.KerberosTime {
	result := types.KerberosTime{Time: value, Present: true}
	return &result
}
