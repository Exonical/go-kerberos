package spnego

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	kasn1 "github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestNegTokenInitDERGolden(t *testing.T) {
	token, err := EncodeToken(Token{Init: &NegTokenInit{
		MechTypes: []asn1.ObjectIdentifier{kerberosOID},
		MechToken: []byte{0x01, 0x02, 0x03},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(
		"602206062b0601050502a0183016a00d300b06092a864886f712010202a2050403010203",
	)
	if !bytes.Equal(token, want) {
		t.Fatalf("NegTokenInit DER = %x, want %x", token, want)
	}
	decoded, err := DecodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Init == nil || len(decoded.Init.MechTypes) != 1 ||
		!decoded.Init.MechTypes[0].Equal(kerberosOID) ||
		!bytes.Equal(decoded.Init.MechToken, []byte{1, 2, 3}) {
		t.Fatalf("decoded NegTokenInit = %#v", decoded.Init)
	}
}

func TestNegTokenRespDERGoldenAndLegacyOID(t *testing.T) {
	token, err := EncodeToken(Token{Resp: &NegTokenResp{
		NegState:      NegStateRequestMIC,
		SupportedMech: legacyKerberosOID,
		ResponseToken: []byte{0x99},
		MechListMIC:   []byte{0x77, 0x88},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(
		"602906062b0601050502a11f301da0030a0103a10b06092a864882f712010202a203040199a30404027788",
	)
	if !bytes.Equal(token, want) {
		t.Fatalf("NegTokenResp DER = %x, want %x", token, want)
	}
	decoded, err := DecodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Resp == nil || decoded.Resp.NegState != NegStateRequestMIC ||
		!decoded.Resp.SupportedMech.Equal(legacyKerberosOID) ||
		!bytes.Equal(decoded.Resp.ResponseToken, []byte{0x99}) ||
		!bytes.Equal(decoded.Resp.MechListMIC, []byte{0x77, 0x88}) {
		t.Fatalf("decoded NegTokenResp = %#v", decoded.Resp)
	}
	if !isKerberos(decoded.Resp.SupportedMech) {
		t.Fatal("legacy Kerberos OID was not recognized")
	}
}

func TestSPNEGRejectsMalformedAndAmbiguousTokens(t *testing.T) {
	if _, err := DecodeToken([]byte{0x60, 0x00}); err == nil {
		t.Fatal("empty GSS token accepted")
	}
	if _, err := EncodeToken(Token{Init: &NegTokenInit{}, Resp: &NegTokenResp{}}); err == nil {
		t.Fatal("ambiguous token accepted")
	}
	if _, err := EncodeToken(Token{Init: &NegTokenInit{MechTypes: []asn1.ObjectIdentifier{}}}); err == nil {
		t.Fatal("empty mechanism list accepted")
	}
	if _, err := DecodeToken([]byte{0x60, 0x03, 0x06, 0x01, 0x00}); err == nil {
		t.Fatal("invalid mechanism OID accepted")
	}
}

func TestSelectKerberosAcceptsMSAlias(t *testing.T) {
	selected, index := selectKerberos([]asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7},
		legacyKerberosOID,
	})
	if index != 1 || !selected.Equal(legacyKerberosOID) {
		t.Fatalf("selected = %v at %d", selected, index)
	}
}

func TestKerberosSPNEGOSessionAndWrap(t *testing.T) {
	creds, kt := syntheticCredentials(t)
	now := time.Unix(1700000000, 0).UTC()
	initiator, err := NewInitiator(creds, gssapiFlags())
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatal(err)
	}
	acceptor := NewAcceptor(kt)
	acceptorContext, reply, err := acceptor.Accept(first, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.Continue(reply); err != nil {
		t.Fatal(err)
	}
	message := []byte("SPNEGO round trip")
	wrapped, err := initiator.Context()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := wrapped.Wrap(message, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := acceptorContext.Unwrap(wire); err != nil || !bytes.Equal(got, message) {
		t.Fatalf("unwrap = %q, %v", got, err)
	}
}

func TestKerberosSPNEGOMechListMICExchange(t *testing.T) {
	creds, kt := syntheticCredentials(t)
	now := time.Unix(1700000010, 0).UTC()
	initiator, err := NewInitiatorWithMechs(creds, gssapiFlags(), []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7},
		kerberosOID,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatal(err)
	}
	acceptor := NewAcceptor(kt)
	acceptorContext, reply, err := acceptor.Accept(first, now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeToken(reply)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Resp == nil || decoded.Resp.NegState != NegStateRequestMIC ||
		len(decoded.Resp.MechListMIC) == 0 {
		t.Fatalf("acceptor response did not request mechListMIC: %#v", decoded.Resp)
	}
	final, err := initiator.Continue(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(final) == 0 {
		t.Fatal("initiator did not send required mechListMIC")
	}
	ctx, _, err := acceptor.Accept(final, now)
	if err != nil {
		t.Fatal(err)
	}
	if ctx != acceptorContext {
		t.Fatal("acceptor replaced context during mechListMIC exchange")
	}
	message := []byte("SPNEGO MIC exchange")
	wire, err := initiator.Context()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := wire.Wrap(message, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ctx.Unwrap(sealed); err != nil || !bytes.Equal(got, message) {
		t.Fatalf("post-MIC unwrap = %q, %v", got, err)
	}
}

func TestSPNEGORejectsIncompleteAcceptorCompletion(t *testing.T) {
	creds, _ := syntheticCredentials(t)
	initiator, err := NewInitiator(creds, gssapiFlags())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.InitialToken(time.Unix(1700000011, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	token, err := encodeBareResp(NegTokenResp{
		NegState:      NegStateAcceptCompleted,
		SupportedMech: kerberosOID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.Continue(token); err == nil {
		t.Fatal("acceptor completion without mechanism response accepted")
	}
}

func TestSPNEGORequiresAcceptorMICWhenRequested(t *testing.T) {
	creds, kt := syntheticCredentials(t)
	initiator, err := NewInitiatorWithMechs(creds, gssapiFlags(), []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7},
		kerberosOID,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.InitialToken(time.Unix(1700000012, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, reply, err := NewAcceptor(kt).Accept(first, time.Unix(1700000012, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeToken(reply)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Resp.MechListMIC = nil
	reply, err = EncodeToken(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.Continue(reply); err == nil {
		t.Fatal("missing acceptor mechListMIC accepted")
	}
}

func TestNegoExMessageRoundTrips(t *testing.T) {
	scheme := NegoExSchemeForOID(oidBytes(kerberosOID))
	var conversation [16]byte
	copy(conversation[:], []byte("negoex-conversation"))
	messages := []NegoExMessage{
		{Type: NegoExInitiatorNego, Sequence: 0, ConversationID: conversation,
			AuthSchemes: []NegoExAuthScheme{scheme}},
		{Type: NegoExInitiatorMetaData, Sequence: 1, ConversationID: conversation,
			AuthScheme: scheme},
		{Type: NegoExAPRequest, Sequence: 2, ConversationID: conversation,
			AuthScheme: scheme, Token: []byte{1, 2, 3}},
		{Type: NegoExAcceptorNego, Sequence: 3, ConversationID: conversation,
			AuthSchemes: []NegoExAuthScheme{scheme}},
		{Type: NegoExAcceptorMetaData, Sequence: 4, ConversationID: conversation,
			AuthScheme: scheme},
		{Type: NegoExChallenge, Sequence: 5, ConversationID: conversation,
			AuthScheme: scheme, Token: []byte{4, 5}},
		{Type: NegoExVerify, Sequence: 6, ConversationID: conversation,
			AuthScheme: scheme, ChecksumType: uint32(crypto.ChecksumHMACSHA196AES256),
			Checksum: bytes.Repeat([]byte{6}, 12)},
		{Type: NegoExAlert, Sequence: 7, ConversationID: conversation, AlertCode: 3,
			AuthScheme: scheme, Alerts: []NegoExAlertEntry{
				{Type: NegoExAlertPulse, Value: []byte{8, 9}},
			}},
	}
	wire, err := EncodeNegoEx(messages)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNegoEx(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(messages) || decoded[7].AlertCode != 3 || len(decoded[2].Token) != 3 ||
		len(decoded[6].Checksum) != 12 || len(decoded[7].Alerts) != 1 {
		t.Fatalf("decoded NegoEx messages = %#v", decoded)
	}
	if got := binary.LittleEndian.Uint32(wire[16:]); got != 96 {
		t.Fatalf("NegoEx header length = %d, want 96", got)
	}
	alertWire, err := EncodeNegoEx([]NegoExMessage{{
		Type: NegoExAlert, AuthScheme: scheme,
		Alerts: NewNegoExVerifyNoKeyAlert(scheme).Alerts,
	}})
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := DecodeNegoEx(alertWire)
	if err != nil || !alerts[0].HasVerifyNoKeyAlert() {
		t.Fatalf("NegoEx verify-no-key alert = %#v, %v", alerts, err)
	}
}

func TestNegoExRejectsMalformedVectorsAndSignatures(t *testing.T) {
	scheme := NegoExSchemeForOID(oidBytes(kerberosOID))
	wire, err := EncodeNegoEx([]NegoExMessage{{
		Type: NegoExInitiatorNego, AuthSchemes: []NegoExAuthScheme{scheme},
	}})
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), wire...)
	bad[0] ^= 1
	if _, err := DecodeNegoEx(bad); err == nil {
		t.Fatal("invalid NegoEx signature accepted")
	}
	bad = append([]byte(nil), wire...)
	binary.LittleEndian.PutUint32(bad[16:], 95)
	if _, err := DecodeNegoEx(bad); err == nil {
		t.Fatal("invalid NegoEx header length accepted")
	}
	bad = append([]byte(nil), wire...)
	binary.LittleEndian.PutUint32(bad[80:], uint32(len(wire)+1))
	if _, err := DecodeNegoEx(bad); err == nil {
		t.Fatal("invalid NegoEx scheme vector accepted")
	}
	if _, err := EncodeNegoEx([]NegoExMessage{{
		Type:        NegoExInitiatorNego,
		AuthSchemes: make([]NegoExAuthScheme, 65536),
	}}); err == nil {
		t.Fatal("oversized NegoEx auth-scheme vector accepted")
	}
	if _, err := EncodeNegoEx([]NegoExMessage{{
		Type:       NegoExInitiatorNego,
		Extensions: make([]NegoExExtension, 65536),
	}}); err == nil {
		t.Fatal("oversized NegoEx extension vector accepted")
	}
	if _, err := EncodeNegoEx([]NegoExMessage{{
		Type:   NegoExAlert,
		Alerts: make([]NegoExAlertEntry, 65536),
	}}); err == nil {
		t.Fatal("oversized NegoEx alert vector accepted")
	}
}

func TestNegoExKerberosHandshake(t *testing.T) {
	creds, kt := syntheticCredentials(t)
	now := time.Unix(1700000020, 0).UTC()
	initiator, err := NewInitiatorWithOptions(creds, gssapiFlags(), InitiatorOptions{NegoEx: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatal(err)
	}
	acceptor := NewAcceptorWithOptions(kt, AcceptorOptions{NegoEx: true})
	acceptorContext, reply, err := acceptor.Accept(first, now)
	if err != nil {
		t.Fatal(err)
	}
	final, err := initiator.Continue(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(final) == 0 {
		t.Fatal("NegoEx initiator did not send VERIFY")
	}
	if _, finalReply, err := acceptor.Accept(final, now); err != nil || finalReply != nil {
		t.Fatalf("NegoEx final accept = %v, reply %x", err, finalReply)
	}
	message := []byte("NegoEx round trip")
	wire, err := initiator.Context()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := wire.Wrap(message, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := acceptorContext.Unwrap(sealed); err != nil || !bytes.Equal(got, message) {
		t.Fatalf("NegoEx unwrap = %q, %v", got, err)
	}
}

func TestNegoExVerifyTamperAndSequenceRejection(t *testing.T) {
	creds, kt := syntheticCredentials(t)
	now := time.Unix(1700000030, 0).UTC()
	initiator, err := NewInitiatorWithOptions(creds, gssapiFlags(), InitiatorOptions{NegoEx: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatal(err)
	}
	acceptor := NewAcceptorWithOptions(kt, AcceptorOptions{NegoEx: true})
	_, reply, err := acceptor.Accept(first, now)
	if err != nil {
		t.Fatal(err)
	}
	final, err := initiator.Continue(reply)
	if err != nil {
		t.Fatal(err)
	}
	finalDecoded, err := DecodeToken(final)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := DecodeNegoEx(finalDecoded.Resp.ResponseToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) == 0 || messages[len(messages)-1].Type != NegoExVerify {
		t.Fatal("NegoEx final token did not contain VERIFY")
	}
	missingVerify, err := EncodeNegoEx(messages[:len(messages)-1])
	if err != nil {
		t.Fatal(err)
	}
	finalDecoded.Resp.ResponseToken = missingVerify
	missingToken, err := EncodeToken(finalDecoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := acceptor.Accept(missingToken, now); err == nil {
		t.Fatal("missing NegoEx VERIFY accepted")
	}
	decoded, err := DecodeToken(final)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Resp.ResponseToken[len(decoded.Resp.ResponseToken)-1] ^= 1
	tampered, err := EncodeToken(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := acceptor.Accept(tampered, now); err == nil {
		t.Fatal("tampered NegoEx VERIFY accepted")
	}

	scheme := NegoExSchemeForOID(oidBytes(kerberosOID))
	sequenceToken, err := EncodeNegoEx([]NegoExMessage{
		{Type: NegoExInitiatorNego, AuthSchemes: []NegoExAuthScheme{scheme}},
		{Type: NegoExInitiatorMetaData, Sequence: 99, AuthScheme: scheme},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeNegoEx(sequenceToken); err == nil {
		t.Fatal("out-of-sequence NegoEx message accepted")
	}
}

func TestNegoExNonMutualHandshake(t *testing.T) {
	creds, kt := syntheticCredentials(t)
	now := time.Unix(1700000040, 0).UTC()
	initiator, err := NewInitiatorWithOptions(creds,
		gssapi.GSSIntegrityFlag|gssapi.GSSConfidentialityFlag,
		InitiatorOptions{NegoEx: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatal(err)
	}
	acceptor := NewAcceptorWithOptions(kt, AcceptorOptions{NegoEx: true})
	_, reply, err := acceptor.Accept(first, now)
	if err != nil {
		t.Fatal(err)
	}
	final, err := initiator.Continue(reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, finalReply, err := acceptor.Accept(final, now); err != nil || finalReply != nil {
		t.Fatalf("non-mutual NegoEx final accept = %v, reply %x", err, finalReply)
	}
}

func TestNegoExRequiresAcceptorOptIn(t *testing.T) {
	creds, kt := syntheticCredentials(t)
	now := time.Unix(1700000050, 0).UTC()
	initiator, err := NewInitiatorWithOptions(creds, gssapiFlags(), InitiatorOptions{NegoEx: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewAcceptor(kt).Accept(first, now); err == nil {
		t.Fatal("NegoEx accepted without acceptor opt-in")
	}
}

func TestDecodeReqFlagsRequiresBitString(t *testing.T) {
	token, err := EncodeToken(Token{Init: &NegTokenInit{
		MechTypes: []asn1.ObjectIdentifier{kerberosOID},
		ReqFlags:  []byte{0x00, 0x01},
	}})
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(token, []byte{0xa1, 0x04, 0x03, 0x02, 0x00, 0x01}, []byte{0xa1, 0x04, 0x04, 0x02, 0x00, 0x01}, 1)
	if bytes.Equal(token, bad) {
		t.Fatal("test token mutation failed")
	}
	if _, err := DecodeToken(bad); err == nil {
		t.Fatal("non-BIT STRING reqFlags accepted")
	}
}

func gssapiFlags() uint32 {
	return 2 | 64 | 32 // mutual, integrity, confidentiality
}

func syntheticCredentials(t *testing.T) (*client.Credentials, *keytab.Keytab) {
	t.Helper()
	etypeID := crypto.EnctypeAES256SHA1
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		t.Fatal(err)
	}
	clientPrincipal := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	servicePrincipal := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"host", "service.test"}}
	sessionKey := bytes.Repeat([]byte{0x31}, etype.KeySize())
	serviceKey := bytes.Repeat([]byte{0x52}, etype.KeySize())
	now := time.Unix(1700000000, 0).UTC()
	end := types.KerberosTime{Time: time.Unix(2000000000, 0).UTC(), Present: true}
	ticketPart, err := kasn1.Marshal(protocol.EncTicketPart{
		Key:      protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionKey},
		CRealm:   clientPrincipal.Realm,
		CName:    protocol.PrincipalName{NameType: int32(clientPrincipal.NameType), NameString: clientPrincipal.Components},
		AuthTime: types.KerberosTime{Time: now, Present: true}, EndTime: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	ticketCipher, err := etype.Encrypt(serviceKey, 2, ticketPart)
	if err != nil {
		t.Fatal(err)
	}
	kvno := uint32(2)
	ticket, err := kasn1.Marshal(protocol.Ticket{
		TktVNO: 5, Realm: servicePrincipal.Realm,
		SName:   protocol.PrincipalName{NameType: int32(servicePrincipal.NameType), NameString: servicePrincipal.Components},
		EncPart: protocol.EncryptedData{EType: etypeID, KVNO: &kvno, Cipher: ticketCipher},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &client.Credentials{
			Client: clientPrincipal, Server: servicePrincipal,
			Key:      protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionKey},
			AuthTime: types.KerberosTime{Time: now, Present: true}, EndTime: end, Ticket: ticket,
		}, &keytab.Keytab{Entries: []keytab.Entry{{
			Principal: servicePrincipal, KVNO: kvno, Enctype: etypeID, Key: serviceKey,
		}}}
}
