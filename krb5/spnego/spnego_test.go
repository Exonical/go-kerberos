package spnego

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"testing"
	"time"

	kasn1 "github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
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
