package fast

import (
	"bytes"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestArmorWrapAndUnwrapRoundTrip(t *testing.T) {
	restore := crypto.SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)))
	defer restore()
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA256)
	if err != nil {
		t.Fatal(err)
	}
	tgtKey := bytes.Repeat([]byte{0x11}, etype.KeySize())
	ticket, err := asn1.Marshal(protocol.Ticket{
		TktVNO: 5, Realm: "TEST.REALM",
		SName:   protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", "TEST.REALM"}},
		EncPart: protocol.EncryptedData{EType: etype.ID(), Cipher: []byte{1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	armor, err := NewArmor(TGT{
		Ticket: ticket, Client: client,
		Key: protocol.EncryptionKey{KeyType: etype.ID(), KeyValue: tgtKey},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	body := protocol.KDCReqBody{
		Realm: "TEST.REALM",
		SName: &protocol.PrincipalName{NameType: int32(principal.NTSrvHst), NameString: []string{"host", "service.test"}},
		Till:  types.KerberosTime{Time: now.Add(time.Hour), Present: true},
		Nonce: 9, EType: []int32{etype.ID()},
	}
	pa, err := armor.WrapASReq(body, protocol.MethodData{{PADataType: 19, PADataValue: []byte("etype-info2")}})
	if err != nil {
		t.Fatal(err)
	}
	var wrapped protocol.PAFXFastRequest
	if err := asn1.Unmarshal(pa.PADataValue, &wrapped); err != nil {
		t.Fatal(err)
	}
	plaintext, err := etype.Decrypt(armor.Key, UsageReq, wrapped.ArmoredData.EncFastReq.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var inner protocol.KrbFastReq
	if err := asn1.Unmarshal(plaintext, &inner); err != nil {
		t.Fatal(err)
	}
	if inner.ReqBody.Nonce != body.Nonce || len(inner.PAData) != 1 {
		t.Fatalf("inner request mismatch: %#v", inner)
	}
	bodyDER, _ := asn1.Marshal(body)
	if err := etype.VerifyChecksum(armor.Key, UsageReqChecksum, bodyDER, wrapped.ArmoredData.ReqChecksum.Checksum); err != nil {
		t.Fatalf("request checksum: %v", err)
	}

	ticketChecksum, err := etype.Checksum(armor.Key, UsageFinished, ticket)
	if err != nil {
		t.Fatal(err)
	}
	responseDER, err := asn1.Marshal(protocol.KrbFastResponse{
		PAData: []protocol.PAData{{PADataType: 19, PADataValue: []byte("reply")}},
		Finished: &protocol.KrbFastFinished{
			Timestamp: types.KerberosTime{Time: now, Present: true},
			Usec:      7, CRealm: client.Realm,
			CName:          protocol.PrincipalName{NameType: int32(client.NameType), NameString: client.Components},
			TicketChecksum: protocol.Checksum{ChecksumType: checksumType(etype.ID()), Checksum: ticketChecksum},
		},
		Nonce: body.Nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	responseCipher, err := etype.Encrypt(armor.Key, UsageRep, responseDER)
	if err != nil {
		t.Fatal(err)
	}
	replyDER, err := asn1.Marshal(protocol.PAFXFastReply{ArmoredData: protocol.KrbFastArmoredRep{
		EncFastRep: protocol.EncryptedData{EType: etype.ID(), Cipher: responseCipher},
	}})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := armor.UnwrapReply(protocol.MethodData{{PADataType: PAFXFast, PADataValue: replyDER}}, ticket, body.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.PAData) != 1 || reply.PAData[0].PADataType != 19 {
		t.Fatalf("reply padata mismatch: %#v", reply.PAData)
	}
}

func TestArmorRejectsReplyNonceAndFinishedChecksum(t *testing.T) {
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA1)
	if err != nil {
		t.Fatal(err)
	}
	armor := &Armor{EType: etype, Key: bytes.Repeat([]byte{1}, etype.KeySize())}
	responseDER, _ := asn1.Marshal(protocol.KrbFastResponse{Nonce: 2})
	cipher, _ := etype.Encrypt(armor.Key, UsageRep, responseDER)
	value, _ := asn1.Marshal(protocol.PAFXFastReply{ArmoredData: protocol.KrbFastArmoredRep{EncFastRep: protocol.EncryptedData{EType: etype.ID(), Cipher: cipher}}})
	if _, err := armor.UnwrapReply(protocol.MethodData{{PADataType: PAFXFast, PADataValue: value}}, []byte("ticket"), 1); err == nil {
		t.Fatal("nonce mismatch unexpectedly accepted")
	}

	ticketChecksum, err := etype.Checksum(armor.Key, UsageFinished, []byte("ticket"))
	if err != nil {
		t.Fatal(err)
	}
	responseDER, err = asn1.Marshal(protocol.KrbFastResponse{
		Finished: &protocol.KrbFastFinished{
			Timestamp:      types.KerberosTime{Time: time.Unix(1, 0).UTC(), Present: true},
			CRealm:         "TEST.REALM",
			CName:          protocol.PrincipalName{NameType: 1, NameString: []string{"alice"}},
			TicketChecksum: protocol.Checksum{ChecksumType: checksumType(etype.ID()), Checksum: ticketChecksum},
		},
		Nonce: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err = etype.Encrypt(armor.Key, UsageRep, responseDER)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := asn1.Marshal(protocol.PAFXFastReply{ArmoredData: protocol.KrbFastArmoredRep{EncFastRep: protocol.EncryptedData{EType: etype.ID(), Cipher: cipher}}})
	if err != nil {
		t.Fatal(err)
	}
	value = wrapper
	value[len(value)-1] ^= 1
	if _, err := armor.UnwrapReply(protocol.MethodData{{PADataType: PAFXFast, PADataValue: value}}, []byte("ticket"), 2); err == nil {
		t.Fatal("tampered FAST reply unexpectedly accepted")
	}
}
