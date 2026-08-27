// Package fast implements the RFC 6113 Kerberos FAST armor exchange.
package fast

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	PAFXCookie     int32 = 133
	PAFXFast       int32 = 136
	PAFXError      int32 = 137
	ArmorTypeAPReq int32 = 1

	UsageReqChecksum uint32 = 50
	UsageReq         uint32 = 51
	UsageRep         uint32 = 52
	UsageFinished    uint32 = 53
)

// TGT contains the fields needed to use a ticket as FAST armor.
type TGT struct {
	Ticket []byte
	Client principal.Principal
	Key    protocol.EncryptionKey
}

// Armor is an RFC 6113 AP-REQ armor context.
type Armor struct {
	EType crypto.EType
	Key   []byte
	APReq []byte
}

// Reply contains the authenticated contents of a FAST response.
type Reply struct {
	PAData        protocol.MethodData
	StrengthenKey *protocol.EncryptionKey
	Finished      *protocol.KrbFastFinished
	Nonce         uint32
}

// NewArmor constructs AP-REQ armor from a TGT.
func NewArmor(tgt TGT, now time.Time) (*Armor, error) {
	if len(tgt.Ticket) == 0 || len(tgt.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("FAST armor: incomplete TGT")
	}
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("FAST armor: %w", err)
	}
	if len(tgt.Key.KeyValue) != etype.KeySize() {
		return nil, fmt.Errorf("FAST armor: invalid TGT key")
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(tgt.Ticket, &ticket); err != nil {
		return nil, fmt.Errorf("FAST armor ticket: %w", err)
	}
	subkeyValue := make([]byte, etype.KeySize())
	if _, err := io.ReadFull(crypto.RandomSource, subkeyValue); err != nil {
		return nil, fmt.Errorf("FAST armor subkey: %w", err)
	}
	authenticator, err := asn1.Marshal(protocol.Authenticator{
		AuthenticatorVNO: 5,
		CRealm:           tgt.Client.Realm,
		CName:            *principalProtocol(tgt.Client),
		Cusec:            int32(now.Nanosecond() / 1000),
		Ctime:            types.KerberosTime{Time: now.UTC(), Microseconds: int32(now.Nanosecond() / 1000), Present: true},
		SubKey:           &protocol.EncryptionKey{KeyType: tgt.Key.KeyType, KeyValue: subkeyValue},
	})
	if err != nil {
		return nil, fmt.Errorf("FAST armor authenticator: %w", err)
	}
	encrypted, err := etype.Encrypt(tgt.Key.KeyValue, 11, authenticator)
	if err != nil {
		return nil, fmt.Errorf("FAST armor authenticator encryption: %w", err)
	}
	apReq, err := asn1.Marshal(protocol.APReq{
		PVNO: 5, MsgType: 14, Ticket: ticket,
		Authenticator: protocol.EncryptedData{EType: tgt.Key.KeyType, Cipher: encrypted},
	})
	if err != nil {
		return nil, fmt.Errorf("FAST armor AP-REQ: %w", err)
	}
	armorKey, err := crypto.CF2(etype, subkeyValue, tgt.Key.KeyValue, []byte("subkeyarmor"), []byte("ticketarmor"))
	if err != nil {
		return nil, fmt.Errorf("FAST armor key: %w", err)
	}
	return &Armor{EType: etype, Key: armorKey, APReq: apReq}, nil
}

// WrapASReq wraps an AS request body and inner padata in PA-FX-FAST.
func (a *Armor) WrapASReq(body protocol.KDCReqBody, inner protocol.MethodData) (protocol.PAData, error) {
	if a == nil || a.EType == nil || len(a.Key) == 0 || len(a.APReq) == 0 {
		return protocol.PAData{}, fmt.Errorf("FAST request: incomplete armor")
	}
	bodyDER, err := asn1.Marshal(body)
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("FAST request body: %w", err)
	}
	innerDER, err := asn1.Marshal(protocol.KrbFastReq{FastOptions: 0, PAData: inner, ReqBody: body})
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("FAST request: %w", err)
	}
	cipher, err := a.EType.Encrypt(a.Key, UsageReq, innerDER)
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("FAST request encryption: %w", err)
	}
	checksum, err := a.EType.Checksum(a.Key, UsageReqChecksum, bodyDER)
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("FAST request checksum: %w", err)
	}
	armored, err := asn1.Marshal(protocol.PAFXFastRequest{ArmoredData: protocol.KrbFastArmoredReq{
		Armor:       &protocol.KrbFastArmor{ArmorType: ArmorTypeAPReq, ArmorValue: append([]byte(nil), a.APReq...)},
		ReqChecksum: protocol.Checksum{ChecksumType: checksumType(a.EType.ID()), Checksum: checksum},
		EncFastReq:  protocol.EncryptedData{EType: a.EType.ID(), Cipher: cipher},
	}})
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("FAST request armor: %w", err)
	}
	return protocol.PAData{PADataType: PAFXFast, PADataValue: armored}, nil
}

// UnwrapReply authenticates and decrypts a PA-FX-FAST reply.
func (a *Armor) UnwrapReply(padata protocol.MethodData, ticket []byte, nonce uint32) (*Reply, error) {
	if a == nil || a.EType == nil || len(a.Key) == 0 {
		return nil, fmt.Errorf("FAST reply: incomplete armor")
	}
	var value []byte
	for _, item := range padata {
		if item.PADataType == PAFXFast {
			value = item.PADataValue
			break
		}
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("FAST reply: missing PA-FX-FAST")
	}
	var wrapper protocol.PAFXFastReply
	if err := asn1.Unmarshal(value, &wrapper); err != nil {
		return nil, fmt.Errorf("FAST reply armor: %w", err)
	}
	if wrapper.ArmoredData.EncFastRep.EType != a.EType.ID() {
		return nil, fmt.Errorf("FAST reply enctype %d: %w", wrapper.ArmoredData.EncFastRep.EType, krberrors.ErrUnsupportedEType)
	}
	plaintext, err := a.EType.Decrypt(a.Key, UsageRep, wrapper.ArmoredData.EncFastRep.Cipher)
	if err != nil {
		return nil, fmt.Errorf("FAST reply decrypt: %w", err)
	}
	var response protocol.KrbFastResponse
	if err := asn1.Unmarshal(plaintext, &response); err != nil {
		return nil, fmt.Errorf("FAST response: %w", err)
	}
	if response.Nonce != nonce {
		return nil, fmt.Errorf("FAST reply: nonce mismatch")
	}
	if response.Finished != nil {
		if err := a.EType.VerifyChecksum(a.Key, UsageFinished, ticket, response.Finished.TicketChecksum.Checksum); err != nil {
			return nil, fmt.Errorf("FAST reply finished: %w", err)
		}
	}
	return &Reply{
		PAData: response.PAData, StrengthenKey: response.StrengthenKey,
		Finished: response.Finished, Nonce: response.Nonce,
	}, nil
}

// ReplyKey applies an optional FAST strengthen key to a reply key.
func (a *Armor) ReplyKey(reply protocol.EncryptionKey, strengthen *protocol.EncryptionKey) (protocol.EncryptionKey, error) {
	if strengthen == nil {
		return protocol.EncryptionKey{KeyType: reply.KeyType, KeyValue: append([]byte(nil), reply.KeyValue...)}, nil
	}
	if strengthen.KeyType != reply.KeyType || strengthen.KeyType != a.EType.ID() {
		return protocol.EncryptionKey{}, fmt.Errorf("FAST reply: strengthen key enctype mismatch")
	}
	key, err := crypto.CF2(a.EType, strengthen.KeyValue, reply.KeyValue, []byte("strengthenkey"), []byte("replykey"))
	if err != nil {
		return protocol.EncryptionKey{}, fmt.Errorf("FAST reply key: %w", err)
	}
	return protocol.EncryptionKey{KeyType: reply.KeyType, KeyValue: key}, nil
}

func principalProtocol(value principal.Principal) *protocol.PrincipalName {
	return &protocol.PrincipalName{NameType: int32(value.NameType), NameString: append([]string(nil), value.Components...)}
}

func checksumType(id int32) int32 {
	return ChecksumType(id)
}

// ChecksumType returns the mandatory keyed checksum type for an enctype.
func ChecksumType(id int32) int32 {
	switch id {
	case crypto.EnctypeAES128SHA1:
		return crypto.ChecksumHMACSHA196AES128
	case crypto.EnctypeAES256SHA1:
		return crypto.ChecksumHMACSHA196AES256
	case crypto.EnctypeAES128SHA256:
		return crypto.ChecksumHMACSHA256128AES128
	case crypto.EnctypeAES256SHA384:
		return crypto.ChecksumHMACSHA384192AES256
	default:
		return 0
	}
}

func randomNonce() uint32 {
	var value [4]byte
	if _, err := io.ReadFull(crypto.RandomSource, value[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint32(value[:]) & 0x7fffffff
}
