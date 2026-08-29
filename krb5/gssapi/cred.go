package gssapi

import (
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const krbCredEncPartUsage uint32 = 14

// MarshalKRBCred encodes forwarded credentials as an RFC 4120 KRB-CRED.
// The encrypted part uses KRB5_KEYUSAGE_KRB_CRED_ENCPART (14). A nil key
// produces the unencrypted form accepted by older GSS implementations.
func MarshalKRBCred(creds []*client.Credentials, key *protocol.EncryptionKey, usage uint32) ([]byte, error) {
	if len(creds) == 0 {
		return nil, fmt.Errorf("KRB-CRED: no credentials")
	}
	tickets := make([]protocol.Ticket, len(creds))
	infos := make([]protocol.KrbCredInfo, len(creds))
	for i, credential := range creds {
		if credential == nil || len(credential.Ticket) == 0 {
			return nil, fmt.Errorf("KRB-CRED: incomplete credential %d", i)
		}
		if err := asn1.Unmarshal(credential.Ticket, &tickets[i]); err != nil {
			return nil, fmt.Errorf("KRB-CRED ticket %d: %w", i, err)
		}
		realm := credential.Client.Realm
		name := protocol.PrincipalName{
			NameType:   int32(credential.Client.NameType),
			NameString: append([]string(nil), credential.Client.Components...),
		}
		srealm := credential.Server.Realm
		sname := protocol.PrincipalName{
			NameType:   int32(credential.Server.NameType),
			NameString: append([]string(nil), credential.Server.Components...),
		}
		flags := credential.Flags
		infos[i] = protocol.KrbCredInfo{
			Key: protocol.EncryptionKey{
				KeyType:  credential.Key.KeyType,
				KeyValue: append([]byte(nil), credential.Key.KeyValue...),
			},
			Prealm: &realm, PName: &name, Flags: &flags,
			AuthTime: &credential.AuthTime, StartTime: credential.StartTime,
			EndTime: &credential.EndTime, RenewTill: credential.RenewTill,
			SRealm: &srealm, SName: &sname,
		}
	}
	encPart := protocol.EncKrbCredPart{TicketInfo: infos}
	plain, err := asn1.Marshal(encPart)
	if err != nil {
		return nil, fmt.Errorf("KRB-CRED encrypted part: %w", err)
	}
	encrypted := protocol.EncryptedData{EType: 0, Cipher: plain}
	if key != nil {
		if len(key.KeyValue) == 0 {
			return nil, fmt.Errorf("KRB-CRED: empty encryption key")
		}
		etype, err := crypto.NewRegistry().Get(key.KeyType)
		if err != nil {
			return nil, fmt.Errorf("KRB-CRED encryption type: %w", err)
		}
		cipher, err := etype.Encrypt(key.KeyValue, usage, plain)
		if err != nil {
			return nil, fmt.Errorf("KRB-CRED encrypt: %w", err)
		}
		encrypted = protocol.EncryptedData{EType: key.KeyType, Cipher: cipher}
	}
	message, err := asn1.Marshal(protocol.KRBCred{
		PVNO: 5, MsgType: 22, Tickets: tickets, EncPart: encrypted,
	})
	if err != nil {
		return nil, fmt.Errorf("KRB-CRED: %w", err)
	}
	return message, nil
}

// ReadKRBCred decodes an RFC 4120 KRB-CRED. If key is non-nil, the encrypted
// part is decrypted with usage 14; a plaintext encrypted part is also
// accepted for compatibility with GSS implementations which use ETYPE-NULL.
func ReadKRBCred(data []byte, key *protocol.EncryptionKey, usage uint32) ([]*client.Credentials, error) {
	var message protocol.KRBCred
	if err := asn1.Unmarshal(data, &message); err != nil {
		return nil, fmt.Errorf("KRB-CRED: %w", err)
	}
	if message.PVNO != 5 || message.MsgType != 22 || len(message.Tickets) == 0 {
		return nil, fmt.Errorf("KRB-CRED: invalid header")
	}
	plain := message.EncPart.Cipher
	if message.EncPart.EType != 0 {
		if key == nil || len(key.KeyValue) == 0 {
			return nil, fmt.Errorf("KRB-CRED: encrypted part requires a key")
		}
		if message.EncPart.EType != key.KeyType {
			return nil, fmt.Errorf("KRB-CRED: encrypted part enctype mismatch")
		}
		etype, err := crypto.NewRegistry().Get(message.EncPart.EType)
		if err != nil {
			return nil, fmt.Errorf("KRB-CRED encryption type: %w", err)
		}
		plain, err = etype.Decrypt(key.KeyValue, usage, plain)
		if err != nil {
			return nil, fmt.Errorf("KRB-CRED decrypt: %w", err)
		}
	}
	var encPart protocol.EncKrbCredPart
	if err := asn1.Unmarshal(plain, &encPart); err != nil {
		return nil, fmt.Errorf("KRB-CRED encrypted part: %w", err)
	}
	if len(encPart.TicketInfo) != len(message.Tickets) {
		return nil, fmt.Errorf("KRB-CRED: ticket-info count mismatch")
	}
	result := make([]*client.Credentials, len(message.Tickets))
	for i := range message.Tickets {
		info := encPart.TicketInfo[i]
		if info.PName == nil || info.Prealm == nil || info.SName == nil || info.SRealm == nil {
			return nil, fmt.Errorf("KRB-CRED: incomplete ticket-info %d", i)
		}
		ticket, err := asn1.Marshal(message.Tickets[i])
		if err != nil {
			return nil, fmt.Errorf("KRB-CRED ticket %d: %w", i, err)
		}
		result[i] = &client.Credentials{
			Client: principalFromProtocol(*info.PName, *info.Prealm),
			Server: principalFromProtocol(*info.SName, *info.SRealm),
			Key: protocol.EncryptionKey{
				KeyType:  info.Key.KeyType,
				KeyValue: append([]byte(nil), info.Key.KeyValue...),
			},
			Ticket: ticket,
		}
		if info.Flags != nil {
			result[i].Flags = *info.Flags
		}
		if info.AuthTime != nil {
			result[i].AuthTime = *info.AuthTime
		}
		result[i].StartTime = info.StartTime
		if info.EndTime != nil {
			result[i].EndTime = *info.EndTime
		}
		result[i].RenewTill = info.RenewTill
	}
	return result, nil
}

func principalFromProtocol(name protocol.PrincipalName, realm string) principal.Principal {
	return principal.Principal{
		Realm: realm, NameType: principal.NameType(name.NameType),
		Components: append([]string(nil), name.NameString...),
	}
}
