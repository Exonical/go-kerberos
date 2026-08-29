package pac

import (
	"encoding/binary"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/crypto"
)

const (
	// CredentialInfoKeyUsage is the MS-PAC 2.6.1 Kerberos encryption usage.
	CredentialInfoKeyUsage uint32 = 16
)

// CredentialInfo is the PAC_CREDENTIAL_INFO envelope.  The encrypted
// PAC_CREDENTIAL_DATA contents remain opaque, as they are to MIT krb5.
type CredentialInfo struct {
	Version        uint32
	EncryptionType int32
	Data           []byte
}

// MarshalBinary encodes a version-zero PAC_CREDENTIAL_INFO envelope.
func (c CredentialInfo) MarshalBinary() ([]byte, error) {
	if c.Version != 0 {
		return nil, fmt.Errorf("PAC: unsupported credential-info version %d", c.Version)
	}
	out := make([]byte, 8+len(c.Data))
	binary.LittleEndian.PutUint32(out, c.Version)
	binary.LittleEndian.PutUint32(out[4:], uint32(c.EncryptionType))
	copy(out[8:], c.Data)
	return out, nil
}

// Marshal is an alias for MarshalBinary.
func (c CredentialInfo) Marshal() ([]byte, error) { return c.MarshalBinary() }

// ParseCredentialInfo decodes a PAC_CREDENTIAL_INFO envelope.
func ParseCredentialInfo(data []byte) (CredentialInfo, error) {
	if len(data) < 8 {
		return CredentialInfo{}, fmt.Errorf("PAC: truncated credential-info")
	}
	version := binary.LittleEndian.Uint32(data)
	if version != 0 {
		return CredentialInfo{}, fmt.Errorf("PAC: unsupported credential-info version %d", version)
	}
	return CredentialInfo{
		Version: version, EncryptionType: int32(binary.LittleEndian.Uint32(data[4:])),
		Data: append([]byte(nil), data[8:]...),
	}, nil
}

// EncryptCredentialInfo encrypts opaque PAC_CREDENTIAL_DATA with key usage 16.
func EncryptCredentialInfo(etype crypto.EType, key, plaintext []byte) (CredentialInfo, error) {
	if etype == nil {
		return CredentialInfo{}, fmt.Errorf("PAC: missing credential-info enctype")
	}
	ciphertext, err := etype.Encrypt(key, CredentialInfoKeyUsage, plaintext)
	if err != nil {
		return CredentialInfo{}, err
	}
	return CredentialInfo{EncryptionType: etype.ID(), Data: ciphertext}, nil
}

// Decrypt decrypts opaque PAC_CREDENTIAL_DATA with key usage 16.
func (c CredentialInfo) Decrypt(key []byte) ([]byte, error) {
	if c.Version != 0 {
		return nil, fmt.Errorf("PAC: unsupported credential-info version %d", c.Version)
	}
	etype, err := crypto.NewRegistry().Get(c.EncryptionType)
	if err != nil {
		return nil, err
	}
	return etype.Decrypt(key, CredentialInfoKeyUsage, c.Data)
}
