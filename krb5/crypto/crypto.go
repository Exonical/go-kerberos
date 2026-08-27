package crypto

import (
	"fmt"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

const (
	EnctypeAES128SHA1   int32 = 17
	EnctypeAES256SHA1   int32 = 18
	EnctypeAES128SHA256 int32 = 19
	EnctypeAES256SHA384 int32 = 20

	ChecksumHMACSHA196AES128    int32 = 15
	ChecksumHMACSHA196AES256    int32 = 16
	ChecksumHMACSHA256128AES128 int32 = 19
	ChecksumHMACSHA384192AES256 int32 = 20
)

// EType is the common Kerberos encryption-type and checksum contract.
type EType interface {
	ID() int32
	KeySize() int
	StringToKey(password, salt, params []byte) ([]byte, error)
	Encrypt(key []byte, usage uint32, plaintext []byte) ([]byte, error)
	Decrypt(key []byte, usage uint32, ciphertext []byte) ([]byte, error)
	Checksum(key []byte, usage uint32, data []byte) ([]byte, error)
	ChecksumSize() int
	VerifyChecksum(key []byte, usage uint32, data, checksum []byte) error
}

type unimplementedEType struct{ id int32 }

func (e unimplementedEType) ID() int32    { return e.id }
func (e unimplementedEType) KeySize() int { return 0 }
func (e unimplementedEType) StringToKey(_, _, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("etype %d string-to-key: %w", e.id, krberrors.ErrNotImplemented)
}
func (e unimplementedEType) Encrypt(_ []byte, _ uint32, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("etype %d encrypt: %w", e.id, krberrors.ErrNotImplemented)
}
func (e unimplementedEType) Decrypt(_ []byte, _ uint32, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrNotImplemented)
}
func (e unimplementedEType) Checksum(_ []byte, _ uint32, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("etype %d checksum: %w", e.id, krberrors.ErrNotImplemented)
}
func (e unimplementedEType) ChecksumSize() int { return 0 }
func (e unimplementedEType) VerifyChecksum(_ []byte, _ uint32, _, _ []byte) error {
	return fmt.Errorf("etype %d verify checksum: %w", e.id, krberrors.ErrNotImplemented)
}

// Registry selects one of the initially supported AES enctypes.
type Registry struct{}

func NewRegistry() *Registry { return &Registry{} }

// Get returns an intentionally unimplemented profile for a supported enctype.
func (r *Registry) Get(id int32) (EType, error) {
	_ = r
	switch id {
	case EnctypeAES128SHA1, EnctypeAES256SHA1, EnctypeAES128SHA256, EnctypeAES256SHA384:
		return unimplementedEType{id: id}, nil
	default:
		return nil, krberrors.ErrUnsupportedEType
	}
}
