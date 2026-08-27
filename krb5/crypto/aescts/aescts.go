package aescts

import (
	"fmt"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

// Encrypt applies the raw AES ciphertext-stealing primitive. Kerberos
// confounders are intentionally outside this package.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	_, _ = key, plaintext
	return nil, fmt.Errorf("AES CTS encrypt: %w", krberrors.ErrNotImplemented)
}

// Decrypt reverses the raw AES ciphertext-stealing primitive.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	_, _ = key, ciphertext
	return nil, fmt.Errorf("AES CTS decrypt: %w", krberrors.ErrNotImplemented)
}
