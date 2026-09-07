package aescts

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/crypto/internal/cts"
)

// Encrypt applies the raw AES CBC-CS3 ciphertext-stealing primitive.
// Kerberos confounders and integrity checks are intentionally outside this
// package.
func Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	out, _, err := EncryptWithState(key, iv, plaintext)
	return out, err
}

// EncryptWithState applies AES CBC-CS3 and returns the chaining state for the
// next message. The returned state is the last complete ciphertext block
// before ciphertext stealing's final partial block, matching MIT's
// auth-context i_vector behavior.
func EncryptWithState(key, iv, plaintext []byte) ([]byte, []byte, error) {
	block, err := newBlock(key, iv)
	if err != nil {
		return nil, nil, err
	}
	if len(plaintext) < aes.BlockSize {
		return nil, nil, fmt.Errorf("AES CTS encrypt: plaintext shorter than one block")
	}
	out, state, err := cts.Encrypt(block, iv, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("AES CTS encrypt: %w", err)
	}
	return out, state, nil
}

// Decrypt reverses the raw AES CBC-CS3 ciphertext-stealing primitive.
func Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	out, _, err := DecryptWithState(key, iv, ciphertext)
	return out, err
}

// DecryptWithState reverses AES CBC-CS3 and returns the chaining state encoded
// in ciphertext for the next message.
func DecryptWithState(key, iv, ciphertext []byte) ([]byte, []byte, error) {
	block, err := newBlock(key, iv)
	if err != nil {
		return nil, nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, nil, fmt.Errorf("AES CTS decrypt: ciphertext shorter than one block")
	}
	out, state, err := cts.Decrypt(block, iv, ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("AES CTS decrypt: %w", err)
	}
	return out, state, nil
}

func newBlock(key, iv []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES CTS cipher: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("AES CTS IV length = %d, want %d", len(iv), block.BlockSize())
	}
	return block, nil
}
