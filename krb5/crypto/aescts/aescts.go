package aescts

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
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
	if len(plaintext) == aes.BlockSize {
		out := make([]byte, aes.BlockSize)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
		return out, append([]byte(nil), out...), nil
	}
	if len(plaintext)%aes.BlockSize == 0 {
		out := make([]byte, len(plaintext))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
		last := len(out) - aes.BlockSize
		previous := last - aes.BlockSize
		swapped := append([]byte(nil), out[previous:last]...)
		copy(out[previous:last], out[last:])
		copy(out[last:], swapped)
		return out, append([]byte(nil), out[len(out)-2*aes.BlockSize:len(out)-aes.BlockSize]...), nil
	}

	fullBlocks := len(plaintext) / aes.BlockSize
	remainder := len(plaintext) % aes.BlockSize
	out := make([]byte, 0, len(plaintext))
	previous := iv
	for i := 0; i < fullBlocks-1; i++ {
		encrypted := make([]byte, aes.BlockSize)
		xorBlock(encrypted, plaintext[i*aes.BlockSize:(i+1)*aes.BlockSize], previous)
		block.Encrypt(encrypted, encrypted)
		out = append(out, encrypted...)
		previous = encrypted
	}

	penultimate := plaintext[(fullBlocks-1)*aes.BlockSize : fullBlocks*aes.BlockSize]
	last := plaintext[fullBlocks*aes.BlockSize:]
	x := make([]byte, aes.BlockSize)
	xorBlock(x, penultimate, previous)
	block.Encrypt(x, x)

	paddedLast := make([]byte, aes.BlockSize)
	copy(paddedLast, last)
	xorBlock(paddedLast, paddedLast, x)
	y := make([]byte, aes.BlockSize)
	block.Encrypt(y, paddedLast)

	out = append(out, y...)
	if remainder == 0 {
		out = append(out, x...)
	} else {
		out = append(out, x[:remainder]...)
	}
	nextOffset := len(out) - remainder - aes.BlockSize
	return out, append([]byte(nil), out[nextOffset:nextOffset+aes.BlockSize]...), nil
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
	if len(ciphertext) == aes.BlockSize {
		out := make([]byte, aes.BlockSize)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
		return out, append([]byte(nil), ciphertext...), nil
	}

	fullBlocks := len(ciphertext) / aes.BlockSize
	remainder := len(ciphertext) % aes.BlockSize
	out := make([]byte, 0, len(ciphertext))
	previous := iv
	previousBlocks := fullBlocks - 2
	if remainder != 0 {
		previousBlocks = fullBlocks - 1
	}
	for i := 0; i < previousBlocks; i++ {
		plain := make([]byte, aes.BlockSize)
		cipher.NewCBCDecrypter(block, previous).CryptBlocks(plain, ciphertext[i*aes.BlockSize:(i+1)*aes.BlockSize])
		out = append(out, plain...)
		previous = ciphertext[i*aes.BlockSize : (i+1)*aes.BlockSize]
	}

	yBlock := fullBlocks - 2
	if remainder != 0 {
		yBlock = fullBlocks - 1
	}
	yOffset := yBlock * aes.BlockSize
	y := ciphertext[yOffset : yOffset+aes.BlockSize]
	xPart := ciphertext[yOffset+aes.BlockSize:]
	if remainder == 0 {
		x := xPart
		dy := make([]byte, aes.BlockSize)
		block.Decrypt(dy, y)
		plainLast := make([]byte, aes.BlockSize)
		xorBlock(plainLast, dy, x)
		dx := make([]byte, aes.BlockSize)
		block.Decrypt(dx, x)
		plainPenultimate := make([]byte, aes.BlockSize)
		xorBlock(plainPenultimate, dx, previous)
		out = append(out, plainPenultimate...)
		out = append(out, plainLast...)
		return out, append([]byte(nil), ciphertext[len(ciphertext)-2*aes.BlockSize:len(ciphertext)-aes.BlockSize]...), nil
	}

	dy := make([]byte, aes.BlockSize)
	block.Decrypt(dy, y)
	x := make([]byte, aes.BlockSize)
	copy(x, xPart)
	copy(x[remainder:], dy[remainder:])

	plainLast := make([]byte, remainder)
	for i := range plainLast {
		plainLast[i] = dy[i] ^ x[i]
	}
	dx := make([]byte, aes.BlockSize)
	block.Decrypt(dx, x)
	plainPenultimate := make([]byte, aes.BlockSize)
	xorBlock(plainPenultimate, dx, previous)
	out = append(out, plainPenultimate...)
	out = append(out, plainLast...)
	nextOffset := len(ciphertext) - remainder - aes.BlockSize
	return out, append([]byte(nil), ciphertext[nextOffset:nextOffset+aes.BlockSize]...), nil
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

func xorBlock(dst, left, right []byte) {
	for i := range dst {
		dst[i] = left[i] ^ right[i]
	}
}
