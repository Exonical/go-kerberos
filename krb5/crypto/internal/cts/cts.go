package cts

import (
	"crypto/cipher"
	"errors"
)

var (
	ErrInvalidIV  = errors.New("invalid IV length")
	ErrShortInput = errors.New("input shorter than one block")
)

func Encrypt(block cipher.Block, iv, plaintext []byte) ([]byte, []byte, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, nil, ErrInvalidIV
	}
	if len(plaintext) < bs {
		return nil, nil, ErrShortInput
	}
	if len(plaintext) == bs {
		out := make([]byte, bs)
		encryptBlock(block, out, plaintext, iv)
		return out, append([]byte(nil), out...), nil
	}
	if len(plaintext)%bs == 0 {
		out := make([]byte, len(plaintext))
		previous := iv
		for offset := 0; offset < len(plaintext); offset += bs {
			encryptBlock(block, out[offset:offset+bs], plaintext[offset:offset+bs], previous)
			previous = out[offset : offset+bs]
		}
		last := len(out) - bs
		previousOffset := last - bs
		swapped := append([]byte(nil), out[previousOffset:last]...)
		copy(out[previousOffset:last], out[last:])
		copy(out[last:], swapped)
		return out, append([]byte(nil), out[len(out)-2*bs:len(out)-bs]...), nil
	}

	fullBlocks := len(plaintext) / bs
	remainder := len(plaintext) % bs
	out := make([]byte, 0, len(plaintext))
	previous := iv
	for i := 0; i < fullBlocks-1; i++ {
		encrypted := make([]byte, bs)
		encryptBlock(block, encrypted, plaintext[i*bs:(i+1)*bs], previous)
		out = append(out, encrypted...)
		previous = encrypted
	}

	penultimate := plaintext[(fullBlocks-1)*bs : fullBlocks*bs]
	last := plaintext[fullBlocks*bs:]
	x := make([]byte, bs)
	encryptBlock(block, x, penultimate, previous)
	paddedLast := make([]byte, bs)
	copy(paddedLast, last)
	xor(paddedLast, paddedLast, x)
	y := make([]byte, bs)
	block.Encrypt(y, paddedLast)
	out = append(out, y...)
	out = append(out, x[:remainder]...)
	nextOffset := len(out) - remainder - bs
	return out, append([]byte(nil), out[nextOffset:nextOffset+bs]...), nil
}

func Decrypt(block cipher.Block, iv, ciphertext []byte) ([]byte, []byte, error) {
	bs := block.BlockSize()
	if len(iv) != bs {
		return nil, nil, ErrInvalidIV
	}
	if len(ciphertext) < bs {
		return nil, nil, ErrShortInput
	}
	if len(ciphertext) == bs {
		out := make([]byte, bs)
		block.Decrypt(out, ciphertext)
		xor(out, out, iv)
		return out, append([]byte(nil), ciphertext...), nil
	}

	fullBlocks := len(ciphertext) / bs
	remainder := len(ciphertext) % bs
	out := make([]byte, 0, len(ciphertext))
	previous := iv
	previousBlocks := fullBlocks - 2
	if remainder != 0 {
		previousBlocks = fullBlocks - 1
	}
	for i := 0; i < previousBlocks; i++ {
		plain := make([]byte, bs)
		block.Decrypt(plain, ciphertext[i*bs:(i+1)*bs])
		xor(plain, plain, previous)
		out = append(out, plain...)
		previous = ciphertext[i*bs : (i+1)*bs]
	}

	yBlock := fullBlocks - 2
	if remainder != 0 {
		yBlock = fullBlocks - 1
	}
	yOffset := yBlock * bs
	y := ciphertext[yOffset : yOffset+bs]
	xPart := ciphertext[yOffset+bs:]
	if remainder == 0 {
		dy := make([]byte, bs)
		block.Decrypt(dy, y)
		plainLast := make([]byte, bs)
		xor(plainLast, dy, xPart)
		dx := make([]byte, bs)
		block.Decrypt(dx, xPart)
		plainPenultimate := make([]byte, bs)
		xor(plainPenultimate, dx, previous)
		out = append(out, plainPenultimate...)
		out = append(out, plainLast...)
		return out, append([]byte(nil), ciphertext[len(ciphertext)-2*bs:len(ciphertext)-bs]...), nil
	}

	dy := make([]byte, bs)
	block.Decrypt(dy, y)
	x := make([]byte, bs)
	copy(x, xPart)
	copy(x[remainder:], dy[remainder:])
	plainLast := make([]byte, remainder)
	for i := range plainLast {
		plainLast[i] = dy[i] ^ x[i]
	}
	dx := make([]byte, bs)
	block.Decrypt(dx, x)
	plainPenultimate := make([]byte, bs)
	xor(plainPenultimate, dx, previous)
	out = append(out, plainPenultimate...)
	out = append(out, plainLast...)
	nextOffset := len(ciphertext) - remainder - bs
	return out, append([]byte(nil), ciphertext[nextOffset:nextOffset+bs]...), nil
}

func encryptBlock(block cipher.Block, dst, plain, previous []byte) {
	xor(dst, plain, previous)
	block.Encrypt(dst, dst)
}

func xor(dst, left, right []byte) {
	for i := range dst {
		dst[i] = left[i] ^ right[i]
	}
}
