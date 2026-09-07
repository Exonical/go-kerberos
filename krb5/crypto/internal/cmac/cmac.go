package cmac

import "crypto/cipher"

func Sum(block cipher.Block, data []byte) []byte {
	bs := block.BlockSize()
	zero := make([]byte, bs)
	l := make([]byte, bs)
	block.Encrypt(l, zero)
	k1 := double(l)
	k2 := double(k1)
	n := (len(data) + bs - 1) / bs
	complete := len(data) > 0 && len(data)%bs == 0
	if n == 0 {
		n = 1
	}
	last := make([]byte, bs)
	if complete {
		copy(last, data[(n-1)*bs:])
		xor(last, last, k1)
	} else {
		copy(last, data[(n-1)*bs:])
		last[len(data)%bs] = 0x80
		xor(last, last, k2)
	}
	state := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		input := make([]byte, bs)
		copy(input, data[i*bs:])
		xor(input, input, state)
		block.Encrypt(state, input)
	}
	xor(last, last, state)
	block.Encrypt(state, last)
	return state
}

func double(in []byte) []byte {
	out := make([]byte, len(in))
	carry := byte(0)
	for i := len(in) - 1; i >= 0; i-- {
		next := in[i] >> 7
		out[i] = in[i]<<1 | carry
		carry = next
	}
	if carry != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}

func xor(dst, left, right []byte) {
	for i := range dst {
		dst[i] = left[i] ^ right[i]
	}
}
