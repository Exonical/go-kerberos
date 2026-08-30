package camellia

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRFC3713Vectors(t *testing.T) {
	tests := []struct {
		name, key, plaintext, ciphertext string
	}{
		{
			"128",
			"0123456789abcdeffedcba9876543210",
			"0123456789abcdeffedcba9876543210",
			"67673138549669730857065648eabe43",
		},
		{
			"256",
			"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
			"0123456789abcdeffedcba9876543210",
			"9acc237dff16d76c20ef7c919e3a7509",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tt.key)
			plain, _ := hex.DecodeString(tt.plaintext)
			want, _ := hex.DecodeString(tt.ciphertext)
			c, err := New(key)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, BlockSize)
			c.Encrypt(got, plain)
			if !bytes.Equal(got, want) {
				t.Fatalf("ciphertext = %x, want %x", got, want)
			}
			decoded := make([]byte, BlockSize)
			c.Decrypt(decoded, got)
			if !bytes.Equal(decoded, plain) {
				t.Fatalf("plaintext = %x, want %x", decoded, plain)
			}
		})
	}
}
