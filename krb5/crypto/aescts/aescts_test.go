package aescts

import (
	"encoding/hex"
	"testing"
)

func TestRFC3962AESCTSVectors(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		plain string
		want  string
	}{
		{"partial", "636869636b656e207465726979616b69", "4920776f756c64206c696b652074686520", "c6353568f2bf8cb4d8a580362d7ff7f97"},
		{"multi", "636869636b656e207465726979616b69", "4920776f756c64206c696b65207468652047656e6572616c20476175277320", "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6eccc0c07b25e25ecfe5"},
		{"exact-block", "636869636b656e207465726979616b69", "4920776f756c64206c696b65207468652047656e6572616c2047617527732043", "39312523a78662d5be7fcbcc98ebf5a897687268d6eccc0c07b25e25ecfe584"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tt.key)
			plain, _ := hex.DecodeString(tt.plain)
			want, _ := hex.DecodeString(tt.want)
			got, err := Encrypt(key, plain)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if string(got) != string(want) {
				t.Fatalf("ciphertext = %x, want %x", got, want)
			}
			decoded, err := Decrypt(key, got)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(decoded) != string(plain) {
				t.Fatalf("plaintext = %x, want %x", decoded, plain)
			}
		})
	}
}

func TestAESCTSRejectsShortInput(t *testing.T) {
	if _, err := Encrypt(make([]byte, 16), []byte("short")); err == nil {
		t.Fatal("short plaintext unexpectedly accepted")
	}
	if _, err := Decrypt(make([]byte, 16), []byte("short")); err == nil {
		t.Fatal("short ciphertext unexpectedly accepted")
	}
}

func TestAESCTSOneBlock(t *testing.T) {
	key, _ := hex.DecodeString("636869636b656e207465726979616b69")
	plain, _ := hex.DecodeString("4920776f756c64206c696b6520746865")
	if _, err := Encrypt(key, plain); err != nil {
		t.Fatalf("one-block Encrypt: %v", err)
	}
}
