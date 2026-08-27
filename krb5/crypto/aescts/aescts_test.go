package aescts

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRFC3962AESCTSVectors(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		plain      string
		want       string
		next       string
		nextOffset int
	}{
		// RFC 3962 Appendix B, CBC-CTS vectors. Every vector uses the
		// explicitly listed all-zero 16-byte IV.
		{"17-byte", "636869636b656e207465726979616b69", "4920776f756c64206c696b652074686520", "c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f 97", "c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f", 0},
		{"31-byte", "636869636b656e207465726979616b69", "4920776f756c64206c696b65207468652047656e6572616c20476175277320", "fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22 97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5", "fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22", 0},
		{"32-byte", "636869636b656e207465726979616b69", "4920776f756c64206c696b65207468652047656e6572616c2047617527732043", "39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8 97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84", "39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8", 0},
		{"47-byte", "636869636b656e207465726979616b69", "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c", "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84 b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e 39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5", "b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e", 16},
		{"48-byte", "636869636b656e207465726979616b69", "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20", "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84 9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8 39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8", "9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8", 16},
		{"64-byte", "636869636b656e207465726979616b69", "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e", "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84 39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8 48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40 9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8", "48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40", 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := hex.DecodeString(tt.key)
			if err != nil {
				t.Fatalf("decode key: %v", err)
			}
			plain, err := hex.DecodeString(tt.plain)
			if err != nil {
				t.Fatalf("decode plaintext: %v", err)
			}
			want, err := hex.DecodeString(strings.Join(strings.Fields(tt.want), ""))
			if err != nil {
				t.Fatalf("decode ciphertext: %v", err)
			}
			next, err := hex.DecodeString(strings.Join(strings.Fields(tt.next), ""))
			if err != nil {
				t.Fatalf("decode next IV: %v", err)
			}
			if len(next) != 16 {
				t.Fatalf("next IV length = %d, want 16", len(next))
			}
			if len(want) < tt.nextOffset+16 {
				t.Fatalf("ciphertext length = %d, next IV offset = %d", len(want), tt.nextOffset)
			}
			if !bytes.Equal(want[tt.nextOffset:tt.nextOffset+16], next) {
				t.Fatalf("next IV = %x, want %x", want[tt.nextOffset:tt.nextOffset+16], next)
			}
			iv := make([]byte, 16)
			got, err := Encrypt(key, iv, plain)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("ciphertext = %x, want %x", got, want)
			}
			decoded, err := Decrypt(key, iv, got)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(decoded, plain) {
				t.Fatalf("plaintext = %x, want %x", decoded, plain)
			}
		})
	}
}

func TestAESCTSRejectsShortInput(t *testing.T) {
	if _, err := Encrypt(make([]byte, 16), make([]byte, 16), []byte("short")); err == nil {
		t.Fatal("short plaintext unexpectedly accepted")
	}
	if _, err := Decrypt(make([]byte, 16), make([]byte, 16), []byte("short")); err == nil {
		t.Fatal("short ciphertext unexpectedly accepted")
	}
}

func TestAESCTSOneBlock(t *testing.T) {
	key, err := hex.DecodeString("636869636b656e207465726979616b69")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := hex.DecodeString("4920776f756c64206c696b6520746865")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Encrypt(key, make([]byte, 16), plain); err != nil {
		t.Fatalf("one-block Encrypt: %v", err)
	}
}
