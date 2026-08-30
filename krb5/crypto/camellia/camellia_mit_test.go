package camellia

import (
	"bufio"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMITCamelliaVariableTextVectors(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(source), "..", "..", "..", "testdata", "mit", "crypto", "camellia-expect-vt.txt")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var key, plaintext, ciphertext []byte
	keySize := 0
	run := func() {
		if len(key) == 0 || len(plaintext) == 0 || len(ciphertext) == 0 {
			return
		}
		if len(key) != keySize/8 {
			t.Fatalf("MIT Camellia key length = %d, want %d", len(key), keySize/8)
		}
		cipher, err := New(key)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, BlockSize)
		cipher.Encrypt(got, plaintext)
		if string(got) != string(ciphertext) {
			t.Fatalf("MIT Camellia vector keysize %d plaintext %x = %x, want %x", keySize, plaintext, got, ciphertext)
		}
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "=") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "KEYSIZE="):
			keySize = atoiVector(t, strings.TrimPrefix(line, "KEYSIZE="))
		case strings.HasPrefix(line, "KEY="):
			key = decodeVector(t, strings.TrimPrefix(line, "KEY="))
		case strings.HasPrefix(line, "PT="):
			plaintext = decodeVector(t, strings.TrimPrefix(line, "PT="))
		case strings.HasPrefix(line, "CT="):
			ciphertext = decodeVector(t, strings.TrimPrefix(line, "CT="))
			run()
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func decodeVector(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode MIT Camellia vector %q: %v", value, err)
	}
	return data
}

func atoiVector(t *testing.T, value string) int {
	t.Helper()
	var result int
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			t.Fatalf("invalid MIT Camellia key size %q", value)
		}
		result = result*10 + int(digit-'0')
	}
	return result
}
