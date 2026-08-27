package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

func TestPRFRFC8009Vectors(t *testing.T) {
	vectors := []struct {
		etype int32
		key   string
		want  string
	}{
		{EnctypeAES128SHA256, "3705d96080c17728a0e800eab6e0d23c",
			"9d188616f63852fe86915bb840b4a886ff3e6bb0f819b49b893393d393854295"},
		{EnctypeAES256SHA384, "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
			"9801f69a368c2bf675e59521e177d9a07f67efe1cfde8d3c8d6f6a0256e3b17db3c1b62ad1b8553360d17367eb1514d2"},
	}
	for _, vector := range vectors {
		etype, err := NewRegistry().Get(vector.etype)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := hex.DecodeString(vector.key)
		want, _ := hex.DecodeString(vector.want)
		got, err := PRF(etype, key, []byte("test"))
		if err != nil {
			t.Fatalf("PRF(%d): %v", vector.etype, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("PRF(%d) = %x, want %x", vector.etype, got, want)
		}
	}
}

func TestCF2UsesDistinctPepperInputs(t *testing.T) {
	etype, err := NewRegistry().Get(EnctypeAES128SHA256)
	if err != nil {
		t.Fatal(err)
	}
	key1 := bytes.Repeat([]byte{0x11}, etype.KeySize())
	key2 := bytes.Repeat([]byte{0x22}, etype.KeySize())
	first, err := CF2(etype, key1, key2, []byte("a"), []byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := CF2(etype, key1, key2, []byte("b"), []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("CF2 returned the same key for swapped peppers")
	}
	if len(first) != etype.KeySize() {
		t.Fatalf("CF2 key length = %d, want %d", len(first), etype.KeySize())
	}
}

func TestCF2RFC6113Vectors(t *testing.T) {
	vectors := []struct {
		etype int32
		want  string
	}{
		{EnctypeAES128SHA1, "97df97e4b798b29eb31ed7280287a92a"},
		{EnctypeAES256SHA1, "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b"},
	}
	for _, vector := range vectors {
		etype, err := NewRegistry().Get(vector.etype)
		if err != nil {
			t.Fatal(err)
		}
		key1, err := etype.StringToKey([]byte("key1"), []byte("key1"), nil)
		if err != nil {
			t.Fatal(err)
		}
		key2, err := etype.StringToKey([]byte("key2"), []byte("key2"), nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := CF2(etype, key1, key2, []byte("a"), []byte("b"))
		if err != nil {
			t.Fatalf("CF2(%d): %v", vector.etype, err)
		}
		want, _ := hex.DecodeString(vector.want)
		if !bytes.Equal(got, want) {
			t.Fatalf("CF2(%d) = %x, want %x", vector.etype, got, want)
		}
	}
}

func TestRegistrySupportsModernEnctypes(t *testing.T) {
	registry := NewRegistry()
	for _, id := range []int32{EnctypeAES128SHA1, EnctypeAES256SHA1, EnctypeAES128SHA256, EnctypeAES256SHA384} {
		etype, err := registry.Get(id)
		if err != nil {
			t.Fatalf("registry.Get(%d): %v", id, err)
		}
		if etype.ID() != id {
			t.Fatalf("etype ID = %d, want %d", etype.ID(), id)
		}
	}
}

func TestRegistryRejectsLegacyAndUnknownEnctypes(t *testing.T) {
	for _, id := range []int32{1, 2, 23, 9999} {
		if _, err := NewRegistry().Get(id); !errors.Is(err, krberrors.ErrUnsupportedEType) {
			t.Fatalf("registry.Get(%d) error = %v, want ErrUnsupportedEType", id, err)
		}
	}
}

func TestETypeVectorAndUsageSeparation(t *testing.T) {
	etype, err := NewRegistry().Get(EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	plaintext := []byte("kerberos test plaintext")
	ciphertext, err := etype.Encrypt(key, 42, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := etype.Decrypt(key, 43, ciphertext); err == nil {
		t.Fatal("Decrypt with a different key usage unexpectedly succeeded")
	}
}

func TestETypeNegativeInputs(t *testing.T) {
	etype, err := NewRegistry().Get(EnctypeAES128SHA1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := etype.StringToKey([]byte("password"), []byte("salt"), nil); err != nil {
		t.Fatalf("StringToKey: %v", err)
	}
	if _, err := etype.Decrypt(make([]byte, 16), 1, []byte{1}); err == nil {
		t.Fatal("short ciphertext unexpectedly accepted")
	}
}

func TestChecksumAndVerificationVector(t *testing.T) {
	etype, err := NewRegistry().Get(EnctypeAES128SHA256)
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := etype.Checksum(make([]byte, 16), 2, []byte("data"))
	if err != nil {
		t.Fatalf("Checksum: %v", err)
	}
	if len(checksum) != etype.ChecksumSize() {
		t.Fatalf("checksum length = %d, want %d", len(checksum), etype.ChecksumSize())
	}
	if err := etype.VerifyChecksum(make([]byte, 16), 2, []byte("data"), checksum); err != nil {
		t.Fatalf("VerifyChecksum: %v", err)
	}
}

func TestChecksumTypeNumbers(t *testing.T) {
	tests := map[int32]int32{
		EnctypeAES128SHA1:   ChecksumHMACSHA196AES128,
		EnctypeAES256SHA1:   ChecksumHMACSHA196AES256,
		EnctypeAES128SHA256: ChecksumHMACSHA256128AES128,
		EnctypeAES256SHA384: ChecksumHMACSHA384192AES256,
	}
	if tests[EnctypeAES128SHA1] != 15 || tests[EnctypeAES256SHA1] != 16 ||
		tests[EnctypeAES128SHA256] != 19 || tests[EnctypeAES256SHA384] != 20 {
		t.Fatalf("unexpected checksum type assignments: %#v", tests)
	}
}
