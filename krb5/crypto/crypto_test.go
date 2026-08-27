package crypto

import (
	"errors"
	"testing"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

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
