package pac

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
)

func TestCredentialInfoEnvelope(t *testing.T) {
	value := CredentialInfo{EncryptionType: crypto.EnctypeAES256SHA1, Data: []byte{1, 2, 3, 4}}
	wire, err := value.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 12)
	binary.LittleEndian.PutUint32(want[4:], uint32(crypto.EnctypeAES256SHA1))
	copy(want[8:], value.Data)
	if !bytes.Equal(wire, want) {
		t.Fatalf("wire = %x, want %x", wire, want)
	}
	got, err := ParseCredentialInfo(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 0 || got.EncryptionType != value.EncryptionType || !bytes.Equal(got.Data, value.Data) {
		t.Fatalf("decoded = %#v, want %#v", got, value)
	}
}

func TestCredentialInfoEncryptDecrypt(t *testing.T) {
	registry := crypto.NewRegistry()
	plaintext := []byte("opaque PAC credential data")
	for _, id := range []int32{crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1} {
		etype, err := registry.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		key := bytes.Repeat([]byte{0x41}, etype.KeySize())
		info, err := EncryptCredentialInfo(etype, key, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := info.Decrypt(key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("decrypted = %q, want %q", got, plaintext)
		}
	}
}
