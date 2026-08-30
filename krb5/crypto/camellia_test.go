package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCamelliaStringToKeyVectors(t *testing.T) {
	tests := []struct {
		etype      int32
		password   string
		salt       string
		iterations []byte
		want       string
	}{
		{EnctypeCamellia128, "password", "ATHENA.MIT.EDUraeburn", []byte{0, 0, 0, 1}, "57d0297298ffd9d35de5a47fb4bde24b"},
		{EnctypeCamellia128, "password", "ATHENA.MIT.EDUraeburn", []byte{0, 0, 0, 2}, "73f1b53aa0f310f93b1de8ccaa0cb152"},
		{EnctypeCamellia128, "password", "ATHENA.MIT.EDUraeburn", []byte{0, 0, 4, 176}, "8e571145452855575fd916e7b04487aa"},
		{EnctypeCamellia256, "password", "ATHENA.MIT.EDUraeburn", []byte{0, 0, 0, 1}, "b9d6828b2056b7be656d88a123b1fac68214ac2b727ecf5f69afe0c4df2a6d2c"},
		{EnctypeCamellia256, "password", "ATHENA.MIT.EDUraeburn", []byte{0, 0, 0, 2}, "83fc5866e5f8f4c6f38663c65c87549f342bc47ed394dc9d3cd4d163ade375e3"},
		{EnctypeCamellia256, "password", "ATHENA.MIT.EDUraeburn", []byte{0, 0, 4, 176}, "77f421a6f25e138395e837e5d85d385b4c1bfd772e112cd9208ce72a530b15e6"},
		{EnctypeCamellia128, "password", string([]byte{0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12}), []byte{0, 0, 0, 5}, "00498fd916bfc1c2b1031c170801b381"},
		{EnctypeCamellia256, "password", string([]byte{0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12}), []byte{0, 0, 0, 5}, "11083a00bdfe6a41b2f19716d6202f0afa94289afe8b27a049bd28b1d76c389a"},
	}
	for _, tt := range tests {
		etype, err := NewRegistry().Get(tt.etype)
		if err != nil {
			t.Fatal(err)
		}
		got, err := etype.StringToKey([]byte(tt.password), []byte(tt.salt), tt.iterations)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, mustHex(t, tt.want)) {
			t.Errorf("etype %d string-to-key = %x, want %s", tt.etype, got, tt.want)
		}
	}
}

func TestCamelliaChecksumVectors(t *testing.T) {
	tests := []struct {
		etype int32
		key   string
		usage uint32
		data  string
		want  string
	}{
		{EnctypeCamellia128, "1dc46a8d763f4f93742bcba3387576c3", 7, "abcdefghijk", "1178e6c5c47a8c1ae0c4b9c7d4eb7b6b"},
		{EnctypeCamellia128, "5027bc231d0f3a9d23333f1ca6fdbe7c", 8, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "d1b34f7004a731f23a0c00bf6c3f753a"},
		{EnctypeCamellia256, "b61c86cc4e5d2757545ad423399fb7031ecab913cbb900bd7a3c6dd8bf92015b", 9, "123456789", "87a12cfd2b96214810f01c826e7744b1"},
		{EnctypeCamellia256, "32164c5b434d1d1538e4cfd9be8040fe8c4ac7acc4b93d3314d2133668147a05", 10, "!@#$%^&*()!@#$%^&*()!@#$%^&*()", "3fa0b42355e52b189187294aa252ab64"},
	}
	for _, tt := range tests {
		etype, err := NewRegistry().Get(tt.etype)
		if err != nil {
			t.Fatal(err)
		}
		got, err := etype.Checksum(mustHex(t, tt.key), tt.usage, []byte(tt.data))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, mustHex(t, tt.want)) {
			t.Errorf("etype %d checksum = %x, want %s", tt.etype, got, tt.want)
		}
	}
}

func TestCamelliaDerivationVector(t *testing.T) {
	key := mustHex(t, "57d0297298ffd9d35de5a47fb4bde24b")
	got, err := camelliaDerive(key, mustHex(t, "0000000299"), len(key))
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "d155775a209d05f02b38d42a389e5a56")
	if !bytes.Equal(got, want) {
		t.Fatalf("derived key = %x, want %x", got, want)
	}
}

func TestCamelliaEncryptionRoundTrip(t *testing.T) {
	restore := SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	defer restore()
	for _, id := range []int32{EnctypeCamellia128, EnctypeCamellia256} {
		etype, err := NewRegistry().Get(id)
		if err != nil {
			t.Fatal(err)
		}
		key := bytes.Repeat([]byte{0x11}, etype.KeySize())
		plain := []byte("camellia CTS supports partial final blocks")
		ciphertext, err := etype.Encrypt(key, 42, plain)
		if err != nil {
			t.Fatalf("etype %d encrypt: %v", id, err)
		}
		got, err := etype.Decrypt(key, 42, ciphertext)
		if err != nil {
			t.Fatalf("etype %d decrypt: %v", id, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("etype %d plaintext = %q, want %q", id, got, plain)
		}
	}
}
