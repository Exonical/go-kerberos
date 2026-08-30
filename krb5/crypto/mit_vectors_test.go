package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mitHex(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode MIT vector %q: %v", value, err)
	}
	return data
}

// These vectors are transcribed from MIT Kerberos 1.22.2
// src/lib/crypto/crypto_tests.
func TestMITCF2Vectors(t *testing.T) {
	vectors := []struct {
		etype int32
		want  string
	}{
		{EnctypeAES128SHA1, "97df97e4b798b29eb31ed7280287a92a"},
		{EnctypeAES256SHA1, "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b"},
		{EnctypeAES128SHA256, "edd02a39d2dbde31611c16e610be062c"},
		{EnctypeAES256SHA384, "67f6ea530aea85a37dcbb23349ea52dcc61ca8493ff557252327fd8304341584"},
	}
	for _, vector := range vectors {
		etype, err := NewRegistry().Get(vector.etype)
		if err != nil {
			t.Fatalf("MIT CF2 etype %d: %v", vector.etype, err)
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
			t.Fatalf("MIT CF2 etype %d: %v", vector.etype, err)
		}
		if !bytes.Equal(got, mitHex(t, vector.want)) {
			t.Errorf("MIT CF2 etype %d = %x, want %s", vector.etype, got, vector.want)
		}
	}
}

func TestMITNFoldVectors(t *testing.T) {
	vectors := []struct {
		input string
		bits  int
		want  string
	}{
		{"012345", 64, "be072631276b1955"},
		{"password", 56, "78a07b6caf85fa"},
		{"Rough Consensus, and Running Code", 64, "bb6ed30870b7f0e0"},
		{"password", 168, "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"},
		{"MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 192, "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b"},
		{"basch", 192, "1aab6b42964b98b21f8cde2d2448ba3455d7862c9731643f"},
		{"eichin", 192, "65696368696e4b732b4b1b43da1a5b995a58d2c6d0d2dcca"},
		{"sommerfeld", 192, "2f7a98557c6ee4abadf4e71192dd442bd4ff5325a5def75c"},
	}
	for _, vector := range vectors {
		got := nFold([]byte(vector.input), vector.bits)
		if !bytes.Equal(got, mitHex(t, vector.want)) {
			t.Errorf("MIT n-fold(%q, %d) = %x, want %s", vector.input, vector.bits, got, vector.want)
		}
	}
}

func TestMITStringToKeyVectors(t *testing.T) {
	vectors := []struct {
		etype int32
		salt  string
		iter  []byte
		want  string
	}{
		{EnctypeAES128SHA256, "\x10\xdf\x9d\xd7\x83\xe5\xbc\x8a\xce\xa1\x73\x0e\x74\x35\x5f\x61ATHENA.MIT.EDUraeburn", []byte{0, 0, 0x80, 0}, "089bca48b105ea6ea77ca5d2f39dc5e7"},
		{EnctypeAES256SHA384, "\x10\xdf\x9d\xd7\x83\xe5\xbc\x8a\xce\xa1\x73\x0e\x74\x35\x5f\x61ATHENA.MIT.EDUraeburn", []byte{0, 0, 0x80, 0}, "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467"},
	}
	for _, vector := range vectors {
		etype, err := NewRegistry().Get(vector.etype)
		if err != nil {
			t.Fatal(err)
		}
		got, err := etype.StringToKey([]byte("password"), []byte(vector.salt), vector.iter)
		if err != nil {
			t.Fatalf("MIT string-to-key etype %d: %v", vector.etype, err)
		}
		if !bytes.Equal(got, mitHex(t, vector.want)) {
			t.Errorf("MIT string-to-key etype %d = %x, want %s", vector.etype, got, vector.want)
		}
	}
}

func TestMITChecksumVectors(t *testing.T) {
	vectors := []struct {
		etype int32
		key   string
		usage uint32
		data  string
		want  string
	}{
		{EnctypeAES128SHA256, "3705d96080c17728a0e800eab6e0d23c", 2, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14", "d78367186643d67b411cba9139fc1dee"},
		{EnctypeAES256SHA384, "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52", 2, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14", "45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a"},
	}
	for _, vector := range vectors {
		etype, err := NewRegistry().Get(vector.etype)
		if err != nil {
			t.Fatal(err)
		}
		got, err := etype.Checksum(mitHex(t, vector.key), vector.usage, []byte(vector.data))
		if err != nil {
			t.Fatalf("MIT checksum etype %d: %v", vector.etype, err)
		}
		if !bytes.Equal(got, mitHex(t, vector.want)) {
			t.Errorf("MIT checksum etype %d = %x, want %s", vector.etype, got, vector.want)
		}
	}
}

func TestMITDeriveVectors(t *testing.T) {
	vectors := []struct {
		etype int32
		key   string
		want  string
	}{
		{EnctypeAES128SHA1, "42263c6e89f4fc28b8df68ee09799f15", "34280a382bc92769b2da2f9ef066854b"},
		{EnctypeAES256SHA1, "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161", "bfab388bdcb238e9f9c98d6a878304f04d30c82556375ac507a7a852790f4674"},
		{EnctypeAES128SHA256, "3705d96080c17728a0e800eab6e0d23c", "b31a018a48f54776f403e9a396325dc3"},
		{EnctypeAES256SHA384, "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52", "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d"},
	}
	for _, vector := range vectors {
		etype, err := NewRegistry().Get(vector.etype)
		if err != nil {
			t.Fatal(err)
		}
		aes, ok := etype.(aesEType)
		if !ok {
			t.Fatalf("etype %d is not AES", vector.etype)
		}
		kc, _, _, err := aes.deriveKeys(mitHex(t, vector.key), 2)
		if err != nil {
			t.Fatalf("MIT derive etype %d: %v", vector.etype, err)
		}
		if !bytes.Equal(kc, mitHex(t, vector.want)) {
			t.Errorf("MIT derive etype %d = %x, want %s", vector.etype, kc, vector.want)
		}
	}
}

func TestMITShortCiphertextSemantics(t *testing.T) {
	for _, id := range []int32{EnctypeAES128SHA1, EnctypeAES256SHA1, EnctypeAES128SHA256, EnctypeAES256SHA384, EnctypeCamellia128, EnctypeCamellia256} {
		etype, err := NewRegistry().Get(id)
		if err != nil {
			t.Fatal(err)
		}
		key := bytes.Repeat([]byte{0x42}, etype.KeySize())
		minimum := 16 + etype.ChecksumSize()
		for length := 0; length < minimum; length++ {
			if _, err := etype.Decrypt(key, 0, make([]byte, length)); err == nil {
				t.Fatalf("MIT short ciphertext etype %d length %d unexpectedly succeeded", id, length)
			}
		}
	}
}
