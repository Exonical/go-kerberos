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

func TestCamelliaEncryptionVectors(t *testing.T) {
	tests := []struct {
		name       string
		etype      int32
		key        string
		confounder string
		usage      uint32
		plaintext  string
		ciphertext string
	}{
		{
			name:       "128-empty",
			etype:      EnctypeCamellia128,
			key:        "1dc46a8d763f4f93742bcba3387576c3",
			confounder: "b69822a19a6b09c0ebc8557d1f1b6c0a",
			usage:      0,
			plaintext:  "",
			ciphertext: "c466f1871069921edb7c6fde244a52db0ba10edc197bdb8006658ca3ccce6eb8",
		},
		{
			name:       "128-short",
			etype:      EnctypeCamellia128,
			key:        "5027bc231d0f3a9d23333f1ca6fdbe7c",
			confounder: "6f2fc3c2a166fd8898967a83de9596d9",
			usage:      1,
			plaintext:  "1",
			ciphertext: "842d21fd950311c0dd464a3f4be8d6da88a56d559c9b47d3f9a85067af661559b8",
		},
		{
			name:       "128-partial",
			etype:      EnctypeCamellia128,
			key:        "a1bb61e805f9ba6dde8fdbddc05cdea0",
			confounder: "a5b4a71e077aeef93c8763c18fdb1f10",
			usage:      2,
			plaintext:  "9 bytesss",
			ciphertext: "619ff072e36286ff0a28deb3a352ec0d0edf5c5160d663c901758ccf9d1ed33d71db8f23aabf8348a0",
		},
		{
			name:       "128-long",
			etype:      EnctypeCamellia128,
			key:        "7824f8c16f83ff354c6bf7515b973f43",
			confounder: "ca7a7ab4be192dabd603506db19c39e2",
			usage:      4,
			plaintext:  "30 bytes bytes bytes bytes byt",
			ciphertext: "a26a3905a4ffd5816b7b1e27380d08090c8ec1f304496e1abdcd2bdcd1dffc660989e117a713ddbb57a4146c1587cba4356665591d2240282f5842b105a5",
		},
		{
			name:       "128-13-bytes",
			etype:      EnctypeCamellia128,
			key:        "2ca27a5faf5532244506434e1cef6676",
			confounder: "19fee40d810c524b5b22f01874c693da",
			usage:      3,
			plaintext:  "13 bytes byte",
			ciphertext: "b8eca3167ae6315512e59f98a7c500205e5f63ff3bb389af1c41a21d640d8615c9ed3fbeb05ab6acb67689b5ea",
		},
		{
			name:       "256-empty",
			etype:      EnctypeCamellia256,
			key:        "b61c86cc4e5d2757545ad423399fb7031ecab913cbb900bd7a3c6dd8bf92015b",
			confounder: "3cbbd2b45917941067f96599bb98926c",
			usage:      0,
			plaintext:  "",
			ciphertext: "03886d03310b47a6d8f06d7b94d1dd837ecce315ef652aff620859d94a259266",
		},
		{
			name:       "256-short",
			etype:      EnctypeCamellia256,
			key:        "1b97fe0a190e2021eb30753e1b6e1e77b0754b1d684610355864104963463833",
			confounder: "def487fcebe6de6346d4da4521bba2d2",
			usage:      1,
			plaintext:  "1",
			ciphertext: "2c9c1570133c99bf6a34bc1b0212002fd194338749db4135497a347cfcd9d18a12",
		},
		{
			name:       "256-partial",
			etype:      EnctypeCamellia256,
			key:        "32164c5b434d1d1538e4cfd9be8040fe8c4ac7acc4b93d3314d2133668147a05",
			confounder: "ad4ff904d34e555384b14100fc465f88",
			usage:      2,
			plaintext:  "9 bytesss",
			ciphertext: "9c6de75f812de7ed0d28b2963557a115640998275b0af5152709913ff52a2a9c8e63b872f92e64c839",
		},
		{
			name:       "256-long",
			etype:      EnctypeCamellia256,
			key:        "ccfcd349bf4c6677e86e4b02b8eab924a546ac731cf9bf6989b996e7d6bfbba7",
			confounder: "644def38da35007275878d216855e228",
			usage:      4,
			plaintext:  "30 bytes bytes bytes bytes byt",
			ciphertext: "0e44680985855f2d1f1812529ca83bfd8e349de6fd9ada0baaa048d68e265febf34ad1255a344999ad37146887a6c6845731ac7f46376a0504cd06571474",
		},
		{
			name:       "256-13-bytes",
			etype:      EnctypeCamellia256,
			key:        "b038b132cd8e06612267fab7170066d88aeccba0b744bfc60dc89bca182d0715",
			confounder: "cf9bca6df1144e0c0af9b8f34c90d514",
			usage:      3,
			plaintext:  "13 bytes byte",
			ciphertext: "eeec85a9813cdc536772ab9b42defc5706f726e975dde05a87eb5406ea324ca185c9986b42aabe794b84821bee",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := SetRandomSource(bytes.NewReader(mustHex(t, tt.confounder)))
			defer restore()
			etype, err := NewRegistry().Get(tt.etype)
			if err != nil {
				t.Fatal(err)
			}
			got, err := etype.Encrypt(mustHex(t, tt.key), tt.usage, []byte(tt.plaintext))
			if err != nil {
				t.Fatal(err)
			}
			want := mustHex(t, tt.ciphertext)
			if !bytes.Equal(got, want) {
				t.Fatalf("ciphertext = %x, want %x", got, want)
			}
		})
	}
}
