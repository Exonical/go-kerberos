package crypto

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRFC3962StringToKeyVectorsAreTranscribed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rfc", "rfc3962.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// Inputs and expected outputs below are copied from RFC 3962 Appendix B.
	// The implementation call is intentionally RED until the AES profiles land.
	vectors := []struct {
		iteration string
		key128    string
		key256    string
	}{
		{"Iteration count = 1", "42 26 3c 6e 89 f4 fc 28 b8 df 68 ee 09 79 9f 15", "fe 69 7b 52 bc 0d 3c e1 44 32 ba 03 6a 92 e6 5b"},
		{"Iteration count = 2", "c6 51 bf 29 e2 30 0a c2 7f a4 69 d6 93 bd da 13", "a2 e1 6d 16 b3 60 69 c1 35 d5 e9 d2 e2 5f 89 61"},
		{"Iteration count = 1200", "4c 01 cd 46 d6 32 d0 1e 6d be 23 0a 01 ed 64 2a", "55 a6 ac 74 0a d1 7b 48 46 94 10 51 e1 e8 b0 a7"},
		{"Iteration count = 5", "e9 b2 3d 52 27 37 47 dd 5c 35 cb 55 be 61 9d 8e", "97 a4 e7 86 be 20 d8 1a 38 2d 5e bc 96 d5 90 9c"},
		{"pass phrase equals block size", "59 d1 bb 78 9a 82 8b 1a a5 4e f9 c2 88 3f 69 ed", "89 ad ee 36 08 db 8b c7 1f 1b fb fe 45 94 86 b0"},
		{"pass phrase exceeds block size", "cb 80 05 dc 5f 90 17 9a 7f 02 10 4c 00 18 75 1d", "d7 8c 5c 9c b8 72 a8 c9 da d4 69 7f 0b b5 b2 d2"},
		{"Pass phrase = g-clef", "f1 49 c1 f2 e1 54 a7 34 52 d4 3e 7f e6 2a 56 e5", "4b 6d 98 39 f8 44 06 df 1f 09 cc 16 6d b4 b8 3c"},
	}
	text := string(data)
	for _, vector := range vectors {
		if !strings.Contains(text, vector.iteration) {
			t.Errorf("RFC 3962 Appendix B missing %q", vector.iteration)
		}
		if !strings.Contains(text, vector.key128) || !strings.Contains(text, vector.key256) {
			t.Errorf("RFC 3962 Appendix B expected key output missing for %q", vector.iteration)
		}
	}

	type vectorInput struct {
		name, password, salt string
		iterations           uint32
		key128, key256       string
	}
	cases := []vectorInput{
		{"iteration-1", "password", "ATHENA.MIT.EDUraeburn", 1,
			"42263c6e89f4fc28b8df68ee09799f15",
			"fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"},
		{"iteration-2", "password", "ATHENA.MIT.EDUraeburn", 2,
			"c651bf29e2300ac27fa469d693bdda13",
			"a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff"},
		{"iteration-1200", "password", "ATHENA.MIT.EDUraeburn", 1200,
			"4c01cd46d632d01e6dbe230a01ed642a",
			"55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"},
		{"iteration-5", "password", string([]byte{0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12}), 5,
			"e9b23d52273747dd5c35cb55be619d8e",
			"97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31"},
		{"equals-block", strings.Repeat("X", 64), "pass phrase equals block size", 1200,
			"59d1bb789a828b1aa54ef9c2883f69ed",
			"89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34"},
		{"exceeds-block", strings.Repeat("X", 65), "pass phrase exceeds block size", 1200,
			"cb8005dc5f90179a7f02104c0018751d",
			"d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b"},
		{"g-clef", string([]byte{0xf0, 0x9d, 0x84, 0x9e}), "EXAMPLE.COMpianist", 50,
			"f149c1f2e154a73452d43e7fe62a56e5",
			"4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e"},
	}
	registry := NewRegistry()
	for _, vector := range cases {
		var params [4]byte
		binary.BigEndian.PutUint32(params[:], vector.iterations)
		for _, profile := range []struct {
			id   int32
			want string
		}{
			{EnctypeAES128SHA1, vector.key128},
			{EnctypeAES256SHA1, vector.key256},
		} {
			t.Run(vector.name+"/"+strconv.Itoa(int(profile.id)), func(t *testing.T) {
				etype, err := registry.Get(profile.id)
				if err != nil {
					t.Fatal(err)
				}
				got, err := etype.StringToKey([]byte(vector.password), []byte(vector.salt), params[:])
				if err != nil {
					t.Fatalf("StringToKey: %v", err)
				}
				want, err := hex.DecodeString(profile.want)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != string(want) {
					t.Fatalf("key = %x, want %x", got, want)
				}
			})
		}
	}
}

func TestRFC6070PBKDF2VectorsAreTranscribed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rfc", "rfc6070.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, output := range []string{
		"0c 60 c8 0f 96 1f 0e 71",
		"ea 6c 01 4d c7 2d 6f 8c",
		"4b 00 79 01 b7 65 48 9a",
		"ee fe 3d 61 cd 4d a4 e4",
		"3d 2e ec 4f e4 1c 84 9b",
		"56 fa 6a a7 55 48 09 9d",
	} {
		if !strings.Contains(text, output) {
			t.Errorf("RFC 6070 expected output missing %q", output)
		}
	}
}

func TestRFC8009AppendixAVectorsAreTranscribed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rfc", "rfc8009.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, marker := range []string{
		"Sample results for string-to-key conversion",
		"Sample results for key derivation",
		"Sample encryptions",
		"Sample checksums",
		"Sample pseudorandom function",
		"08 9B CA 48 B1 05 EA 6E",
		"45 BD 80 6D BF 6A 83 3A",
		"D7 83 67 18 66 43 D6 7B",
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("RFC 8009 Appendix A missing %q", marker)
		}
	}
}

func TestRFCVectorSourcesPresent(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "rfc")
	for _, name := range []string{"rfc3961.txt", "rfc3962.txt", "rfc6070.txt", "rfc8009.txt"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read RFC source %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("RFC source %s is empty", name)
		}
	}
}

func TestRFC3962VectorCoverage(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rfc", "rfc3962.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, marker := range []string{
		"Iteration count = 1", "Iteration count = 2", "Iteration count = 1200",
		"Iteration count = 5", "pass phrase equals block size",
		"pass phrase exceeds block size", "Pass phrase = g-clef",
		"Some test vectors for CBC with ciphertext stealing",
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("RFC 3962 Appendix B missing marker %q", marker)
		}
	}
	// RFC 3961 sections 5.1 and 5.2 define DK/DR behavior but do not provide
	// AES vectors; the RFC 3962 and RFC 8009 appendices are authoritative here.
}
