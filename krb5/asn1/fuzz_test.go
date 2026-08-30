package asn1

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func FuzzASN1Decode(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x01, 0x00})
	addMITFuzzSeeds(f, "FuzzASN1Decode")
	f.Fuzz(func(t *testing.T, input []byte) {
		var value protocol.PrincipalName
		_, _ = Marshal(value)
		_ = Unmarshal(input, &value)
	})
}

func FuzzKRBError(f *testing.F) {
	f.Add([]byte{0x7e, 0x00})
	addMITFuzzSeeds(f, "FuzzKRBError")
	f.Fuzz(func(t *testing.T, input []byte) {
		var value protocol.KRBError
		_ = Unmarshal(input, &value)
	})
}

func FuzzASRep(f *testing.F) {
	f.Add([]byte{0x6b, 0x00})
	addMITFuzzSeeds(f, "FuzzASRep")
	f.Fuzz(func(t *testing.T, input []byte) {
		var value protocol.ASRep
		_ = Unmarshal(input, &value)
	})
}

func FuzzTGSRep(f *testing.F) {
	f.Add([]byte{0x6d, 0x00})
	addMITFuzzSeeds(f, "FuzzTGSRep")
	f.Fuzz(func(t *testing.T, input []byte) {
		var value protocol.TGSRep
		_ = Unmarshal(input, &value)
	})
}

func FuzzAPReq(f *testing.F) {
	f.Add([]byte{0x6e, 0x00})
	addMITFuzzSeeds(f, "FuzzAPReq")
	f.Fuzz(func(t *testing.T, input []byte) {
		var value protocol.APReq
		_ = Unmarshal(input, &value)
	})
}

func addMITFuzzSeeds(f *testing.F, target string) {
	dir := filepath.Join("..", "..", "testdata", "mit", "fuzz", target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatalf("read MIT fuzz seeds: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			f.Fatalf("read MIT fuzz seed %s: %v", entry.Name(), err)
		}
		f.Add(data)
	}
}
