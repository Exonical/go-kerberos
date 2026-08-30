package pkinit

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
)

func FuzzParseAuthPack(f *testing.F) {
	seed := authPackDER(PKAuthenticator{
		Cusec:      1234,
		CTime:      time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Nonce:      42,
		PAChecksum: []byte{0xaa, 0xbb},
	}, derSeq(derInt(7)))
	f.Add(seed)
	addMITFuzzSeeds(f, "FuzzParseAuthPack")
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseAuthPack(input)
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

func FuzzVerifyPAASReq(f *testing.F) {
	cert, key := testCertificate(f)
	body := []byte{0x30, 0x02, 0x05, 0x00}
	private := big.NewInt(2)
	public := new(big.Int).Exp(group14G, private, group14P)
	pa, err := (&Client{Certificate: cert, Signer: key, Private: private, Public: public}).BuildPAASReq(body, time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), 42)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pa.PADataValue)
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = VerifyPAASReq(input, body)
	})
}

func FuzzVerifyPAASRep(f *testing.F) {
	cert, key := testCertificate(f)
	content := derSeq(
		derExplicit(0, derBitString(derIntBig(big.NewInt(2))[2:])),
		derExplicit(1, derInt(42)),
	)
	cms, err := signCMS(content, cert, key)
	if err != nil {
		f.Fatal(err)
	}
	seed := der(0xa0, derSeq(der(0x80, cms)))
	f.Add(seed)
	client := &Client{Private: big.NewInt(2)}
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = client.VerifyPAASRep(input, nil, crypto.EnctypeAES256SHA1, 42)
	})
}
