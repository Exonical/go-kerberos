package pkinit

import (
	"math/big"
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
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseAuthPack(input)
	})
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
