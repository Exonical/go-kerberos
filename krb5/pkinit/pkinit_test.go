package pkinit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
)

func TestOctetString2KeyRFC4556Vector(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		enctype int32
		want    string
	}{
		{"set1", make([]byte, 256), crypto.EnctypeAES256SHA1, "5ee50d675c809fe59e4a7762c54b65837547eafb159bd8cdc75ffca5911e4c41"},
		{"set2", make([]byte, 128), crypto.EnctypeAES256SHA1, "acf7707c08973ddfdb27cd361442ccfba355c8884cb472f37da636d07d56787e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := octetString2Key(tc.input, tc.enctype)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(key); got != tc.want {
				t.Fatalf("octetstring2key = %s, want %s", got, tc.want)
			}
		})
	}
}
func TestAuthPackGoldenDER(t *testing.T) {
	got := authPackDER(PKAuthenticator{
		Cusec: 1234, CTime: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), Nonce: 42,
		PAChecksum: []byte{0xaa, 0xbb},
	}, derSeq(derInt(7)))
	const want = "302fa0263024a004020204d2a111180f32303234303130323033303430355aa20302012aa3040402aabba1053003020107"
	if gotHex := hex.EncodeToString(got); gotHex != want {
		t.Fatalf("AuthPack DER = %s, want %s", gotHex, want)
	}
}

func testCertificate(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestCMSRoundTripAndTamperRejection(t *testing.T) {
	cert, key := testCertificate(t)
	client, err := NewClient(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pa, err := client.BuildPAASReq([]byte{0x30, 0x00}, time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), 42)
	if err != nil {
		t.Fatal(err)
	}
	content, _, err := verifyCMSChoice(pa.PADataValue, nil)
	if err != nil {
		t.Fatalf("verify CMS: %v", err)
	}
	if len(content) == 0 {
		t.Fatal("empty AuthPack")
	}
	tampered := append([]byte(nil), pa.PADataValue...)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := verifyCMSChoice(tampered, nil); err == nil {
		t.Fatal("tampered CMS accepted")
	}
}

func TestDHSharedKeyRejectsInvalidPublicValue(t *testing.T) {
	cert, key := testCertificate(t)
	client, err := NewClient(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SharedKey([]byte{0}, crypto.EnctypeAES256SHA1); err == nil {
		t.Fatal("zero DH public value accepted")
	}
	if _, err := client.SharedKey(group14P.Bytes(), crypto.EnctypeAES256SHA1); err == nil {
		t.Fatal("out-of-range DH public value accepted")
	}
}

func TestPAASReqChecksumAndNonce(t *testing.T) {
	cert, key := testCertificate(t)
	body := []byte{0x30, 0x02, 0x05, 0x00}
	pa, _, err := BuildPAASReq(body, time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), 77, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := VerifyPAASReq(pa.PADataValue, body)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Nonce != 77 {
		t.Fatalf("nonce = %d, want 77", auth.Nonce)
	}
	if _, err := VerifyPAASReq(pa.PADataValue, []byte{0x30, 0x00}); err == nil {
		t.Fatal("bad paChecksum accepted")
	}
	if _, err := VerifyPAASReq(append(append([]byte(nil), pa.PADataValue...), 0), body); err == nil {
		t.Fatal("trailing PA-PK-AS-REQ data accepted")
	}
}

func TestValidateKDCSAN(t *testing.T) {
	realm := "PKINIT.TEST"
	principal := derSeq(
		derExplicit(0, der(0x1b, []byte(realm))),
		derExplicit(1, derSeq(
			derExplicit(0, derInt(2)),
			derExplicit(1, derSeq(
				der(0x1b, []byte("krbtgt")),
				der(0x1b, []byte(realm)),
			)),
		)),
	)
	otherName := der(0xa0, append(
		derOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}),
		der(0xa0, principal)...,
	))
	cert := &x509.Certificate{Extensions: []pkix.Extension{{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
		Value: derSeq(otherName),
	}}}
	if err := validateKDCSAN(cert); err != nil {
		t.Fatalf("validate KDC SAN: %v", err)
	}

	invalid := *cert
	invalid.Extensions = []pkix.Extension{{
		Id: asn1.ObjectIdentifier{2, 5, 29, 17},
		Value: derSeq(der(0xa0, append(
			derOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}),
			der(0xa0, derSeq(
				derExplicit(0, der(0x1b, []byte(realm))),
				derExplicit(1, derSeq(
					derExplicit(0, derInt(2)),
					derExplicit(1, derSeq(der(0x1b, []byte("alice")))),
				)),
			))...,
		))),
	}}
	if err := validateKDCSAN(&invalid); err == nil {
		t.Fatal("non-krbtgt KDC SAN accepted")
	}
}

func TestValidateKDCEKU(t *testing.T) {
	cert := &x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 2, 3, 5},
	}}
	if err := validateKDC(nil, cert); err == nil {
		t.Fatal("KDC certificate without SAN accepted")
	}
	cert.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3}}
	if err := validateKDC(nil, cert); err == nil {
		t.Fatal("certificate with incorrect EKU accepted")
	}
}
