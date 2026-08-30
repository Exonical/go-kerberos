package pkinit

import (
	"bytes"
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
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestSupportedKDFAlgorithms(t *testing.T) {
	got := SupportedKDFAlgorithmIDs()
	if len(got) != 3 {
		t.Fatalf("supported KDF count = %d, want 3", len(got))
	}
	want := []string{"1.3.6.1.5.2.3.6.2", "1.3.6.1.5.2.3.6.1", "1.3.6.1.5.2.3.6.3"}
	for i, id := range got {
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(der(0x06, id), &oid); err != nil {
			t.Fatalf("KDF %d OID: %v", i, err)
		}
		if oid.String() != want[i] {
			t.Errorf("KDF %d = %s, want %s", i, oid, want[i])
		}
	}
}

func TestPickKDFAlgorithmUsesServerPreference(t *testing.T) {
	got := PickKDFAlgorithm([][]byte{KDFSHA512, KDFSHA1, KDFSHA256})
	if !bytes.Equal(got, KDFSHA256) {
		t.Fatalf("selected KDF = %x, want SHA-256 %x", got, KDFSHA256)
	}
	if got := PickKDFAlgorithm([][]byte{[]byte{0x01}}); got != nil {
		t.Fatalf("unsupported selected KDF = %x, want nil", got)
	}
}

func TestAuthPackSupportedKDFWireEncoding(t *testing.T) {
	auth := PKAuthenticator{
		Cusec: 7,
		CTime: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Nonce: 42,
		PAChecksum: []byte{
			0xaa, 0xbb,
		},
	}
	public := []byte{0x01, 0x02}
	data := authPackDER(auth, public, SupportedKDFAlgorithmIDs())
	fields, err := sequenceFields(data)
	if err != nil || len(fields) != 3 {
		t.Fatalf("AuthPack fields = %d, err=%v; want authenticator, public value, supported KDFs", len(fields), err)
	}
	if fields[2][0] != 0xa4 {
		t.Fatalf("supportedKDFs tag = 0x%x, want 0xa4", fields[2][0])
	}
	items, err := sequenceFields(mustContent(fields[2]))
	if err != nil || len(items) != 3 {
		t.Fatalf("supportedKDFs items = %d, err=%v; want 3", len(items), err)
	}
	for i, item := range items {
		itemFields, err := sequenceFields(item)
		if err != nil || len(itemFields) != 1 || itemFields[0][0] != 0xa0 {
			t.Fatalf("KDF item %d malformed: err=%v", i, err)
		}
		oidDER, err := tlvContent(itemFields[0])
		if err != nil || len(oidDER) == 0 || oidDER[0] != 0x06 {
			t.Fatalf("KDF item %d OID malformed: err=%v", i, err)
		}
	}
	_, _, got, err := parseAuthPack(data)
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		if !bytes.Equal(got[i], SupportedKDFAlgorithmIDs()[i]) {
			t.Fatalf("decoded KDF %d = %x, want %x", i, got[i], SupportedKDFAlgorithmIDs()[i])
		}
	}
}

func TestParseAuthPackPreservesOptionalCMSAndDHNonce(t *testing.T) {
	auth := PKAuthenticator{
		Cusec: 1, CTime: time.Unix(1700000000, 0).UTC(), Nonce: 2,
		PAChecksum: []byte("checksum"),
	}
	base := authPackDER(auth, nil)
	content := mustContent(base)
	cms := derSeq(derSeq(derOID(asn1.ObjectIdentifier{1, 2, 3}), derNull()))
	dhNonce := []byte{4, 5, 6, 7}
	content = append(content, derExplicit(2, cms)...)
	content = append(content, derExplicit(3, derOctet(dhNonce))...)
	pack := der(0x30, content)
	parsed, err := ParseAuthPack(pack)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.SupportedCMSTypes) != 1 ||
		!bytes.Equal(parsed.SupportedCMSTypes[0], cms[2:]) {
		t.Fatalf("supported CMS types = %x, want %x", parsed.SupportedCMSTypes, cms[2:])
	}
	if !bytes.Equal(parsed.DHNonce, dhNonce) {
		t.Fatalf("DH nonce = %x, want %x", parsed.DHNonce, dhNonce)
	}
}

func TestAuthPackFreshnessTokenWireEncoding(t *testing.T) {
	token := []byte{0xde, 0xad, 0xbe, 0xef}
	auth := PKAuthenticator{
		Cusec: 7, CTime: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Nonce: 42, PAChecksum: []byte{0xaa, 0xbb}, FreshnessToken: token,
	}
	data := authPackDER(auth, []byte{1})
	fields, err := sequenceFields(data)
	if err != nil || len(fields) != 2 {
		t.Fatalf("AuthPack fields = %d, err=%v; want 2", len(fields), err)
	}
	authFields, err := sequenceFields(mustContent(fields[0]))
	if err != nil || len(authFields) != 5 || authFields[4][0] != 0xa4 {
		t.Fatalf("PKAuthenticator fields = %d, err=%v; want freshness [4]", len(authFields), err)
	}
	encodedToken, err := tlvContent(authFields[4])
	if err != nil {
		t.Fatal(err)
	}
	encodedToken, err = tlvContent(encodedToken)
	if err != nil || !bytes.Equal(encodedToken, token) {
		t.Fatalf("freshness token = %x, err=%v; want %x", encodedToken, err, token)
	}
	authDecoded, _, _, err := parseAuthPack(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authDecoded.FreshnessToken, token) {
		t.Fatalf("decoded freshness token = %x, want %x", authDecoded.FreshnessToken, token)
	}
}

func TestPKINITKDFMITVectors(t *testing.T) {
	secret := make([]byte, 256)
	u := principal.Principal{Realm: "SU.SE", NameType: principal.NTPrincipal, Components: []string{"lha"}}
	v := principal.Principal{Realm: "SU.SE", NameType: principal.NTPrincipal, Components: []string{"krbtgt", "SU.SE"}}
	asReq := bytes.Repeat([]byte{0xaa}, 10)
	pkAsRep := bytes.Repeat([]byte{0xbb}, 9)
	vectors := []struct {
		name string
		oid  []byte
		want string
	}{
		{"SHA-1/AES", KDFSHA1, "e6ab38c9413e035bb079201ed0b6b73d8d49a814a737c04ee6649614206f73ad"},
		{"SHA-256/AES", KDFSHA256, "77ef4e48c420ae3fec75109d7981697eed5d295c90c62564f7bfd101fa9bc1d5"},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			got, err := DeriveKey(secret, vector.oid, u, v, crypto.EnctypeAES256SHA1, asReq, pkAsRep)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(vector.want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("derived key = %x, want %x", got, want)
			}
		})
	}
}

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

func testCertificate(t testing.TB) (*x509.Certificate, *rsa.PrivateKey) {
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

func TestCMSRejectsSignerWithoutSignedAttributes(t *testing.T) {
	cert, key := testCertificate(t)
	content := []byte{0x30, 0x00}
	cms, err := signCMS(content, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := sequenceFields(cms)
	if err != nil || len(outer) != 2 {
		t.Fatalf("CMS outer fields: %v", err)
	}
	signedData, err := sequenceFields(mustContent(outer[1]))
	if err != nil {
		t.Fatal(err)
	}
	signerInfos, err := collectionFields(signedData[4])
	if err != nil || len(signerInfos) != 1 {
		t.Fatalf("signer infos: %v", err)
	}
	signer, err := sequenceFields(signerInfos[0])
	if err != nil {
		t.Fatal(err)
	}
	withoutAttrs := derSeq(signer[0], signer[1], signer[2], signer[4], signer[5])
	signedData[4] = derSet(withoutAttrs)
	malformed := derSeq(
		derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}),
		derExplicit(0, derSeq(signedData...)),
	)
	if _, _, err := verifyCMSChoice(malformed, nil); err == nil {
		t.Fatal("CMS signer without signed attributes accepted")
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
	if _, err := client.SharedKey([]byte{1}, crypto.EnctypeAES256SHA1); err == nil {
		t.Fatal("one DH public value accepted")
	}
	pMinusOne := new(big.Int).Sub(group14P, big.NewInt(1))
	if _, err := client.SharedKey(pMinusOne.Bytes(), crypto.EnctypeAES256SHA1); err == nil {
		t.Fatal("order-two DH public value accepted")
	}
	if _, err := client.SharedKey(group14P.Bytes(), crypto.EnctypeAES256SHA1); err == nil {
		t.Fatal("out-of-range DH public value accepted")
	}
}

func TestBuildPAASRepRejectsDegenerateClientPublicValues(t *testing.T) {
	kdcCert, kdcKey := testPKINITCertificate(t, "krbtgt", "PKINIT.TEST",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5})
	pMinusOne := new(big.Int).Sub(group14P, big.NewInt(1))
	for _, value := range []*big.Int{big.NewInt(1), pMinusOne} {
		if _, _, err := BuildPAASRep(marshalSPKI(value),
			crypto.EnctypeAES256SHA1, 42, kdcCert, kdcKey); err == nil {
			t.Fatalf("client DH public value %v accepted", value)
		}
	}
}

func TestVerifyPAASRepRejectsDegenerateServerPublicValues(t *testing.T) {
	clientCert, clientKey := testCertificate(t)
	client, err := NewClient(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	kdcCert, kdcKey := testPKINITCertificate(t, "krbtgt", "PKINIT.TEST",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5})
	pMinusOne := new(big.Int).Sub(group14P, big.NewInt(1))
	for _, value := range []*big.Int{big.NewInt(1), pMinusOne} {
		dhInfo := derSeq(
			derExplicit(0, derBitString(derIntBig(value))),
			derExplicit(1, derInt(42)),
		)
		signed, err := signCMSWithContentType(dhInfo,
			asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}, kdcCert, kdcKey)
		if err != nil {
			t.Fatal(err)
		}
		data := derExplicit(0, derSeq(derImplicitOctet(0, signed)))
		if _, err := client.VerifyPAASRep(data, nil,
			crypto.EnctypeAES256SHA1, 42); err == nil {
			t.Fatalf("server DH public value %v accepted", value)
		}
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

func TestLegacyPAASReqDoesNotAdvertiseKDFs(t *testing.T) {
	cert, key := testCertificate(t)
	client, err := NewClient(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte{0x30, 0x02, 0x05, 0x00}
	legacy, err := client.BuildPAASReq(body, time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), 77)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPAASReqForKDC(legacy.PADataValue, body)
	if err != nil {
		t.Fatal(err)
	}
	if verified.SupportedKDFs != nil {
		t.Fatalf("legacy request advertised supported KDFs: %v", verified.SupportedKDFs)
	}
	clientName := principal.Principal{Realm: "PKINIT.TEST", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	serverName := principal.Principal{Realm: "PKINIT.TEST", NameType: principal.NTSrvInstance, Components: []string{"krbtgt", "PKINIT.TEST"}}
	agile, err := client.BuildPAASReqForPrincipals(body, time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), 77, clientName, serverName)
	if err != nil {
		t.Fatal(err)
	}
	verified, err = VerifyPAASReqForKDC(agile.PADataValue, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.SupportedKDFs) != len(SupportedKDFAlgorithmIDs()) {
		t.Fatalf("context-aware request KDF count = %d, want %d", len(verified.SupportedKDFs), len(SupportedKDFAlgorithmIDs()))
	}
}

func TestAnonymousPAASReqUnsignedCMS(t *testing.T) {
	body := []byte{0x30, 0x00}
	pa, client, err := BuildAnonymousPAASReq(body,
		time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), 77)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPAASReqForKDC(pa.PADataValue, body)
	if err != nil {
		t.Fatalf("verify anonymous request: %v", err)
	}
	if verified.Signed || verified.Certificate != nil {
		t.Fatal("anonymous request unexpectedly signed")
	}
	if len(verified.PublicValue) == 0 || client.Private == nil {
		t.Fatal("anonymous request omitted DH value")
	}
	tampered := append([]byte(nil), pa.PADataValue...)
	tampered[len(tampered)-1] ^= 1
	if _, err := VerifyPAASReqForKDC(tampered, body); err == nil {
		t.Fatal("tampered anonymous CMS accepted")
	}
}

func TestBuildPAASRepRoundTrip(t *testing.T) {
	clientCert, clientKey := testCertificate(t)
	client, err := NewClient(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	kdcCert, kdcKey := testPKINITCertificate(t, "krbtgt", "PKINIT.TEST", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5})
	pa, replyKey, err := BuildPAASRep(marshalSPKI(client.Public), crypto.EnctypeAES256SHA1, 42, kdcCert, kdcKey)
	if err != nil {
		t.Fatal(err)
	}
	if pa.PADataType != PADataASRep || len(replyKey) == 0 {
		t.Fatalf("PA-PK-AS-REP = %#v, key length %d", pa, len(replyKey))
	}
	derivedKey, err := client.VerifyPAASRep(pa.PADataValue, nil, crypto.EnctypeAES256SHA1, 42)
	if err != nil {
		t.Fatal(err)
	}
	if string(derivedKey) != string(replyKey) {
		t.Fatal("client and KDC DH reply keys differ")
	}
}

func TestValidateClientCertificate(t *testing.T) {
	cert, _, roots := testPKINITCertificateWithCA(t, "alice", "PKINIT.TEST", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4})
	if err := ValidateClientCertificate(cert, roots, "PKINIT.TEST", []string{"alice"}); err != nil {
		t.Fatalf("validate client certificate: %v", err)
	}
	if err := ValidateClientCertificate(cert, roots, "PKINIT.TEST", []string{"bob"}); err == nil {
		t.Fatal("client SAN mismatch accepted")
	}
	invalid := *cert
	invalid.UnknownExtKeyUsage = nil
	if err := ValidateClientCertificate(&invalid, roots, "PKINIT.TEST", []string{"alice"}); err == nil {
		t.Fatal("client certificate without EKU accepted")
	}
	otherCA, _, _ := testPKINITCertificateWithCA(t, "alice", "PKINIT.TEST", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4})
	if err := ValidateClientCertificate(otherCA, roots, "PKINIT.TEST", []string{"alice"}); err == nil {
		t.Fatal("untrusted client certificate accepted")
	}
}

func testPKINITCertificate(t testing.TB, component, realm string, eku asn1.ObjectIdentifier) (*x509.Certificate, *rsa.PrivateKey) {
	cert, key, _ := testPKINITCertificateWithCA(t, component, realm, eku)
	return cert, key
}

func testPKINITCertificateWithCA(t testing.TB, component, realm string, eku asn1.ObjectIdentifier) (*x509.Certificate, *rsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "PKINIT CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nameType := int64(1)
	components := []string{component}
	if component == "krbtgt" {
		nameType = 2
		components = []string{component, realm}
	}
	nameParts := make([][]byte, 0, len(components))
	for _, value := range components {
		nameParts = append(nameParts, der(0x1b, []byte(value)))
	}
	principalDER := derSeq(
		derExplicit(0, der(0x1b, []byte(realm))),
		derExplicit(1, derSeq(
			derExplicit(0, derInt(nameType)),
			derExplicit(1, derSeq(nameParts...)),
		)),
	)
	otherName := der(0xa0, append(
		derOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}),
		der(0xa0, principalDER)...,
	))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: component},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{eku},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: derSeq(otherName)}},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return cert, key, roots
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
	cert.UnknownExtKeyUsage = nil
	if err := validateKDC(nil, cert); err == nil {
		t.Fatal("certificate without EKU accepted")
	}
}
