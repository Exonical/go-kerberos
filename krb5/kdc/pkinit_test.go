package kdc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestServerPKINITASExchange(t *testing.T) {
	now := time.Unix(2000001000, 0).UTC()
	server, kclient := testServer(t, now)
	ca, caKey, clientCert, clientKey := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	server.PKINITClientCAs = roots

	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	credentials, err := kclient.ASExchangePKINIT(context.Background(), user, clientCert, clientKey, roots)
	if err != nil {
		t.Fatalf("PKINIT AS exchange: %v", err)
	}
	if !samePrincipal(credentials.Client, user) {
		t.Fatalf("PKINIT client = %v, want %v", credentials.Client, user)
	}
}

func TestServerPKINITRejectsUntrustedClient(t *testing.T) {
	now := time.Unix(2000001010, 0).UTC()
	server, kclient := testServer(t, now)
	ca, caKey, _, _ := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)
	kdcCert, kdcKey := makePKINITTestCertificateWithCA(t, ca, caKey, "krbtgt", "TEST.REALM", true)
	server.PKINITCertificate = kdcCert
	server.PKINITSigner = kdcKey
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.PKINITClientCAs = roots
	_, _, clientCert, clientKey := makePKINITTestCertificate(t, "alice", "TEST.REALM", false)

	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	_, err := kclient.ASExchangePKINIT(context.Background(), user, clientCert, clientKey, roots)
	if err == nil || !hasKRBCode(err, kdcErrClientNotTrusted) {
		t.Fatalf("untrusted PKINIT client error = %v, want KDC error %d", err, kdcErrClientNotTrusted)
	}
}

func makePKINITTestCertificate(t *testing.T, component, realm string, kdc bool) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, *rsa.PrivateKey) {
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
	cert, key := makePKINITTestCertificateWithCA(t, ca, caKey, component, realm, kdc)
	return ca, caKey, cert, key
}

func makePKINITTestCertificateWithCA(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, component, realm string, kdc bool) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	components := []string{component}
	nameType := int64(1)
	eku := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4}
	if kdc {
		components = append(components, realm)
		nameType = 2
		eku = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5}
	}
	nameParts := make([][]byte, 0, len(components))
	for _, value := range components {
		nameParts = append(nameParts, testGeneralString(value))
	}
	principalDER := testSequence(
		testExplicit(0, testGeneralString(realm)),
		testExplicit(1, testSequence(
			testExplicit(0, testInteger(nameType)),
			testExplicit(1, testSequence(nameParts...)),
		)),
	)
	otherName := testContext(0, append(
		testOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}),
		testContext(0, principalDER)...,
	))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: component},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{eku},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: testSequence(otherName)}},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func testTLV(tag byte, content []byte) []byte {
	return append(append([]byte{tag, byte(len(content))}, content...), nil...)
}

func testSequence(values ...[]byte) []byte {
	var content []byte
	for _, value := range values {
		content = append(content, value...)
	}
	return testTLV(0x30, content)
}

func testExplicit(tag int, value []byte) []byte { return testTLV(0xa0|byte(tag), value) }
func testContext(tag int, value []byte) []byte  { return testTLV(0xa0|byte(tag), value) }
func testGeneralString(value string) []byte     { return testTLV(0x1b, []byte(value)) }
func testInteger(value int64) []byte            { return testTLV(0x02, []byte{byte(value)}) }
func testOID(value asn1.ObjectIdentifier) []byte {
	encoded, _ := asn1.Marshal(value)
	return encoded
}
