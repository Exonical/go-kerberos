package kdc

import (
	"crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

type certAuthTestModule struct {
	decision   CertAuthDecision
	indicators []string
	err        error
}

func (m certAuthTestModule) Authorize(*x509.Certificate, principal.Principal,
	*kdb.PrincipalRecord) (CertAuthDecision, []string, error) {
	return m.decision, m.indicators, m.err
}

func TestCertAuthChainSemantics(t *testing.T) {
	client := principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}}
	cert := &x509.Certificate{}
	entry := &kdb.PrincipalRecord{}
	tests := []struct {
		name       string
		modules    []CertAuthModule
		accepted   bool
		hwauth     bool
		indicators []string
		wantCode   int32
		wantError  bool
	}{
		{"pass does not authorize", []CertAuthModule{
			certAuthTestModule{decision: CertAuthPass, indicators: []string{"pass"}},
		}, false, false, []string{"pass"}, 75, true},
		{"accept authorizes", []CertAuthModule{
			certAuthTestModule{decision: CertAuthPass, indicators: []string{"one"}},
			certAuthTestModule{decision: CertAuthAccept, indicators: []string{"two"}},
		}, true, false, []string{"one", "two"}, 0, false},
		{"hardware accept", []CertAuthModule{
			certAuthTestModule{decision: CertAuthHWAuth, indicators: []string{"hardware"}},
		}, true, true, []string{"hardware"}, 0, false},
		{"hardware pass still needs accept", []CertAuthModule{
			certAuthTestModule{decision: CertAuthHWAuthPass, indicators: []string{"hardware"}},
		}, false, true, []string{"hardware"}, 75, true},
		{"module error rejects", []CertAuthModule{
			certAuthTestModule{decision: CertAuthAccept, indicators: []string{"one"}},
			certAuthTestModule{err: &CertAuthError{Code: 89, Err: errors.New("mismatch")}},
		}, false, false, []string{"one"}, 89, true},
		{"invalid decision rejects", []CertAuthModule{
			certAuthTestModule{decision: CertAuthDecision(99)},
		}, false, false, nil, 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accepted, hwauth, gotIndicators, err := authorizeCertificateModules(
				test.modules, cert, client, entry)
			if !test.wantError && err != nil {
				t.Fatalf("authorizeCertificate error = %v", err)
			}
			if test.wantError && err == nil {
				t.Fatal("authorizeCertificate unexpectedly succeeded")
			}
			if test.wantCode != 0 {
				var certErr *CertAuthError
				if !errors.As(err, &certErr) || certErr.Code != test.wantCode {
					t.Fatalf("error = %v, want certauth code %d", err, test.wantCode)
				}
			}
			if accepted != test.accepted || hwauth != test.hwauth {
				t.Fatalf("accepted=%v hwauth=%v, want %v/%v",
					accepted, hwauth, test.accepted, test.hwauth)
			}
			if len(gotIndicators) != len(test.indicators) {
				t.Fatalf("indicators = %v, want %v", gotIndicators, test.indicators)
			}
			for i := range gotIndicators {
				if gotIndicators[i] != test.indicators[i] {
					t.Fatalf("indicators = %v, want %v", gotIndicators, test.indicators)
				}
			}
		})
	}
}

func TestMatchCertificateMITComponents(t *testing.T) {
	cert := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "alice", Organization: []string{"Example"}},
		Issuer:      pkix.Name{CommonName: "Example CA"},
		DNSNames:    []string{"alice.example.test"},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	tests := []struct {
		rule string
		want bool
	}{
		{"<SUBJECT>CN=alice", true},
		{"<ISSUER>CN=Example CA", true},
		{"<SAN>alice\\.example", false},
		{"<KU>digitalSignature,keyEncipherment", true},
		{"<EKU>clientAuth", true},
		{"<SUBJECT>CN=alice<KU>keyEncipherment", true},
		{"&&<SUBJECT>CN=alice<EKU>CLIENTAUTH", true},
		{"||<SUBJECT>CN=missing<SAN>alice\\.example", false},
		{"<SUBJECT>CN=missing", false},
		{"<KU>digitalSignature<EKU>emailProtection", false},
	}
	for _, test := range tests {
		got, err := MatchCertificate(cert, test.rule)
		if err != nil {
			t.Fatalf("MatchCertificate(%q): %v", test.rule, err)
		}
		if got != test.want {
			t.Errorf("MatchCertificate(%q) = %v, want %v", test.rule, got, test.want)
		}
	}
	_, _, principalCert, _ := makePKINITTestCertificate(
		t, "alice", "TEST.REALM", false)
	if got, err := MatchCertificate(principalCert,
		`<SAN>alice@TEST\.REALM`); err != nil || !got {
		t.Fatalf("pkinit SAN match = %v, %v, want true", got, err)
	}
	upnCert := &x509.Certificate{Extensions: []pkix.Extension{
		{Id: stdasn1.ObjectIdentifier{2, 5, 29, 17},
			Value: makeUPNSANExtension(t, "alice@TEST.REALM")},
	}}
	if got, err := MatchCertificate(upnCert,
		`<SAN>alice@TEST\.REALM`); err != nil || !got {
		t.Fatalf("UPN SAN match = %v, %v, want true", got, err)
	}
	if _, err := MatchCertificate(cert, "<SUBJECT>["); err == nil {
		t.Fatal("invalid regexp accepted")
	}
}

func TestCertificateNameUsesMITRDNOrder(t *testing.T) {
	raw, err := stdasn1.Marshal(pkix.RDNSequence{
		{{Type: stdasn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"}},
		{{Type: stdasn1.ObjectIdentifier{2, 5, 4, 10}, Value: `Comma,Plus+Equal=Quote"Semi;`}},
		{{Type: stdasn1.ObjectIdentifier{2, 5, 4, 3}, Value: " Alice "},
			{Type: stdasn1.ObjectIdentifier{1, 2, 3, 4}, Value: "é"}},
		{{Type: stdasn1.ObjectIdentifier{1, 2, 3, 5}, Value: "\x01x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{RawSubject: raw, RawIssuer: raw}
	const want = "C=US,O=Comma,Plus+Equal=Quote\"Semi;,1.2.3.4=é+CN= Alice ,1.2.3.5=\x01x"
	if got := certificateName(cert.Subject, cert.RawSubject); got != want {
		t.Fatalf("subject = %q, want %q", got, want)
	}
	if got, err := MatchCertificate(cert, "<SUBJECT>^"+regexp.QuoteMeta(want)+"$"); err != nil || !got {
		t.Fatalf("MIT-order subject match = %v, %v", got, err)
	}
	if got, err := MatchCertificate(cert, "<ISSUER>^"+regexp.QuoteMeta(want)+"$"); err != nil || !got {
		t.Fatalf("MIT-order issuer match = %v, %v", got, err)
	}
}

func TestPKINITSANMatchesSecondPrincipal(t *testing.T) {
	_, _, cert, _ := makePKINITTestCertificate(t, "wrong", "TEST.REALM", false)
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(stdasn1.ObjectIdentifier{2, 5, 29, 17}) {
			cert.Extensions[i].Value = testDERSequence(
				testPKINITOtherName("wrong", "TEST.REALM"),
				testPKINITOtherName("alice", "TEST.REALM"),
			)
			break
		}
	}
	client := principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}}
	if decision, _, err := (pkinitSANModule{}).Authorize(cert, client, nil); err != nil ||
		decision != CertAuthAccept {
		t.Fatalf("second PKINIT SAN authorization = %v, %v, want accept", decision, err)
	}
	if got, err := MatchCertificate(cert, `<SAN>alice@TEST\.REALM`); err != nil || !got {
		t.Fatalf("second PKINIT SAN match = %v, %v, want true", got, err)
	}
}

func TestMatchCertificateLiteralAngleBrackets(t *testing.T) {
	raw, err := stdasn1.Marshal(pkix.RDNSequence{{
		{Type: stdasn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Alice <Admin>"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		RawSubject: raw,
		KeyUsage:   x509.KeyUsageDigitalSignature,
	}
	for _, rule := range []string{
		`<SUBJECT>CN=Alice <Admin>`,
		`<SUBJECT>CN=Alice <Admin><KU>digitalSignature`,
	} {
		if got, err := MatchCertificate(cert, rule); err != nil || !got {
			t.Fatalf("literal angle-bracket rule %q = %v, %v, want true", rule, got, err)
		}
	}
}

func testPKINITOtherName(component, realm string) []byte {
	principal := testDERSequence(
		testDERExplicit(0, testDER(0x1b, []byte(realm))),
		testDERExplicit(1, testDERSequence(
			testDERExplicit(0, testDERInteger(1)),
			testDERExplicit(1, testDERSequence(testDER(0x1b, []byte(component)))),
		)),
	)
	return testDER(0xa0, append(
		testDEROID(stdasn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}),
		testDER(0xa0, principal)...,
	))
}

func testDERSequence(values ...[]byte) []byte {
	var content []byte
	for _, value := range values {
		content = append(content, value...)
	}
	return testDER(0x30, content)
}

func testDERExplicit(tag byte, value []byte) []byte {
	return testDER(0xa0|tag, value)
}

func testDERInteger(value byte) []byte {
	return testDER(0x02, []byte{value})
}

func testDEROID(value stdasn1.ObjectIdentifier) []byte {
	encoded, _ := stdasn1.Marshal(value)
	return encoded
}

func testDER(tag byte, content []byte) []byte {
	if len(content) < 128 {
		return append([]byte{tag, byte(len(content))}, content...)
	}
	panic("test DER value too long")
}

func makeUPNSANExtension(t *testing.T, upn string) []byte {
	t.Helper()
	oid, err := stdasn1.Marshal(stdasn1.ObjectIdentifier{
		1, 3, 6, 1, 4, 1, 311, 20, 2, 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	stringValue, err := stdasn1.Marshal(stdasn1.RawValue{
		Tag: 12, Bytes: []byte(upn),
	})
	if err != nil {
		t.Fatal(err)
	}
	explicitValue, err := stdasn1.Marshal(stdasn1.RawValue{
		Class: 2, Tag: 0, IsCompound: true, Bytes: stringValue,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherName := append(oid, explicitValue...)
	generalName, err := stdasn1.Marshal(stdasn1.RawValue{
		Class: 2, Tag: 0, IsCompound: true, Bytes: otherName,
	})
	if err != nil {
		t.Fatal(err)
	}
	extension, err := stdasn1.Marshal(stdasn1.RawValue{
		Tag: 16, IsCompound: true, Bytes: generalName,
	})
	if err != nil {
		t.Fatal(err)
	}
	return extension
}

func TestBuiltinCertAuthModules(t *testing.T) {
	client := principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}}
	if decision, _, err := (pkinitSANModule{}).Authorize(
		&x509.Certificate{}, client, nil); err != nil || decision != CertAuthPass {
		t.Fatalf("SAN without id-pkinit-san = %v, %v, want pass", decision, err)
	}
	_, _, cert, _ := makePKINITTestCertificate(t, "bob", "TEST.REALM", false)
	decision, _, err := (pkinitSANModule{}).Authorize(cert, client, nil)
	var certErr *CertAuthError
	if decision != CertAuthPass || !errors.As(err, &certErr) || certErr.Code != 75 {
		t.Fatalf("mismatching PKINIT SAN = %v, %v, want code 75", decision, err)
	}
	decision, _, err = (pkinitEKUModule{}).Authorize(
		&x509.Certificate{}, client, nil)
	certErr = nil
	if decision != CertAuthPass || !errors.As(err, &certErr) || certErr.Code != certAuthInconsistentKeyPurpose {
		t.Fatalf("missing PKINIT EKU = %v, %v, want code 77", decision, err)
	}
}

func TestDBMatchModule(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "alice"}}
	client := principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}}
	entry := &kdb.PrincipalRecord{Strings: map[string]string{
		"pkinit_cert_match": "<SUBJECT>CN=alice",
	}}
	decision, _, err := (dbMatchModule{}).Authorize(cert, client, entry)
	if err != nil || decision != CertAuthAccept {
		t.Fatalf("dbmatch = %v, %v, want accept", decision, err)
	}
	entry.Strings["pkinit_cert_match"] = "<SUBJECT>CN=bob"
	decision, _, err = (dbMatchModule{}).Authorize(cert, client, entry)
	var certErr *CertAuthError
	if decision != CertAuthPass || !errors.As(err, &certErr) || certErr.Code != 66 {
		t.Fatalf("dbmatch mismatch = %v, %v, want code 66", decision, err)
	}
}

func TestBuildASRepHWAuthSetsTicketFlag(t *testing.T) {
	server, _ := testServer(t, time.Unix(2000001000, 0).UTC())
	client := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"host", "service.test"}}
	clientRecord, ok, err := server.DB.Lookup(client)
	if err != nil || !ok {
		t.Fatalf("client lookup: %v", err)
	}
	serviceRecord, ok, err := server.DB.Lookup(service)
	if err != nil || !ok {
		t.Fatalf("service lookup: %v", err)
	}
	etypeID := crypto.EnctypeAES256SHA1
	clientKey := clientRecord.Keys[etypeID]
	serviceKey := serviceRecord.Keys[etypeID]
	reply := server.buildASRepWithHWAuth(asRequest(client, service, 7),
		client, clientRecord, service, serviceRecord, etypeID, clientKey, serviceKey,
		nil, true, nil, nil, nil, true)
	var asRep protocol.ASRep
	if err := asn1.Unmarshal(reply, &asRep); err != nil {
		t.Fatalf("decode AS-REP: %v", err)
	}
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(serviceKey.Key, 2, asRep.Ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt ticket: %v", err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatalf("decode ticket: %v", err)
	}
	if part.Flags&types.TicketHWAuthent == 0 {
		t.Fatalf("ticket flags %#x do not include HW-AUTHENT", part.Flags)
	}
}
