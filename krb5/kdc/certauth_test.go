package kdc

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
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
		}, false, false, []string{"pass"}, 62, true},
		{"accept authorizes", []CertAuthModule{
			certAuthTestModule{decision: CertAuthPass, indicators: []string{"one"}},
			certAuthTestModule{decision: CertAuthAccept, indicators: []string{"two"}},
		}, true, false, []string{"one", "two"}, 0, false},
		{"hardware accept", []CertAuthModule{
			certAuthTestModule{decision: CertAuthHWAuth, indicators: []string{"hardware"}},
		}, true, true, []string{"hardware"}, 0, false},
		{"hardware pass still needs accept", []CertAuthModule{
			certAuthTestModule{decision: CertAuthHWAuthPass, indicators: []string{"hardware"}},
		}, false, true, []string{"hardware"}, 62, true},
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
		{"<SAN>alice\\.example", true},
		{"<KU>digitalSignature,keyEncipherment", true},
		{"<EKU>clientAuth", true},
		{"<SUBJECT>CN=alice<KU>keyEncipherment", true},
		{"&&<SUBJECT>CN=alice<EKU>CLIENTAUTH", true},
		{"||<SUBJECT>CN=missing<SAN>alice\\.example", true},
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
	if _, err := MatchCertificate(cert, "<SUBJECT>["); err == nil {
		t.Fatal("invalid regexp accepted")
	}
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
	if decision != CertAuthPass || !errors.As(err, &certErr) || certErr.Code != 62 {
		t.Fatalf("mismatching PKINIT SAN = %v, %v, want code 62", decision, err)
	}
	decision, _, err = (pkinitEKUModule{}).Authorize(
		&x509.Certificate{}, client, nil)
	certErr = nil
	if decision != CertAuthPass || !errors.As(err, &certErr) || certErr.Code != 77 {
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
	if decision != CertAuthPass || !errors.As(err, &certErr) || certErr.Code != 89 {
		t.Fatalf("dbmatch mismatch = %v, %v, want code 89", decision, err)
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
