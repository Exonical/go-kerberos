//go:build integration

package mit_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestGoClientPKINITAgainstMITKDC(t *testing.T) {
	for _, name := range []string{"/usr/bin/openssl", "/usr/sbin/kdb5_util", "/usr/sbin/kadmin.local", "/usr/sbin/krb5kdc", "/usr/bin/kinit", "/usr/bin/klist"} {
		if _, err := os.Stat(name); err != nil {
			t.Skipf("PKINIT harness skipped: missing %s", name)
		}
	}
	dir := t.TempDir()
	realm := "PKINIT.TEST"
	port := freeTestPort(t)
	if err := generatePKINITFixtures(t, dir, realm); err != nil {
		t.Skipf("PKINIT certificate generation failed: %v", err)
	}
	t.Logf("PKINIT harness dir=%s", dir)
	conf := filepath.Join(dir, "krb5.conf")
	kdcConf := filepath.Join(dir, "kdc.conf")
	writePKFile(t, conf, fmt.Sprintf("[libdefaults]\n default_realm = %s\n dns_lookup_kdc = false\n dns_lookup_realm = false\n pkinit_anchors = FILE:%s\n pkinit_identities = FILE:%s,%s\n[realms]\n %s = {\n  kdc = 127.0.0.1:%d\n  pkinit_anchors = FILE:%s\n  pkinit_identities = FILE:%s,%s\n }\n", realm, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "alice.crt"), filepath.Join(dir, "alice.key"), realm, port, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "alice.crt"), filepath.Join(dir, "alice.key")))
	writePKFile(t, kdcConf, fmt.Sprintf("[kdcdefaults]\nkdc_ports = %d\nkdc_tcp_ports = %d\n[realms]\n%s = {\n database_name = %s/principal\n admin_database_name = %s/principal.kadm5\n admin_database_lockfile = %s/principal.kadm5.lock\n admin_keytab = %s/kadm5.keytab\n acl_file = %s/kadm5.acl\n key_stash_file = %s/.k5.%s\n pkinit_identity = FILE:%s/kdc.crt,%s/kdc.key\n pkinit_anchors = FILE:%s/ca.crt\n}\n", port, port, realm, dir, dir, dir, dir, dir, dir, realm, dir, dir, dir))
	writePKFile(t, filepath.Join(dir, "kadm5.acl"), "*/*@"+realm+" *\n")
	env := appendPKEnv(conf, kdcConf)
	if _, err := runPK(env, "", "/usr/sbin/kdb5_util", "create", "-s", "-P", "master"); err != nil {
		t.Fatal(err)
	}
	if _, err := runPK(env, "", "/usr/sbin/kadmin.local", "-q", "addprinc -pw alice-password alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := runPK(env, "", "/usr/sbin/kadmin.local", "-q", "modprinc +requires_preauth alice"); err != nil {
		t.Fatal(err)
	}
	kdc := exec.Command("/usr/sbin/krb5kdc", "-n")
	kdc.Env = append(env, "KRB5_TRACE="+filepath.Join(dir, "kdc-trace"))
	var kdcOut strings.Builder
	kdc.Stdout = &kdcOut
	kdc.Stderr = &kdcOut
	if err := kdc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = kdc.Process.Kill(); _ = kdc.Wait() })
	waitPKPort(t, port)
	cache := filepath.Join(dir, "mit.ccache")
	if out, err := runPK(append(env, "KRB5_TRACE="+filepath.Join(dir, "trace"), "KRB5CCNAME="+cache), "", "/usr/bin/kinit", "-X", "X509_user_identity=FILE:"+filepath.Join(dir, "alice.crt")+","+filepath.Join(dir, "alice.key"), "alice@"+realm); err != nil {
		trace, _ := os.ReadFile(filepath.Join(dir, "trace"))
		kdcTrace, _ := os.ReadFile(filepath.Join(dir, "kdc-trace"))
		t.Skipf("MIT PKINIT harness self-test failed: %v\noutput: %s\ntrace: %s\nkdc: %s\nkdc-trace: %s", err, out, trace, kdcOut.String(), kdcTrace)
	}
	certDER, err := os.ReadFile(filepath.Join(dir, "alice.crt"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pemDecodePK(t, certDER, "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := os.ReadFile(filepath.Join(dir, "alice.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyDER)
	var key *rsa.PrivateKey
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			key, _ = parsed.(*rsa.PrivateKey)
		}
	}
	if err != nil || key == nil {
		t.Fatalf("parse client key: %v", err)
	}
	caDER, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	ca, err := x509.ParseCertificate(pemDecodePK(t, caDER, "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	anchors := x509.NewCertPool()
	anchors.AddCert(ca)
	cfgBytes, _ := os.ReadFile(conf)
	cfg, err := config.Parse(cfgBytes)
	if err != nil {
		t.Fatal(err)
	}
	user := principal.Principal{Realm: realm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	goClient := &client.Client{Config: cfg, Now: func() time.Time { return time.Now().UTC() }}
	goClient.Exchange = func(ctx context.Context, _ string, payload []byte) ([]byte, error) {
		conn, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		if _, err := conn.Write(payload); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		return buf[:n], err
	}
	creds, err := goClient.ASExchangePKINIT(context.Background(), user, cert, key, anchors)
	if err != nil {
		kdcTrace, _ := os.ReadFile(filepath.Join(dir, "kdc-trace"))
		t.Fatalf("Go PKINIT AS exchange after MIT self-test: %v\nKDC trace: %s", err, kdcTrace)
	}
	f, err := os.Create(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := ccache.Write(f, &ccache.Cache{DefaultPrincipal: user, Credentials: []ccache.Credential{creds.ToCCacheCredential()}}); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	out, err := runPK(append(env, "KRB5CCNAME="+cache), "", "/usr/bin/klist", "-e", "-c", cache)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MIT klist PKINIT:\n%s", out)
}

func TestMITClientPKINITAgainstGoKDC(t *testing.T) {
	for _, name := range []string{"/usr/bin/openssl", "/usr/bin/kinit"} {
		if _, err := os.Stat(name); err != nil {
			t.Skipf("PKINIT harness skipped: missing %s", name)
		}
	}
	dir := t.TempDir()
	realm := "GOKDC.PKINIT.TEST"
	if err := generatePKINITFixtures(t, dir, realm); err != nil {
		t.Skipf("PKINIT certificate generation failed: %v", err)
	}
	roots := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(pemDecodePK(t, caPEM, "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(ca)
	kdcPEM, err := os.ReadFile(filepath.Join(dir, "kdc.crt"))
	if err != nil {
		t.Fatal(err)
	}
	kdcCert, err := x509.ParseCertificate(pemDecodePK(t, kdcPEM, "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	kdcKeyPEM, err := os.ReadFile(filepath.Join(dir, "kdc.key"))
	if err != nil {
		t.Fatal(err)
	}
	kdcKey := parsePKRSAKey(t, kdcKeyPEM)
	db := kdb.NewDatabase(realm)
	for _, item := range []struct {
		name, password string
	}{
		{"alice", "alice-password"},
		{"krbtgt/" + realm, "krbtgt-password"},
	} {
		if err := db.AddPrincipal(item.name, item.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	server := &kdc.Server{
		Realm: realm, DB: db, MaxTicketLife: 10 * time.Hour,
		MaxRenewableLife: 24 * time.Hour, PKINITCertificate: kdcCert,
		PKINITSigner: kdcKey, PKINITClientCAs: roots,
		PKINITRequireFreshness: true,
	}
	port := freeTestPort(t)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServe(ctx, udp, tcp) }()
	t.Cleanup(func() {
		cancel()
		_ = udp.Close()
		_ = tcp.Close()
		select {
		case <-errs:
		case <-time.After(time.Second):
		}
	})
	conf := filepath.Join(dir, "gokdc-krb5.conf")
	writePKFile(t, conf, fmt.Sprintf("[libdefaults]\n default_realm = %s\n dns_lookup_kdc = false\n dns_lookup_realm = false\n pkinit_anchors = FILE:%s\n pkinit_identities = FILE:%s,%s\n[realms]\n %s = {\n  kdc = 127.0.0.1:%d\n  pkinit_anchors = FILE:%s\n  pkinit_identities = FILE:%s,%s\n }\n", realm, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "alice.crt"), filepath.Join(dir, "alice.key"), realm, port, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "alice.crt"), filepath.Join(dir, "alice.key")))
	cache := filepath.Join(dir, "gokdc.ccache")
	trace := filepath.Join(dir, "gokdc-trace")
	out, err := runPK(append(os.Environ(), "KRB5_CONFIG="+conf, "KRB5_TRACE="+trace), "", "/usr/bin/kinit", "-X", "X509_user_identity=FILE:"+filepath.Join(dir, "alice.crt")+","+filepath.Join(dir, "alice.key"), "-c", cache, "alice@"+realm)
	if err != nil {
		traceData, _ := os.ReadFile(trace)
		t.Fatalf("MIT kinit against Go KDC: %v\noutput: %s\ntrace: %s", err, out, traceData)
	}
	traceData, err := os.ReadFile(trace)
	if err != nil {
		t.Fatalf("read MIT PKINIT trace: %v", err)
	}
	traceText := string(traceData)
	if !strings.Contains(traceText, "PKINIT client used KDF") ||
		!strings.Contains(strings.ToUpper(traceText), "2B06010502030602") {
		t.Fatalf("MIT PKINIT trace did not show SHA-256 KDF negotiation:\n%s", traceText)
	}
}

func TestMITClientAnonymousPKINITAgainstGoKDC(t *testing.T) {
	for _, name := range []string{"/usr/bin/openssl", "/usr/bin/kinit", "/usr/bin/klist", "/usr/bin/kvno"} {
		if _, err := os.Stat(name); err != nil {
			t.Skipf("anonymous PKINIT harness skipped: missing %s", name)
		}
	}
	dir := t.TempDir()
	if err := generatePKINITFixtures(t, dir, goKDCRealm); err != nil {
		t.Skipf("anonymous PKINIT certificate generation failed: %v", err)
	}
	realm := startGoKDC(t)
	realmCert, err := os.ReadFile(filepath.Join(dir, "kdc.crt"))
	if err != nil {
		t.Fatal(err)
	}
	kdcCert, err := x509.ParseCertificate(pemDecodePK(t, realmCert, "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	kdcKey, err := os.ReadFile(filepath.Join(dir, "kdc.key"))
	if err != nil {
		t.Fatal(err)
	}
	realm.server.PKINITCertificate = kdcCert
	realm.server.PKINITSigner = parsePKRSAKey(t, kdcKey)
	conf := filepath.Join(dir, "anonymous-client.conf")
	writePKFile(t, conf, fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_kdc = false
 dns_lookup_realm = false
 pkinit_anchors = FILE:%s
[realms]
 %s = {
  kdc = 127.0.0.1:%d
 }
`, goKDCRealm, filepath.Join(dir, "ca.crt"), goKDCRealm, realm.port))
	cache := filepath.Join(dir, "anonymous.ccache")
	trace := filepath.Join(dir, "trace")
	out, err := runPK(append(os.Environ(), "KRB5_CONFIG="+conf, "KRB5_TRACE="+trace,
		"KRB5CCNAME="+cache), "", "/usr/bin/kinit", "-n")
	if err != nil {
		traceData, _ := os.ReadFile(trace)
		t.Fatalf("MIT anonymous kinit against Go KDC: %v\noutput: %s\ntrace: %s", err, out, traceData)
	}
	traceData, _ := os.ReadFile(trace)
	traceText := string(traceData)
	if !strings.Contains(strings.ToLower(traceText), "pkinit") {
		t.Fatalf("MIT anonymous kinit trace did not use PKINIT:\n%s", traceText)
	}
	if strings.Contains(strings.ToLower(traceText), "encrypted timestamp") {
		t.Fatalf("MIT anonymous kinit fell back to encrypted timestamp:\n%s", traceText)
	}
	listing := realm.run(t, "", "/usr/bin/klist", "-e", "-c", cache)
	if !strings.Contains(strings.ToUpper(listing), "ANONYMOUS") {
		t.Fatalf("MIT anonymous klist missing ANONYMOUS:\n%s", listing)
	}
	if output, err := runPK(append(os.Environ(),
		"KRB5_CONFIG="+conf, "KRB5CCNAME="+cache,
	), "", "/usr/bin/kvno", "host/service.test"); err != nil ||
		!strings.Contains(
			output, "host/service.test@"+goKDCRealm,
		) {
		t.Fatalf("MIT anonymous kvno missing service ticket:\n%s", output)
	}
}

func TestGoClientAnonymousPKINITAgainstMITKDC(t *testing.T) {
	for _, name := range []string{"/usr/bin/openssl", "/usr/sbin/kdb5_util", "/usr/sbin/kadmin.local", "/usr/sbin/krb5kdc"} {
		if _, err := os.Stat(name); err != nil {
			t.Skipf("anonymous PKINIT harness skipped: missing %s", name)
		}
	}
	dir := t.TempDir()
	realm := "ANON.PKINIT.TEST"
	port := freeTestPort(t)
	if err := generatePKINITFixtures(t, dir, realm); err != nil {
		t.Skipf("anonymous PKINIT certificate generation failed: %v", err)
	}
	conf := filepath.Join(dir, "krb5.conf")
	kdcConf := filepath.Join(dir, "kdc.conf")
	writePKFile(t, conf, fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 pkinit_anchors = FILE:%s
[realms]
 %s = {
  kdc = 127.0.0.1:%d
 }
`, realm, filepath.Join(dir, "ca.crt"), realm, port))
	writePKFile(t, kdcConf, fmt.Sprintf(`[kdcdefaults]
 kdc_ports = %d
 kdc_tcp_ports = %d
[realms]
 %s = {
  database_name = %s/principal
  admin_database_name = %s/principal.kadm5
  admin_database_lockfile = %s/principal.kadm5.lock
  admin_keytab = %s/kadm5.keytab
  acl_file = %s/kadm5.acl
  key_stash_file = %s/.k5.%s
  pkinit_identity = FILE:%s/kdc.crt,%s/kdc.key
  pkinit_anchors = FILE:%s/ca.crt
 }
`, port, port, realm, dir, dir, dir, dir, dir, dir, realm, dir, dir, dir))
	writePKFile(t, filepath.Join(dir, "kadm5.acl"), "*/*@"+realm+" *\n")
	env := appendPKEnv(conf, kdcConf)
	if _, err := runPK(env, "", "/usr/sbin/kdb5_util", "create", "-s", "-P", "master"); err != nil {
		t.Fatal(err)
	}
	if _, err := runPK(env, "", "/usr/sbin/kadmin.local", "-q",
		"addprinc -randkey WELLKNOWN/ANONYMOUS"); err != nil {
		t.Fatal(err)
	}
	kdc := exec.Command("/usr/sbin/krb5kdc", "-n")
	kdc.Env = env
	var kdcOutput strings.Builder
	kdc.Stdout, kdc.Stderr = &kdcOutput, &kdcOutput
	if err := kdc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = kdc.Process.Kill(); _ = kdc.Wait() })
	waitPKPort(t, port)
	if out, err := runPK(append(env, "KRB5CCNAME="+filepath.Join(dir, "mit-anon.ccache")),
		"", "/usr/bin/kinit", "-n"); err != nil {
		t.Fatalf("MIT anonymous self-test: %v\noutput: %s\nKDC: %s", err, out, kdcOutput.String())
	}
	caDER, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(pemDecodePK(t, caDER, "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	cfgBytes, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(cfgBytes)
	if err != nil {
		t.Fatal(err)
	}
	goClient := &client.Client{Config: cfg, Now: func() time.Time { return time.Now().UTC() }}
	creds, err := goClient.AnonymousASExchange(context.Background(), realm, roots)
	if err != nil {
		t.Fatalf("Go anonymous PKINIT against MIT KDC: %v\nKDC: %s", err, kdcOutput.String())
	}
	if creds.Client.Realm != "WELLKNOWN:ANONYMOUS" ||
		creds.Flags&types.TicketAnonymous == 0 {
		t.Fatalf("Go anonymous credentials = %+v", creds)
	}
	cache := filepath.Join(dir, "go-anon.ccache")
	f, err := os.Create(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := ccache.Write(f, &ccache.Cache{
		DefaultPrincipal: creds.Client,
		Credentials:      []ccache.Credential{creds.ToCCacheCredential()},
	}); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := runPK(append(env, "KRB5CCNAME="+cache), "",
		"/usr/bin/klist", "-e", "-c", cache); err != nil {
		t.Fatalf("klist anonymous MIT credentials: %v\noutput: %s", err, out)
	} else if !strings.Contains(strings.ToUpper(out), "ANONYMOUS") {
		t.Fatalf("klist anonymous MIT credentials missing ANONYMOUS:\n%s", out)
	}
}

func parsePKRSAKey(t *testing.T, data []byte) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("invalid private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("private key is not RSA")
	}
	return key
}

func generatePKINITFixtures(t *testing.T, dir, realm string) error {
	if _, err := runPK(nil, "", "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", filepath.Join(dir, "ca.key"), "-out", filepath.Join(dir, "ca.crt"), "-days", "2", "-subj", "/CN=PKINIT-CA"); err != nil {
		return err
	}
	opensslEnv := append(os.Environ(), "REALM="+realm, "CLIENT=alice")
	for _, x := range []struct {
		name, cn, section string
	}{
		{"kdc", "krbtgt-" + realm, "kdc_cert"},
		{"alice", "alice-" + realm, "client_cert"},
	} {
		key, csr := filepath.Join(dir, x.name+".key"), filepath.Join(dir, x.name+".csr")
		if _, err := runPK(nil, "", "/usr/bin/openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN="+x.cn); err != nil {
			return err
		}
		ext := filepath.Join(dir, x.name+".ext")
		var content string
		if x.name == "kdc" {
			content = `[kdc_cert]
+basicConstraints=CA:FALSE
+keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
+extendedKeyUsage=1.3.6.1.5.2.3.5
+subjectKeyIdentifier=hash
+authorityKeyIdentifier=keyid,issuer
+issuerAltName=issuer:copy
+subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name
+[kdc_princ_name]
+realm=EXP:0,GeneralString:${ENV::REALM}
+principal_name=EXP:1,SEQUENCE:kdc_principal_seq
+[kdc_principal_seq]
+name_type=EXP:0,INTEGER:2
+name_string=EXP:1,SEQUENCE:kdc_principals
+[kdc_principals]
+princ1=GeneralString:krbtgt
+princ2=GeneralString:${ENV::REALM}
+`
		} else {
			content = `[client_cert]
+basicConstraints=CA:FALSE
+keyUsage=digitalSignature,keyEncipherment,keyAgreement
+extendedKeyUsage=1.3.6.1.5.2.3.4
+subjectKeyIdentifier=hash
+authorityKeyIdentifier=keyid,issuer
+issuerAltName=issuer:copy
+subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name
+[princ_name]
+realm=EXP:0,GeneralString:${ENV::REALM}
+principal_name=EXP:1,SEQUENCE:principal_seq
+[principal_seq]
+name_type=EXP:0,INTEGER:1
+name_string=EXP:1,SEQUENCE:principals
+[principals]
+princ1=GeneralString:${ENV::CLIENT}
+`
		}
		content = strings.ReplaceAll(content, "\n+", "\n")
		writePKFile(t, ext, content)
		if _, err := runPK(opensslEnv, "", "/usr/bin/openssl", "x509", "-req", "-in", csr, "-CA", filepath.Join(dir, "ca.crt"), "-CAkey", filepath.Join(dir, "ca.key"), "-CAcreateserial", "-out", filepath.Join(dir, x.name+".crt"), "-days", "2", "-extfile", ext, "-extensions", x.section); err != nil {
			return err
		}
	}
	return nil
}

func runPK(env []string, input, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if env != nil {
		cmd.Env = env
	}
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
func appendPKEnv(conf, kdc string) []string {
	e := os.Environ()
	return append(e, "KRB5_CONFIG="+conf, "KRB5_KDC_PROFILE="+kdc)
}
func writePKFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
func pemDecodePK(t *testing.T, data []byte, typ string) []byte {
	t.Helper()
	b, _ := pem.Decode(data)
	if b == nil || b.Type != typ {
		t.Fatalf("invalid PEM %s", typ)
	}
	return b.Bytes
}
func freeTestPort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func waitPKPort(t *testing.T, p int) {
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)), 50*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("PKINIT KDC did not start")
}
