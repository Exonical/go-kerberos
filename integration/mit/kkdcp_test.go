//go:build integration

package mit_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/kkdcp"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/transport"
)

func TestGoKKDCPClientAgainstMIT(t *testing.T) {
	realm := testenv.Start(t)
	proxy := httptest.NewTLSServer(&kkdcp.Handler{
		Backend: mitKDCBackend(t, realm.Port),
	})
	defer proxy.Close()
	cfgData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(cfgData)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Realms[testenv.RealmName] = []string{proxy.URL + "/KdcProxy"}
	kclient := &client.Client{
		Config: cfg,
		KKDCP:  &kkdcp.Client{HTTPClient: proxy.Client()},
	}
	alice := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal,
		Components: []string{"alice"},
	}
	tgt, err := kclient.ASExchange(context.Background(), alice, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	service, err := kclient.TGSExchange(context.Background(), tgt, principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if service == nil || len(service.Ticket) == 0 {
		t.Fatal("KKDCP TGS exchange returned no service ticket")
	}
}

func TestMITKKDCPClientAgainstGoProxy(t *testing.T) {
	if !mitHTTPSProxySupport() {
		t.Skip("installed MIT krb5 lacks the k5tls HTTPS plugin; see docs/test-matrix.md")
	}
	realm := testenv.Start(t)
	proxy := httptest.NewTLSServer(&kkdcp.Handler{
		Backend: mitKDCBackend(t, realm.Port),
	})
	defer proxy.Close()
	certFile := filepath.Join(realm.Dir, "proxy-ca.pem")
	certificate := proxy.Certificate()
	if certificate == nil {
		t.Fatal("TLS proxy has no certificate")
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certificate.Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(realm.Dir, "kkdcp-client.conf")
	configText := fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false

[realms]
 %s = {
  kdc = %s/KdcProxy
  http_anchors = FILE:%s
 }
`, testenv.RealmName, testenv.RealmName, proxy.URL, certFile)
	if err := os.WriteFile(configFile, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(realm.Dir, "mit-kkdcp.ccache")
	trace := filepath.Join(realm.Dir, "mit-kkdcp.trace")
	env := cleanKerberosEnv()
	env = append(env,
		"KRB5_CONFIG="+configFile,
		"KRB5CCNAME=FILE:"+cache,
		"KRB5_TRACE="+trace,
	)
	runCommand(t, env, "alice-password\n", "/usr/bin/kinit", "-c", cache,
		"alice@"+testenv.RealmName)
	output := runCommand(t, env, "", "/usr/bin/klist", "-c", cache)
	if !strings.Contains(output, testenv.RealmName) {
		t.Fatalf("klist output does not contain realm: %s", output)
	}
	traceData, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(traceData, []byte("Sending HTTPS request")) {
		t.Fatalf("MIT trace does not show HTTPS KDC proxy transport:\n%s", traceData)
	}
}

func mitHTTPSProxySupport() bool {
	paths := []string{
		"/usr/lib/x86_64-linux-gnu/krb5/plugins/libkrb5/k5tls.so",
		"/usr/lib/x86_64-linux-gnu/krb5/plugins/libkrb5/k5tls.so.0",
		"/usr/lib/x86_64-linux-gnu/krb5/plugins/tls/k5tls.so",
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func mitKDCBackend(t *testing.T, port int) func(context.Context, []byte) ([]byte, error) {
	t.Helper()
	return func(ctx context.Context, message []byte) ([]byte, error) {
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		address, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err != nil {
			return nil, err
		}
		return (transport.Exchange{
			Dialer:             &net.Dialer{},
			Timeout:            5 * time.Second,
			UDPPreferenceLimit: 1,
		}).Request(ctx, conn, address, message)
	}
}

func cleanKerberosEnv() []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "KRB5_CONFIG=") ||
			strings.HasPrefix(value, "KRB5_KDC_PROFILE=") ||
			strings.HasPrefix(value, "KRB5CCNAME=") ||
			strings.HasPrefix(value, "KRB5_TRACE=") {
			continue
		}
		env = append(env, value)
	}
	return env
}

func runCommand(t *testing.T, env []string, input, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = env
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output.String())
	}
	return output.String()
}
