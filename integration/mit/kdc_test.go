//go:build integration

package mit_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const goKDCRealm = "GOKDC.TEST"

type goKDC struct {
	config string
	cache  string
	db     *kdb.Database
	cancel context.CancelFunc
	done   chan error
}

func startGoKDC(t *testing.T) *goKDC {
	return startGoKDCWithPolicy(t, nil)
}

func startGoKDCWithPolicy(t *testing.T, policy *kdb.PolicyRecord) *goKDC {
	t.Helper()
	db := kdb.NewDatabase(goKDCRealm)
	for _, item := range []struct{ name, password string }{
		{"alice", "alice-password"},
		{"krbtgt/" + goKDCRealm, "krbtgt-password"},
		{"host/service.test", "host-password"},
		{"HTTP/backend.test", "backend-password"},
	} {
		if err := db.AddPrincipal(item.name, item.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AddAlias("alice-alias", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAlias("host/alias.test", "host/service.test"); err != nil {
		t.Fatal(err)
	}
	if policy != nil {
		if err := db.CreatePolicy(*policy); err != nil {
			t.Fatal(err)
		}
		user, err := principal.Parse("alice@" + goKDCRealm)
		if err != nil {
			t.Fatal(err)
		}
		record, ok, err := db.Lookup(*user)
		if err != nil || !ok {
			t.Fatalf("lookup policy principal: %v, %v", err, ok)
		}
		record.Policy = policy.Name
		if err := db.UpdatePrincipal(record); err != nil {
			t.Fatal(err)
		}
	}
	server := &kdc.Server{
		Realm:            goKDCRealm,
		DB:               db,
		Now:              time.Now,
		ClockSkew:        5 * time.Minute,
		MaxTicketLife:    10 * time.Hour,
		MaxRenewableLife: 24 * time.Hour,
	}
	service := principal.Principal{Realm: goKDCRealm, NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	backend := principal.Principal{Realm: goKDCRealm, NameType: principal.NTSrvHst, Components: []string{"HTTP", "backend.test"}}
	server.CheckAllowedToDelegate = func(impersonated *principal.Principal, requester principal.Principal, target *principal.Principal) error {
		if requester.String() != service.String() {
			return fmt.Errorf("unexpected delegation service %s", requester)
		}
		if impersonated != nil && target != nil {
			if target.String() != backend.String() {
				return fmt.Errorf("unexpected delegation target %s", target)
			}
		}
		return nil
	}
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		udpConn.Close()
		t.Fatal(err)
	}
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	tcpPort := tcpListener.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	configPath := filepath.Join(dir, "krb5.conf")
	configText := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false

[realms]
    %s = {
        kdc = 127.0.0.1:%d
        kdc = tcp/127.0.0.1:%d
    }
`, goKDCRealm, goKDCRealm, udpPort, tcpPort)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		udpConn.Close()
		tcpListener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx, udpConn, tcpListener) }()
	k := &goKDC{
		config: configPath,
		cache:  filepath.Join(dir, "ccache"),
		db:     db,
		cancel: cancel,
		done:   done,
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort), 50*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Go KDC did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-k.done:
		case <-time.After(5 * time.Second):
		}
	})
	return k
}

func (k *goKDC) run(t *testing.T, input, command string, args ...string) string {
	t.Helper()
	output, err := k.runResult(input, command, args...)
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", command, args, err, output)
	}
	return output
}

func (k *goKDC) runResult(input, command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	env := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "KRB5_CONFIG=") || strings.HasPrefix(value, "KRB5CCNAME=") {
			continue
		}
		env = append(env, value)
	}
	cmd.Env = append(env, "KRB5_CONFIG="+k.config, "KRB5CCNAME=FILE:"+k.cache, "KRB5_TRACE=/dev/stderr")
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func TestMITClientAgainstGoKDC(t *testing.T) {
	k := startGoKDC(t)
	k.run(t, "alice-password\n", "/usr/bin/kinit", "alice")
	klist := k.run(t, "", "/usr/bin/klist")
	t.Logf("MIT klist after kinit:\n%s", klist)
	if !strings.Contains(klist, "krbtgt/"+goKDCRealm+"@"+goKDCRealm) {
		t.Fatalf("klist does not show TGT:\n%s", klist)
	}
	armorCache := filepath.Join(filepath.Dir(k.cache), "armor-ccache")
	k.run(t, "alice-password\n", "/usr/bin/kinit", "-c", armorCache, "alice")
	k.run(t, "alice-password\n", "/usr/bin/kinit", "-T", armorCache, "alice")
	fastKlist := k.run(t, "", "/usr/bin/klist")
	t.Logf("MIT klist after FAST kinit:\n%s", fastKlist)
	if !strings.Contains(fastKlist, "krbtgt/"+goKDCRealm+"@"+goKDCRealm) {
		t.Fatalf("klist after FAST kinit does not show TGT:\n%s", fastKlist)
	}
	k.run(t, "alice-password\n", "/usr/bin/kinit", "-r", "20h", "alice")
	renewable := k.run(t, "", "/usr/bin/klist")
	t.Logf("MIT klist after renewable kinit:\n%s", renewable)
	if !strings.Contains(renewable, "renew until") {
		t.Fatalf("klist does not show renewable TGT:\n%s", renewable)
	}
	k.run(t, "", "/usr/bin/kinit", "-R")
	renewed := k.run(t, "", "/usr/bin/klist")
	t.Logf("MIT klist after renewal:\n%s", renewed)
	if !strings.Contains(renewed, "krbtgt/"+goKDCRealm+"@"+goKDCRealm) {
		t.Fatalf("klist after renewal does not show TGT:\n%s", renewed)
	}
	kvno := k.run(t, "", "/usr/bin/kvno", "host/service.test")
	t.Logf("MIT kvno output:\n%s", kvno)
	if !strings.Contains(kvno, "Encoding request body and padata into FAST") {
		t.Fatalf("MIT kvno did not send a FAST-armored TGS request:\n%s", kvno)
	}
	if !strings.Contains(kvno, "kvno = 1") {
		t.Fatalf("kvno output unexpected:\n%s", kvno)
	}
	full := k.run(t, "", "/usr/bin/klist", "-e")
	t.Logf("MIT klist -e output:\n%s", full)
	if !strings.Contains(full, "host/service.test@"+goKDCRealm) {
		t.Fatalf("klist -e does not show service ticket:\n%s", full)
	}
}

func TestMITClientAccountLockoutAgainstGoKDC(t *testing.T) {
	k := startGoKDCWithPolicy(t, &kdb.PolicyRecord{
		Name: "lockout", MaxFailure: 2, FailureCountInterval: 300,
	})
	for attempt := 0; attempt < 2; attempt++ {
		output, err := k.runResult("wrong-password\n", "/usr/bin/kinit", "alice")
		if err == nil {
			t.Fatalf("wrong-password kinit attempt %d unexpectedly succeeded", attempt+1)
		}
		t.Logf("wrong-password kinit attempt %d:\n%s", attempt+1, output)
	}
	output, err := k.runResult("alice-password\n", "/usr/bin/kinit", "alice")
	if err == nil {
		t.Fatalf("locked correct-password kinit unexpectedly succeeded")
	}
	t.Logf("locked correct-password kinit:\n%s", output)
	if !strings.Contains(strings.ToLower(output), "revoked") {
		t.Fatalf("locked kinit output lacks revoked error:\n%s", output)
	}
}

func TestMITClientAliasesAgainstGoKDC(t *testing.T) {
	k := startGoKDC(t)
	k.run(t, "alice-password\n", "/usr/bin/kinit", "-C", "alice-alias")
	klist := k.run(t, "", "/usr/bin/klist")
	if !strings.Contains(klist, "Default principal: alice@"+goKDCRealm) {
		t.Fatalf("canonicalized kinit principal missing:\n%s", klist)
	}
	kvno := k.run(t, "", "/usr/bin/kvno", "host/alias.test")
	if !strings.Contains(kvno, "host/service.test@"+goKDCRealm) ||
		!strings.Contains(kvno, "kvno = 1") {
		t.Fatalf("alias kvno output unexpected:\n%s", kvno)
	}
}

func TestMITClientS4U2SelfAgainstGoKDC(t *testing.T) {
	k := startGoKDC(t)
	k.run(t, "host-password\n", "/usr/bin/kinit", "-f", "host/service.test")
	output := k.run(t, "", "/usr/bin/kvno", "-U", "alice", "host/service.test")
	t.Logf("MIT kvno S4U2Self output:\n%s", output)
	if !strings.Contains(output, "host/service.test@"+goKDCRealm) ||
		!strings.Contains(output, "kvno = 1") {
		t.Fatalf("MIT kvno S4U2Self output unexpected:\n%s", output)
	}
	proxy := k.run(t, "", "/usr/bin/kvno", "-P", "-U", "alice", "HTTP/backend.test")
	t.Logf("MIT kvno S4U2Proxy output:\n%s", proxy)
	if !strings.Contains(proxy, "HTTP/backend.test@"+goKDCRealm) ||
		!strings.Contains(proxy, "kvno = 1") {
		t.Fatalf("MIT kvno S4U2Proxy output unexpected:\n%s", proxy)
	}
}

func TestGoClientS4UAgainstGoKDC(t *testing.T) {
	k := startGoKDC(t)
	data, err := os.ReadFile(k.config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	cfg.UDPPreferenceLimit = 1400
	cfg.Forwardable = true
	goClient := &client.Client{Config: cfg}
	service := principal.Principal{Realm: goKDCRealm, NameType: principal.NTSrvHst, Components: []string{"host", "service.test"}}
	user := principal.Principal{Realm: goKDCRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	backend := principal.Principal{Realm: goKDCRealm, NameType: principal.NTSrvHst, Components: []string{"HTTP", "backend.test"}}
	tgt, err := goClient.ASExchange(context.Background(), service, "host-password")
	if err != nil {
		t.Fatal(err)
	}
	self, err := goClient.S4U2Self(context.Background(), tgt, user)
	if err != nil {
		t.Fatalf("S4U2Self: %v", err)
	}
	if self.Client.String() != user.String() || self.Server.String() != service.String() ||
		self.Flags&types.TicketForwardable == 0 {
		t.Fatalf("unexpected S4U2Self credentials: %#v", self)
	}
	proxy, err := goClient.S4U2Proxy(context.Background(), tgt, self, backend)
	if err != nil {
		t.Fatalf("S4U2Proxy: %v", err)
	}
	if proxy.Client.String() != user.String() || proxy.Server.String() != backend.String() {
		t.Fatalf("unexpected S4U2Proxy credentials: %#v", proxy)
	}
}

func TestGoClientAliasesAgainstGoKDC(t *testing.T) {
	k := startGoKDC(t)
	data, err := os.ReadFile(k.config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	cfg.UDPPreferenceLimit = 1400
	aliasUser := principal.Principal{
		Realm: goKDCRealm, NameType: principal.NTPrincipal,
		Components: []string{"alice-alias"},
	}
	canonicalUser := principal.Principal{
		Realm: goKDCRealm, NameType: principal.NTPrincipal,
		Components: []string{"alice"},
	}
	plain := &client.Client{Config: cfg}
	if _, err := plain.ASExchange(context.Background(), aliasUser, "alice-password"); err == nil {
		t.Fatal("non-canonicalized alias AS unexpectedly succeeded")
	}
	canonical := &client.Client{Config: cfg, Canonicalize: true}
	tgt, err := canonical.ASExchange(context.Background(), aliasUser, "alice-password")
	if err != nil {
		t.Fatalf("canonicalized alias AS: %v", err)
	}
	if tgt.Client.String() != canonicalUser.String() {
		t.Fatalf("canonicalized AS client = %s, want %s", tgt.Client, canonicalUser)
	}
	aliasService := principal.Principal{
		Realm: goKDCRealm, NameType: principal.NTSrvHst,
		Components: []string{"host", "alias.test"},
	}
	plainTGT, err := plain.ASExchange(context.Background(), canonicalUser, "alice-password")
	if err != nil {
		t.Fatalf("plain AS exchange: %v", err)
	}
	echoed, err := plain.TGSExchange(context.Background(), plainTGT, aliasService)
	if err != nil {
		t.Fatalf("alias TGS echo: %v", err)
	}
	if echoed.Server.String() != aliasService.String() {
		t.Fatalf("echoed alias service = %s, want %s", echoed.Server, aliasService)
	}
	canonicalized, err := canonical.TGSExchange(context.Background(), tgt, aliasService)
	if err != nil {
		t.Fatalf("canonicalized alias TGS: %v", err)
	}
	if canonicalized.Server.String() != "host/service.test@"+goKDCRealm {
		t.Fatalf("canonicalized service = %s", canonicalized.Server)
	}
}
