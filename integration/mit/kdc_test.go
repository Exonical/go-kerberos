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

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
)

const goKDCRealm = "GOKDC.TEST"

type goKDC struct {
	config string
	cache  string
	cancel context.CancelFunc
	done   chan error
}

func startGoKDC(t *testing.T) *goKDC {
	t.Helper()
	db := kdb.NewDatabase(goKDCRealm)
	for _, item := range []struct{ name, password string }{
		{"alice", "alice-password"},
		{"krbtgt/" + goKDCRealm, "krbtgt-password"},
		{"host/service.test", "host-password"},
	} {
		if err := db.AddPrincipal(item.name, item.password, 1); err != nil {
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
		cancel: cancel,
		done:   done,
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
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", command, args, err, output)
	}
	return string(output)
}

func TestMITClientAgainstGoKDC(t *testing.T) {
	k := startGoKDC(t)
	k.run(t, "alice-password\n", "/usr/bin/kinit", "alice")
	klist := k.run(t, "", "/usr/bin/klist")
	t.Logf("MIT klist after kinit:\n%s", klist)
	if !strings.Contains(klist, "krbtgt/"+goKDCRealm+"@"+goKDCRealm) {
		t.Fatalf("klist does not show TGT:\n%s", klist)
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
	if !strings.Contains(kvno, "kvno = 1") {
		t.Fatalf("kvno output unexpected:\n%s", kvno)
	}
	full := k.run(t, "", "/usr/bin/klist", "-e")
	t.Logf("MIT klist -e output:\n%s", full)
	if !strings.Contains(full, "host/service.test@"+goKDCRealm) {
		t.Fatalf("klist -e does not show service ticket:\n%s", full)
	}
}
