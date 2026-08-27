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

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/kdc"
)

func TestMITDumpToGoKDCPersistence(t *testing.T) {
	mitRealm := testenv.Start(t)
	dumpPath := filepath.Join(mitRealm.Dir, "principal.dump")
	mitRealm.Run(t, "", "/usr/sbin/kdb5_util", "dump", "-r18", dumpPath)
	store, err := mitdump.LoadWithMasterPassword(dumpPath, testenv.MasterKey)
	if err != nil {
		t.Fatalf("load MIT dump: %v", err)
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
	t.Cleanup(func() {
		udpConn.Close()
		tcpListener.Close()
	})
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	tcpPort := tcpListener.Addr().(*net.TCPAddr).Port
	configPath := filepath.Join(mitRealm.Dir, "go-kdc.conf")
	config := fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false

[realms]
 %s = {
  kdc = 127.0.0.1:%d
  kdc = tcp/127.0.0.1:%d
 }
`, testenv.RealmName, testenv.RealmName, udpPort, tcpPort)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	server := &kdc.Server{
		Realm:            testenv.RealmName,
		DB:               store,
		Now:              time.Now,
		ClockSkew:        5 * time.Minute,
		MaxTicketLife:    10 * time.Hour,
		MaxRenewableLife: 24 * time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx, udpConn, tcpListener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Go KDC did not stop")
		}
	})

	cachePath := filepath.Join(mitRealm.Dir, "go-kdc.ccache")
	run := func(input string, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Env = []string{"KRB5_CONFIG=" + configPath, "KRB5CCNAME=FILE:" + cachePath,
			"KRB5_TRACE=/dev/stderr"}
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v failed: %v\n%s", name, args, err, output)
		}
		return string(output)
	}
	run("alice-password\n", "/usr/bin/kinit", "alice")
	kvno := run("", "/usr/bin/kvno", "host/service.test")
	if !strings.Contains(kvno, "host/service.test@"+testenv.RealmName) {
		t.Fatalf("unexpected kvno output: %s", kvno)
	}
	listing := run("", "/usr/bin/klist", "-e")
	if !strings.Contains(listing, "host/service.test@"+testenv.RealmName) {
		t.Fatalf("klist does not show persisted service ticket:\n%s", listing)
	}
}
