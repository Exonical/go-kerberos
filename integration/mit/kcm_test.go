//go:build integration

package mit_test

import (
	"bytes"
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
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestGoKCMServerWithMITTools(t *testing.T) {
	realm := testenv.Start(t)
	socket := filepath.Join(realm.Dir, "go-kcm.sock")
	server := ccache.NewKCMServer(socket)
	go func() { _ = server.Serve() }()
	waitForUnixSocket(t, socket)
	defer server.Close()

	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatal(err)
	}
	configData = bytes.Replace(configData, []byte("[libdefaults]\n"),
		[]byte("[libdefaults]\nkcm_socket = "+socket+"\n"), 1)
	configPath := filepath.Join(realm.Dir, "kcm-krb5.conf")
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "KRB5_CONFIG="+configPath, "KRB5CCNAME=KCM:")
	runMITKCM(t, env, "kinit", "alice")
	listing := runMITKCM(t, env, "klist")
	if !strings.Contains(listing, "krbtgt/"+testenv.RealmName) {
		t.Fatalf("MIT klist did not read Go KCM cache:\n%s", listing)
	}
	kvno := runMITKCM(t, env, "kvno", "host/service.test")
	if !strings.Contains(kvno, "host/service.test@"+testenv.RealmName) {
		t.Fatalf("MIT kvno did not use Go KCM cache:\n%s", kvno)
	}
	runMITKCM(t, env, "kdestroy")
}

func TestGoKCMClientWithMITTestServer(t *testing.T) {
	script := "/home/ubuntu/krb5-src/src/tests/kcmserver.py"
	if _, err := os.Stat(script); err != nil {
		t.Skipf("MIT KCM test server unavailable: %v", err)
	}
	socket := filepath.Join(t.TempDir(), "mit-kcm.sock")
	cmd := exec.Command("python3", script, socket)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Skipf("python3 unavailable: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	waitForUnixSocket(t, socket)
	cache, err := ccache.ResolveKCM("go-client", socket)
	if err != nil {
		t.Fatal(err)
	}
	value := &ccache.Cache{DefaultPrincipal: principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}, Credentials: []ccache.Credential{{
		Client: principal.Principal{
			Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
		},
		Server: principal.Principal{
			Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"krbtgt", testenv.RealmName},
		},
		Enctype: 18, Key: bytes.Repeat([]byte{0x42}, 32),
		AuthTime: 1, StartTime: 1, EndTime: uint32(time.Now().Add(time.Hour).Unix()),
		Ticket: []byte("ticket"),
	}}}
	if err := cache.Write(value); err != nil {
		t.Fatalf("write through MIT KCM test server: %v (%s)", err, output.String())
	}
	got, err := cache.Read()
	if err != nil {
		t.Fatalf("read through MIT KCM test server: %v", err)
	}
	if len(got.Credentials) != 1 || got.Credentials[0].Server.Components[0] != "krbtgt" {
		t.Fatalf("unexpected MIT KCM credentials: %#v", got.Credentials)
	}

	fallbackSocket := filepath.Join(t.TempDir(), "mit-kcm-fallback.sock")
	fallback := exec.Command("python3", script, "--fallback", fallbackSocket)
	fallback.Stdout, fallback.Stderr = &output, &output
	if err := fallback.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = fallback.Process.Kill()
		_ = fallback.Wait()
	}()
	waitForUnixSocket(t, fallbackSocket)
	fallbackCache, err := ccache.ResolveKCM("fallback", fallbackSocket)
	if err != nil {
		t.Fatal(err)
	}
	if err := fallbackCache.Initialize(value.DefaultPrincipal); err != nil {
		t.Fatal(err)
	}
	if err := fallbackCache.Store(value.Credentials[0]); err != nil {
		t.Fatal(err)
	}
	fallbackValue, err := fallbackCache.Read()
	if err != nil || len(fallbackValue.Credentials) != 1 {
		t.Fatalf("UUID fallback read = %#v, %v", fallbackValue, err)
	}
}

func waitForUnixSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Unix socket %s did not become ready", path)
}

func runMITKCM(t *testing.T, env []string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/"+name, args...)
	cmd.Env = env
	if name == "kinit" {
		cmd.Stdin = strings.NewReader("alice-password\n")
	}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output.String())
	}
	return fmt.Sprint(output.String())
}
