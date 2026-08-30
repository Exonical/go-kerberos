package ccache

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestSelectForServerUsesK5Identity(t *testing.T) {
	dir := t.TempDir()
	collection, err := Resolve("DIR:" + dir)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	first, err := collection.New()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := collection.New()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	alice := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	bob := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"bob"}}
	if err := first.Write(&Cache{DefaultPrincipal: alice}); err != nil {
		t.Fatal(err)
	}
	if err := second.Write(&Cache{DefaultPrincipal: bob}); err != nil {
		t.Fatal(err)
	}
	if err := second.SetPrimary(); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "identity")
	if err := os.WriteFile(identity, []byte("alice@EXAMPLE.COM service=host host=web.example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{K5IdentityPath: identity}
	server := principal.Principal{
		Realm: "EXAMPLE.COM", NameType: principal.NTSrvHst,
		Components: []string{"host", "web.example.com"},
	}
	selected, got, err := SelectForServer("DIR:"+dir, cfg, server)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Name() != first.Name() || got.String() != alice.String() {
		t.Fatalf("selected %s/%s, want %s/%s", selected.Name(), got, first.Name(), alice)
	}
}

func TestSelectForServerClosesNonSelectedKCMHandles(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "kcm.sock")
	server := NewKCMServer(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeListener(listener)
	}()
	defer func() {
		_ = server.Close()
		<-done
		_ = os.Remove(socket)
	}()

	originalSocket := DefaultKCMSocketPath
	DefaultKCMSocketPath = socket
	defer func() { DefaultKCMSocketPath = originalSocket }()

	alice, err := Resolve("KCM:alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := Resolve("KCM:bob")
	if err != nil {
		_ = alice.Close()
		t.Fatal(err)
	}
	aliceValue := &Cache{DefaultPrincipal: principal.Principal{
		Realm: "EXAMPLE.COM", Components: []string{"alice"},
	}}
	bobValue := &Cache{DefaultPrincipal: principal.Principal{
		Realm: "EXAMPLE.COM", Components: []string{"bob"},
	}}
	if err := alice.Write(aliceValue); err != nil {
		t.Fatal(err)
	}
	if err := bob.Write(bobValue); err != nil {
		t.Fatal(err)
	}
	if err := alice.SetDefault(); err != nil {
		t.Fatal(err)
	}
	_ = alice.Close()
	_ = bob.Close()
	waitKCMConnections(t, server, 0)

	identity := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(identity, []byte("alice@EXAMPLE.COM service=host host=web.example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{K5IdentityPath: identity}
	target := principal.Principal{
		Realm: "EXAMPLE.COM", NameType: principal.NTSrvHst,
		Components: []string{"host", "web.example.com"},
	}
	for i := 0; i < 3; i++ {
		selected, got, err := SelectForServer("KCM:", cfg, target)
		if err != nil {
			t.Fatalf("selection %d: %v", i, err)
		}
		if selected.Name() != "KCM:alice" || got.Components[0] != "alice" {
			t.Fatalf("selection %d = %s/%s", i, selected.Name(), got)
		}
		waitKCMConnections(t, server, 1)
		open := kcmConnectionCount(server)
		if open != 1 {
			t.Fatalf("selection %d left %d KCM connections open, want selected handle only", i, open)
		}
		if err := selected.Close(); err != nil {
			t.Fatalf("close selected %d: %v", i, err)
		}
		waitKCMConnections(t, server, 0)
	}
}

func kcmConnectionCount(server *KCMServer) int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return len(server.conns)
}

func waitKCMConnections(t *testing.T, server *KCMServer, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if got := kcmConnectionCount(server); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("KCM connections = %d, want %d", kcmConnectionCount(server), want)
		}
		time.Sleep(time.Millisecond)
	}
}
