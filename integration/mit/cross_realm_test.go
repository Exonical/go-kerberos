//go:build integration

package mit_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/transport"
)

func TestGoClientCrossRealmAgainstMITKDC(t *testing.T) {
	mitRealm := testenv.Start(t)
	const goRealm = "GO.A"
	mitRealm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"addprinc -pw shared-password krbtgt/"+testenv.RealmName+"@"+goRealm)

	db := kdb.NewDatabase(goRealm)
	for _, item := range []struct{ name, password string }{
		{"alice", "alice-password"},
		{"krbtgt/" + goRealm, "go-tgt-password"},
		{"krbtgt/" + testenv.RealmName + "@" + goRealm, "shared-password"},
	} {
		if err := db.AddPrincipal(item.name, item.password, 1); err != nil {
			t.Fatal(err)
		}
	}
	server := &kdc.Server{
		Realm:            goRealm,
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
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx, udpConn, tcpListener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	now := time.Now().UTC().Truncate(time.Second)
	kclient := &client.Client{
		Now: func() time.Time { return now },
		Exchange: func(ctx context.Context, realm string, payload []byte) ([]byte, error) {
			if realm == goRealm {
				return server.HandleMessage(payload), nil
			}
			conn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			exchange := transport.Exchange{Timeout: 5 * time.Second, UDPPreferenceLimit: 1}
			return exchange.Request(ctx, conn, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: mitRealm.Port}, payload)
		},
	}
	user := principal.Principal{Realm: goRealm, NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("Go AS exchange: %v", err)
	}
	service := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	}
	credentials, err := kclient.TGSExchange(context.Background(), tgt, service)
	if err != nil {
		t.Fatalf("cross-realm TGS exchange: %v", err)
	}
	if credentials.Server.Realm != testenv.RealmName ||
		credentials.Server.Components[0] != "host" ||
		credentials.Server.Components[1] != "service.test" {
		t.Fatalf("service credentials = %#v", credentials)
	}
	outputPath := filepath.Join(mitRealm.Dir, "go-cross-realm.ccache")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	cache := &ccache.Cache{
		DefaultPrincipal: user,
		Credentials:      []ccache.Credential{tgt.ToCCacheCredential(), credentials.ToCCacheCredential()},
	}
	if err := ccache.Write(output, cache); err != nil {
		output.Close()
		t.Fatalf("write ccache: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	listing := mitRealm.Run(t, "", "/usr/bin/klist", "-e", "-c", outputPath)
	if !strings.Contains(listing, "alice@"+goRealm) ||
		!strings.Contains(listing, "host/service.test@"+testenv.RealmName) {
		t.Fatalf("MIT klist does not show cross-realm credentials:\n%s", listing)
	}
}
