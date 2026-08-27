//go:build integration

package mit_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestGoClientS4U2SelfAgainstMITKDC(t *testing.T) {
	realm := testenv.Start(t)
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"modprinc +ok_to_auth_as_delegate host/server.test")
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read realm config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse realm config: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	service := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"host", "server.test"},
	}
	user := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	kclient := &client.Client{Config: cfg, Now: func() time.Time { return now }}
	tgt, err := kclient.ASExchange(context.Background(), service, "host-password")
	if err != nil {
		t.Fatalf("service AS exchange: %v", err)
	}
	credentials, err := kclient.S4U2Self(context.Background(), tgt, user)
	if err != nil {
		t.Fatalf("S4U2Self against MIT KDC: %v", err)
	}
	if credentials.Client.String() != user.String() {
		t.Fatalf("S4U2Self client = %s, want %s", credentials.Client, user)
	}
	if credentials.Server.String() != service.String() {
		t.Fatalf("S4U2Self server = %s, want %s", credentials.Server, service)
	}
	outputPath := filepath.Join(realm.Dir, "go-client-s4u.ccache")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("create Go client ccache: %v", err)
	}
	cache := &ccache.Cache{
		DefaultPrincipal: user,
		Credentials:      []ccache.Credential{credentials.ToCCacheCredential()},
	}
	if err := ccache.Write(output, cache); err != nil {
		output.Close()
		t.Fatalf("write Go client ccache: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close Go client ccache: %v", err)
	}
	listing := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", outputPath)
	t.Logf("MIT klist of the S4U2Self ticket:\n%s", listing)
	for _, expected := range []string{
		"alice@" + testenv.RealmName,
		"host/server.test@" + testenv.RealmName,
	} {
		if !strings.Contains(listing, expected) {
			t.Fatalf("MIT klist does not contain %s:\n%s", expected, listing)
		}
	}
}

func TestGoClientS4U2ProxyAgainstMITKDC(t *testing.T) {
	realm := testenv.Start(t)
	for _, command := range []string{
		"modprinc +ok_to_auth_as_delegate host/server.test",
		"modprinc +ok_as_delegate host/server.test",
		"addprinc -pw backend-password HTTP/backend.test",
	} {
		realm.Run(t, "", "/usr/sbin/kadmin.local", "-q", command)
	}
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read realm config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse realm config: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	service := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"host", "server.test"},
	}
	backend := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"HTTP", "backend.test"},
	}
	user := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	kclient := &client.Client{Config: cfg, Now: func() time.Time { return now }}
	tgt, err := kclient.ASExchange(context.Background(), service, "host-password")
	if err != nil {
		t.Fatalf("service AS exchange: %v", err)
	}
	evidence, err := kclient.S4U2Self(context.Background(), tgt, user)
	if err != nil {
		t.Fatalf("S4U2Self against MIT KDC: %v", err)
	}
	credentials, err := kclient.S4U2Proxy(context.Background(), tgt, evidence, backend)
	if err != nil {
		t.Skipf("MIT db2 KDB does not authorize constrained delegation: %v", err)
	}
	if credentials.Client.String() != user.String() {
		t.Fatalf("S4U2Proxy client = %s, want %s", credentials.Client, user)
	}
	if credentials.Server.String() != backend.String() {
		t.Fatalf("S4U2Proxy server = %s, want %s", credentials.Server, backend)
	}
}
