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

func TestMITDIRCcacheToGoCollection(t *testing.T) {
	realm := testenv.Start(t)
	dir := filepath.Join(realm.Dir, "mit-collection")
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", "DIR:"+dir, "alice")

	collection, err := ccache.Resolve("DIR:" + dir)
	if err != nil {
		t.Fatalf("Resolve MIT DIR cache: %v", err)
	}
	primary, err := collection.Primary()
	if err != nil {
		t.Fatalf("resolve MIT primary: %v", err)
	}
	cache, err := primary.Read()
	if err != nil {
		t.Fatalf("read MIT primary cache: %v", err)
	}
	if cache.DefaultPrincipal.Components[0] != "alice" {
		t.Fatalf("MIT DIR default principal = %#v", cache.DefaultPrincipal)
	}
	if len(cache.Credentials) == 0 {
		t.Fatal("MIT DIR primary contains no credentials")
	}
	caches, err := collection.Collection()
	if err != nil {
		t.Fatalf("iterate MIT DIR collection: %v", err)
	}
	if len(caches) == 0 {
		t.Fatal("MIT DIR collection is empty")
	}
}

func TestGoDIRCcacheToMITTools(t *testing.T) {
	realm := testenv.Start(t)
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read realm config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse realm config: %v", err)
	}
	user := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal,
		Components: []string{"alice"},
	}
	credentials, err := (&client.Client{
		Config: cfg,
		Now:    func() time.Time { return time.Now().UTC().Truncate(time.Second) },
	}).ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("Go AS exchange: %v", err)
	}

	dir := filepath.Join(realm.Dir, "go-collection")
	collection, err := ccache.Resolve("DIR:" + dir)
	if err != nil {
		t.Fatalf("Resolve Go DIR cache: %v", err)
	}
	primary, err := collection.Primary()
	if err != nil {
		t.Fatalf("resolve Go primary: %v", err)
	}
	if err := primary.Write(&ccache.Cache{
		DefaultPrincipal: user,
		Credentials:      []ccache.Credential{credentials.ToCCacheCredential()},
	}); err != nil {
		t.Fatalf("write Go DIR cache: %v", err)
	}

	listing := realm.Run(t, "", "/usr/bin/klist", "-l", "-c", "DIR:"+dir)
	if !strings.Contains(listing, dir) && !strings.Contains(listing, "tkt") {
		t.Fatalf("MIT klist -l does not list Go DIR collection:\n%s", listing)
	}
	all := realm.Run(t, "", "/usr/bin/klist", "-A", "-c", "DIR:"+dir)
	if !strings.Contains(all, "krbtgt/"+testenv.RealmName) {
		t.Fatalf("MIT klist -A does not read Go DIR primary:\n%s", all)
	}
	kvno := realm.Run(t, "", "/usr/bin/kvno", "-c", "DIR:"+dir, "host/service.test")
	if !strings.Contains(kvno, "host/service.test@"+testenv.RealmName) {
		t.Fatalf("MIT kvno cannot use Go DIR cache:\n%s", kvno)
	}
}
