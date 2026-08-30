//go:build integration

package mit_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestMITPythonCcacheCollectionScenarios(t *testing.T) {
	realm := testenv.Start(t)
	dir := filepath.Join(realm.Dir, "python-ccache-collection")
	ccname := "DIR:" + dir

	collection, err := ccache.Resolve(ccname)
	if err != nil {
		t.Fatalf("resolve Go DIR collection: %v", err)
	}
	entries := []string{
		"alice",
		"bob",
	}
	for _, name := range entries {
		handle, err := collection.New()
		if err != nil {
			t.Fatalf("create Go DIR subsidiary: %v", err)
		}
		user := principal.Principal{
			Realm: testenv.RealmName, NameType: principal.NTPrincipal,
			Components: []string{name},
		}
		if err := handle.Write(&ccache.Cache{
			DefaultPrincipal: user,
			Credentials: []ccache.Credential{{
				Client: user,
				Server: principal.Principal{
					Realm: testenv.RealmName, NameType: principal.NTPrincipal,
					Components: []string{"krbtgt", testenv.RealmName},
				},
				TicketFlags: 0x40000000,
				Ticket:      []byte("MIT Python suite ccache scenario"),
			}},
		}); err != nil {
			t.Fatalf("write Go DIR subsidiary for %s: %v", name, err)
		}
		if err := handle.SetPrimary(); err != nil {
			t.Fatalf("set Go DIR primary for %s: %v", name, err)
		}
	}

	listing := realm.Run(t, "", "/usr/bin/klist", "-l", "-c", ccname)
	if !strings.Contains(listing, "alice@"+testenv.RealmName) ||
		!strings.Contains(listing, "bob@"+testenv.RealmName) {
		t.Fatalf("MIT klist did not show DIR collection members:\n%s", listing)
	}

	caches, err := collection.Collection()
	if err != nil {
		t.Fatalf("read Go DIR collection: %v", err)
	}
	if len(caches) != 2 {
		t.Fatalf("MIT DIR collection cache count = %d, want 2", len(caches))
	}
	seen := make(map[string]bool, len(caches))
	for _, handle := range caches {
		cache, err := handle.Read()
		if err != nil {
			t.Fatalf("read MIT DIR subsidiary: %v", err)
		}
		seen[cache.DefaultPrincipal.String()] = true
	}
	for _, name := range []string{"alice@" + testenv.RealmName, "bob@" + testenv.RealmName} {
		if !seen[name] {
			t.Fatalf("MIT DIR collection lacks %s", name)
		}
	}

	all := realm.Run(t, "", "/usr/bin/klist", "-A", "-c", ccname)
	if strings.Count(all, "Default principal:") != 2 {
		t.Fatalf("MIT klist -A reported unexpected collection:\n%s", all)
	}
}
