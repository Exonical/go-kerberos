//go:build integration

package mit_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func goCommandPath(t *testing.T, name string) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration source")
	}
	return filepath.Join(filepath.Dir(source), "..", "..", "cmd", name)
}

func TestGoCacheCommandsAgainstMITCollection(t *testing.T) {
	realm := testenv.Start(t)
	dir := filepath.Join(realm.Dir, "cli-collection")
	collection, err := ccache.Resolve("DIR:" + dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"alice", "bob"} {
		cache, err := collection.New()
		if err != nil {
			t.Fatal(err)
		}
		p := principal.Principal{Realm: testenv.RealmName,
			NameType: principal.NTPrincipal, Components: []string{name}}
		if err := cache.Write(&ccache.Cache{DefaultPrincipal: p}); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := cache.SetPrimary(); err != nil {
				t.Fatal(err)
			}
		}
	}
	caches, err := collection.Collection()
	if err != nil {
		t.Fatal(err)
	}
	if len(caches) != 2 {
		t.Fatalf("cache count = %d, want 2", len(caches))
	}
	target := caches[1].Name()
	realm.Run(t, "", "go", "run", goCommandPath(t, "gokswitch"), "-c", target)
	listing := realm.Run(t, "", "/usr/bin/klist", "-l", "-c", "DIR:"+dir)
	bobIndex := strings.Index(listing, "bob@"+testenv.RealmName)
	aliceIndex := strings.Index(listing, "alice@"+testenv.RealmName)
	if bobIndex < 0 || aliceIndex < 0 || bobIndex > aliceIndex {
		t.Fatalf("MIT klist did not report bob as primary first:\n%s", listing)
	}
	allBefore := realm.Run(t, "", "/usr/bin/klist", "-A", "-c", "DIR:"+dir)
	if strings.Count(allBefore, "Default principal:") != 2 {
		t.Fatalf("MIT klist -A reported unexpected collection:\n%s", allBefore)
	}
	realm.Run(t, "", "go", "run", goCommandPath(t, "gokdestroy"), "-A", "-c", "DIR:"+dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "tkt") {
			t.Fatalf("gokdestroy left cache %s", entry.Name())
		}
	}
}

func TestGoUtilKeytabConsumedByMIT(t *testing.T) {
	realm := testenv.Start(t)
	path := filepath.Join(realm.Dir, "gokutil.keytab")
	realm.Run(t, "", "go", "run", goCommandPath(t, "gokutil"), "addent", "-k", path,
		"-p", "host/cli.test@"+testenv.RealmName, "-kvno", "1", "-e",
		"aes256-cts-hmac-sha1-96", "-key",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	listing := realm.Run(t, "", "/usr/bin/klist", "-k", "-e", path)
	if !strings.Contains(listing, "host/cli.test@"+testenv.RealmName) {
		t.Fatalf("MIT klist did not read gokutil keytab:\n%s", listing)
	}
	ktutil := realm.Run(t, "read_kt "+path+"\nlist\nquit\n", "/usr/bin/ktutil")
	if !strings.Contains(ktutil, "host/cli.test@"+testenv.RealmName) {
		t.Fatalf("MIT ktutil did not read gokutil keytab:\n%s", ktutil)
	}
	parsed, err := keytab.Resolve(path)
	if err != nil {
		t.Fatalf("Go did not read its keytab: %v", err)
	}
	if len(parsed.EntriesSnapshot()) != 1 {
		t.Fatalf("Go read %d keytab entries, want 1",
			len(parsed.EntriesSnapshot()))
	}
}

func TestGoPasswdAgainstMITKadmind(t *testing.T) {
	realm := testenv.Start(t)
	realm.Run(t, "alice-password\nalice-cli-password\nalice-cli-password\n",
		"go", "run", goCommandPath(t, "gokpasswd"), "alice")
	realm.Run(t, "alice-cli-password\n", "/usr/bin/kinit", "-c", realm.Cache, "alice")
}
