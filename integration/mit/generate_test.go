//go:build integration

package mit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/internal/testenv"
)

func TestGenerateFixtures(t *testing.T) {
	realm := testenv.Start(t)
	keytabListing := realm.Run(t, "", "/usr/bin/klist", "-k", "-e", realm.Keytab)
	t.Logf("MIT keytab listing:\n%s", keytabListing)
	for _, enctype := range []string{
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
	} {
		if !strings.Contains(keytabListing, enctype) {
			t.Fatalf("keytab listing lacks %s", enctype)
		}
	}
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", realm.Cache, "alice")
	cacheListing := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", realm.Cache)
	t.Logf("MIT ccache listing:\n%s", cacheListing)
	if !strings.Contains(cacheListing, testenv.RealmName) {
		t.Fatalf("ccache listing does not mention realm %s", testenv.RealmName)
	}

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	keytabDestination := filepath.Join(root, "testdata", "keytabs", "mit-multi-enctype.keytab")
	ccacheDestination := filepath.Join(root, "testdata", "ccaches", "mit-alice.ccache")
	if err := os.MkdirAll(filepath.Dir(keytabDestination), 0o755); err != nil {
		t.Fatalf("create keytab fixture directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(ccacheDestination), 0o755); err != nil {
		t.Fatalf("create ccache fixture directory: %v", err)
	}
	testenv.CopyFile(t, realm.Keytab, keytabDestination)
	testenv.CopyFile(t, realm.Cache, ccacheDestination)
	t.Logf("wrote %s and %s", keytabDestination, ccacheDestination)
}
