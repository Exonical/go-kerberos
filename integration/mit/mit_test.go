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
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestHarnessSelfTest(t *testing.T) {
	realm := testenv.Start(t)
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", realm.Cache, "alice")
	output := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", realm.Cache)
	t.Logf("MIT klist output:\n%s", output)
	if !strings.Contains(output, testenv.RealmName) {
		t.Fatalf("klist output does not mention realm %s", testenv.RealmName)
	}
	if _, err := os.Stat(realm.Keytab); err != nil {
		t.Fatalf("generated keytab: %v", err)
	}
	if _, err := os.Stat(realm.Cache); err != nil {
		t.Fatalf("generated ccache: %v", err)
	}
}

func TestMITKeytabToGoParser(t *testing.T) {
	realm := testenv.Start(t)
	file, err := os.Open(realm.Keytab)
	if err != nil {
		t.Fatalf("open MIT keytab: %v", err)
	}
	defer file.Close()
	if _, err := keytab.Read(file); err != nil {
		t.Fatalf("Go keytab parser: %v", err)
	}
}

func TestMITCCacheToGoParser(t *testing.T) {
	realm := testenv.Start(t)
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", realm.Cache, "alice")
	file, err := os.Open(realm.Cache)
	if err != nil {
		t.Fatalf("open MIT ccache: %v", err)
	}
	defer file.Close()
	if _, err := ccache.Read(file); err != nil {
		t.Fatalf("Go ccache parser: %v", err)
	}
}

func TestGoKeytabToMITKlist(t *testing.T) {
	realm := testenv.Start(t)
	outputPath := filepath.Join(realm.Dir, "go.keytab")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("create Go keytab: %v", err)
	}
	kt := &keytab.Keytab{Entries: []keytab.Entry{{
		Principal: principal.Principal{
			Realm:      testenv.RealmName,
			NameType:   principal.NTSrvHst,
			Components: []string{"host", "service.test"},
		},
		KVNO:    1,
		Enctype: 17,
		Key:     []byte{1, 2, 3, 4},
	}}}
	if err := keytab.Write(output, kt); err != nil {
		output.Close()
		t.Fatalf("Go keytab writer: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close Go keytab: %v", err)
	}
	listing := realm.Run(t, "", "/usr/bin/klist", "-k", "-e", outputPath)
	if !strings.Contains(listing, "host/service.test@"+testenv.RealmName) {
		t.Fatalf("MIT klist does not contain generated principal:\n%s", listing)
	}
}

func TestGoCCacheToMITKlist(t *testing.T) {
	realm := testenv.Start(t)
	outputPath := filepath.Join(realm.Dir, "go.ccache")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("create Go ccache: %v", err)
	}
	client := principal.Principal{
		Realm:      testenv.RealmName,
		NameType:   principal.NTPrincipal,
		Components: []string{"alice"},
	}
	cache := &ccache.Cache{
		DefaultPrincipal: client,
		Credentials: []ccache.Credential{{
			Client:      client,
			Server:      client,
			TicketFlags: 0x40000000,
			Ticket:      []byte{1, 2},
		}},
	}
	if err := ccache.Write(output, cache); err != nil {
		output.Close()
		t.Fatalf("Go ccache writer: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close Go ccache: %v", err)
	}
	listing := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", outputPath)
	if !strings.Contains(listing, testenv.RealmName) {
		t.Fatalf("MIT klist does not contain generated ccache realm:\n%s", listing)
	}
}

func TestGoClientASExchange(t *testing.T) {
	realm := testenv.Start(t)
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read realm config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse realm config: %v", err)
	}
	clientPrincipal := principal.Principal{
		Realm:      testenv.RealmName,
		NameType:   principal.NTPrincipal,
		Components: []string{"alice"},
	}
	credentials, err := (&client.Client{
		Config: cfg,
		Now:    func() time.Time { return time.Now().UTC().Truncate(time.Second) },
	}).ASExchange(context.Background(), clientPrincipal, "alice-password")
	if err != nil {
		t.Fatalf("Go AS exchange: %v", err)
	}
	outputPath := filepath.Join(realm.Dir, "go-client.ccache")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("create Go client ccache: %v", err)
	}
	cache := &ccache.Cache{
		DefaultPrincipal: clientPrincipal,
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
	if !strings.Contains(listing, "krbtgt/"+testenv.RealmName+"@"+testenv.RealmName) {
		t.Fatalf("MIT klist does not contain TGT:\n%s", listing)
	}
}

func TestGoClientTGSExchange(t *testing.T) {
	t.Skip("Go TGS exchange is not implemented")
}

func TestGoClientAPExchange(t *testing.T) {
	t.Skip("Go AP exchange is not implemented")
}

func TestFixturePathsRemainStable(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(root, "testdata", "keytabs"),
		filepath.Join(root, "testdata", "ccaches"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("fixture directory %s: %v", path, err)
		}
	}
}
