package ccache

import (
	"os"
	"path/filepath"
	"testing"

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
