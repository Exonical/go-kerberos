package ccache

import (
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestRetrieveSupportedKeyTypes(t *testing.T) {
	client := mustMatchPrincipal(t, "alice@EXAMPLE.COM")
	server := mustMatchPrincipal(t, "host/server@EXAMPLE.COM")
	cache, err := Resolve("MEMORY:match-supported")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if err := cache.Write(&Cache{
		DefaultPrincipal: *client,
		Credentials: []Credential{
			{Client: *client, Server: *server, Enctype: 999},
			{Client: *client, Server: *server, Enctype: crypto.EnctypeAES128SHA1},
			{Client: *client, Server: *server, Enctype: crypto.EnctypeAES256SHA1},
		},
	}); err != nil {
		t.Fatal(err)
	}
	match := Credential{Client: *client, Server: *server}
	got, err := cache.Retrieve(match, MITMatchServerName|MITMatchSupportedKTypes)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enctype != crypto.EnctypeAES256SHA1 {
		t.Fatalf("enctype = %d, want %d", got.Enctype, crypto.EnctypeAES256SHA1)
	}
	match.Enctype = crypto.EnctypeAES128SHA1
	got, err = cache.Retrieve(match, MITMatchServerName|MITMatchSupportedKTypes)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enctype != crypto.EnctypeAES256SHA1 {
		t.Fatalf("requested enctype = %d, want preferred %d", got.Enctype, crypto.EnctypeAES256SHA1)
	}
}

func TestRetrieveSupportedKeyTypesUsesConfiguredOrder(t *testing.T) {
	client := mustMatchPrincipal(t, "alice@EXAMPLE.COM")
	server := mustMatchPrincipal(t, "host/server@EXAMPLE.COM")
	cache, err := ResolveWithConfig("MEMORY:match-configured-order", &config.Config{
		DefaultTGSEnctypes: []int32{crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if err := cache.Write(&Cache{
		DefaultPrincipal: *client,
		Credentials: []Credential{
			{Client: *client, Server: *server, Enctype: crypto.EnctypeAES256SHA1},
			{Client: *client, Server: *server, Enctype: crypto.EnctypeAES128SHA1},
		},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Retrieve(
		Credential{Client: *client, Server: *server},
		MITMatchServerName|MITMatchSupportedKTypes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enctype != crypto.EnctypeAES128SHA1 {
		t.Fatalf("configured enctype = %d, want %d", got.Enctype, crypto.EnctypeAES128SHA1)
	}
}

func TestRetrieveSupportedKeyTypesRejectsUnsupportedOnly(t *testing.T) {
	client := mustMatchPrincipal(t, "alice@EXAMPLE.COM")
	server := mustMatchPrincipal(t, "host/server@EXAMPLE.COM")
	cache, err := Resolve("MEMORY:match-unsupported")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if err := cache.Write(&Cache{
		DefaultPrincipal: *client,
		Credentials: []Credential{
			{Client: *client, Server: *server, Enctype: 999},
		},
	}); err != nil {
		t.Fatal(err)
	}
	_, err = cache.Retrieve(
		Credential{Client: *client, Server: *server},
		MITMatchServerName|MITMatchSupportedKTypes,
	)
	if err == nil {
		t.Fatal("unsupported credential unexpectedly matched")
	}
}

func TestRetrieveDefaultsToNonUserToUserCredentials(t *testing.T) {
	client := mustMatchPrincipal(t, "alice@EXAMPLE.COM")
	server := mustMatchPrincipal(t, "host/server@EXAMPLE.COM")
	cache, err := Resolve("MEMORY:match-skey")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if err := cache.Write(&Cache{
		DefaultPrincipal: *client,
		Credentials: []Credential{
			{Client: *client, Server: *server, IsSKey: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	_, err = cache.Retrieve(
		Credential{Client: *client, Server: *server},
		MITMatchServerName,
	)
	if err == nil {
		t.Fatal("user-to-user credential unexpectedly matched without MATCH_IS_SKEY")
	}
}

func TestRetrieveServerNameOnlyIgnoresServerRealm(t *testing.T) {
	client := mustMatchPrincipal(t, "alice@EXAMPLE.COM")
	stored := mustMatchPrincipal(t, "host/server@OTHER.COM")
	requested := mustMatchPrincipal(t, "host/server@EXAMPLE.COM")
	cache, err := Resolve("MEMORY:match-server-realm")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if err := cache.Write(&Cache{
		DefaultPrincipal: *client,
		Credentials:      []Credential{{Client: *client, Server: *stored, Enctype: crypto.EnctypeAES256SHA1}},
	}); err != nil {
		t.Fatal(err)
	}
	match := Credential{Client: *client, Server: *requested}
	if _, err := cache.Retrieve(match, 0); err == nil {
		t.Fatal("credential matched without server-name-only flag")
	}
	if _, err := cache.Retrieve(match, MITMatchServerName); err != nil {
		t.Fatalf("server-name-only retrieval: %v", err)
	}
}

func TestRetrieveAndRemoveFileDirMemory(t *testing.T) {
	client := mustMatchPrincipal(t, "alice@EXAMPLE.COM")
	server := mustMatchPrincipal(t, "host/server@EXAMPLE.COM")
	credential := Credential{Client: *client, Server: *server, Enctype: crypto.EnctypeAES256SHA1}
	names := []string{
		"MEMORY:match-local",
		"FILE:" + filepath.Join(t.TempDir(), "cache"),
		"DIR:" + filepath.Join(t.TempDir(), "collection"),
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			cache, err := Resolve(name)
			if err != nil {
				t.Fatal(err)
			}
			defer cache.Close()
			if err := cache.Write(&Cache{DefaultPrincipal: *client, Credentials: []Credential{credential}}); err != nil {
				t.Fatal(err)
			}
			match := Credential{Client: *client, Server: *server}
			if _, err := cache.Retrieve(match, MITMatchServerName); err != nil {
				t.Fatal(err)
			}
			if err := cache.Remove(match, 0); err != nil {
				t.Fatal(err)
			}
			value, err := cache.Read()
			if err != nil {
				t.Fatal(err)
			}
			if len(value.Credentials) != 0 {
				t.Fatalf("credentials after removal = %d, want 0", len(value.Credentials))
			}
		})
	}
}

func mustMatchPrincipal(t *testing.T, value string) *principal.Principal {
	t.Helper()
	result, err := principal.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
