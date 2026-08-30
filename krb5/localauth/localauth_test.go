package localauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func testPrincipal(t *testing.T, value string) principal.Principal {
	t.Helper()
	p, err := principal.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return *p
}

func TestAnameToLocalnameNamesAndRules(t *testing.T) {
	cfg, err := config.Parse([]byte(`[libdefaults]
default_realm = EXAMPLE.COM
[realms]
EXAMPLE.COM = {
  auth_to_local_names = {
    alice/admin = deploy
  }
  auth_to_local = RULE:[2:$1](.*)s/^.*$/mapped/
  auth_to_local = RULE:[1:$1](.*)s/^([^@]+)$/user/
  auth_to_local = DEFAULT
}
`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, principal, want string
	}{
		{"explicit name", "alice/admin@EXAMPLE.COM", "deploy"},
		{"rule", "bob/admin@EXAMPLE.COM", "mapped"},
		{"default", "carol@EXAMPLE.COM", "user"},
	}
	for _, test := range tests {
		got, err := AnameToLocalname(cfg, testPrincipal(t, test.principal))
		if err != nil || got != test.want {
			t.Errorf("%s: got %q, %v; want %q", test.name, got, err, test.want)
		}
	}
	if got, err := AnameToLocalname(cfg, testPrincipal(t, "x@OTHER.COM")); err != nil || got != "user" {
		t.Fatalf("cross-realm rule = %q, %v", got, err)
	}
}

func TestAnameToLocalnameImplicitDefault(t *testing.T) {
	cfg := &config.Config{DefaultRealm: "EXAMPLE.COM"}
	got, err := AnameToLocalname(cfg, testPrincipal(t, "alice@EXAMPLE.COM"))
	if err != nil || got != "alice" {
		t.Fatalf("implicit default = %q, %v", got, err)
	}
	if _, err := AnameToLocalname(cfg, testPrincipal(t, "alice/admin@EXAMPLE.COM")); err == nil {
		t.Fatal("multi-component principal unexpectedly translated")
	}
}

func TestAnameToLocalnameRuleSelectionAndSubstitution(t *testing.T) {
	cfg := &config.Config{
		DefaultRealm: "EXAMPLE.COM",
		RealmAuthToLocal: map[string][]string{
			"EXAMPLE.COM": {"RULE:[2:$1_$2](^alice_admin$)s/admin/ops/"},
		},
	}
	got, err := AnameToLocalname(cfg, testPrincipal(t, "alice/admin@EXAMPLE.COM"))
	if err != nil || got != "alice_ops" {
		t.Fatalf("translation = %q, %v", got, err)
	}
	_, err = AnameToLocalname(&config.Config{
		DefaultRealm:     "EXAMPLE.COM",
		RealmAuthToLocal: map[string][]string{"EXAMPLE.COM": {"RULE:[bad:$1]"}},
	}, testPrincipal(t, "alice@EXAMPLE.COM"))
	if err == nil {
		t.Fatal("malformed rule unexpectedly accepted")
	}
	cfg = &config.Config{
		DefaultRealm: "EXAMPLE.COM",
		RealmAuthToLocal: map[string][]string{
			"EXAMPLE.COM": {"RULE:[1:$1](.*)s/^/$1/g"},
		},
	}
	got, err = AnameToLocalname(cfg, testPrincipal(t, "alice@EXAMPLE.COM"))
	if err != nil || got != "$1alice" {
		t.Fatalf("literal replacement = %q, %v", got, err)
	}
}

func TestKuserokK5LoginAndFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".k5login")
	p := testPrincipal(t, "alice@EXAMPLE.COM")
	if err := os.WriteFile(path, []byte(p.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ok, err := KuserokWithOptions(nil, p, "alice", KuserokOptions{
		HomeDir: dir, K5LoginPath: path,
	})
	if err != nil || !ok {
		t.Fatalf("authorized k5login = %v, %v", ok, err)
	}
	other := testPrincipal(t, "bob@EXAMPLE.COM")
	ok, err = KuserokWithOptions(nil, other, "alice", KuserokOptions{
		HomeDir: dir, K5LoginPath: path,
	})
	if err != nil || ok {
		t.Fatalf("unauthorized k5login = %v, %v", ok, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		DefaultRealm:     "EXAMPLE.COM",
		RealmAuthToLocal: map[string][]string{"EXAMPLE.COM": {"DEFAULT"}},
	}
	ok, err = KuserokWithOptions(cfg, p, "alice", KuserokOptions{HomeDir: dir})
	if err != nil || !ok {
		t.Fatalf("fallback = %v, %v", ok, err)
	}
}

func TestKuserokNonAuthoritativeFallsBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".k5login")
	if err := os.WriteFile(path, []byte("other@EXAMPLE.COM\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		DefaultRealm:     "EXAMPLE.COM",
		RealmAuthToLocal: map[string][]string{"EXAMPLE.COM": {"DEFAULT"}},
	}
	ok, err := KuserokWithOptions(cfg, testPrincipal(t, "alice@EXAMPLE.COM"), "alice",
		KuserokOptions{HomeDir: dir, K5LoginPath: path, K5LoginAuthoritative: false, AuthoritativeSet: true})
	if err != nil || !ok {
		t.Fatalf("non-authoritative fallback = %v, %v", ok, err)
	}
}

func TestSelectIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".k5identity")
	if err := os.WriteFile(path, []byte(`# ignored
alice@EXAMPLE.COM realm=EXAMPLE.COM service=host host=*.example.com
bob@EXAMPLE.COM realm=OTHER.COM
`), 0600); err != nil {
		t.Fatal(err)
	}
	server := principal.Principal{
		Realm: "EXAMPLE.COM", NameType: principal.NTSrvHst,
		Components: []string{"host", "web.example.com"},
	}
	got, ok, err := SelectIdentity(path, server)
	if err != nil || !ok || got.String() != "alice@EXAMPLE.COM" {
		t.Fatalf("identity = %v, %v, %v", got, ok, err)
	}
	server.Components[1] = "other.invalid"
	if _, ok, err := SelectIdentity(path, server); err != nil || ok {
		t.Fatalf("unmatched identity = %v, %v", ok, err)
	}
}
