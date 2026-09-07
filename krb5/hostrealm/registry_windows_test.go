//go:build windows

package hostrealm

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/config"
	"golang.org/x/sys/windows/registry"
)

func TestRegistryDefaultRealmWindows(t *testing.T) {
	oldPath := hostrealmRegistryPath
	defer func() { hostrealmRegistryPath = oldPath }()
	hostrealmRegistryPath = `Software\GoKerberosTest\HostRealm\` + filepath.Base(t.TempDir())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, hostrealmRegistryPath, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		key.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, hostrealmRegistryPath)
	}()
	if err := key.SetStringValue("default_realm", "EXAMPLE.TEST"); err != nil {
		t.Fatal(err)
	}
	if got := registryDefaultRealm(); got != "EXAMPLE.TEST" {
		t.Fatalf("registry default realm = %q", got)
	}
	cfg := &config.Config{
		DefaultRealm: "PROFILE.TEST",
		DomainRealm:  map[string]string{".example.test": "PROFILE.TEST"},
	}
	realm, authoritative, err := HostRealm(context.Background(), cfg, "host.example.test", Options{})
	if err != nil || realm != "PROFILE.TEST" || !authoritative {
		t.Fatalf("domain mapping host realm = %q, authoritative=%v, err=%v",
			realm, authoritative, err)
	}
	realm, authoritative, err = HostRealm(context.Background(),
		&config.Config{DefaultRealm: "PROFILE.TEST"}, "host.example.test", Options{})
	if err != nil || realm != "EXAMPLE.TEST" || authoritative {
		t.Fatalf("registry default realm = %q, authoritative=%v, err=%v",
			realm, authoritative, err)
	}
	realm, authoritative, err = HostRealm(context.Background(), &config.Config{},
		"host.example.test", Options{Resolver: &txtResolver{}})
	if err != nil || realm != "EXAMPLE.TEST" || authoritative {
		t.Fatalf("registry without profile default = %q, authoritative=%v, err=%v",
			realm, authoritative, err)
	}
	realm, authoritative, err = HostRealm(context.Background(), nil,
		"host.example.test", Options{Resolver: &txtResolver{}})
	if err != nil || realm != "EXAMPLE.TEST" || authoritative {
		t.Fatalf("registry with nil config = %q, authoritative=%v, err=%v",
			realm, authoritative, err)
	}
	if realm, ok := FallbackRealm(&config.Config{DefaultRealm: "PROFILE.TEST"}, "host.example.test"); !ok || realm != "EXAMPLE.TEST" {
		t.Fatalf("registry fallback realm = %q, found=%v", realm, ok)
	}
	if realm, ok := FallbackRealm(nil, "host.example.test"); !ok || realm != "EXAMPLE.TEST" {
		t.Fatalf("registry fallback without config = %q, found=%v", realm, ok)
	}
}
