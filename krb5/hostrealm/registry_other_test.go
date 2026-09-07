//go:build !windows

package hostrealm

import "testing"

func TestRegistryDefaultRealmOther(t *testing.T) {
	if got := registryDefaultRealm(); got != "" {
		t.Fatalf("non-Windows registry realm = %q", got)
	}
}
