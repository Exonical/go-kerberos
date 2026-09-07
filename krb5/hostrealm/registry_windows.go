//go:build windows

package hostrealm

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

var hostrealmRegistryPath = `Software\MIT\Kerberos5`

func registryDefaultRealm() string {
	for _, root := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
		key, err := registry.OpenKey(root, hostrealmRegistryPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		value, _, err := key.GetStringValue("default_realm")
		key.Close()
		if err == nil && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
