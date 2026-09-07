//go:build windows

package ccache

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

var ccacheRegistryPath = `Software\MIT\Kerberos5`

func osDefaultCCacheName() string {
	if value := os.Getenv("KRB5CCNAME"); value != "" {
		return value
	}
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		if value := ccacheRegistryValue(root, "ccname"); value != "" {
			return value
		}
	}
	for _, directory := range []string{
		os.Getenv("TEMP"),
		os.Getenv("TMP"),
		os.Getenv("WINDIR"),
	} {
		if directory == "" {
			continue
		}
		if info, err := os.Stat(directory); err == nil && info.IsDir() {
			return "FILE:" + filepath.Join(directory, "krb5cc")
		}
	}
	return ""
}

func setOSDefaultCCacheName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("ccache: empty default cache name")
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, ccacheRegistryPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue("ccname", name)
}

func ccacheRegistryValue(root registry.Key, name string) string {
	key, err := registry.OpenKey(root, ccacheRegistryPath, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}
