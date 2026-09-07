//go:build windows

package config

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	windowsConfigRegistryPath = `Software\MIT\Kerberos5`
	windowsKnownFolderPath    = windows.KnownFolderPath
	windowsExecutablePath     = os.Executable
	windowsConfigFileExists   = func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}
)

func defaultConfigFiles(secure bool) []string {
	files := make([]string, 0, 5)
	if !secure {
		if path := os.Getenv("KRB5_CONFIG"); path != "" {
			files = append(files, path)
		}
		if path := windowsConfigRegistryValue(registry.CURRENT_USER, "config"); path != "" {
			files = append(files, path)
		}
	}
	if path := windowsConfigRegistryValue(registry.LOCAL_MACHINE, "config"); path != "" {
		files = append(files, path)
	}
	if !secure {
		if appData := windowsKnownFolder(windows.FOLDERID_RoamingAppData); appData != "" {
			path := filepath.Join(appData, "MIT", "Kerberos5", "krb5.ini")
			if windowsConfigFileExists(path) {
				files = append(files, path)
			}
		}
	}
	if windowsDir := os.Getenv("WINDIR"); windowsDir != "" {
		files = append(files, filepath.Join(windowsDir, "krb5.ini"))
	}
	if executable, err := windowsExecutablePath(); err == nil {
		path := filepath.Join(filepath.Dir(executable), "krb5.ini")
		if windowsConfigFileExists(path) {
			files = append(files, path)
		}
	}
	return files
}

func windowsConfigRegistryValue(root registry.Key, name string) string {
	key, err := registry.OpenKey(root, windowsConfigRegistryPath, registry.QUERY_VALUE)
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

func windowsKnownFolder(folderID *windows.KNOWNFOLDERID) string {
	path, err := windowsKnownFolderPath(folderID, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return ""
	}
	return strings.TrimRight(path, `\/`)
}
