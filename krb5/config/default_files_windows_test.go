//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestDefaultConfigFilesWindowsOrderAndSecureMode(t *testing.T) {
	oldPath := windowsConfigRegistryPath
	oldKnownFolder := windowsKnownFolderPath
	oldExecutable := windowsExecutablePath
	oldExists := windowsConfigFileExists
	defer func() {
		windowsConfigRegistryPath = oldPath
		windowsKnownFolderPath = oldKnownFolder
		windowsExecutablePath = oldExecutable
		windowsConfigFileExists = oldExists
	}()

	registryPath := `Software\GoKerberosTest\Config\` + filepath.Base(t.TempDir())
	windowsConfigRegistryPath = registryPath
	key, _, err := registry.CreateKey(registry.CURRENT_USER, registryPath, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		key.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, registryPath)
	}()
	if err := key.SetStringValue("config", `C:\user\krb5.ini`); err != nil {
		t.Fatal(err)
	}

	appData := t.TempDir()
	if err := os.MkdirAll(filepath.Join(appData, "MIT", "Kerberos5"), 0700); err != nil {
		t.Fatal(err)
	}
	appConfig := filepath.Join(appData, "MIT", "Kerberos5", "krb5.ini")
	if err := os.WriteFile(appConfig, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	windowsKnownFolderPath = func(*windows.KNOWNFOLDERID, uint32) (string, error) {
		return appData, nil
	}
	module := filepath.Join(t.TempDir(), "krb5.ini")
	if err := os.WriteFile(module, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	windowsExecutablePath = func() (string, error) {
		return filepath.Join(filepath.Dir(module), "client.exe"), nil
	}
	windowsConfigFileExists = func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}
	t.Setenv("KRB5_CONFIG", `C:\env\krb5.ini`)
	t.Setenv("WINDIR", `C:\Windows`)
	files := defaultConfigFiles(false)
	if len(files) < 4 || files[0] != `C:\env\krb5.ini` ||
		files[1] != `C:\user\krb5.ini` || files[2] != appConfig ||
		files[len(files)-1] != module {
		t.Fatalf("default Windows config files = %v", files)
	}
	secure := defaultConfigFiles(true)
	if len(secure) != 2 || secure[0] != `C:\Windows\krb5.ini` || secure[1] != module {
		t.Fatalf("secure Windows config files = %v", secure)
	}
}
