//go:build windows

package ccache

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestWindowsRegistryDefaultCCache(t *testing.T) {
	oldPath := ccacheRegistryPath
	defer func() { ccacheRegistryPath = oldPath }()
	ccacheRegistryPath = `Software\GoKerberosTest\CCache\` + filepath.Base(t.TempDir())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, ccacheRegistryPath, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		key.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, ccacheRegistryPath)
	}()
	if err := key.SetStringValue("ccname", "FILE:C:\\Tickets\\krb5cc"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5CCNAME", "")
	if got := osDefaultCCacheName(); got != "FILE:C:\\Tickets\\krb5cc" {
		t.Fatalf("registry default ccache = %q", got)
	}
}

func TestWindowsCCacheDefaultPrecedenceAndFallback(t *testing.T) {
	oldPath := ccacheRegistryPath
	defer func() { ccacheRegistryPath = oldPath }()
	ccacheRegistryPath = `Software\GoKerberosTest\CCache\` + filepath.Base(t.TempDir())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, ccacheRegistryPath, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		key.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, ccacheRegistryPath)
	}()
	if err := key.SetStringValue("ccname", "FILE:C:\\Registry\\krb5cc"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5CCNAME", "FILE:C:\\Environment\\krb5cc")
	if got := osDefaultCCacheName(); got != "FILE:C:\\Environment\\krb5cc" {
		t.Fatalf("environment default ccache = %q", got)
	}
	if err := key.DeleteValue("ccname"); err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	t.Setenv("KRB5CCNAME", "")
	t.Setenv("TEMP", filepath.Join(temp, "missing"))
	t.Setenv("TMP", temp)
	t.Setenv("WINDIR", filepath.Join(temp, "windows"))
	if got := osDefaultCCacheName(); got != "FILE:"+filepath.Join(temp, "krb5cc") {
		t.Fatalf("TMP fallback ccache = %q", got)
	}
	if err := os.Mkdir(filepath.Join(temp, "windows"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := osDefaultCCacheName(); got != "FILE:"+filepath.Join(temp, "krb5cc") {
		t.Fatalf("TEMP/TMP fallback ccache = %q", got)
	}
	t.Setenv("TMP", filepath.Join(temp, "missing-tmp"))
	if got := osDefaultCCacheName(); got != "FILE:"+filepath.Join(temp, "windows", "krb5cc") {
		t.Fatalf("WINDIR fallback ccache = %q", got)
	}
}

func TestSetDefaultNameWindows(t *testing.T) {
	oldPath := ccacheRegistryPath
	defer func() { ccacheRegistryPath = oldPath }()
	ccacheRegistryPath = `Software\GoKerberosTest\CCache\` + filepath.Base(t.TempDir())
	if err := SetDefaultName("FILE:C:\\Tickets\\krb5cc"); err != nil {
		t.Fatal(err)
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, ccacheRegistryPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := key.GetStringValue("ccname")
	if err != nil || got != "FILE:C:\\Tickets\\krb5cc" {
		key.Close()
		t.Fatalf("stored default ccache = %q, %v", got, err)
	}
	key.Close()
	_ = registry.DeleteKey(registry.CURRENT_USER, ccacheRegistryPath)
}
