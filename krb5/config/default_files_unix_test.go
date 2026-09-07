//go:build !windows

package config

import "testing"

func TestDefaultConfigFilesUnix(t *testing.T) {
	t.Setenv("KRB5_CONFIG", "/tmp/krb5-test.conf")
	files := DefaultConfigFiles(false)
	if len(files) != 1 || files[0] != "/tmp/krb5-test.conf" {
		t.Fatalf("default config files = %v", files)
	}
	files = DefaultConfigFiles(true)
	if len(files) != 1 || files[0] != "/etc/krb5.conf" {
		t.Fatalf("secure config files = %v", files)
	}
}
