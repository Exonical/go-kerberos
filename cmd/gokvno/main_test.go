package main

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/config"
)

func TestServicePrincipalUsesDefaultRealm(t *testing.T) {
	value, err := servicePrincipal("host/service.test", &config.Config{DefaultRealm: "EXAMPLE.COM"})
	if err != nil {
		t.Fatal(err)
	}
	if value.String() != "host/service.test@EXAMPLE.COM" {
		t.Fatalf("service = %s", value)
	}
}

func TestParseVNOArgsErrors(t *testing.T) {
	if _, err := parseVNOArgs([]string{"-c"}); err == nil {
		t.Fatal("missing cache path accepted")
	}
	if _, err := parseVNOArgs(nil); err == nil {
		t.Fatal("missing service accepted")
	}
}
