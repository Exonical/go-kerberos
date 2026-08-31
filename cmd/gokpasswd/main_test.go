package main

import (
	"bufio"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/config"
)

func TestParsePasswdPrincipal(t *testing.T) {
	p, err := parsePasswdPrincipal("alice", &config.Config{DefaultRealm: "TEST.REALM"})
	if err != nil || p.String() != "alice@TEST.REALM" {
		t.Fatalf("principal = %v, err = %v", p, err)
	}
}

func TestPromptPasswordAndMismatch(t *testing.T) {
	var stderr strings.Builder
	value, err := promptPassword(bufio.NewReader(strings.NewReader("secret\n")), &stderr, "Password: ")
	if err != nil || value != "secret" || stderr.String() != "Password: " {
		t.Fatalf("value=%q err=%v prompt=%q", value, err, stderr.String())
	}
	if err := validatePasswordConfirmation("one", "two"); err == nil {
		t.Fatal("mismatched passwords accepted")
	}
}
