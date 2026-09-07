//go:build windows

package config

import (
	"regexp"
	"strings"
	"testing"
)

func TestExpandPathTokensWindows(t *testing.T) {
	sid, err := ExpandPathTokens("%{USERID}")
	if err != nil && strings.Contains(err.Error(), "empty SID") {
		t.Skip("Windows runner has no token-owner SID")
	}
	for _, token := range []string{
		"APPDATA", "COMMON_APPDATA", "LOCAL_APPDATA", "SYSTEM", "WINDOWS",
		"USERCONFIG", "COMMONCONFIG", "LIBDIR", "BINDIR", "SBINDIR",
		"TEMP", "euid", "USERID", "uid",
	} {
		value, err := ExpandPathTokens("%{" + token + "}")
		if err != nil {
			t.Fatalf("ExpandPathTokens(%s): %v", token, err)
		}
		if value == "" {
			t.Fatalf("ExpandPathTokens(%s) returned an empty value", token)
		}
	}
	for _, token := range []string{"USERCONFIG", "COMMONCONFIG"} {
		value, err := ExpandPathTokens("%{" + token + "}")
		if err != nil {
			t.Fatalf("ExpandPathTokens(%s): %v", token, err)
		}
		if !strings.HasSuffix(value, `\MIT\Kerberos5`) {
			t.Fatalf("ExpandPathTokens(%s) = %q, want MIT config suffix", token, value)
		}
	}
	value, err := ExpandPathTokens(`left/%{TEMP}/right`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(value, "/") {
		t.Fatalf("expanded Windows path contains slash: %q", value)
	}
	sid, err = ExpandPathTokens("%{USERID}")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^S-\d-(?:\d+-)+\d+$`).MatchString(sid) {
		t.Fatalf("USERID = %q, want SID format", sid)
	}
	if _, err := ExpandPathTokens("%{username}"); err == nil {
		t.Fatal("ExpandPathTokens(%{username}) unexpectedly succeeded on Windows")
	}
}
