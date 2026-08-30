package config

import (
	"testing"
	"time"
)

func TestMITDurationParserSupportedCases(t *testing.T) {
	tests := map[string]time.Duration{
		"3d":          3 * 24 * time.Hour,
		"3h":          3 * time.Hour,
		"3m":          3 * time.Minute,
		"3s":          3 * time.Second,
		"3d 4h 5m 6s": 3*24*time.Hour + 4*time.Hour + 5*time.Minute + 6*time.Second,
		"42":          42 * time.Second,
		"12h":         12 * time.Hour,
		"1d 0h 0m 0s": 24 * time.Hour,
		"12345s":      12345 * time.Second,
	}
	for input, want := range tests {
		got, err := ParseDuration(input)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
	for _, input := range []string{"3dd", "3:4", "1-2"} {
		if _, err := ParseDuration(input); err == nil {
			t.Errorf("ParseDuration(%q) accepted malformed duration", input)
		}
	}
}

func TestMITConfigurationDefaultsAndCapaths(t *testing.T) {
	cfg, err := Parse([]byte(`[libdefaults]
default_realm = EXAMPLE.COM
default_ccache_name = FILE:/tmp/krb5cc_test
permitted_enctypes = aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96
[realms]
EXAMPLE.COM = {
  kdc = kdc.example.com
}
[domain_realm]
.example.com = EXAMPLE.COM
[capaths]
EXAMPLE.COM = {
  OTHER.COM = INTERMEDIATE.COM
}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultRealm != "EXAMPLE.COM" ||
		cfg.DefaultCCacheName != "FILE:/tmp/krb5cc_test" {
		t.Fatalf("defaults = %#v", cfg)
	}
	if got, ok := cfg.RealmForHost("host.example.com"); !ok || got != "EXAMPLE.COM" {
		t.Fatalf("host realm = %q, %v", got, ok)
	}
	if got, ok := cfg.RealmForHostWithFallback("host.other.test"); !ok || got != "OTHER.TEST" {
		t.Fatalf("fallback realm = %q, %v", got, ok)
	}
	path, ok, err := cfg.RealmPath("EXAMPLE.COM", "OTHER.COM")
	if err != nil || !ok || len(path) != 3 ||
		path[0] != "EXAMPLE.COM" || path[1] != "INTERMEDIATE.COM" || path[2] != "OTHER.COM" {
		t.Fatalf("capath = %#v, %v, %v", path, ok, err)
	}
}

func TestMITKDCEnctypeListTokenization(t *testing.T) {
	cfg, err := ParseKDCConf([]byte(`[realms]
EXAMPLE.COM = {
  supported_enctypes = aes256-cts-hmac-sha1-96:normal, aes128-cts-hmac-sha1-96:normal
  spake_preauth_indicator = otp, hardware
}
`))
	if err != nil {
		t.Fatal(err)
	}
	realm, ok := cfg.Realm("EXAMPLE.COM")
	if !ok || len(realm.SupportedEnctypes) != 2 ||
		realm.SupportedEnctypes[0] != "aes256-cts-hmac-sha1-96:normal" ||
		len(realm.SPAKEPreauthIndicators) != 2 ||
		realm.SPAKEPreauthIndicators[1] != "hardware" {
		t.Fatalf("KDC enctype/indicator lists = %#v", realm)
	}
}
