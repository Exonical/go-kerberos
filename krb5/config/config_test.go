package config

import (
	"testing"
	"time"
)

const sampleConfig = `
[libdefaults]
    default_realm = TEST.REALM
    dns_lookup_kdc = true
    dns_lookup_realm = false
    rdns = false
    canonicalize = true
    clockskew = 300
    ticket_lifetime = 24h
    renew_lifetime = 1d
    forwardable = yes
    proxiable = no
    permitted_enctypes = aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96
    unknown_future_option = tolerated
[realms]
    TEST.REALM = {
        kdc = kdc.test
    }
[domain_realm]
    .test = TEST.REALM
[capaths]
    TEST.REALM = {
        OTHER.REALM = .
    }
`

func TestParseMITConfigSectionsAndOptions(t *testing.T) {
	cfg, err := Parse([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.DefaultRealm != "TEST.REALM" || !cfg.DNSLookupKDC || cfg.DNSLookupRealm || cfg.RDNS {
		t.Fatalf("libdefaults = %#v", cfg)
	}
	if cfg.ClockSkew != 300*time.Second || cfg.TicketLifetime != 24*time.Hour || cfg.RenewLifetime != 24*time.Hour {
		t.Fatalf("durations = %#v", cfg)
	}
	if len(cfg.Realms) == 0 || len(cfg.DomainRealm) == 0 || len(cfg.Capaths) == 0 {
		t.Fatalf("sections not parsed: %#v", cfg)
	}
}

func TestParseMITDurations(t *testing.T) {
	tests := map[string]time.Duration{"24h": 24 * time.Hour, "1d": 24 * time.Hour, "36000": 10 * time.Hour}
	for input, want := range tests {
		got, err := ParseDuration(input)
		if err != nil {
			t.Fatalf("ParseDuration(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ParseDuration(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestConfigMalformedSection(t *testing.T) {
	if _, err := Parse([]byte("[libdefaults\nfoo = bar")); err == nil {
		t.Fatal("malformed section unexpectedly accepted")
	}
}
