package config

import (
	"fmt"
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

func TestCapathRealmPath(t *testing.T) {
	cfg, err := Parse([]byte(`[capaths]
 A = {
  C = B
  C = .
 }
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cfg.RealmPath("A", "C"); err == nil {
		t.Fatal("mixed direct and intermediate capath unexpectedly accepted")
	}
	cfg, err = Parse([]byte(`[capaths]
 A = {
  C = B
  C = D
 }
`))
	if err != nil {
		t.Fatal(err)
	}
	path, ok, err := cfg.RealmPath("A", "C")
	if err != nil || !ok {
		t.Fatalf("RealmPath = %#v, %v, %v", path, ok, err)
	}
	if len(path) != 4 || path[0] != "A" || path[1] != "B" || path[2] != "D" || path[3] != "C" {
		t.Fatalf("RealmPath = %#v", path)
	}
	cfg, err = Parse([]byte(`[capaths]
 A = {
  C = B
 }
`))
	if err != nil {
		t.Fatal(err)
	}
	if path, ok, err := cfg.RealmPath("A", "C"); err != nil || !ok ||
		len(path) != 3 || path[1] != "B" {
		t.Fatalf("single intermediate RealmPath = %#v, %v, %v", path, ok, err)
	}
}

func TestCapathRealmPathRejectsLoopsAndExcessHops(t *testing.T) {
	cfg := &Config{CapathOptions: map[string]map[string][]string{
		"A": {"C": {"B", "A"}},
	}}
	if _, _, err := cfg.RealmPath("A", "C"); err == nil {
		t.Fatal("capath loop unexpectedly accepted")
	}
	values := make([]string, 10)
	for i := range values {
		values[i] = fmt.Sprintf("R%d", i)
	}
	cfg.CapathOptions["A"]["C"] = values
	if _, _, err := cfg.RealmPath("A", "C"); err == nil {
		t.Fatal("excessive capath unexpectedly accepted")
	}
}

func TestCapathRealmPathDirect(t *testing.T) {
	cfg := &Config{CapathOptions: map[string]map[string][]string{
		"A": {"C": {"."}},
	}}
	path, ok, err := cfg.RealmPath("A", "C")
	if err != nil || !ok || len(path) != 2 || path[0] != "A" || path[1] != "C" {
		t.Fatalf("direct RealmPath = %#v, %v, %v", path, ok, err)
	}
}
