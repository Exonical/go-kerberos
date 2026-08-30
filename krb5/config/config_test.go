package config

import (
	"fmt"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
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

func TestParseCamelliaEnctypeAliases(t *testing.T) {
	cfg, err := Parse([]byte(`[libdefaults]
    default_realm = TEST.REALM
    permitted_enctypes = camellia128-cts-cmac camellia256-cts
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []int32{crypto.EnctypeCamellia128, crypto.EnctypeCamellia256}
	if fmt.Sprint(cfg.PermittedEnctypes) != fmt.Sprint(want) {
		t.Fatalf("enctypes = %v, want %v", cfg.PermittedEnctypes, want)
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

func TestKCMSocketSetting(t *testing.T) {
	cfg, err := Parse([]byte("[libdefaults]\nkcm_socket = /tmp/test-kcm.sock\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KCMSocket != "/tmp/test-kcm.sock" {
		t.Fatalf("KCMSocket = %q", cfg.KCMSocket)
	}
}

func TestDefaultRCacheNameSetting(t *testing.T) {
	cfg, err := Parse([]byte("[libdefaults]\ndefault_rcache_name = file2:/var/tmp/example.rcache2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultRCacheName != "file2:/var/tmp/example.rcache2" {
		t.Fatalf("DefaultRCacheName = %q", cfg.DefaultRCacheName)
	}
}

func TestParseLocalAuthorizationSettings(t *testing.T) {
	cfg, err := Parse([]byte(`[libdefaults]
    default_realm = EXAMPLE.COM
    k5login_directory = /etc/krb5/k5login
    k5login_authoritative = false
    k5identity = /tmp/test.k5identity
[realms]
    EXAMPLE.COM = {
        auth_to_local = RULE:[1:$1](.*)s/^/user-/
        auth_to_local_names =
        {
            Alice = deploy
        }
    }
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.K5LoginDirectory != "/etc/krb5/k5login" ||
		cfg.K5LoginAuthoritative || !cfg.K5LoginAuthoritativeSet ||
		cfg.K5IdentityPath != "/tmp/test.k5identity" {
		t.Fatalf("local authorization settings = %#v", cfg)
	}
	if len(cfg.RealmAuthToLocal["EXAMPLE.COM"]) != 1 ||
		cfg.RealmAuthToLocalNames["EXAMPLE.COM"]["Alice"][0] != "deploy" {
		t.Fatalf("local authorization mappings = %#v/%#v", cfg.RealmAuthToLocal, cfg.RealmAuthToLocalNames)
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

func TestRealmForHostMITProfileSearchOrder(t *testing.T) {
	cfg, err := Parse([]byte(`[domain_realm]
    app.example.com = EXACT
    .example.com = PARENT
    example.com = SUFFIX
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host, want string
	}{
		{"app.example.com", "EXACT"},
		{"other.example.com", "PARENT"},
		{"example.com", "SUFFIX"},
		{"other.invalid", ""},
		{"APP.EXAMPLE.COM.", "EXACT"},
	} {
		got, ok := cfg.RealmForHost(test.host)
		if (test.want == "") != !ok || got != test.want {
			t.Errorf("RealmForHost(%q) = %q, %v; want %q", test.host, got, ok, test.want)
		}
	}
	if got, ok := cfg.RealmForHostWithFallback("service.fallback.test"); !ok || got != "FALLBACK.TEST" {
		t.Fatalf("fallback realm = %q, %v", got, ok)
	}
	if _, ok := cfg.RealmForHostWithFallback("127.0.0.1"); ok {
		t.Fatal("numeric-address fallback unexpectedly matched")
	}
}

func TestParseKDCConf(t *testing.T) {
	cfg, err := ParseKDCConf([]byte(`[kdcdefaults]
    kdc_ports = 88, 750
    kdc_tcp_ports = 88
    max_life = 12h 0m 0s
[realms]
    EXAMPLE.COM = {
        max_renewable_life = 7d 0h 0m 0s
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        database_module = custom
    }
`))
	if err != nil {
		t.Fatal(err)
	}
	realm, ok := cfg.Realm("example.com")
	if !ok || len(realm.KDCPorts) != 2 || realm.KDCPorts[1] != 750 ||
		realm.KDCTCPPorts[0] != 88 || realm.MaxLife != 12*time.Hour ||
		realm.MaxRenewableLife != 7*24*time.Hour ||
		realm.MasterKeyType != "aes256-cts-hmac-sha1-96" ||
		len(realm.SupportedEnctypes) != 2 || realm.Values["database_module"][0] != "custom" {
		t.Fatalf("KDC realm = %#v", realm)
	}
	if len(cfg.Defaults["kdc_ports"]) != 2 {
		t.Fatalf("KDC defaults = %#v", cfg.Defaults)
	}
}

func TestDNSURIEnabledMITDefault(t *testing.T) {
	cfg, err := Parse([]byte(`[libdefaults]
    dns_uri_lookup = false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNSURIEnabled() {
		t.Fatal("explicit dns_uri_lookup=false ignored")
	}
	cfg, err = Parse([]byte(`[libdefaults]
    default_realm = EXAMPLE.COM
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DNSURIEnabled() {
		t.Fatal("MIT default dns_uri_lookup should be enabled")
	}
}
