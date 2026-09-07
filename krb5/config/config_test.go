package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

func TestParsePKINITDHMinBits(t *testing.T) {
	cfg, err := Parse([]byte(`[libdefaults]
pkinit_dh_min_bits = P-256
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PKINITDHMinBits != "P-256" {
		t.Fatalf("pkinit_dh_min_bits = %q", cfg.PKINITDHMinBits)
	}
}

func TestParseKDCPKINITDHMinBits(t *testing.T) {
	cfg, err := ParseKDCConf([]byte(`[realms]
TEST.REALM = {
    pkinit_dh_min_bits = P-384
}
`))
	if err != nil {
		t.Fatal(err)
	}
	realm, ok := cfg.Realm("TEST.REALM")
	if !ok || realm.PKINITDHMinBits != "P-384" {
		t.Fatalf("KDC pkinit_dh_min_bits = %#v, ok=%v", realm.PKINITDHMinBits, ok)
	}
}

func TestParseKDCConfigRelationsAndFallback(t *testing.T) {
	profile, err := ParseKDCConf([]byte(`[kdcdefaults]
reject_bad_transit = false
host_based_services = host, ldap
no_host_referral = nfs
[realms]
EXAMPLE.COM = {
    disable_pac = true
    restrict_anonymous_to_tgt = true
    host_based_services = ftp
    no_host_referral = ldap
}
`))
	if err != nil {
		t.Fatal(err)
	}
	settings, ok := profile.Realm("example.com")
	if !ok {
		t.Fatal("realm settings missing")
	}
	if !settings.DisablePAC || settings.RejectBadTransit ||
		!settings.RestrictAnonymousToTGT {
		t.Fatalf("boolean relations = %#v", settings)
	}
	if fmt.Sprint(settings.HostBasedServices) != "[host ldap ftp]" ||
		fmt.Sprint(settings.NoHostReferral) != "[nfs ldap]" {
		t.Fatalf("referral relations = %#v", settings)
	}
}

func TestParseKDCConfigIPROPRelations(t *testing.T) {
	profile, err := ParseKDCConf([]byte(`[kdcdefaults]
 iprop_replica_poll = 1m 30s
 iprop_port = 2121
 iprop_enable = true
[realms]
 EXAMPLE.COM = {
   iprop_logfile = /var/lib/krb5kdc/replica.ulog
   iprop_ulogsize = 4096
 }`))
	if err != nil {
		t.Fatal(err)
	}
	settings, ok := profile.Realm("EXAMPLE.COM")
	if !ok {
		t.Fatal("realm settings missing")
	}
	if !settings.IpropEnabled || settings.IpropPort != 2121 ||
		settings.IpropPollTime != 90*time.Second ||
		settings.IpropUlogSize != 4096 ||
		settings.IpropLogfile != "/var/lib/krb5kdc/replica.ulog" {
		t.Fatalf("iprop settings = %#v", settings)
	}
}

func TestParseHostRealmOptions(t *testing.T) {
	cfg, err := Parse([]byte(`[libdefaults]
qualify_shortname = EXAMPLE.TEST
dns_canonicalize_hostname = fallback
realm_try_domains = 2
rdns = false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QualifyShortname != "EXAMPLE.TEST" || !cfg.QualifyShortnameSet ||
		cfg.DNSCanonicalizeHostname != "fallback" || cfg.RealmTryDomains != 2 ||
		!cfg.RealmTryDomainsSet ||
		cfg.RDNS || !cfg.RDNSSet {
		t.Fatalf("hostrealm options = %#v", cfg)
	}
	if _, err := Parse([]byte(`[libdefaults]
dns_canonicalize_hostname = invalid
`)); err == nil {
		t.Fatal("invalid dns_canonicalize_hostname accepted")
	}
}

func TestParseRealmLibDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`[libdefaults]
verify_ap_req_nofail = false
TEST.REALM = {
    verify_ap_req_nofail = true
}
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.LibDefaultValues("test.realm", "verify_ap_req_nofail"); len(got) != 1 || got[0] != "true" {
		t.Fatalf("realm libdefault = %#v, want [true]", got)
	}
	if got := cfg.LibDefaultValues("OTHER.REALM", "verify_ap_req_nofail"); len(got) != 1 || got[0] != "false" {
		t.Fatalf("global libdefault = %#v, want [false]", got)
	}
}

func TestParseClientConfigRelations(t *testing.T) {
	cfg, err := Parse([]byte(`[libdefaults]
preferred_preauth_types = 17, 16 15
request_timeout = 2m
noaddresses = false
extra_addresses = 192.0.2.10 2001:db8::10
kdc_default_options = 0x4000
TEST.REALM = {
    preferred_preauth_types = 14, 13
    request_timeout = 3s
}
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.LibDefaultValues("TEST.REALM", "preferred_preauth_types"); len(got) != 2 ||
		got[0] != "14," || got[1] != "13" {
		t.Fatalf("preferred_preauth_types = %#v", got)
	}
	if got := cfg.LibDefaultValues("TEST.REALM", "request_timeout"); len(got) != 1 ||
		got[0] != "3s" {
		t.Fatalf("request_timeout = %#v", got)
	}
	if cfg.NoAddressesEnabled("OTHER.REALM") {
		t.Fatal("noaddresses unexpectedly enabled")
	}
	if cfg.KDCDefaultOptions != 0x4000 || len(cfg.ExtraAddresses) != 2 {
		t.Fatalf("parsed client relations = %#v", cfg)
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

func TestParseFileIncludesInPlaceAndNested(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child.conf")
	if err := os.WriteFile(child, []byte(`[libdefaults]
default_realm = INCLUDED
include `+filepath.Join(dir, "grandchild.conf")+`
`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "grandchild.conf"), []byte(`[libdefaults]
default_realm = GRANDCHILD
`), 0600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(root, []byte(`[libdefaults]
include `+child+`
default_realm = ROOT
`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseFile(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultRealm != "ROOT" {
		t.Fatalf("default realm = %q, want ROOT after included files", cfg.DefaultRealm)
	}
}

func TestParseFileIncludedirFilteringAndOrdering(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"z.conf":  "[libdefaults]\ndefault_realm = Z\n",
		"a":       "[libdefaults]\ndefault_realm = A\n",
		"ignored": "[libdefaults]\ndefault_realm = IGNORED\n",
		".hidden": "[libdefaults]\ndefault_realm = HIDDEN\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(root, []byte(`[libdefaults]
includedir `+dir+`
`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseFile(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultRealm != "Z" {
		t.Fatalf("includedir ordering/filtering realm = %q, want Z", cfg.DefaultRealm)
	}
}

func TestParseFileIncludeErrors(t *testing.T) {
	for _, directive := range []string{"include /does/not/exist", "includedir /does/not/exist"} {
		root := filepath.Join(t.TempDir(), "krb5.conf")
		if err := os.WriteFile(root, []byte("[libdefaults]\n"+directive+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ParseFile(root); err == nil {
			t.Fatalf("%s unexpectedly succeeded", directive)
		}
	}
}

func TestExpandPathTokensPOSIX(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX path-token semantics are unavailable on Windows")
	}
	t.Setenv("TMPDIR", "/tmp/kerberos-token-test")
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	path, err := ExpandPathTokens("%{TEMP}/%{uid}/%{euid}/%{USERID}/%{username}/%{LIBDIR}/%{BINDIR}/%{SBINDIR}/%{null}")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"/tmp/kerberos-token-test",
		strconv.Itoa(os.Getuid()), strconv.Itoa(os.Geteuid()), strconv.Itoa(os.Getuid()),
		current.Username, "/usr/lib", "/usr/bin", "/usr/sbin", ""}, "/")
	if path != want {
		t.Fatalf("expanded path = %q, want %q", path, want)
	}
	for _, input := range []string{"%{unknown}", "%{uid"} {
		if _, err := ExpandPathTokens(input); err == nil {
			t.Fatalf("ExpandPathTokens(%q) unexpectedly succeeded", input)
		}
	}
	for _, test := range []struct {
		input string
		want  string
	}{
		{"prefix/%{null}/suffix", "prefix//suffix"},
		{"%{uid}%{uid}", strconv.Itoa(os.Getuid()) + strconv.Itoa(os.Getuid())},
		{"literal", "literal"},
	} {
		got, err := ExpandPathTokens(test.input)
		if err != nil || got != test.want {
			t.Errorf("ExpandPathTokens(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
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

func TestStripCommentOnlyRecognizesLeadingDelimiters(t *testing.T) {
	for _, line := range []string{"# comment", "   ; comment", "\t# comment"} {
		if got := stripComment(line); got != "" {
			t.Fatalf("stripComment(%q) = %q, want empty", line, got)
		}
	}
	for _, line := range []string{"FILE:/etc/pki/ca#1.pem", "value;still-data", `value\#escaped`} {
		if got := stripComment(line); got != line {
			t.Fatalf("stripComment(%q) = %q, want unchanged", line, got)
		}
	}
}
