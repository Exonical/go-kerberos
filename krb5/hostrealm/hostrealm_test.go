package hostrealm

import (
	"context"
	"reflect"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/discovery"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

type txtResolver struct {
	records map[string][]string
	queries []string
}

type hostRealmResolver struct {
	records map[string][]discovery.SRVRecord
	queries []string
}

func (r *hostRealmResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return nil, nil
}

func (r *hostRealmResolver) LookupSRV(_ context.Context, _, _, name string) ([]discovery.SRVRecord, error) {
	r.queries = append(r.queries, name)
	return r.records[name], nil
}

func (r *txtResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.queries = append(r.queries, name)
	return r.records[name], nil
}

func TestExpandHostnameQualificationAndModes(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.Parse([]byte(`[libdefaults]
qualify_shortname = example.test
dns_canonicalize_hostname = false
`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ExpandHostname(ctx, cfg, "Host", Options{})
	if err != nil || got != "host.example.test" {
		t.Fatalf("ExpandHostname = %q, %v", got, err)
	}

	cfg.DNSCanonicalizeHostname = "true"
	got, err = ExpandHostname(ctx, cfg, "Alias", Options{
		ForwardLookup: func(context.Context, string) (string, error) {
			return "", context.DeadlineExceeded
		},
	})
	if err != nil || got != "alias.example.test" {
		t.Fatalf("failed forward lookup qualification = %q, %v", got, err)
	}
}

func TestExpandHostnameReverseAndFallback(t *testing.T) {
	cfg := &config.Config{DNSCanonicalizeHostname: "true", RDNS: true}
	var reverseInput string
	got, err := ExpandHostname(context.Background(), cfg, "alias", Options{
		ForwardLookup: func(context.Context, string) (string, error) {
			return "canonical.example.test", nil
		},
		ResolveAddress: func(_ context.Context, host string) (string, error) {
			if host != "canonical.example.test" {
				t.Fatalf("address lookup host = %q", host)
			}
			return "192.0.2.10", nil
		},
		ReverseLookup: func(_ context.Context, host string) (string, error) {
			reverseInput = host
			return "reverse.example.test.", nil
		},
	})
	if err != nil || got != "reverse.example.test" || reverseInput != "192.0.2.10" {
		t.Fatalf("reverse canonicalization = %q, input %q, %v", got, reverseInput, err)
	}

	cfg.DNSCanonicalizeHostname = "fallback"
	got, err = ExpandHostname(context.Background(), cfg, "short", Options{SearchDomains: []string{"example.test"}})
	if err != nil || got != "short.example.test" {
		t.Fatalf("fallback qualification = %q, %v", got, err)
	}
}

func TestExpandHostnameExplicitRDNSFalse(t *testing.T) {
	cfg := &config.Config{DNSCanonicalizeHostname: "true", RDNS: false, RDNSSet: true}
	reversed := false
	got, err := ExpandHostname(context.Background(), cfg, "alias", Options{
		ForwardLookup: func(context.Context, string) (string, error) {
			return "canonical.example.test", nil
		},
		ResolveAddress: func(context.Context, string) (string, error) {
			t.Fatal("address lookup called with rdns disabled")
			return "", nil
		},
		ReverseLookup: func(context.Context, string) (string, error) {
			reversed = true
			return "", nil
		},
	})
	if err != nil || got != "canonical.example.test" || reversed {
		t.Fatalf("rdns=false expansion = %q, reversed=%v, err=%v", got, reversed, err)
	}
}

func TestExpandHostnameEmptySearchDomainsOverrideSystem(t *testing.T) {
	cfg := &config.Config{DNSCanonicalizeHostname: "false"}
	got, err := ExpandHostname(context.Background(), cfg, "short", Options{SearchDomains: []string{}})
	if err != nil || got != "short" {
		t.Fatalf("empty search override = %q, %v", got, err)
	}
}

func TestHostRealmRealmTryDomains(t *testing.T) {
	cfg := &config.Config{DNSLookupRealm: true, RealmTryDomainsSet: true, RealmTryDomains: 1}
	var tried []string
	realm, authoritative, err := HostRealm(context.Background(), cfg, "a.b.example.test", Options{
		Resolver: &txtResolver{},
		RealmExists: func(_ context.Context, value string) bool {
			tried = append(tried, value)
			return value == "B.EXAMPLE.TEST"
		},
	})
	if err != nil || authoritative || realm != "B.EXAMPLE.TEST" {
		t.Fatalf("realm_try_domains result = %q, authoritative=%v, err=%v", realm, authoritative, err)
	}
	if !reflect.DeepEqual(tried, []string{"A.B.EXAMPLE.TEST", "B.EXAMPLE.TEST"}) {
		t.Fatalf("realm_try_domains probes = %v", tried)
	}

	cfg.RealmTryDomains = -1
	tried = nil
	realm, _, err = HostRealm(context.Background(), cfg, "a.b.example.test", Options{
		Resolver: &txtResolver{},
		RealmExists: func(_ context.Context, value string) bool {
			tried = append(tried, value)
			return true
		},
	})
	if err != nil || realm != "B.EXAMPLE.TEST" || len(tried) != 0 {
		t.Fatalf("realm_try_domains=-1 result = %q, probes=%v, err=%v", realm, tried, err)
	}
}

func TestHostRealmRealmTryDomainsUsesDefaultLocator(t *testing.T) {
	cfg := &config.Config{DNSLookupRealm: true, RealmTryDomainsSet: true, RealmTryDomains: 0}
	resolver := &hostRealmResolver{records: map[string][]discovery.SRVRecord{
		"A.B.EXAMPLE.TEST": {{Target: "kdc.example.test.", Port: 88}},
	}}
	realm, authoritative, err := HostRealm(context.Background(), cfg, "a.b.example.test", Options{
		Resolver: resolver,
	})
	if err != nil || authoritative || realm != "A.B.EXAMPLE.TEST" {
		t.Fatalf("default realm locator result = %q, authoritative=%v, err=%v", realm, authoritative, err)
	}
	if !reflect.DeepEqual(resolver.queries, []string{"A.B.EXAMPLE.TEST", "A.B.EXAMPLE.TEST"}) {
		t.Fatalf("default realm locator queries = %v", resolver.queries)
	}
	resolver.records = nil
	resolver.queries = nil
	realm, authoritative, err = HostRealm(context.Background(), cfg, "a.b.example.test", Options{
		Resolver: resolver,
	})
	if err != nil || authoritative || realm != "B.EXAMPLE.TEST" {
		t.Fatalf("missing KDC fallback result = %q, authoritative=%v, err=%v", realm, authoritative, err)
	}
	if !reflect.DeepEqual(resolver.queries, []string{"A.B.EXAMPLE.TEST", "A.B.EXAMPLE.TEST"}) {
		t.Fatalf("missing KDC locator queries = %v", resolver.queries)
	}
}

func TestHostRealmRealmTryDomainsUsesConfiguredKDC(t *testing.T) {
	cfg := &config.Config{
		DNSLookupRealm: true, RealmTryDomainsSet: true, RealmTryDomains: 0,
		Realms: map[string][]string{
			"a.b.example.test": {"kdc.example.test:88"},
		},
	}
	realm, authoritative, err := HostRealm(context.Background(), cfg,
		"a.b.example.test", Options{Resolver: &hostRealmResolver{}})
	if err != nil || authoritative || realm != "A.B.EXAMPLE.TEST" {
		t.Fatalf("configured realm result = %q, authoritative=%v, err=%v",
			realm, authoritative, err)
	}
}

func TestCanonicalizePrincipalPreservesTrailer(t *testing.T) {
	cfg := &config.Config{DNSCanonicalizeHostname: "false", QualifyShortname: "example.test", QualifyShortnameSet: true}
	p := principal.Principal{NameType: principal.NTSrvHst, Components: []string{"HTTP", "web:8443"}}
	got, err := CanonicalizePrincipal(context.Background(), cfg, p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Components[1] != "web.example.test:8443" {
		t.Fatalf("host component = %q", got.Components[1])
	}
}

func TestHostRealmModuleOrderAndFallback(t *testing.T) {
	cfg := &config.Config{
		DefaultRealm:   "DEFAULT.TEST",
		DNSLookupRealm: true,
		DomainRealm:    map[string]string{".example.test": "PROFILE.TEST"},
	}
	resolver := &txtResolver{records: map[string][]string{
		"_kerberos.host.example.test": {"DNS.TEST"},
	}}
	realm, authoritative, err := HostRealm(context.Background(), cfg, "host.example.test", Options{Resolver: resolver})
	if err != nil || realm != "PROFILE.TEST" || !authoritative {
		t.Fatalf("profile realm = %q, authoritative=%v, err=%v", realm, authoritative, err)
	}

	cfg.DomainRealm = map[string]string{}
	realm, authoritative, err = HostRealm(context.Background(), cfg, "host.example.test", Options{Resolver: resolver})
	if err != nil || realm != "DNS.TEST" || !authoritative {
		t.Fatalf("DNS realm = %q, authoritative=%v, err=%v", realm, authoritative, err)
	}
	if !reflect.DeepEqual(resolver.queries, []string{"_kerberos.host.example.test"}) {
		t.Fatalf("TXT queries = %v", resolver.queries)
	}

	resolver.records = map[string][]string{}
	realm, authoritative, err = HostRealm(context.Background(), cfg, "host.example.test", Options{
		Resolver:    resolver,
		RealmExists: func(context.Context, string) bool { return false },
	})
	if err != nil || realm != "EXAMPLE.TEST" || authoritative {
		t.Fatalf("fallback realm = %q, authoritative=%v, err=%v", realm, authoritative, err)
	}
}

func TestHostRealmNumericAndContextErrors(t *testing.T) {
	cfg := &config.Config{DNSLookupRealm: true, DefaultRealm: "DEFAULT.TEST"}
	resolver := &txtResolver{}
	realm, authoritative, err := HostRealm(context.Background(), cfg, "192.0.2.1", Options{Resolver: resolver})
	if err != nil || realm != "DEFAULT.TEST" || authoritative {
		t.Fatalf("numeric fallback = %q, authoritative=%v, err=%v", realm, authoritative, err)
	}
	_, err = ExpandHostname(nil, cfg, "host", Options{})
	if err == nil {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestCanonicalizePrincipalCandidatesFallback(t *testing.T) {
	cfg := &config.Config{DNSCanonicalizeHostname: "fallback"}
	p := principal.Principal{
		Realm: "EXAMPLE.COM", NameType: principal.NTSrvHst,
		Components: []string{"host", "alias.example.test"},
	}
	candidates, err := CanonicalizePrincipalCandidates(context.Background(), cfg, p, Options{
		ForwardLookup: func(context.Context, string) (string, error) {
			return "canonical.example.test.", nil
		},
	})
	if err != nil || len(candidates) != 2 ||
		candidates[0].Components[1] != p.Components[1] ||
		candidates[1].Components[1] != "canonical.example.test" {
		t.Fatalf("fallback candidates = %#v, %v", candidates, err)
	}
	cfg.DNSCanonicalizeHostname = "false"
	candidates, err = CanonicalizePrincipalCandidates(context.Background(), cfg, p, Options{})
	if err != nil || len(candidates) != 1 {
		t.Fatalf("non-fallback candidates = %#v, %v", candidates, err)
	}
}

func TestCanonicalizePrincipalNonHostAndTrailers(t *testing.T) {
	plain := principal.Principal{Realm: "EXAMPLE.COM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	got, err := CanonicalizePrincipal(context.Background(), nil, plain, Options{})
	if err != nil || got.String() != plain.String() {
		t.Fatalf("non-host canonicalization = %#v, %v", got, err)
	}
	cfg := &config.Config{DNSCanonicalizeHostname: "false", QualifyShortname: "example.test"}
	for _, host := range []string{"host", "host:88", "host:a:b"} {
		got, err := CanonicalizePrincipal(context.Background(), cfg,
			principal.Principal{NameType: principal.NTSrvHst, Components: []string{"http", host}}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if host == "host:88" && got.Components[1] != "host.example.test:88" {
			t.Fatalf("trailer preserved as %q", got.Components[1])
		}
		if host == "host:a:b" && got.Components[1] != "host:a:b.example.test" {
			t.Fatalf("multi-colon host = %q", got.Components[1])
		}
	}
}

func TestHostRealmProfileAndFallbackAPI(t *testing.T) {
	if realm, ok := FallbackRealm(nil, "host.example.test"); ok || realm != "" {
		t.Fatalf("nil fallback = %q, %v", realm, ok)
	}
	cfg := &config.Config{DefaultRealm: "DEFAULT.TEST",
		DomainRealm: map[string]string{".example.test": "PROFILE.TEST"}}
	if realm, ok := FallbackRealm(cfg, "host.example.test"); !ok || realm != "PROFILE.TEST" {
		t.Fatalf("profile fallback = %q, %v", realm, ok)
	}
	if realm, ok := FallbackRealm(cfg, "other.test"); !ok || realm != "TEST" {
		t.Fatalf("domain fallback = %q, %v", realm, ok)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExpandHostname(ctx, cfg, "host", Options{}); err == nil {
		t.Fatal("cancelled expansion unexpectedly succeeded")
	}
}
