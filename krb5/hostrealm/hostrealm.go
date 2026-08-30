// Package hostrealm implements the hostname and host-to-realm portions of
// MIT krb5's hostrealm interface.
package hostrealm

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/discovery"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// Options supplies injectable network and host configuration hooks.
// SearchDomains overrides the system resolver search list when non-nil.
type Options struct {
	Resolver       discovery.TXTResolver
	SearchDomains  []string
	ForwardLookup  func(context.Context, string) (string, error)
	ResolveAddress func(context.Context, string) (string, error)
	ReverseLookup  func(context.Context, string) (string, error)
	// RealmExists optionally reports whether a realm has a locatable KDC.
	// It makes the realm_try_domains heuristic injectable for tests.
	RealmExists func(context.Context, string) bool
}

// NetResolver adapts net.Resolver for hostname canonicalization and TXT
// lookups. Forward canonicalization uses CNAME, matching MIT's forward-only
// getaddrinfo(AI_CANONNAME) behavior as closely as the Go resolver permits.
type NetResolver struct {
	Resolver *net.Resolver
}

func (r NetResolver) resolver() *net.Resolver {
	if r.Resolver != nil {
		return r.Resolver
	}
	return net.DefaultResolver
}

func (r NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.resolver().LookupTXT(ctx, name)
}

func (r NetResolver) Forward(ctx context.Context, host string) (string, error) {
	return r.resolver().LookupCNAME(ctx, host)
}

func (r NetResolver) Reverse(ctx context.Context, host string) (string, error) {
	if net.ParseIP(host) == nil {
		addresses, err := r.resolver().LookupHost(ctx, host)
		if err != nil {
			return "", err
		}
		if len(addresses) == 0 {
			return "", fmt.Errorf("reverse hostname %q: no addresses", host)
		}
		host = addresses[0]
	}
	names, err := r.resolver().LookupAddr(ctx, host)
	if err != nil || len(names) == 0 {
		return "", err
	}
	return names[0], nil
}

func (r NetResolver) ResolveAddress(ctx context.Context, host string) (string, error) {
	addresses, err := r.resolver().LookupHost(ctx, host)
	if err != nil {
		return "", err
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("resolve hostname %q: no addresses", host)
	}
	return addresses[0], nil
}

func resolverFor(opts Options) NetResolver {
	if opts.Resolver != nil {
		if r, ok := opts.Resolver.(NetResolver); ok {
			return r
		}
	}
	return NetResolver{}
}

func qualifyDomain(cfg *config.Config, opts Options) string {
	if cfg != nil && cfg.QualifyShortnameSet {
		return strings.TrimSuffix(strings.TrimSpace(cfg.QualifyShortname), ".")
	}
	if cfg != nil && cfg.QualifyShortname != "" {
		return strings.TrimSuffix(strings.TrimSpace(cfg.QualifyShortname), ".")
	}
	if opts.SearchDomains != nil {
		if len(opts.SearchDomains) == 0 {
			return ""
		}
		return strings.TrimSuffix(strings.TrimSpace(opts.SearchDomains[0]), ".")
	}
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 1 && (fields[0] == "search" || fields[0] == "domain") {
			return strings.TrimSuffix(fields[1], ".")
		}
	}
	return ""
}

func canonicalMode(cfg *config.Config) string {
	if cfg == nil || cfg.DNSCanonicalizeHostname == "" {
		return "fallback"
	}
	return strings.ToLower(cfg.DNSCanonicalizeHostname)
}

// ExpandHostname applies MIT's k5_expand_hostname rules. Short names are
// qualified without DNS; true enables forward canonicalization and optional
// reverse lookup; fallback defers DNS canonicalization.
func ExpandHostname(ctx context.Context, cfg *config.Config, host string, opts Options) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("expand hostname: nil context")
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("expand hostname: %w", err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("expand hostname: empty hostname")
	}
	canon := host
	dnsReplaced := false
	if canonicalMode(cfg) == "true" {
		lookup := opts.ForwardLookup
		if lookup == nil {
			r := resolverFor(opts)
			lookup = r.Forward
		}
		if value, err := lookup(ctx, host); err == nil && value != "" {
			canon = value
			dnsReplaced = true
			rdns := true
			if cfg != nil && cfg.RDNSSet {
				rdns = cfg.RDNS
			}
			if rdns {
				resolveAddress := opts.ResolveAddress
				if resolveAddress == nil {
					r := resolverFor(opts)
					resolveAddress = r.ResolveAddress
				}
				reverse := opts.ReverseLookup
				if reverse == nil {
					r := resolverFor(opts)
					reverse = r.Reverse
				}
				if address, err := resolveAddress(ctx, canon); err == nil {
					if value, err := reverse(ctx, address); err == nil && value != "" {
						canon = value
					}
				}
			}
		}
	}
	if !dnsReplaced && !strings.Contains(host, ".") {
		if domain := qualifyDomain(cfg, opts); domain != "" {
			canon += "." + domain
		}
	}
	canon = strings.ToLower(strings.TrimSuffix(canon, "."))
	return canon, nil
}

// CanonicalizePrincipal expands the host component of an NTSrvHst principal.
func CanonicalizePrincipal(ctx context.Context, cfg *config.Config, p principal.Principal, opts Options) (principal.Principal, error) {
	if p.NameType != principal.NTSrvHst || len(p.Components) < 2 {
		return p, nil
	}
	host, trailer := splitTrailer(p.Components[1])
	expanded, err := ExpandHostname(ctx, cfg, host, opts)
	if err != nil {
		return principal.Principal{}, err
	}
	p.Components = append([]string(nil), p.Components...)
	p.Components[1] = expanded + trailer
	return p, nil
}

// CanonicalizePrincipalCandidates returns the first principal requested by
// MIT's fallback mode and the DNS-canonicalized retry candidate, if distinct.
// The caller must retry the latter only after KDC_ERR_S_PRINCIPAL_UNKNOWN.
func CanonicalizePrincipalCandidates(ctx context.Context, cfg *config.Config,
	p principal.Principal, opts Options) ([]principal.Principal, error) {
	first, err := CanonicalizePrincipal(ctx, cfg, p, opts)
	if err != nil {
		return nil, err
	}
	if canonicalMode(cfg) != "fallback" || p.NameType != principal.NTSrvHst ||
		len(p.Components) < 2 {
		return []principal.Principal{first}, nil
	}
	secondCfg := &config.Config{}
	if cfg != nil {
		*secondCfg = *cfg
	}
	secondCfg.DNSCanonicalizeHostname = "true"
	second, err := CanonicalizePrincipal(ctx, secondCfg, p, opts)
	if err != nil {
		return nil, err
	}
	if second.Realm == first.Realm && len(second.Components) == len(first.Components) {
		same := true
		for i := range first.Components {
			if first.Components[i] != second.Components[i] {
				same = false
				break
			}
		}
		if same {
			return []principal.Principal{first}, nil
		}
	}
	return []principal.Principal{first, second}, nil
}

func splitTrailer(host string) (string, string) {
	index := strings.IndexByte(host, ':')
	if index < 0 || index == len(host)-1 ||
		strings.Contains(host[index+1:], ":") {
		return host, ""
	}
	return host[:index], host[index:]
}

// HostRealm resolves a host using profile mappings, DNS TXT records, and the
// MIT domain fallback. The bool reports whether the answer was authoritative.
func HostRealm(ctx context.Context, cfg *config.Config, host string, opts Options) (string, bool, error) {
	if ctx == nil {
		return "", false, fmt.Errorf("host realm: nil context")
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return "", false, fmt.Errorf("host realm: empty hostname")
	}
	if cfg != nil {
		if realm, ok := cfg.RealmForHost(host); ok {
			return realm, true, nil
		}
	}
	if cfg == nil || cfg.DNSLookupRealm {
		resolver := opts.Resolver
		if resolver == nil {
			r := NetResolver{}
			resolver = r
		}
		if realm, ok, err := discovery.LookupRealmTXT(ctx, resolver, host); err != nil {
			return "", false, err
		} else if ok {
			return realm, true, nil
		}
	}
	if cfg != nil {
		if realm, ok := fallbackRealm(ctx, cfg, host, opts); ok {
			return realm, false, nil
		}
		if cfg.DefaultRealm != "" {
			return cfg.DefaultRealm, false, nil
		}
	}
	return "", false, nil
}

func fallbackRealm(ctx context.Context, cfg *config.Config, host string, opts Options) (string, bool) {
	if cfg == nil || net.ParseIP(host) != nil {
		return "", false
	}
	limit := -1
	if cfg.RealmTryDomainsSet {
		limit = cfg.RealmTryDomains
	}
	realmExists := opts.RealmExists
	if realmExists == nil {
		realmExists = func(ctx context.Context, realm string) bool {
			for configuredRealm, values := range cfg.Realms {
				if strings.EqualFold(configuredRealm, realm) {
					for _, value := range values {
						if strings.TrimSpace(value) != "" {
							return true
						}
					}
				}
			}
			resolver, ok := opts.Resolver.(discovery.Resolver)
			if !ok {
				resolver = discovery.NetResolver{}
			}
			servers, err := discovery.Discover(ctx, resolver, realm)
			return err == nil && len(servers) > 0
		}
	}
	upper := strings.ToUpper(strings.TrimSuffix(host, "."))
	suffix := upper
	for limit >= 0 {
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			break
		}
		if realmExists(ctx, suffix) {
			return suffix, true
		}
		suffix = suffix[dot+1:]
		limit--
	}
	if dot := strings.IndexByte(upper, '.'); dot >= 0 && dot+1 < len(upper) {
		return upper[dot+1:], true
	}
	return "", false
}

// FallbackRealm returns the non-authoritative realm selected by MIT's domain
// fallback, or the configured default realm.
func FallbackRealm(cfg *config.Config, host string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	if realm, ok := cfg.RealmForHostWithFallback(host); ok {
		return realm, true
	}
	if cfg.DefaultRealm != "" {
		return cfg.DefaultRealm, true
	}
	return "", false
}
