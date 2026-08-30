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
	if len(opts.SearchDomains) > 0 {
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
			if cfg != nil && cfg.RDNS {
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
			dnsReplaced = canon != host
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
		if realm, ok := cfg.RealmForHostWithFallback(host); ok {
			return realm, false, nil
		}
		if cfg.DefaultRealm != "" {
			return cfg.DefaultRealm, false, nil
		}
	}
	return "", false, nil
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
