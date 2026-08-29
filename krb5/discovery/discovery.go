package discovery

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

type SRVRecord struct {
	Target   string
	Port     uint16
	Priority uint16
	Weight   uint16
}

type Resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) ([]SRVRecord, error)
}

// TXTResolver is implemented by DNS resolvers which support realm TXT
// discovery.  It is separate from Resolver so existing SRV-only resolvers
// remain source-compatible.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// URIResolver is implemented by DNS resolvers which support URI records.
type URIResolver interface {
	LookupURI(ctx context.Context, name string) ([]URIRecord, error)
}

// NetResolver adapts net.Resolver for SRV and TXT lookups. URI records are
// left to URIResolver implementations because the standard library does not
// expose a generic URI-RR query.
type NetResolver struct {
	Resolver *net.Resolver
}

func (r NetResolver) resolver() *net.Resolver {
	if r.Resolver != nil {
		return r.Resolver
	}
	return net.DefaultResolver
}

func (r NetResolver) LookupSRV(ctx context.Context, service, proto, name string) ([]SRVRecord, error) {
	_, records, err := r.resolver().LookupSRV(ctx, service, proto, name)
	if err != nil {
		return nil, err
	}
	result := make([]SRVRecord, 0, len(records))
	for _, record := range records {
		result = append(result, SRVRecord{
			Target: record.Target, Port: record.Port,
			Priority: record.Priority, Weight: record.Weight,
		})
	}
	return result, nil
}

func (r NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.resolver().LookupTXT(ctx, name)
}

type URIRecord struct {
	Target   string
	Priority uint16
	Weight   uint16
}

type KDC struct {
	Host      string
	Port      uint16
	Transport string
	URI       string
	Primary   bool
}

func Discover(ctx context.Context, resolver Resolver, realm string) ([]KDC, error) {
	return DiscoverWithOptions(ctx, resolver, realm, true)
}

// DiscoverWithOptions locates KDCs, trying URI records before SRV records as
// MIT does.  URI lookup is enabled by default in MIT's locator; callers can
// disable it to model dns_uri_lookup = false.
func DiscoverWithOptions(ctx context.Context, resolver Resolver, realm string, dnsURILookup bool) ([]KDC, error) {
	if ctx == nil {
		return nil, fmt.Errorf("discover KDC: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("discover KDC: %w", err)
	}
	if resolver == nil {
		return nil, fmt.Errorf("discover KDC: nil resolver")
	}
	realm = strings.TrimSpace(realm)
	if realm == "" {
		return nil, fmt.Errorf("discover KDC: empty realm")
	}
	if dnsURILookup {
		if uriResolver, ok := resolver.(URIResolver); ok {
			records, err := uriResolver.LookupURI(ctx, "_kerberos."+realm)
			if err == nil {
				uris := parseURIRecords(records)
				if len(uris) > 0 {
					return uris, nil
				}
			}
		}
	}
	var records []SRVRecord
	var lookupErrs []error
	for _, proto := range []string{"udp", "tcp"} {
		found, err := resolver.LookupSRV(ctx, "_kerberos", proto, realm)
		if err != nil {
			lookupErrs = append(lookupErrs, err)
			continue
		}
		records = append(records, found...)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("discover KDC: %w", err)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Priority != records[j].Priority {
			return records[i].Priority < records[j].Priority
		}
		return records[i].Weight > records[j].Weight
	})
	result := make([]KDC, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.Target == "" || record.Port == 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d", record.Target, record.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, KDC{Host: strings.TrimSuffix(record.Target, "."), Port: record.Port, Transport: "srv"})
	}
	if len(result) == 0 {
		if len(lookupErrs) > 0 {
			return nil, fmt.Errorf("discover KDC: %v", lookupErrs[0])
		}
		return nil, fmt.Errorf("discover KDC: no SRV records for realm %q", realm)
	}
	return result, nil
}

// LookupRealmTXT performs MIT's hostrealm DNS fallback.  It queries
// _kerberos.<host>, then each progressively shorter parent, and returns the
// first non-empty TXT answer.  Numeric addresses are never queried.
func LookupRealmTXT(ctx context.Context, resolver TXTResolver, host string) (string, bool, error) {
	if ctx == nil {
		return "", false, fmt.Errorf("discover realm: nil context")
	}
	if err := ctx.Err(); err != nil {
		return "", false, fmt.Errorf("discover realm: %w", err)
	}
	if resolver == nil {
		return "", false, fmt.Errorf("discover realm: nil resolver")
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || net.ParseIP(host) != nil {
		return "", false, nil
	}
	for name := host; name != ""; {
		answers, err := resolver.LookupTXT(ctx, "_kerberos."+name)
		if err == nil {
			for _, answer := range answers {
				answer = strings.TrimSuffix(strings.TrimSpace(answer), ".")
				if answer != "" {
					return answer, true, nil
				}
			}
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			break
		}
		name = name[dot+1:]
	}
	if err := ctx.Err(); err != nil {
		return "", false, fmt.Errorf("discover realm: %w", err)
	}
	return "", false, nil
}

// DiscoverRealmTXT is the configuration-gated form of LookupRealmTXT.
func DiscoverRealmTXT(ctx context.Context, resolver TXTResolver, host string, dnsLookupRealm bool) (string, bool, error) {
	if !dnsLookupRealm {
		return "", false, nil
	}
	return LookupRealmTXT(ctx, resolver, host)
}

// ParseURIRecord parses MIT's krb5srv:flags:transport:residual URI format.
// Weight is intentionally not used: MIT orders URI answers by priority and
// documents weight as currently unused.
func ParseURIRecord(record URIRecord) (KDC, bool) {
	value := strings.TrimSpace(record.Target)
	parts := strings.SplitN(value, ":", 4)
	if len(parts) != 4 || !strings.EqualFold(parts[0], "krb5srv") ||
		parts[2] == "" || parts[3] == "" {
		return KDC{}, false
	}
	transport := strings.ToLower(parts[2])
	primary := strings.ContainsAny(parts[1], "mM")
	residual := parts[3]
	switch transport {
	case "udp", "tcp":
		host, port := splitHostPort(residual, 88)
		if host == "" || port == 0 {
			return KDC{}, false
		}
		return KDC{Host: host, Port: port, Transport: transport, Primary: primary}, true
	case "kkdcp":
		parsed, err := url.Parse(residual)
		if err != nil || !strings.EqualFold(parsed.Scheme, "https") ||
			parsed.Host == "" {
			return KDC{}, false
		}
		host, port := splitHostPort(parsed.Host, 443)
		if host == "" || port == 0 {
			return KDC{}, false
		}
		return KDC{Host: host, Port: port, Transport: "kkdcp", URI: parsed.String(), Primary: primary}, true
	default:
		return KDC{}, false
	}
}

func parseURIRecords(records []URIRecord) []KDC {
	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Priority < records[j].Priority
	})
	result := make([]KDC, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		kdc, ok := ParseURIRecord(record)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s:%s:%d", kdc.Transport, kdc.Host, kdc.Port)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, kdc)
	}
	return result
}

func splitHostPort(value string, defaultPort uint16) (string, uint16) {
	value = strings.TrimSpace(value)
	if host, port, err := net.SplitHostPort(value); err == nil {
		var number int
		if _, err := fmt.Sscanf(port, "%d", &number); err != nil || number < 1 || number > 65535 {
			return "", 0
		}
		return strings.TrimSuffix(strings.Trim(host, "[]"), "."), uint16(number)
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.Trim(value, "[]")
	}
	if strings.Count(value, ":") > 1 {
		return value, defaultPort
	}
	return strings.TrimSuffix(value, "."), defaultPort
}
