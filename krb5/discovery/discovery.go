package discovery

import (
	"context"
	"fmt"
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

type KDC struct {
	Host string
	Port uint16
}

func Discover(ctx context.Context, resolver Resolver, realm string) ([]KDC, error) {
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
		result = append(result, KDC{Host: record.Target, Port: record.Port})
	}
	if len(result) == 0 {
		if len(lookupErrs) > 0 {
			return nil, fmt.Errorf("discover KDC: %v", lookupErrs[0])
		}
		return nil, fmt.Errorf("discover KDC: no SRV records for realm %q", realm)
	}
	return result, nil
}
