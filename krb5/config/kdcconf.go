package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// KDCConfig contains the KDC-facing portions of an MIT kdc.conf profile.
// Values retains relations for which this package does not implement server
// behavior, so callers can inspect them without silently discarding policy.
type KDCConfig struct {
	Defaults map[string][]string
	Realms   map[string]KDCRealmConfig
}

// KDCRealmConfig contains one [realms] subsection from kdc.conf.
type KDCRealmConfig struct {
	Values            map[string][]string
	KDCPorts          []int
	KDCTCPPorts       []int
	MaxLife           time.Duration
	MaxRenewableLife  time.Duration
	MasterKeyType     string
	SupportedEnctypes []string
}

// ParseKDCConf parses MIT's profile-format kdc.conf.  Unknown relations are
// preserved in Values and Defaults rather than being applied speculatively.
func ParseKDCConf(data []byte) (*KDCConfig, error) {
	profile, err := Parse(data)
	if err != nil {
		return nil, err
	}
	result := &KDCConfig{
		Defaults: cloneOptions(profile.Options["kdcdefaults"]),
		Realms:   make(map[string]KDCRealmConfig, len(profile.RealmOptions)),
	}
	defaults := cloneOptions(result.Defaults)
	for realm, values := range profile.RealmOptions {
		merged := cloneOptions(defaults)
		for key, value := range values {
			merged[key] = append([]string(nil), value...)
		}
		settings, err := parseKDCRealm(merged)
		if err != nil {
			return nil, fmt.Errorf("realm %s: %w", realm, err)
		}
		settings.Values = cloneOptions(merged)
		result.Realms[realm] = settings
	}
	return result, nil
}

func (c *KDCConfig) Realm(realm string) (KDCRealmConfig, bool) {
	if c == nil {
		return KDCRealmConfig{}, false
	}
	if value, ok := c.Realms[realm]; ok {
		return value, true
	}
	for name, value := range c.Realms {
		if strings.EqualFold(name, realm) {
			return value, true
		}
	}
	return KDCRealmConfig{}, false
}

func cloneOptions(values map[string][]string) map[string][]string {
	result := make(map[string][]string, len(values))
	for key, value := range values {
		result[key] = append([]string(nil), value...)
	}
	return result
}

func firstValues(values map[string][]string, key string) string {
	parts := values[strings.ToLower(key)]
	return strings.TrimSpace(strings.Join(parts, " "))
}

func parseKDCRealm(values map[string][]string) (KDCRealmConfig, error) {
	settings := KDCRealmConfig{}
	var err error
	settings.KDCPorts, err = parsePorts(firstValues(values, "kdc_ports"))
	if err != nil {
		return settings, fmt.Errorf("kdc_ports: %w", err)
	}
	settings.KDCTCPPorts, err = parsePorts(firstValues(values, "kdc_tcp_ports"))
	if err != nil {
		return settings, fmt.Errorf("kdc_tcp_ports: %w", err)
	}
	if raw := firstValues(values, "max_life"); raw != "" {
		settings.MaxLife, err = ParseDuration(raw)
		if err != nil {
			return settings, fmt.Errorf("max_life: %w", err)
		}
	}
	if raw := firstValues(values, "max_renewable_life"); raw != "" {
		settings.MaxRenewableLife, err = ParseDuration(raw)
		if err != nil {
			return settings, fmt.Errorf("max_renewable_life: %w", err)
		}
	}
	settings.MasterKeyType = firstValues(values, "master_key_type")
	settings.SupportedEnctypes = splitList(firstValues(values, "supported_enctypes"))
	return settings, nil
}

func parsePorts(raw string) ([]int, error) {
	if raw == "" {
		return nil, nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	result := make([]int, 0, len(fields))
	for _, field := range fields {
		port, err := strconv.Atoi(field)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", field)
		}
		result = append(result, port)
	}
	return result, nil
}

func splitList(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}
