package config

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DefaultRealm            string
	DNSLookupKDC            bool
	DNSLookupRealm          bool
	RDNS                    bool
	Canonicalize            bool
	ClockSkew               time.Duration
	TicketLifetime          time.Duration
	RenewLifetime           time.Duration
	Forwardable             bool
	Proxiable               bool
	DefaultCCacheName       string
	DefaultKeytabName       string
	DefaultClientKeytabName string
	UDPPreferenceLimit      int
	PermittedEnctypes       []int32
	DefaultTKTEnctypes      []int32
	DefaultTGSEnctypes      []int32
	Realms                  map[string][]string
	DomainRealm             map[string]string
	Capaths                 map[string][]string
	RealmOptions            map[string]map[string][]string
	CapathOptions           map[string]map[string][]string
}

func Parse(data []byte) (*Config, error) {
	const maxConfigSize = 16 << 20
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("parse krb5.conf: input exceeds %d bytes", maxConfigSize)
	}
	cfg := &Config{
		Realms:        make(map[string][]string),
		DomainRealm:   make(map[string]string),
		Capaths:       make(map[string][]string),
		RealmOptions:  make(map[string]map[string][]string),
		CapathOptions: make(map[string]map[string][]string),
	}
	section := ""
	subsection := ""
	pendingSubsection := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024), maxConfigSize)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if subsection != "" || pendingSubsection != "" {
				return nil, fmt.Errorf("parse krb5.conf line %d: unclosed subsection", lineNumber)
			}
			if !strings.HasSuffix(line, "]") || strings.Count(line, "[") != 1 ||
				strings.Count(line, "]") != 1 {
				return nil, fmt.Errorf("parse krb5.conf line %d: malformed section", lineNumber)
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "" {
				return nil, fmt.Errorf("parse krb5.conf line %d: empty section", lineNumber)
			}
			continue
		}
		if section == "" {
			return nil, fmt.Errorf("parse krb5.conf line %d: relation before section", lineNumber)
		}
		if line == "{" {
			if pendingSubsection == "" {
				return nil, fmt.Errorf("parse krb5.conf line %d: unexpected opening brace", lineNumber)
			}
			subsection = pendingSubsection
			pendingSubsection = ""
			continue
		}
		if line == "}" {
			if subsection == "" {
				return nil, fmt.Errorf("parse krb5.conf line %d: unexpected closing brace", lineNumber)
			}
			subsection = ""
			continue
		}
		key, value, ok := splitRelation(line)
		if !ok {
			return nil, fmt.Errorf("parse krb5.conf line %d: malformed relation", lineNumber)
		}
		rawKey := key
		key = strings.ToLower(key)
		if key == "" {
			return nil, fmt.Errorf("parse krb5.conf line %d: empty relation key", lineNumber)
		}
		if pendingSubsection != "" {
			return nil, fmt.Errorf("parse krb5.conf line %d: expected opening brace", lineNumber)
		}
		if strings.HasSuffix(value, "{") {
			if strings.TrimSpace(strings.TrimSuffix(value, "{")) != "" ||
				subsection != "" {
				return nil, fmt.Errorf("parse krb5.conf line %d: malformed subsection", lineNumber)
			}
			subsection = strings.TrimSpace(rawKey)
			continue
		}
		if value == "" {
			if subsection != "" {
				return nil, fmt.Errorf("parse krb5.conf line %d: empty relation value", lineNumber)
			}
			pendingSubsection = strings.TrimSpace(rawKey)
			continue
		}
		values := splitValues(value)
		if len(values) == 0 {
			return nil, fmt.Errorf("parse krb5.conf line %d: empty relation value", lineNumber)
		}
		if subsection != "" {
			addSubsection(cfg, section, subsection, key, values)
			continue
		}
		if err := applyOption(cfg, section, key, values); err != nil {
			return nil, fmt.Errorf("parse krb5.conf line %d: %w", lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse krb5.conf: %w", err)
	}
	if subsection != "" || pendingSubsection != "" {
		return nil, fmt.Errorf("parse krb5.conf: unclosed subsection")
	}
	return cfg, nil
}

func ParseDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return 0, fmt.Errorf("parse MIT duration: empty value")
	}
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(value, "d"), 64)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("parse MIT duration: invalid value")
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	if duration, err := time.ParseDuration(value); err == nil {
		if duration < 0 {
			return 0, fmt.Errorf("parse MIT duration: invalid value")
		}
		return duration, nil
	}
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || seconds < 0 || seconds > float64(time.Duration(1<<63-1))/float64(time.Second) {
		return 0, fmt.Errorf("parse MIT duration: invalid value")
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

func stripComment(line string) string {
	for i, r := range line {
		if r == '#' || r == ';' {
			if i == 0 || line[i-1] != '\\' {
				return line[:i]
			}
		}
	}
	return line
}

func splitRelation(line string) (string, string, bool) {
	index := strings.IndexByte(line, '=')
	if index < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:index]), strings.TrimSpace(line[index+1:]), true
}

func splitValues(value string) []string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return []string{value[1 : len(value)-1]}
	}
	return strings.Fields(value)
}

func applyOption(cfg *Config, section, key string, values []string) error {
	switch section {
	case "libdefaults":
		value := values[len(values)-1]
		switch key {
		case "default_realm":
			cfg.DefaultRealm = value
		case "dns_lookup_kdc":
			cfg.DNSLookupKDC = parseBool(value)
		case "dns_lookup_realm":
			cfg.DNSLookupRealm = parseBool(value)
		case "rdns":
			cfg.RDNS = parseBool(value)
		case "canonicalize":
			cfg.Canonicalize = parseBool(value)
		case "clockskew":
			duration, err := ParseDuration(value)
			if err != nil {
				return err
			}
			cfg.ClockSkew = duration
		case "ticket_lifetime":
			duration, err := ParseDuration(value)
			if err != nil {
				return err
			}
			cfg.TicketLifetime = duration
		case "renew_lifetime":
			duration, err := ParseDuration(value)
			if err != nil {
				return err
			}
			cfg.RenewLifetime = duration
		case "forwardable":
			cfg.Forwardable = parseBool(value)
		case "proxiable":
			cfg.Proxiable = parseBool(value)
		case "default_ccache_name":
			cfg.DefaultCCacheName = value
		case "default_keytab_name":
			cfg.DefaultKeytabName = value
		case "default_client_keytab_name":
			cfg.DefaultClientKeytabName = value
		case "udp_preference_limit":
			limit, err := strconv.Atoi(value)
			if err != nil || limit < 0 {
				return fmt.Errorf("invalid udp_preference_limit")
			}
			cfg.UDPPreferenceLimit = limit
		case "permitted_enctypes":
			cfg.PermittedEnctypes = parseEnctypes(values)
		case "default_tgs_enctypes":
			cfg.DefaultTGSEnctypes = parseEnctypes(values)
		case "default_tkt_enctypes":
			cfg.DefaultTKTEnctypes = parseEnctypes(values)
		}
	case "domain_realm":
		cfg.DomainRealm[key] = values[len(values)-1]
	}
	return nil
}

func addSubsection(cfg *Config, section, subsection, key string, values []string) {
	target := cfg.RealmOptions
	if section == "capaths" {
		target = cfg.CapathOptions
	}
	if target[subsection] == nil {
		target[subsection] = make(map[string][]string)
	}
	target[subsection][key] = append(target[subsection][key], values...)
	if section == "realms" {
		cfg.Realms[subsection] = append(cfg.Realms[subsection], values...)
	} else if section == "capaths" {
		cfg.Capaths[subsection] = append(cfg.Capaths[subsection], values...)
	}
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true
	default:
		return false
	}
}

func parseEnctypes(values []string) []int32 {
	result := make([]int32, 0, len(values))
	for _, value := range values {
		switch strings.ToLower(value) {
		case "aes128-cts-hmac-sha1-96":
			result = append(result, 17)
		case "aes256-cts-hmac-sha1-96":
			result = append(result, 18)
		case "aes128-cts-hmac-sha256-128":
			result = append(result, 19)
		case "aes256-cts-hmac-sha384-192":
			result = append(result, 20)
		default:
			if number, err := strconv.ParseInt(value, 10, 32); err == nil {
				result = append(result, int32(number))
			}
		}
	}
	return result
}

// RealmForHost returns the realm configured for host, preferring exact
// mappings and then the longest matching leading-dot suffix.
func (cfg *Config) RealmForHost(host string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	if realm, ok := cfg.DomainRealm[host]; ok {
		return realm, true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var match string
	for domain, realm := range cfg.DomainRealm {
		domainLower := strings.ToLower(domain)
		if strings.HasPrefix(domainLower, ".") &&
			strings.HasSuffix(host, domainLower) &&
			len(domainLower) > len(match) {
			match = domainLower
			if realm == "" {
				continue
			}
			return realm, true
		}
	}
	return "", false
}
