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
	OTP      map[string]map[string][]string
}

// KDCRealmConfig contains one [realms] subsection from kdc.conf.
type KDCRealmConfig struct {
	Values                      map[string][]string
	KDCPorts                    []int
	KDCTCPPorts                 []int
	IpropEnabled                bool
	IpropPort                   int
	IpropPollTime               time.Duration
	IpropResyncTimeout          time.Duration
	IpropUlogSize               int
	IpropLogfile                string
	MaxLife                     time.Duration
	MaxRenewableLife            time.Duration
	DisablePAC                  bool
	RejectBadTransit            bool
	RestrictAnonymousToTGT      bool
	HostBasedServices           []string
	NoHostReferral              []string
	MasterKeyType               string
	SupportedEnctypes           []string
	EncryptedChallengeIndicator string
	SPAKEPreauthIndicators      []string
	PKINITIndicators            []string
	PKINITDHMinBits             string
	OTPIndicators               []string
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
		OTP:      cloneSubsectionOptions(profile.SubsectionOptions["otp"]),
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
		settings.HostBasedServices = append(
			splitList(firstValues(defaults, "host_based_services")),
			splitList(firstValues(values, "host_based_services"))...,
		)
		settings.NoHostReferral = append(
			splitList(firstValues(defaults, "no_host_referral")),
			splitList(firstValues(values, "no_host_referral"))...,
		)
		settings.Values = cloneOptions(merged)
		result.Realms[realm] = settings
	}
	return result, nil
}

func cloneSubsectionOptions(values map[string]map[string][]string) map[string]map[string][]string {
	result := make(map[string]map[string][]string, len(values))
	for subsection, options := range values {
		result[subsection] = cloneOptions(options)
	}
	return result
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
	settings := KDCRealmConfig{RejectBadTransit: true}
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
	if raw := firstValues(values, "disable_pac"); raw != "" {
		settings.DisablePAC = parseBool(raw)
	}
	if raw := firstValues(values, "reject_bad_transit"); raw != "" {
		settings.RejectBadTransit = parseBool(raw)
	}
	if raw := firstValues(values, "restrict_anonymous_to_tgt"); raw != "" {
		settings.RestrictAnonymousToTGT = parseBool(raw)
	}
	settings.HostBasedServices = splitList(firstValues(values, "host_based_services"))
	settings.NoHostReferral = splitList(firstValues(values, "no_host_referral"))
	settings.MasterKeyType = firstValues(values, "master_key_type")
	settings.SupportedEnctypes = splitList(firstValues(values, "supported_enctypes"))
	settings.EncryptedChallengeIndicator = firstValues(values, "encrypted_challenge_indicator")
	settings.SPAKEPreauthIndicators = splitList(firstValues(values, "spake_preauth_indicator"))
	settings.PKINITIndicators = splitList(firstValues(values, "pkinit_indicator"))
	settings.PKINITDHMinBits = firstValues(values, "pkinit_dh_min_bits")
	settings.OTPIndicators = splitList(firstValues(values, "otp_indicator"))
	if raw := firstValues(values, "iprop_enable"); raw != "" {
		settings.IpropEnabled = parseBool(raw)
	}
	if raw := firstValues(values, "iprop_port"); raw != "" {
		settings.IpropPort, err = strconv.Atoi(raw)
		if err != nil || settings.IpropPort < 1 || settings.IpropPort > 65535 {
			return settings, fmt.Errorf("iprop_port: invalid port %q", raw)
		}
	}
	rawPoll := firstValues(values, "iprop_replica_poll")
	if rawPoll == "" {
		rawPoll = firstValues(values, "iprop_slave_poll")
	}
	if rawPoll == "" {
		rawPoll = firstValues(values, "iprop_poll")
	}
	if raw := rawPoll; raw != "" {
		settings.IpropPollTime, err = ParseDuration(raw)
		if err != nil {
			return settings, fmt.Errorf("iprop_poll: %w", err)
		}
	}
	if raw := firstValues(values, "iprop_resync_timeout"); raw != "" {
		settings.IpropResyncTimeout, err = ParseDuration(raw)
		if err != nil {
			return settings, fmt.Errorf("iprop_resync_timeout: %w", err)
		}
	}
	if raw := firstValues(values, "iprop_ulogsize"); raw != "" {
		settings.IpropUlogSize, err = strconv.Atoi(raw)
		if err != nil || settings.IpropUlogSize < 0 {
			return settings, fmt.Errorf("iprop_ulogsize: invalid size %q", raw)
		}
	}
	settings.IpropLogfile = firstValues(values, "iprop_logfile")
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
