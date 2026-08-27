package kdc

import (
	"fmt"
	"strings"
)

const domainX500Compress = 1

// encodeTransited encodes an ordered list of intermediate realms using the
// DOMAIN-X500-COMPRESS representation from RFC 4120 section 3.3.3.2.
func encodeTransited(realms []string) ([]byte, error) {
	if len(realms) == 0 {
		return nil, nil
	}
	var fields []string
	var previous string
	for _, realm := range realms {
		if realm == "" || strings.IndexByte(realm, 0) >= 0 {
			return nil, fmt.Errorf("invalid transited realm")
		}
		realm = escapeTransited(realm)
		field := realm
		if previous != "" {
			if strings.HasPrefix(realm, previous) && strings.HasPrefix(realm[len(previous):], "/") {
				field = realm[len(previous):]
			} else if len(realm) > len(previous) &&
				strings.HasSuffix(realm, previous) &&
				realm[len(realm)-len(previous)-1] == '.' {
				field = strings.TrimSuffix(realm, previous)
				if !strings.HasSuffix(field, ".") {
					field += "."
				}
			}
		}
		fields = append(fields, field)
		previous = realm
	}
	return []byte(strings.Join(fields, ",")), nil
}

func decodeTransited(contents []byte) ([]string, error) {
	if len(contents) == 0 {
		return nil, nil
	}
	var fields []string
	var field strings.Builder
	escaped := false
	flush := func() error {
		value := field.String()
		field.Reset()
		if value == "" {
			return nil
		}
		if strings.HasPrefix(value, " ") {
			value = value[1:]
		} else if strings.HasPrefix(value, "/") && len(fields) > 0 && strings.HasPrefix(fields[len(fields)-1], "/") {
			value = fields[len(fields)-1] + value
		} else if strings.HasSuffix(value, ".") && len(fields) > 0 {
			value += fields[len(fields)-1]
		}
		value = unescapeTransited(value)
		if value == "" {
			return fmt.Errorf("empty transited realm")
		}
		fields = append(fields, value)
		return nil
	}
	for _, char := range contents {
		if escaped {
			field.WriteByte(char)
			escaped = false
		} else if char == '\\' {
			field.WriteByte(char)
			escaped = true
		} else if char == ',' {
			if err := flush(); err != nil {
				return nil, err
			}
		} else {
			field.WriteByte(char)
		}
	}
	if escaped {
		return nil, fmt.Errorf("transited field ends with escape")
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return fields, nil
}

func appendTransited(contents []byte, realm string) ([]byte, error) {
	realms, err := decodeTransited(contents)
	if err != nil {
		return nil, err
	}
	realms = append(realms, realm)
	return encodeTransited(realms)
}

func escapeTransited(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, ",", `\,`)
}

func unescapeTransited(value string) string {
	var result strings.Builder
	escaped := false
	for _, char := range value {
		if escaped {
			result.WriteRune(char)
			escaped = false
		} else if char == '\\' {
			escaped = true
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

func transitedPermitted(contents []byte, clientRealm, serverRealm string, capaths map[string]map[string][]string) bool {
	realms, err := decodeTransited(contents)
	if err != nil {
		return false
	}
	allowed := make(map[string]bool)
	path := []string{clientRealm, serverRealm}
	for source, targets := range capaths {
		if !strings.EqualFold(source, clientRealm) {
			continue
		}
		for target, values := range targets {
			if !strings.EqualFold(target, serverRealm) {
				continue
			}
			path = []string{clientRealm}
			if len(values) == 1 && values[0] == "." {
				path = append(path, serverRealm)
			} else {
				path = append(path, values...)
				path = append(path, serverRealm)
			}
		}
	}
	for _, realm := range path {
		allowed[strings.ToUpper(realm)] = true
	}
	for _, realm := range append([]string{clientRealm, serverRealm}, hierarchyRealms(clientRealm, serverRealm)...) {
		allowed[strings.ToUpper(realm)] = true
	}
	for _, realm := range realms {
		if !allowed[strings.ToUpper(realm)] {
			return false
		}
	}
	return true
}

func hierarchyRealms(clientRealm, serverRealm string) []string {
	var result []string
	for _, realm := range []string{clientRealm, serverRealm} {
		parts := strings.Split(realm, ".")
		for i := 1; i < len(parts); i++ {
			result = append(result, strings.Join(parts[i:], "."))
		}
	}
	return result
}
