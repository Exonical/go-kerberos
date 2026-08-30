package localauth

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// SelectIdentity reads a .k5identity file and returns the first principal
// whose constraints match server. The bool is false when no rule applies.
func SelectIdentity(path string, server principal.Principal) (principal.Principal, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return principal.Principal{}, false, nil
		}
		return principal.Principal{}, false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		p, err := principal.Parse(fields[0])
		if err != nil {
			continue
		}
		matches := true
		for _, field := range fields[1:] {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) != 2 || !identityConstraint(parts[0], parts[1], server) {
				matches = false
				break
			}
		}
		if matches {
			return *p, true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return principal.Principal{}, false, err
	}
	return principal.Principal{}, false, nil
}

// IdentityPath returns the configured .k5identity path, or the current user's
// home-directory path when no path is configured.
func IdentityPath(cfg *config.Config) string {
	if cfg != nil && cfg.K5IdentityPath != "" {
		return cfg.K5IdentityPath
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".k5identity")
	}
	return ""
}

func identityConstraint(name, pattern string, server principal.Principal) bool {
	switch strings.ToLower(name) {
	case "realm":
		return identityMatch(pattern, server.Realm, false)
	case "service":
		return server.NameType == principal.NTSrvHst && len(server.Components) >= 2 &&
			identityMatch(pattern, server.Components[0], false)
	case "host":
		return server.NameType == principal.NTSrvHst && len(server.Components) >= 2 &&
			identityMatch(pattern, strings.ToLower(server.Components[1]), true)
	default:
		return false
	}
}

func identityMatch(pattern, value string, fold bool) bool {
	if fold {
		pattern, value = strings.ToLower(pattern), strings.ToLower(value)
	}
	matched, err := filepath.Match(pattern, value)
	return err == nil && matched
}

// ParseIdentityLine parses one .k5identity line for callers which need to
// inspect rules without opening a file.
func ParseIdentityLine(line string, server principal.Principal) (principal.Principal, bool, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
		return principal.Principal{}, false, nil
	}
	p, err := principal.Parse(fields[0])
	if err != nil {
		return principal.Principal{}, false, fmt.Errorf("parse .k5identity principal: %w", err)
	}
	for _, field := range fields[1:] {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 || !identityConstraint(parts[0], parts[1], server) {
			return principal.Principal{}, false, nil
		}
	}
	return *p, true, nil
}
