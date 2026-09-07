package config

import (
	"errors"
	"os"
)

// DefaultConfigFiles returns the platform's ordered default profile paths.
// secure disables environment and per-user sources where the platform
// supports them.
func DefaultConfigFiles(secure bool) []string {
	return defaultConfigFiles(secure)
}

// ParseDefault loads the first existing profile in the platform's default
// search order.
func ParseDefault(secure bool) (*Config, error) {
	var last error
	for _, filename := range DefaultConfigFiles(secure) {
		cfg, err := ParseFile(filename)
		if err == nil {
			return cfg, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		last = err
	}
	if last != nil {
		return nil, last
	}
	return nil, os.ErrNotExist
}
