//go:build !windows

package config

import "os"

func defaultConfigFiles(secure bool) []string {
	if !secure {
		if path := os.Getenv("KRB5_CONFIG"); path != "" {
			return []string{path}
		}
	}
	return []string{"/etc/krb5.conf"}
}
