//go:build !windows

package config

import "github.com/Exonical/go-kerberos/internal/secureenv"

func defaultConfigFiles(secure bool) []string {
	if !secure {
		if path := secureenv.Get("KRB5_CONFIG"); path != "" {
			return []string{path}
		}
	}
	return []string{"/etc/krb5.conf"}
}
