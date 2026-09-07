//go:build windows

package secureenv

import "os"

// Get returns an environment variable.
func Get(name string) string {
	return os.Getenv(name)
}

// Lookup reports whether an environment variable is set.
func Lookup(name string) (string, bool) {
	return os.LookupEnv(name)
}
