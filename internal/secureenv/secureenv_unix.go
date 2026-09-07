//go:build !windows

package secureenv

import "os"

// Get returns an environment variable only when the process is not running
// with elevated real/effective credentials.
func Get(name string) string {
	if os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return ""
	}
	return os.Getenv(name)
}

// Lookup reports whether an environment variable is available to a secure
// process.
func Lookup(name string) (string, bool) {
	if os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return "", false
	}
	return os.LookupEnv(name)
}
