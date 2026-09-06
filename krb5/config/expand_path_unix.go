//go:build !windows

package config

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

func expandPathTemp() (string, error) {
	if value := os.Getenv("TMPDIR"); value != "" {
		return value, nil
	}
	return os.TempDir(), nil
}

func expandPathUserID() (string, error) {
	return strconv.FormatUint(uint64(os.Getuid()), 10), nil
}

func expandPlatformPathToken(token string) (string, error) {
	switch token {
	case "euid":
		return strconv.FormatUint(uint64(os.Geteuid()), 10), nil
	case "username":
		current, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("expand path: resolve username: %w", err)
		}
		return current.Username, nil
	case "LIBDIR":
		return "/usr/lib", nil
	case "BINDIR":
		return "/usr/bin", nil
	case "SBINDIR":
		return "/usr/sbin", nil
	default:
		return "", fmt.Errorf("expand path: invalid token %%{%s}", token)
	}
}

func normalizeExpandedPath(path string) string {
	return path
}
