//go:build windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func expandPathTemp() (string, error) {
	return trimTrailingSeparators(os.TempDir()), nil
}

func expandPathUserID() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("expand path: resolve user SID: %w", err)
	}
	sid := user.User.Sid.String()
	if sid == "" {
		return "", fmt.Errorf("expand path: resolve user SID: empty SID")
	}
	return sid, nil
}

func expandPlatformPathToken(token string) (string, error) {
	switch token {
	case "APPDATA":
		return knownFolder(windows.FOLDERID_RoamingAppData)
	case "COMMON_APPDATA":
		return knownFolder(windows.FOLDERID_ProgramData)
	case "LOCAL_APPDATA":
		return knownFolder(windows.FOLDERID_LocalAppData)
	case "SYSTEM":
		return knownFolder(windows.FOLDERID_System)
	case "WINDOWS":
		return knownFolder(windows.FOLDERID_Windows)
	case "USERCONFIG":
		return appendConfigFolder(windows.FOLDERID_RoamingAppData)
	case "COMMONCONFIG":
		return appendConfigFolder(windows.FOLDERID_ProgramData)
	case "LIBDIR", "BINDIR", "SBINDIR":
		executable, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("expand path: resolve executable: %w", err)
		}
		return trimTrailingSeparators(filepath.Dir(executable)), nil
	case "euid":
		return expandPathUserID()
	default:
		return "", fmt.Errorf("expand path: invalid token %%{%s}", token)
	}
}

func knownFolder(id *windows.KNOWNFOLDERID) (string, error) {
	path, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("expand path: resolve known folder: %w", err)
	}
	return trimTrailingSeparators(path), nil
}

func appendConfigFolder(id *windows.KNOWNFOLDERID) (string, error) {
	path, err := knownFolder(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "MIT", "Kerberos5"), nil
}

func trimTrailingSeparators(path string) string {
	for len(path) > 1 && strings.HasSuffix(path, `\`) {
		path = strings.TrimSuffix(path, `\`)
	}
	for len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

func normalizeExpandedPath(path string) string {
	return strings.ReplaceAll(path, "/", `\`)
}
