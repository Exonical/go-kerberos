//go:build windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func expandPathTemp() (string, error) {
	return trimTrailingSeparators(os.TempDir()), nil
}

func expandPathUserID() (string, error) {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &token)
	if err == windows.ERROR_NO_TOKEN {
		token = windows.GetCurrentProcessToken()
	} else if err != nil {
		return "", fmt.Errorf("expand path: open thread token: %w", err)
	} else {
		defer token.Close()
	}

	owner, err := tokenOwner(token)
	if err != nil {
		return "", fmt.Errorf("expand path: resolve owner SID: %w", err)
	}
	sid := owner.String()
	if sid == "" {
		return "", fmt.Errorf("expand path: resolve owner SID: empty SID")
	}
	return sid, nil
}

type tokenOwnerInfo struct {
	Owner *windows.SID
}

func tokenOwner(token windows.Token) (*windows.SID, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}
	info := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &info[0], uint32(len(info)), &size); err != nil {
		return nil, err
	}
	owner := (*tokenOwnerInfo)(unsafe.Pointer(&info[0])).Owner // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 GetTokenInformation(TokenOwner)
	if owner == nil {
		return nil, fmt.Errorf("empty owner SID")
	}
	return owner, nil
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
