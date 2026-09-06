package config

import (
	"fmt"
	"strings"
)

// ExpandPathTokens expands the profile path tokens supported by MIT Kerberos.
func ExpandPathTokens(path string) (string, error) {
	var expanded strings.Builder
	for len(path) > 0 {
		start := strings.Index(path, "%{")
		if start < 0 {
			expanded.WriteString(path)
			break
		}
		expanded.WriteString(path[:start])
		end := strings.IndexByte(path[start+2:], '}')
		if end < 0 {
			return "", fmt.Errorf("expand path: variable missing }")
		}
		end += start + 2
		token := path[start+2 : end]
		value, err := expandPathToken(token)
		if err != nil {
			return "", err
		}
		expanded.WriteString(value)
		path = path[end+1:]
	}
	return normalizeExpandedPath(expanded.String()), nil
}

func expandPathToken(token string) (string, error) {
	switch token {
	case "TEMP":
		return expandPathTemp()
	case "uid", "USERID":
		return expandPathUserID()
	case "null":
		return "", nil
	default:
		return expandPlatformPathToken(token)
	}
}
