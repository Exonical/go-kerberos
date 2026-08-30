// Package localauth implements MIT-compatible local principal authorization
// and local-name translation.
package localauth

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

var (
	// ErrNoTranslation indicates that no auth_to_local rule applies.
	ErrNoTranslation = errors.New("local principal has no translation")
	// ErrBadFormat indicates malformed local authorization configuration.
	ErrBadFormat = errors.New("invalid local authorization rule")
	// ErrNoCache indicates that a requested identity has no matching cache.
	ErrNoCache = errors.New("no credential cache for selected principal")
)

// AnameToLocalname translates p using auth_to_local_names and auth_to_local
// in the configured default realm.
func AnameToLocalname(cfg *config.Config, p principal.Principal) (string, error) {
	if cfg == nil {
		return "", ErrNoTranslation
	}
	realm := cfg.DefaultRealm
	name := principalWithoutRealm(p)
	names := realmMap(cfg.RealmAuthToLocalNames, realm)
	if names != nil {
		if values := names[name]; len(values) != 0 {
			return values[len(values)-1], nil
		}
	}
	mappings := realmSlice(cfg.RealmAuthToLocal, realm)
	for _, mapping := range mappings {
		if strings.EqualFold(strings.TrimSpace(mapping), "DEFAULT") {
			if strings.EqualFold(p.Realm, realm) && len(p.Components) == 1 {
				return p.Components[0], nil
			}
			continue
		}
		if !strings.HasPrefix(mapping, "RULE:") {
			return "", fmt.Errorf("%w: %q", ErrBadFormat, mapping)
		}
		value, matched, err := applyRule(strings.TrimPrefix(mapping, "RULE:"), p)
		if err != nil {
			return "", err
		}
		if matched {
			return value, nil
		}
	}
	if len(mappings) == 0 && strings.EqualFold(p.Realm, realm) &&
		len(p.Components) == 1 {
		return p.Components[0], nil
	}
	return "", ErrNoTranslation
}

func principalWithoutRealm(p principal.Principal) string {
	var b strings.Builder
	for i, component := range p.Components {
		if i != 0 {
			b.WriteByte('/')
		}
		for _, r := range component {
			if r == '/' || r == '@' || r == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

func applyRule(body string, p principal.Principal) (string, bool, error) {
	selection := principalWithoutRealm(p)
	if strings.HasPrefix(body, "[") {
		end := strings.IndexByte(body, ']')
		if end < 0 {
			return "", false, fmt.Errorf("%w: missing selection terminator", ErrBadFormat)
		}
		selectionSpec := body[1:end]
		sep := strings.IndexByte(selectionSpec, ':')
		if sep <= 0 {
			return "", false, fmt.Errorf("%w: malformed selection", ErrBadFormat)
		}
		count, err := strconv.Atoi(selectionSpec[:sep])
		if err != nil || count < 0 {
			return "", false, fmt.Errorf("%w: malformed component count", ErrBadFormat)
		}
		if len(p.Components) != count {
			return "", false, nil
		}
		value, err := expandSelection(selectionSpec[sep+1:], p)
		if err != nil {
			return "", false, err
		}
		selection = value
		body = body[end+1:]
	}
	if strings.HasPrefix(body, "(") {
		end := strings.IndexByte(body[1:], ')')
		if end < 0 {
			return "", false, fmt.Errorf("%w: missing match terminator", ErrBadFormat)
		}
		end++
		re, err := regexp.Compile(body[1:end])
		if err != nil {
			return "", false, fmt.Errorf("%w: match expression: %v", ErrBadFormat, err)
		}
		match := re.FindStringIndex(selection)
		if match == nil || match[0] != 0 || match[1] != len(selection) {
			return "", false, nil
		}
		body = body[end+1:]
	}
	result := selection
	for strings.TrimSpace(body) != "" {
		body = strings.TrimSpace(body)
		if len(body) < 4 || body[0] != 's' || body[1] != '/' {
			return "", false, fmt.Errorf("%w: malformed substitution", ErrBadFormat)
		}
		rest := body[2:]
		sep := strings.IndexByte(rest, '/')
		if sep < 0 {
			return "", false, fmt.Errorf("%w: malformed substitution", ErrBadFormat)
		}
		from := rest[:sep]
		rest = rest[sep+1:]
		sep = strings.IndexByte(rest, '/')
		if sep < 0 {
			return "", false, fmt.Errorf("%w: malformed substitution", ErrBadFormat)
		}
		to := rest[:sep]
		body = rest[sep+1:]
		global := false
		if strings.HasPrefix(body, "g") {
			global = true
			body = body[1:]
		}
		re, err := regexp.Compile(from)
		if err != nil {
			return "", false, fmt.Errorf("%w: substitution expression: %v", ErrBadFormat, err)
		}
		if global {
			result = re.ReplaceAllStringFunc(result, func(string) string { return to })
		} else {
			loc := re.FindStringIndex(result)
			if loc != nil {
				result = result[:loc[0]] + to + result[loc[1]:]
			}
		}
	}
	if result == "" {
		return "", false, nil
	}
	return result, true, nil
}

func realmSlice(values map[string][]string, realm string) []string {
	if values == nil {
		return nil
	}
	if result := values[realm]; result != nil {
		return result
	}
	for name, result := range values {
		if strings.EqualFold(name, realm) {
			return result
		}
	}
	return nil
}

func realmMap(values map[string]map[string][]string, realm string) map[string][]string {
	if values == nil {
		return nil
	}
	if result := values[realm]; result != nil {
		return result
	}
	for name, result := range values {
		if strings.EqualFold(name, realm) {
			return result
		}
	}
	return nil
}

func expandSelection(format string, p principal.Principal) (string, error) {
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '$' {
			b.WriteByte(format[i])
			continue
		}
		if i+1 == len(format) || format[i+1] < '0' || format[i+1] > '9' {
			return "", fmt.Errorf("%w: invalid selection variable", ErrBadFormat)
		}
		index := int(format[i+1] - '0')
		if index == 0 {
			b.WriteString(p.Realm)
		} else if index <= len(p.Components) {
			b.WriteString(p.Components[index-1])
		} else {
			return "", fmt.Errorf("%w: selection component out of range", ErrBadFormat)
		}
		i++
	}
	return b.String(), nil
}

// Kuserok checks whether p may authenticate as localUser using the default
// local user's .k5login file and auth_to_local fallback.
func Kuserok(p principal.Principal, localUser string) bool {
	ok, _ := KuserokWithOptions(nil, p, localUser, KuserokOptions{})
	return ok
}

// KuserokOptions provides test hooks and MIT k5login policy settings.
type KuserokOptions struct {
	HomeDir              string
	HomeDirForUser       func(string) (string, error)
	K5LoginPath          string
	K5LoginDirectory     string
	K5LoginAuthoritative bool
	AuthoritativeSet     bool
}

// KuserokWithOptions checks .k5login authorization, falling back to
// aname-to-localname matching when the file is absent or non-authoritative.
func KuserokWithOptions(cfg *config.Config, p principal.Principal, localUser string, opts KuserokOptions) (bool, error) {
	if localUser == "" {
		return false, nil
	}
	if cfg != nil {
		if opts.K5LoginPath == "" && opts.K5LoginDirectory == "" && cfg.K5LoginDirectory != "" {
			opts.K5LoginDirectory = cfg.K5LoginDirectory
		}
		if opts.K5LoginPath == "" && opts.K5LoginDirectory == "" {
			if values := cfg.Options["libdefaults"]["k5login_directory"]; len(values) != 0 {
				opts.K5LoginDirectory = values[len(values)-1]
			}
		}
		if !opts.AuthoritativeSet {
			if values := cfg.Options["libdefaults"]["k5login_authoritative"]; len(values) != 0 {
				opts.K5LoginAuthoritative = strings.EqualFold(values[len(values)-1], "true") ||
					strings.EqualFold(values[len(values)-1], "yes")
				opts.AuthoritativeSet = true
			}
		}
	}
	authoritative := true
	if opts.AuthoritativeSet {
		authoritative = opts.K5LoginAuthoritative
	}
	home, err := localHome(localUser, opts)
	if err != nil {
		return false, err
	}
	path := opts.K5LoginPath
	if path == "" {
		if opts.K5LoginDirectory != "" {
			path = filepath.Join(opts.K5LoginDirectory, localUser)
		} else {
			path = filepath.Join(home, ".k5login")
		}
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fallbackLocalname(cfg, p, localUser, authoritative)
	}
	if err != nil {
		if authoritative {
			return false, nil
		}
		return fallbackLocalname(cfg, p, localUser, false)
	}
	if info.Mode().IsDir() {
		return false, nil
	}
	if uid, ok := fileOwnerUID(info); ok && uid != 0 {
		if expected, uidErr := localUID(localUser); uidErr == nil && uid != expected {
			if authoritative {
				return false, nil
			}
			return fallbackLocalname(cfg, p, localUser, false)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if authoritative {
			return false, nil
		}
		return fallbackLocalname(cfg, p, localUser, false)
	}
	want := p.String()
	for _, line := range strings.Split(string(data), "\n") {
		if line == want {
			return true, nil
		}
	}
	if authoritative {
		return false, nil
	}
	return fallbackLocalname(cfg, p, localUser, false)
}

func fallbackLocalname(cfg *config.Config, p principal.Principal, localUser string, authoritative bool) (bool, error) {
	if cfg == nil {
		if len(p.Components) == 1 && strings.EqualFold(p.Realm, "") {
			return p.Components[0] == localUser, nil
		}
		return false, nil
	}
	name, err := AnameToLocalname(cfg, p)
	if errors.Is(err, ErrNoTranslation) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return name == localUser, nil
}

func localHome(localUser string, opts KuserokOptions) (string, error) {
	if opts.HomeDir != "" {
		return opts.HomeDir, nil
	}
	if opts.HomeDirForUser != nil {
		return opts.HomeDirForUser(localUser)
	}
	current, err := user.Lookup(localUser)
	if err != nil {
		return "", err
	}
	return current.HomeDir, nil
}

func localUID(localUser string) (uint32, error) {
	current, err := user.Lookup(localUser)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(current.Uid, 10, 32)
	return uint32(value), err
}
