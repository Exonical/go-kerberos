package otp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/krad"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

var (
	DefaultSocketDir = "/var/run/krb5kdc"
	SecretDir        = "/etc/krb5kdc"
)

type TokenType struct {
	Name       string
	Server     string
	Secret     string
	Timeout    time.Duration
	Retries    int
	StripRealm bool
	Indicators []string
}

func DefaultTokenType(name string) TokenType {
	if name == "" {
		name = "DEFAULT"
	}
	return TokenType{
		Name:       name,
		Server:     filepath.Join(DefaultSocketDir, name+".socket"),
		Timeout:    5 * time.Second,
		Retries:    3,
		StripRealm: true,
	}
}

func DecodeTokenTypes(profile *config.Config) ([]TokenType, error) {
	sections := map[string]map[string][]string(nil)
	if profile != nil {
		sections = profile.SubsectionOptions["otp"]
	}
	types := make([]TokenType, 0, len(sections)+1)
	hasDefault := false
	for name := range sections {
		if name == "DEFAULT" {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		types = append(types, DefaultTokenType("DEFAULT"))
	}
	names := make([]string, 0, len(sections))
	for name := range sections {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := sections[name]
		token, err := decodeTokenType(name, values)
		if err != nil {
			return nil, err
		}
		types = append(types, token)
	}
	if len(types) == 0 {
		types = append(types, DefaultTokenType("DEFAULT"))
	}
	return types, nil
}

// DecodeKDCConfigTokenTypes decodes the [otp] subsections retained by
// config.ParseKDCConf.
func DecodeKDCConfigTokenTypes(profile *config.KDCConfig) ([]TokenType, error) {
	if profile == nil {
		return DecodeTokenTypes(nil)
	}
	sections := &config.Config{SubsectionOptions: map[string]map[string]map[string][]string{
		"otp": profile.OTP,
	}}
	return DecodeTokenTypes(sections)
}

func decodeTokenType(name string, values map[string][]string) (TokenType, error) {
	token := DefaultTokenType(name)
	for key, entries := range values {
		if len(entries) == 0 {
			continue
		}
		value := strings.TrimSpace(entries[len(entries)-1])
		switch key {
		case "server":
			token.Server = value
		case "secret":
			path := value
			if !filepath.IsAbs(path) {
				path = filepath.Join(SecretDir, path)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return TokenType{}, fmt.Errorf("read OTP secret %q: %w", path, err)
			}
			token.Secret = strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
		case "timeout":
			seconds, err := strconv.Atoi(value)
			if err != nil || seconds < 0 {
				return TokenType{}, fmt.Errorf("invalid OTP timeout %q", value)
			}
			token.Timeout = time.Duration(seconds) * time.Second
		case "retries":
			retries, err := strconv.Atoi(value)
			if err != nil || retries < 0 {
				return TokenType{}, fmt.Errorf("invalid OTP retries %q", value)
			}
			token.Retries = retries
		case "strip_realm":
			token.StripRealm = parseBool(value)
		case "indicator":
			token.Indicators = append([]string(nil), entries...)
		}
	}
	if token.Secret == "" && !strings.HasPrefix(token.Server, "/") {
		return TokenType{}, fmt.Errorf("OTP token type %q has no secret for non-unix server", token.Name)
	}
	return token, nil
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true
	default:
		return false
	}
}

type tokenConfig struct {
	Type       string    `json:"type"`
	Username   string    `json:"username"`
	Indicators *[]string `json:"indicators"`
}

func decodeTokens(client principal.Principal, raw string, types []TokenType) ([]tokenConfig, error) {
	if strings.TrimSpace(raw) == "" {
		raw = "[{}]"
	}
	var values []tokenConfig
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		values = []tokenConfig{{}}
	}
	byName := make(map[string]TokenType, len(types))
	for _, token := range types {
		byName[token.Name] = token
	}
	result := make([]tokenConfig, len(values))
	for i, value := range values {
		if value.Type == "" {
			value.Type = "DEFAULT"
		}
		token, ok := byName[value.Type]
		if !ok {
			return nil, fmt.Errorf("unknown OTP token type %q", value.Type)
		}
		if value.Username == "" {
			value.Username = client.String()
			if token.StripRealm {
				if index := strings.LastIndex(value.Username, "@"); index >= 0 {
					value.Username = value.Username[:index]
				}
			}
		}
		result[i] = value
	}
	return result, nil
}

type RADIUSVerifier struct {
	Types    []TokenType
	Hostname string
	Client   *krad.Client
}

func (v *RADIUSVerifier) Verify(client principal.Principal, rawConfig string,
	otpValue []byte) ([]string, error) {
	if v == nil {
		return nil, errors.New("nil RADIUS verifier")
	}
	hostname := v.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	types := v.Types
	if len(types) == 0 {
		types = []TokenType{DefaultTokenType("DEFAULT")}
	}
	tokens, err := decodeTokens(client, rawConfig, types)
	if err != nil {
		return nil, err
	}
	radius := v.Client
	if radius == nil {
		radius = krad.NewClient()
	}
	base := krad.NewAttributes()
	if err := base.AddString(krad.NASIdentifier, hostname); err != nil {
		return nil, err
	}
	if err := base.AddNumber(krad.ServiceType, 8); err != nil {
		return nil, err
	}
	byName := make(map[string]TokenType, len(types))
	for _, token := range types {
		byName[token.Name] = token
	}
	for _, tokenConfig := range tokens {
		tokenType := byName[tokenConfig.Type]
		attrs := base.Copy()
		if err := attrs.Add(krad.UserPassword, otpValue); err != nil {
			return nil, err
		}
		if err := attrs.AddString(krad.UserName, tokenConfig.Username); err != nil {
			return nil, err
		}
		response, sendErr := radius.Send(context.Background(), krad.AccessRequest,
			attrs, tokenType.Server, tokenType.Secret, tokenType.Timeout, tokenType.Retries)
		if sendErr != nil {
			return nil, sendErr
		}
		if response.Code != krad.AccessAccept {
			continue
		}
		if tokenConfig.Indicators != nil {
			return append([]string(nil), (*tokenConfig.Indicators)...), nil
		}
		return append([]string(nil), tokenType.Indicators...), nil
	}
	return nil, errors.New("RADIUS OTP authentication failed")
}

type KDCVerifier struct {
	Verifier *RADIUSVerifier
	Lookup   func(principal.Principal) (string, error)
}

func NewKDCVerifier(verifier *RADIUSVerifier,
	lookup func(principal.Principal) (string, error)) *KDCVerifier {
	return &KDCVerifier{Verifier: verifier, Lookup: lookup}
}

func (v *KDCVerifier) VerifyOTP(client principal.Principal, otpValue []byte) ([]string, error) {
	if v == nil || v.Verifier == nil || v.Lookup == nil {
		return nil, errors.New("incomplete OTP verifier")
	}
	raw, err := v.Lookup(client)
	if err != nil {
		return nil, err
	}
	return v.Verifier.Verify(client, raw, otpValue)
}
