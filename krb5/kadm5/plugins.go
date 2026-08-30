package kadm5

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// Password quality result codes match the MIT KADM5_PASS_Q_* values.
const (
	PassQualityTooShort uint32 = 43787542
	PassQualityClass    uint32 = 43787543
	PassQualityDict     uint32 = 43787544
	PassQualityGeneric  uint32 = 43787548
)

// PasswordQualityError is returned by a password quality module.
type PasswordQualityError struct {
	Code    uint32
	Message string
}

func (e *PasswordQualityError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// PasswordQualityModule checks a proposed password. Modules are called in
// registration order, after the configured policy checks.
type PasswordQualityModule interface {
	Name() string
	Check(password, policyName string, name principal.Principal) error
}

// EmptyPasswordQuality rejects empty passwords, including for principals
// without a password policy.
type EmptyPasswordQuality struct{}

func (EmptyPasswordQuality) Name() string { return "empty" }
func (EmptyPasswordQuality) Check(password, _ string, _ principal.Principal) error {
	if password == "" {
		return &PasswordQualityError{Code: PassQualityTooShort, Message: "Empty passwords are not allowed"}
	}
	return nil
}

// PrincipalPasswordQuality rejects passwords equal to a principal component
// or realm when a password policy is assigned.
type PrincipalPasswordQuality struct{}

func (PrincipalPasswordQuality) Name() string { return "princ" }
func (PrincipalPasswordQuality) Check(password, policyName string, name principal.Principal) error {
	if policyName == "" {
		return nil
	}
	if strings.EqualFold(password, name.Realm) {
		return &PasswordQualityError{Code: PassQualityDict, Message: "Password may not match principal name"}
	}
	for _, component := range name.Components {
		if strings.EqualFold(password, component) {
			return &PasswordQualityError{Code: PassQualityDict, Message: "Password may not match principal name"}
		}
	}
	return nil
}

// DictionaryPasswordQuality rejects a password which is exactly a dictionary
// word, case-insensitively, when a password policy is assigned.
type DictionaryPasswordQuality struct {
	words map[string]struct{}
}

// NewDictionaryPasswordQuality loads one word per line from path. A missing
// or unreadable dictionary behaves like MIT's optional dictionary module and
// leaves the module enabled without words.
func NewDictionaryPasswordQuality(path string) *DictionaryPasswordQuality {
	m := &DictionaryPasswordQuality{words: make(map[string]struct{})}
	if path == "" {
		return m
	}
	file, err := os.Open(path)
	if err != nil {
		return m
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSuffix(scanner.Text(), "\r")
		m.words[strings.ToLower(word)] = struct{}{}
	}
	return m
}

func (DictionaryPasswordQuality) Name() string { return "dict" }
func (m *DictionaryPasswordQuality) Check(password, policyName string, _ principal.Principal) error {
	if policyName == "" {
		return nil
	}
	if _, ok := m.words[strings.ToLower(password)]; ok {
		return &PasswordQualityError{Code: PassQualityDict, Message: "Password is in the password dictionary"}
	}
	return nil
}

func defaultPasswordQualityModules() []PasswordQualityModule {
	return []PasswordQualityModule{EmptyPasswordQuality{}, PrincipalPasswordQuality{}}
}

func (s *Server) checkPasswordQuality(password, policyName string, name principal.Principal) error {
	modules := s.PasswordQualityModules
	if modules == nil {
		modules = defaultPasswordQualityModules()
	}
	if s.DictionaryFile != "" {
		found := false
		for _, module := range modules {
			if module != nil && module.Name() == "dict" {
				found = true
				break
			}
		}
		if !found {
			modules = append(modules, NewDictionaryPasswordQuality(s.DictionaryFile))
		}
	}
	for _, module := range modules {
		if module == nil {
			continue
		}
		if err := module.Check(password, policyName, name); err != nil {
			return err
		}
	}
	return nil
}

// HookStage identifies whether a kadm5 hook runs before or after commit.
type HookStage int

const (
	HookPreCommit HookStage = iota
	HookPostCommit
)

// HookEvent is the Go equivalent of the MIT kadm5 hook callback arguments.
type HookEvent struct {
	Stage        HookStage
	Operation    string
	Principal    principal.Principal
	NewPrincipal principal.Principal
	Entry        PrincipalEntry
	Mask         int32
	Password     string
	KeepOld      bool
}

// Kadm5Hook receives principal mutation lifecycle events. Alias creation uses
// the operation name "alias" and populates NewPrincipal with its target.
type Kadm5Hook interface {
	Name() string
	Handle(HookEvent) error
}

func (s *Server) runHooks(stage HookStage, event HookEvent) error {
	event.Stage = stage
	for _, hook := range s.Hooks {
		if hook == nil {
			continue
		}
		if err := hook.Handle(event); err != nil {
			if stage == HookPostCommit {
				if s.ErrorLog != nil {
					s.ErrorLog(fmt.Errorf("kadm5 hook %s (%s): %w", hook.Name(), event.Operation, err))
				}
				continue
			}
			return err
		}
	}
	return nil
}

func qualityCode(err error) uint32 {
	var quality *PasswordQualityError
	if errors.As(err, &quality) {
		return quality.Code
	}
	return 0
}

func passwordClasses(password string) int {
	var upper, lower, digit, punct, other bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsPunct(r):
			punct = true
		default:
			other = true
		}
	}
	n := 0
	for _, present := range []bool{upper, lower, digit, punct, other} {
		if present {
			n++
		}
	}
	return n
}

func checkPolicy(password string, policy *kdb.PolicyRecord) error {
	if policy == nil {
		return nil
	}
	if policy.MinLength > 0 && int32(len(password)) < policy.MinLength {
		return kdb.ErrPasswordTooShort
	}
	if policy.MinClasses > 0 && passwordClasses(password) < int(policy.MinClasses) {
		return kdb.ErrPasswordClasses
	}
	return nil
}
