// Package kdb provides the in-memory principal database used by the Go KDC.
package kdb

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// Key is a principal's long-term key for one enctype and KVNO.
type Key struct {
	Enctype int32
	KVNO    uint32
	Key     []byte
	Salt    string
}

// PrincipalRecord contains a principal and its KDC policy.
type PrincipalRecord struct {
	Name               principal.Principal
	Keys               map[int32]Key
	Strings            map[string]string
	KVNO               uint32
	Flags              uint32
	Policy             string
	MaxLife            time.Duration
	MaxRenew           time.Duration
	Expiration         time.Time
	PasswordExpiration time.Time
}

// PolicyRecord contains the mutable policy fields used by kadmind.
type PolicyRecord struct {
	Name                 string
	MinLife              int32
	MaxLife              int32
	MinLength            int32
	MinClasses           int32
	HistoryNum           int32
	MaxFailure           uint32
	FailureCountInterval int32
	LockoutDuration      int32
	Attributes           int32
	MaxTicketLife        int32
	MaxRenewableLife     int32
}

var (
	ErrPrincipalExists   = errors.New("principal already exists")
	ErrPrincipalNotFound = errors.New("principal not found")
	ErrPolicyExists      = errors.New("policy already exists")
	ErrPolicyNotFound    = errors.New("policy not found")
	ErrPolicyInUse       = errors.New("policy is in use")
)

// Store resolves principal records for the KDC. Lookup returns false with a
// nil error when the principal does not exist, and a non-nil error only for
// backend failures.
type Store interface {
	Lookup(principal.Principal) (PrincipalRecord, bool, error)
}

// AliasResolver optionally resolves an alias principal to its canonical
// principal. KDC callers decide whether a resolved alias is exposed in a
// reply; Store implementations may keep ordinary Lookup canonical-only.
type AliasResolver interface {
	ResolveAlias(principal.Principal) (principal.Principal, bool, error)
}

// Database is a concurrency-safe in-memory principal store.
type Database struct {
	Realm string

	mu         sync.RWMutex
	principals map[string]PrincipalRecord
	aliases    map[string]principal.Principal
	policies   map[string]PolicyRecord
}

// NewDatabase creates an empty database for realm.
func NewDatabase(realm string) *Database {
	return &Database{
		Realm:      realm,
		principals: make(map[string]PrincipalRecord),
		aliases:    make(map[string]principal.Principal),
		policies:   make(map[string]PolicyRecord),
	}
}

// AddPrincipal derives all supported AES keys for name and stores them.
// The optional KVNO list permits key rotation; the greatest supplied KVNO is
// used for newly issued tickets.
func (db *Database) AddPrincipal(name, password string, kvnos ...uint32) error {
	if db == nil {
		return fmt.Errorf("add principal: nil database")
	}
	if db.Realm == "" {
		return fmt.Errorf("add principal: empty database realm")
	}
	if len(kvnos) == 0 {
		kvnos = []uint32{1}
	}
	parsedName, err := parseName(name, db.Realm)
	if err != nil {
		return fmt.Errorf("add principal: %w", err)
	}
	for _, kvno := range kvnos {
		if kvno == 0 {
			return fmt.Errorf("add principal: KVNO must be nonzero")
		}
	}
	latest := kvnos[0]
	for _, kvno := range kvnos[1:] {
		if kvno > latest {
			latest = kvno
		}
	}
	keys := make(map[int32]Key, 4)
	for _, enctype := range []int32{
		crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256, crypto.EnctypeAES256SHA384,
	} {
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			return fmt.Errorf("add principal enctype %d: %w", enctype, err)
		}
		salt := []byte(parsedName.Realm + strings.Join(parsedName.Components, ""))
		derived, err := etype.StringToKey([]byte(password), salt, nil)
		if err != nil {
			return fmt.Errorf("add principal enctype %d: %w", enctype, err)
		}
		keys[enctype] = Key{Enctype: enctype, KVNO: latest, Key: derived, Salt: string(salt)}
	}
	record := PrincipalRecord{Name: *parsedName, Keys: keys, Strings: make(map[string]string), KVNO: latest}
	db.mu.Lock()
	db.principals[canonical(*parsedName)] = record
	db.mu.Unlock()
	return nil
}

// CreatePrincipal adds a principal and fails if it already exists.
func (db *Database) CreatePrincipal(name, password string) error {
	if db == nil {
		return fmt.Errorf("create principal: nil database")
	}
	parsedName, err := parseName(name, db.Realm)
	if err != nil {
		return fmt.Errorf("create principal: %w", err)
	}
	record, err := deriveRecord(*parsedName, password, 1)
	if err != nil {
		return err
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(*parsedName)
	if _, exists := db.principals[key]; exists {
		return ErrPrincipalExists
	}
	db.principals[key] = record
	return nil
}

func deriveRecord(name principal.Principal, password string, kvno uint32) (PrincipalRecord, error) {
	keys := make(map[int32]Key, 4)
	for _, enctype := range []int32{
		crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256, crypto.EnctypeAES256SHA384,
	} {
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			return PrincipalRecord{}, fmt.Errorf("principal enctype %d: %w", enctype, err)
		}
		salt := []byte(name.Realm + strings.Join(name.Components, ""))
		derived, err := etype.StringToKey([]byte(password), salt, nil)
		if err != nil {
			return PrincipalRecord{}, fmt.Errorf("principal enctype %d: %w", enctype, err)
		}
		keys[enctype] = Key{Enctype: enctype, KVNO: kvno, Key: derived, Salt: string(salt)}
	}
	return PrincipalRecord{Name: name, Keys: keys, Strings: make(map[string]string), KVNO: kvno}, nil
}

// DeletePrincipal removes a principal.
func (db *Database) DeletePrincipal(name principal.Principal) error {
	if db == nil {
		return ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(name)
	if _, ok := db.principals[key]; !ok {
		return ErrPrincipalNotFound
	}
	delete(db.principals, key)
	return nil
}

// UpdatePrincipal replaces mutable administrative fields on a principal.
func (db *Database) UpdatePrincipal(record PrincipalRecord) error {
	if db == nil {
		return ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(record.Name)
	current, ok := db.principals[key]
	if !ok {
		return ErrPrincipalNotFound
	}
	if record.Keys == nil {
		record.Keys = current.Keys
	}
	if record.Strings == nil {
		record.Strings = current.Strings
	}
	db.principals[key] = copyRecord(record)
	return nil
}

// ChangePassword replaces all supported keys with keys derived from password.
func (db *Database) ChangePassword(name principal.Principal, password string) error {
	if db == nil {
		return ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(name)
	current, ok := db.principals[key]
	if !ok {
		return ErrPrincipalNotFound
	}
	next, err := deriveRecord(current.Name, password, current.KVNO+1)
	if err != nil {
		return err
	}
	current.Keys = next.Keys
	current.KVNO = next.KVNO
	db.principals[key] = current
	return nil
}

// RandomizeKeys generates fresh keys and increments the principal KVNO.
func (db *Database) RandomizeKeys(name principal.Principal) ([]Key, error) {
	if db == nil {
		return nil, ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(name)
	current, ok := db.principals[key]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	nextKVNO := current.KVNO + 1
	keys := make(map[int32]Key, len(current.Keys))
	for enctype, old := range current.Keys {
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			return nil, err
		}
		value := make([]byte, etype.KeySize())
		if _, err := rand.Read(value); err != nil {
			return nil, err
		}
		keys[enctype] = Key{Enctype: enctype, KVNO: nextKVNO, Key: value, Salt: old.Salt}
	}
	current.Keys = keys
	current.KVNO = nextKVNO
	db.principals[key] = current
	return keyList(keys), nil
}

// SetKeys replaces a principal's long-term keys and KVNO.
func (db *Database) SetKeys(name principal.Principal, keys []Key, keepOld bool) error {
	if db == nil {
		return ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(name)
	current, ok := db.principals[key]
	if !ok {
		return ErrPrincipalNotFound
	}
	if len(keys) == 0 {
		return fmt.Errorf("set keys: empty key set")
	}
	next := make(map[int32]Key, len(keys))
	if keepOld {
		next = copyKeys(current.Keys)
	}
	kvno := current.KVNO
	for _, value := range keys {
		if value.KVNO == 0 {
			value.KVNO = kvno + 1
		}
		if value.KVNO > kvno {
			kvno = value.KVNO
		}
		value.Key = append([]byte(nil), value.Key...)
		next[value.Enctype] = value
	}
	current.Keys, current.KVNO = next, kvno
	db.principals[key] = current
	return nil
}

func keyList(keys map[int32]Key) []Key {
	out := make([]Key, 0, len(keys))
	for _, value := range keys {
		out = append(out, Key{Enctype: value.Enctype, KVNO: value.KVNO, Key: append([]byte(nil), value.Key...), Salt: value.Salt})
	}
	return out
}

// RenamePrincipal changes a principal's name while retaining its keys.
func (db *Database) RenamePrincipal(src, dest principal.Principal) error {
	if db == nil {
		return ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	sourceKey, destKey := canonical(src), canonical(dest)
	record, ok := db.principals[sourceKey]
	if !ok {
		return ErrPrincipalNotFound
	}
	if _, exists := db.principals[destKey]; exists {
		return ErrPrincipalExists
	}
	record.Name = dest
	db.principals[destKey] = record
	delete(db.principals, sourceKey)
	return nil
}

// GetStrings returns a copy of a principal's string attributes.
func (db *Database) GetStrings(name principal.Principal) (map[string]string, error) {
	if db == nil {
		return nil, ErrPrincipalNotFound
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	record, ok := db.principals[canonical(name)]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	out := make(map[string]string, len(record.Strings))
	for key, value := range record.Strings {
		out[key] = value
	}
	return out, nil
}

// SetString updates or deletes one principal string attribute.
func (db *Database) SetString(name principal.Principal, key string, value *string) error {
	if db == nil {
		return ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	record, ok := db.principals[canonical(name)]
	if !ok {
		return ErrPrincipalNotFound
	}
	if record.Strings == nil {
		record.Strings = make(map[string]string)
	}
	if value == nil {
		delete(record.Strings, key)
	} else {
		record.Strings[key] = *value
	}
	db.principals[canonical(name)] = record
	return nil
}

// CreatePolicy adds a policy and fails if it already exists.
func (db *Database) CreatePolicy(policy PolicyRecord) error {
	if db == nil {
		return ErrPolicyNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, ok := db.policies[policy.Name]; ok {
		return ErrPolicyExists
	}
	db.policies[policy.Name] = policy
	return nil
}

// GetPolicy returns a policy by name.
func (db *Database) GetPolicy(name string) (PolicyRecord, error) {
	if db == nil {
		return PolicyRecord{}, ErrPolicyNotFound
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	policy, ok := db.policies[name]
	if !ok {
		return PolicyRecord{}, ErrPolicyNotFound
	}
	return policy, nil
}

// UpdatePolicy replaces a policy.
func (db *Database) UpdatePolicy(policy PolicyRecord) error {
	if db == nil {
		return ErrPolicyNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, ok := db.policies[policy.Name]; !ok {
		return ErrPolicyNotFound
	}
	db.policies[policy.Name] = policy
	return nil
}

// DeletePolicy removes an unused policy.
func (db *Database) DeletePolicy(name string) error {
	if db == nil {
		return ErrPolicyNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, ok := db.policies[name]; !ok {
		return ErrPolicyNotFound
	}
	for _, record := range db.principals {
		if record.Policy == name {
			return ErrPolicyInUse
		}
	}
	delete(db.policies, name)
	return nil
}

// ListPolicies returns policy names in lexical order.
func (db *Database) ListPolicies() []string {
	db.mu.RLock()
	defer db.mu.RUnlock()
	out := make([]string, 0, len(db.policies))
	for name := range db.policies {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ListPrincipals returns canonical principal names in lexical order.
func (db *Database) ListPrincipals() []string {
	if db == nil {
		return nil
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	out := make([]string, 0, len(db.principals))
	for _, record := range db.principals {
		name, err := record.Name.Format()
		if err == nil {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// AddAlias maps alias to an existing canonical principal.
func (db *Database) AddAlias(alias, target string) error {
	if db == nil {
		return fmt.Errorf("add alias: nil database")
	}
	if db.Realm == "" {
		return fmt.Errorf("add alias: empty database realm")
	}
	parsedAlias, err := parseName(alias, db.Realm)
	if err != nil {
		return fmt.Errorf("add alias: alias: %w", err)
	}
	parsedTarget, err := parseName(target, db.Realm)
	if err != nil {
		return fmt.Errorf("add alias: target: %w", err)
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, exists := db.principals[canonical(*parsedTarget)]; !exists {
		return fmt.Errorf("add alias: target principal %q does not exist", parsedTarget)
	}
	if canonical(*parsedAlias) == canonical(*parsedTarget) {
		return fmt.Errorf("add alias: alias and target are identical")
	}
	db.aliases[canonical(*parsedAlias)] = *parsedTarget
	return nil
}

// Lookup returns a copy of the record for name.
func (db *Database) Lookup(name principal.Principal) (PrincipalRecord, bool, error) {
	if db == nil {
		return PrincipalRecord{}, false, nil
	}
	db.mu.RLock()
	record, ok := db.principals[canonical(name)]
	db.mu.RUnlock()
	if !ok {
		return PrincipalRecord{}, false, nil
	}
	record = copyRecord(record)
	return record, true, nil
}

// ResolveAlias implements AliasResolver. It returns only configured aliases;
// canonical principals are reported as not aliases.
func (db *Database) ResolveAlias(name principal.Principal) (principal.Principal, bool, error) {
	if db == nil {
		return principal.Principal{}, false, nil
	}
	db.mu.RLock()
	target, ok := db.aliases[canonical(name)]
	db.mu.RUnlock()
	if !ok {
		return principal.Principal{}, false, nil
	}
	return target, true, nil
}

func parseName(name, realm string) (*principal.Principal, error) {
	if !strings.Contains(name, "@") {
		name += "@" + realm
	}
	parsed, err := principal.Parse(name)
	if err != nil {
		return nil, err
	}
	if parsed.Realm != realm &&
		(len(parsed.Components) != 2 || parsed.Components[0] != "krbtgt") {
		return nil, fmt.Errorf("principal realm %q does not match database realm %q", parsed.Realm, realm)
	}
	if len(parsed.Components) == 0 {
		return nil, fmt.Errorf("empty principal components")
	}
	if len(parsed.Components) > 1 {
		parsed.NameType = principal.NTSrvInstance
	}
	return parsed, nil
}

func canonical(name principal.Principal) string {
	return name.Realm + "\x00" + strings.Join(name.Components, "\x00")
}

func copyKeys(keys map[int32]Key) map[int32]Key {
	result := make(map[int32]Key, len(keys))
	for enctype, key := range keys {
		result[enctype] = Key{Enctype: key.Enctype, KVNO: key.KVNO, Key: append([]byte(nil), key.Key...), Salt: key.Salt}
	}
	return result
}

func copyRecord(record PrincipalRecord) PrincipalRecord {
	record.Keys = copyKeys(record.Keys)
	stringsCopy := make(map[string]string, len(record.Strings))
	for key, value := range record.Strings {
		stringsCopy[key] = value
	}
	record.Strings = stringsCopy
	return record
}
