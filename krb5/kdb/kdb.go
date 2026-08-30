// Package kdb provides the in-memory principal database used by the Go KDC.
package kdb

import (
	"crypto/rand"
	"encoding/binary"
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

// TLData is an opaque MIT KDB tagged-data element.
type TLData struct {
	Type int16
	Data []byte
}

// PrincipalRecord contains a principal and its KDC policy.
type PrincipalRecord struct {
	Name principal.Principal
	Keys map[int32]Key
	// PasswordHistory contains prior derived key sets, newest first. When a
	// kadmin/history key is available, it is serialized in MIT KADM_DATA.
	PasswordHistory []map[int32]Key
	// KADMAuxAttributes and AdminHistoryKVNO are fields from MIT's
	// osa_princ_ent_rec KADM_DATA record.
	KADMAuxAttributes  uint32
	AdminHistoryNext   uint32
	AdminHistoryKVNO   uint32
	LastPasswordChange time.Time
	Strings            map[string]string
	KVNO               uint32
	Flags              uint32
	Policy             string
	MaxLife            time.Duration
	MaxRenew           time.Duration
	Expiration         time.Time
	PasswordExpiration time.Time
	LastSuccess        time.Time
	LastFailed         time.Time
	FailAuthCount      uint32
	TLData             []TLData
}

// Principal attribute flags from MIT's kdb.h.
const (
	DisallowPostdated   uint32 = 0x00000001
	DisallowForwardable uint32 = 0x00000002
	DisallowTGTBased    uint32 = 0x00000004
	DisallowRenewable   uint32 = 0x00000008
	DisallowProxiable   uint32 = 0x00000010
	DisallowAllTickets  uint32 = 0x00000040
	RequiresPreAuth     uint32 = 0x00000080
	RequiresHWAuth      uint32 = 0x00000100
	RequiresPWChange    uint32 = 0x00000200
	DisallowServer      uint32 = 0x00001000
	PWChangeService     uint32 = 0x00002000
)

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
	ErrPasswordTooShort  = errors.New("password is too short")
	ErrPasswordClasses   = errors.New("password does not contain enough character classes")
	ErrPasswordTooSoon   = errors.New("password minimum life has not expired")
	ErrPasswordReuse     = errors.New("password reuse")
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

// LockoutUpdater optionally persists authentication status updates made by
// the KDC. Stores which do not implement it remain usable without lockout
// persistence.
type LockoutUpdater interface {
	UpdateLockout(principal.Principal, uint32, time.Time, time.Time) error
}

// LockoutRecorder optionally performs authentication status transitions
// atomically with respect to the store. Stores which do not implement it
// remain compatible with the KDC's read-modify-write fallback.
type LockoutRecorder interface {
	RecordAuthFailure(principal.Principal, time.Time, time.Duration) (uint32, error)
	ResetAuthFailures(principal.Principal, time.Time) error
	RecordAuthSuccess(principal.Principal, time.Time) error
}

// PolicyResolver optionally resolves named password policies for the KDC.
type PolicyResolver interface {
	GetPolicy(string) (PolicyRecord, error)
}

// Database is a concurrency-safe in-memory principal store.
type Database struct {
	Realm string

	mu         sync.RWMutex
	principals map[string]PrincipalRecord
	aliases    map[string]principal.Principal
	policies   map[string]PolicyRecord
	// UpdateLog retains principal mutations for incremental propagation.
	UpdateLog *UpdateLog
}

// NewDatabase creates an empty database for realm.
func NewDatabase(realm string) *Database {
	return &Database{
		Realm:      realm,
		principals: make(map[string]PrincipalRecord),
		aliases:    make(map[string]principal.Principal),
		policies:   make(map[string]PolicyRecord),
		UpdateLog:  NewUpdateLog(1024),
	}
}

// ConfigureUpdateLog replaces the database's incremental propagation log.
func (db *Database) ConfigureUpdateLog(capacity int) {
	if db == nil {
		return
	}
	db.mu.Lock()
	db.UpdateLog = NewUpdateLog(capacity)
	db.mu.Unlock()
}

func (db *Database) recordUpdateLocked(record PrincipalRecord, deleted bool) {
	if db.UpdateLog == nil {
		return
	}
	now := time.Now().UTC()
	if !deleted && !hasTLData(record.TLData, 2) {
		modifier := make([]byte, 4, len(record.Name.String())+5)
		binary.LittleEndian.PutUint32(modifier, uint32(now.Unix()))
		modifier = append(modifier, record.Name.String()...)
		modifier = append(modifier, 0)
		record.TLData = append(record.TLData, TLData{Type: 2, Data: modifier})
	}
	db.UpdateLog.append(UpdateLogEntry{
		Name: record.Name, Record: record, Deleted: deleted, Commit: true,
		Time: now,
	})
}

func hasTLData(values []TLData, typ int16) bool {
	for _, value := range values {
		if value.Type == typ {
			return true
		}
	}
	return false
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
		crypto.EnctypeCamellia128, crypto.EnctypeCamellia256,
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
	record := PrincipalRecord{Name: *parsedName, Keys: keys, Strings: make(map[string]string),
		KVNO: latest, LastPasswordChange: time.Now().UTC()}
	db.mu.Lock()
	db.principals[canonical(*parsedName)] = record
	db.recordUpdateLocked(record, false)
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
	db.recordUpdateLocked(record, false)
	return nil
}

func deriveRecord(name principal.Principal, password string, kvno uint32) (PrincipalRecord, error) {
	keys := make(map[int32]Key, 4)
	for _, enctype := range []int32{
		crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256, crypto.EnctypeAES256SHA384,
		crypto.EnctypeCamellia128, crypto.EnctypeCamellia256,
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
	return PrincipalRecord{Name: name, Keys: keys, Strings: make(map[string]string),
		KVNO: kvno, LastPasswordChange: time.Now().UTC()}, nil
}

func deriveKeys(name principal.Principal, password string, current map[int32]Key,
	kvno uint32) (map[int32]Key, error) {
	keys := make(map[int32]Key, len(current))
	normalSalt := name.Realm + strings.Join(name.Components, "")
	for enctype, old := range current {
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			return nil, err
		}
		salt := old.Salt
		if salt == "" {
			salt = normalSalt
		}
		derived, err := etype.StringToKey([]byte(password), []byte(salt), nil)
		if err != nil {
			return nil, err
		}
		keys[enctype] = Key{Enctype: enctype, KVNO: kvno, Key: derived, Salt: old.Salt}
	}
	return keys, nil
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
	record := db.principals[key]
	delete(db.principals, key)
	db.recordUpdateLocked(record, true)
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
	if record.PasswordHistory == nil {
		record.PasswordHistory = current.PasswordHistory
	}
	if record.LastPasswordChange.IsZero() {
		record.LastPasswordChange = current.LastPasswordChange
	}
	db.principals[key] = copyRecord(record)
	db.recordUpdateLocked(record, false)
	return nil
}

// UpdateLockout updates only authentication status fields for a principal.
func (db *Database) UpdateLockout(name principal.Principal, failCount uint32,
	lastFailed, lastSuccess time.Time) error {
	if db == nil {
		return ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(name)
	record, ok := db.principals[key]
	if !ok {
		return ErrPrincipalNotFound
	}
	record.FailAuthCount = failCount
	record.LastFailed = lastFailed
	record.LastSuccess = lastSuccess
	db.principals[key] = record
	db.recordUpdateLocked(record, false)
	return nil
}

// RecordAuthFailure atomically resets an expired failure window, increments
// the failure count, and records the failure time.
func (db *Database) RecordAuthFailure(name principal.Principal, now time.Time,
	failureCountInterval time.Duration) (uint32, error) {
	if db == nil {
		return 0, ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(name)
	record, ok := db.principals[key]
	if !ok {
		return 0, ErrPrincipalNotFound
	}
	now = now.UTC()
	if failureCountInterval > 0 && !record.LastFailed.IsZero() &&
		!now.Before(record.LastFailed.Add(failureCountInterval)) {
		record.FailAuthCount = 0
	}
	record.FailAuthCount++
	record.LastFailed = now
	db.principals[key] = record
	db.recordUpdateLocked(record, false)
	return record.FailAuthCount, nil
}

// ResetAuthFailures atomically clears the authentication failure count if the
// recorded failure time still matches expectedLastFailed.
func (db *Database) ResetAuthFailures(name principal.Principal,
	expectedLastFailed time.Time) error {
	if db == nil {
		return ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(name)
	record, ok := db.principals[key]
	if !ok {
		return ErrPrincipalNotFound
	}
	if !record.LastFailed.Equal(expectedLastFailed) {
		return nil
	}
	record.FailAuthCount = 0
	db.principals[key] = record
	db.recordUpdateLocked(record, false)
	return nil
}

// RecordAuthSuccess atomically clears failures and records successful
// preauthentication.
func (db *Database) RecordAuthSuccess(name principal.Principal, now time.Time) error {
	if db == nil {
		return ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(name)
	record, ok := db.principals[key]
	if !ok {
		return ErrPrincipalNotFound
	}
	record.FailAuthCount = 0
	record.LastSuccess = now.UTC()
	db.principals[key] = record
	db.recordUpdateLocked(record, false)
	return nil
}

// ChangePassword replaces all supported keys with keys derived from password.
func (db *Database) ChangePassword(name principal.Principal, password string) error {
	return db.ChangePasswordWithPolicy(name, password, time.Now().UTC(), nil, false)
}

// ChangePasswordWithPolicy derives new keys and applies password policy
// checks. A nil policy performs an unrestricted password change.
func (db *Database) ChangePasswordWithPolicy(name principal.Principal, password string,
	now time.Time, policy *PolicyRecord, bypassMinLife bool) error {
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
	if len(current.Keys) > 0 && len(current.Keys) != len(next.Keys) {
		next.Keys, err = deriveKeys(current.Name, password, current.Keys, current.KVNO+1)
		if err != nil {
			return err
		}
	}
	if policy != nil {
		if policy.MinLength > 0 && int32(len(password)) < policy.MinLength {
			return ErrPasswordTooShort
		}
		if policy.MinClasses > 0 && passwordClasses(password) < policy.MinClasses {
			return ErrPasswordClasses
		}
		if !bypassMinLife && policy.MinLife > 0 && !current.LastPasswordChange.IsZero() &&
			now.Before(current.LastPasswordChange.Add(time.Duration(policy.MinLife)*time.Second)) {
			return ErrPasswordTooSoon
		}
		var historyKey *Key
		if policy.HistoryNum > 0 {
			historyKey = db.historyKeyLocked()
			if historyKey != nil && current.AdminHistoryKVNO != 0 &&
				current.AdminHistoryKVNO != historyKey.KVNO {
				current.PasswordHistory = nil
			}
			historyLimit := int(policy.HistoryNum) - 1
			limit := historyLimit
			if passwordMatchesKeys(next.Keys, current.Keys) {
				return ErrPasswordReuse
			}
			if limit > len(current.PasswordHistory) {
				limit = len(current.PasswordHistory)
			}
			for _, historical := range current.PasswordHistory[:limit] {
				if passwordMatchesKeys(next.Keys, historical) {
					return ErrPasswordReuse
				}
			}
			history := make([]map[int32]Key, 0, limit+1)
			history = append(history, copyKeys(current.Keys))
			history = append(history, current.PasswordHistory...)
			if len(history) > historyLimit {
				history = history[:historyLimit]
			}
			current.PasswordHistory = history
			current.AdminHistoryNext = 0
			if historyLimit > len(history) {
				current.AdminHistoryNext = uint32(len(history))
			}
			if historyKey != nil {
				current.AdminHistoryKVNO = historyKey.KVNO
				policyName := current.Policy
				if policyName == "" {
					policyName = policy.Name
				}
				data, encodeErr := EncodeKADMData(KADMData{
					Policy: policyName, AuxAttributes: current.KADMAuxAttributes,
					OldKeyNext:       current.AdminHistoryNext,
					AdminHistoryKVNO: current.AdminHistoryKVNO,
					NormalSalt:       current.Name.Realm + strings.Join(current.Name.Components, ""),
					OldKeys:          current.PasswordHistory,
				}, historyKey)
				if encodeErr != nil {
					return encodeErr
				}
				tlData := make([]TLData, 0, len(current.TLData)+1)
				for _, item := range current.TLData {
					if item.Type != KADMDataType {
						tlData = append(tlData, item)
					}
				}
				tlData = append(tlData, TLData{Type: KADMDataType, Data: data})
				current.TLData = tlData
			}
		}
		if policy.MaxLife > 0 {
			current.PasswordExpiration = now.Add(time.Duration(policy.MaxLife) * time.Second)
		} else {
			current.PasswordExpiration = time.Time{}
		}
	}
	current.Keys = next.Keys
	current.KVNO = next.KVNO
	current.LastPasswordChange = now.UTC()
	db.principals[key] = current
	db.recordUpdateLocked(current, false)
	return nil
}

func (db *Database) historyKeyLocked() *Key {
	record, ok := db.principals[db.Realm+"\x00kadmin\x00history"]
	if !ok || len(record.Keys) == 0 {
		return nil
	}
	if key, ok := record.Keys[crypto.EnctypeAES256SHA1]; ok {
		if etype, err := crypto.NewRegistry().Get(key.Enctype); err == nil &&
			len(key.Key) == etype.KeySize() {
			key.Key = append([]byte(nil), key.Key...)
			return &key
		}
	}
	enctypes := make([]int32, 0, len(record.Keys))
	for enctype := range record.Keys {
		enctypes = append(enctypes, enctype)
	}
	sort.Slice(enctypes, func(i, j int) bool { return enctypes[i] < enctypes[j] })
	for _, enctype := range enctypes {
		key := record.Keys[enctype]
		etype, err := crypto.NewRegistry().Get(key.Enctype)
		if err != nil || len(key.Key) != etype.KeySize() {
			continue
		}
		key.Key = append([]byte(nil), key.Key...)
		return &key
	}
	return nil
}

func passwordClasses(password string) int32 {
	var lower, upper, digit, punct, other bool
	for _, c := range []byte(password) {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		case (c >= '!' && c <= '/') || (c >= ':' && c <= '@') ||
			(c >= '[' && c <= '`') || (c >= '{' && c <= '~'):
			punct = true
		default:
			other = true
		}
	}
	var count int32
	for _, present := range []bool{lower, upper, digit, punct, other} {
		if present {
			count++
		}
	}
	return count
}

func passwordMatchesKeys(candidate, stored map[int32]Key) bool {
	if len(candidate) == 0 || len(candidate) != len(stored) {
		return false
	}
	for enctype, key := range candidate {
		other, ok := stored[enctype]
		if !ok || key.Salt != other.Salt || string(key.Key) != string(other.Key) {
			return false
		}
	}
	return true
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
	db.recordUpdateLocked(current, false)
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
	db.recordUpdateLocked(current, false)
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
	oldRecord := record
	record.Name = dest
	db.principals[destKey] = record
	delete(db.principals, sourceKey)
	db.recordUpdateLocked(oldRecord, true)
	db.recordUpdateLocked(record, false)
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
	db.recordUpdateLocked(record, false)
	return nil
}

// ApplyPrincipal installs or removes a principal without recording a local
// update. Replicas use this method when replaying updates from a master.
func (db *Database) ApplyPrincipal(record PrincipalRecord, deleted bool) error {
	if db == nil {
		return ErrPrincipalNotFound
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	key := canonical(record.Name)
	if deleted {
		delete(db.principals, key)
		return nil
	}
	if record.Strings == nil {
		record.Strings = make(map[string]string)
	}
	db.principals[key] = copyRecord(record)
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
	record.Name.Components = append([]string(nil), record.Name.Components...)
	record.Keys = copyKeys(record.Keys)
	history := make([]map[int32]Key, len(record.PasswordHistory))
	for i, keys := range record.PasswordHistory {
		history[i] = copyKeys(keys)
	}
	record.PasswordHistory = history
	stringsCopy := make(map[string]string, len(record.Strings))
	for key, value := range record.Strings {
		stringsCopy[key] = value
	}
	record.Strings = stringsCopy
	tlData := record.TLData
	record.TLData = make([]TLData, len(tlData))
	for i, data := range tlData {
		record.TLData[i] = TLData{Type: data.Type, Data: append([]byte(nil), data.Data...)}
	}
	return record
}
