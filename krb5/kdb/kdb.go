// Package kdb provides the in-memory principal database used by the Go KDC.
package kdb

import (
	"fmt"
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
	Name     principal.Principal
	Keys     map[int32]Key
	KVNO     uint32
	Flags    uint32
	MaxLife  time.Duration
	MaxRenew time.Duration
}

// Store resolves principal records for the KDC. Lookup returns false with a
// nil error when the principal does not exist, and a non-nil error only for
// backend failures.
type Store interface {
	Lookup(principal.Principal) (PrincipalRecord, bool, error)
}

// Database is a concurrency-safe in-memory principal store.
type Database struct {
	Realm string

	mu         sync.RWMutex
	principals map[string]PrincipalRecord
}

// NewDatabase creates an empty database for realm.
func NewDatabase(realm string) *Database {
	return &Database{Realm: realm, principals: make(map[string]PrincipalRecord)}
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
	record := PrincipalRecord{Name: *parsedName, Keys: keys, KVNO: latest}
	db.mu.Lock()
	db.principals[canonical(*parsedName)] = record
	db.mu.Unlock()
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
	record.Keys = copyKeys(record.Keys)
	return record, true, nil
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
