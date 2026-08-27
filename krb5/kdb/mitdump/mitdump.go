// Package mitdump reads the tagged text dump format emitted by MIT
// Kerberos kdb5_util.
package mitdump

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	headerVersion6 = "kdb5_util load_dump version 6"
	headerVersion7 = "kdb5_util load_dump version 7"
	maxLineSize    = 16 << 20
)

// FileStore is a read-only principal store loaded from an MIT dump.
//
// Writes and kadmin operations are intentionally out of scope. Reload a new
// FileStore after replacing the dump file.
type FileStore struct {
	Realm   string
	records map[string]kdb.PrincipalRecord
}

// Load reads an MIT kdb5_util dump from path. For normal MIT dumps, key data
// remains encrypted under the database master key; use
// LoadWithMasterPassword for a KDC-ready store.
func Load(path string) (*FileStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read MIT dump: %w", err)
	}
	return Parse(data)
}

// LoadWithMasterPassword reads an MIT dump whose key data is encrypted under
// an AES Kerberos K/M master key. MIT's dump format stores key data encrypted
// under the database master key; the password is needed to make those records
// usable by a Go KDC.
func LoadWithMasterPassword(path, password string) (*FileStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read MIT dump: %w", err)
	}
	return ParseWithMasterPassword(data, password)
}

// Parse reads an MIT kdb5_util version 6 or version 7 dump.
func Parse(data []byte) (*FileStore, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxLineSize)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read MIT dump header: %w", err)
		}
		return nil, fmt.Errorf("MIT dump is empty")
	}
	header := strings.TrimSuffix(scanner.Text(), "\r")
	if header != headerVersion6 && header != headerVersion7 {
		return nil, fmt.Errorf("unsupported MIT dump header %q", header)
	}
	store := &FileStore{records: make(map[string]kdb.PrincipalRecord)}
	lineNo := 1
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		record, err := parseRecord(line)
		if err != nil {
			return nil, fmt.Errorf("MIT dump line %d: %w", lineNo, err)
		}
		key := principalKey(record.Name)
		if _, exists := store.records[key]; exists {
			return nil, fmt.Errorf("MIT dump line %d: duplicate principal %s", lineNo, record.Name)
		}
		store.records[key] = record
		if store.Realm == "" && !isForeignTGT(record.Name) {
			store.Realm = record.Name.Realm
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read MIT dump: %w", err)
	}
	if store.Realm == "" {
		for _, record := range store.records {
			if len(record.Name.Components) == 2 && record.Name.Components[0] == "krbtgt" &&
				record.Name.Components[1] == record.Name.Realm {
				store.Realm = record.Name.Realm
				break
			}
		}
	}
	if len(store.records) == 0 {
		return nil, fmt.Errorf("MIT dump contains no principal records")
	}
	return store, nil
}

// ParseWithMasterPassword parses an MIT dump and decrypts its key data using
// the database master password. It supports the AES Kerberos master-key
// enctypes 17, 18, 19, and 20. It also accepts plaintext key data, which is
// useful for synthetic test dumps.
func ParseWithMasterPassword(data []byte, password string) (*FileStore, error) {
	store, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, fmt.Errorf("MIT dump master password is empty")
	}

	masterEnctype, identified, err := dumpMasterEnctype(store)
	if err != nil {
		return nil, err
	}
	candidates := []int32{
		crypto.EnctypeAES128SHA1,
		crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256,
		crypto.EnctypeAES256SHA384,
	}
	if identified {
		candidates = []int32{masterEnctype}
	}
	var lastErr error
	for _, candidate := range candidates {
		masterEType, err := crypto.NewRegistry().Get(candidate)
		if err != nil {
			lastErr = fmt.Errorf("MIT dump master enctype %d: %w", candidate, err)
			continue
		}
		masterKey, err := masterEType.StringToKey([]byte(password),
			[]byte(store.Realm+"KM"), nil)
		if err != nil {
			lastErr = fmt.Errorf("MIT dump master key: %w", err)
			continue
		}
		records, err := decryptRecords(store.records, masterEType, masterKey)
		if err == nil {
			store.records = records
			return store, nil
		}
		lastErr = err
	}
	if identified {
		return nil, fmt.Errorf("MIT dump master enctype %d: %w", masterEnctype, lastErr)
	}
	return nil, fmt.Errorf("MIT dump master key: no supported enctype decrypted key data: %w", lastErr)
}

func dumpMasterEnctype(store *FileStore) (int32, bool, error) {
	for _, record := range store.records {
		if record.Name.Realm != store.Realm ||
			len(record.Name.Components) != 2 ||
			record.Name.Components[0] != "K" ||
			record.Name.Components[1] != "M" {
			continue
		}
		if len(record.Keys) != 1 {
			return 0, false, fmt.Errorf("MIT dump K/M principal has invalid key data")
		}
		for enctype := range record.Keys {
			if _, err := crypto.NewRegistry().Get(enctype); err != nil {
				return 0, false, fmt.Errorf("unsupported MIT dump master enctype %d", enctype)
			}
			return enctype, true, nil
		}
	}
	return 0, false, nil
}

func decryptRecords(records map[string]kdb.PrincipalRecord, masterEType crypto.EType,
	masterKey []byte) (map[string]kdb.PrincipalRecord, error) {
	decrypted := make(map[string]kdb.PrincipalRecord, len(records))
	for name, record := range records {
		record.Keys = copyKeys(record.Keys)
		for enctype, key := range record.Keys {
			etype, err := crypto.NewRegistry().Get(enctype)
			if err != nil {
				continue
			}
			if len(key.Key) == etype.KeySize() {
				continue
			}
			if len(key.Key) < 2 {
				return nil, fmt.Errorf("MIT dump key data is truncated")
			}
			keyLength := int(binary.LittleEndian.Uint16(key.Key[:2]))
			if keyLength != etype.KeySize() {
				return nil, fmt.Errorf("MIT dump key length is invalid")
			}
			plain, err := masterEType.Decrypt(masterKey, 0, key.Key[2:])
			if err != nil {
				return nil, fmt.Errorf("MIT dump key data integrity check failed")
			}
			if len(plain) < keyLength {
				return nil, fmt.Errorf("MIT dump decrypted key data is truncated")
			}
			key.Key = append([]byte(nil), plain[:keyLength]...)
			record.Keys[enctype] = key
		}
		decrypted[name] = record
	}
	return decrypted, nil
}

// Lookup implements kdb.Store.
func (s *FileStore) Lookup(name principal.Principal) (kdb.PrincipalRecord, bool, error) {
	if s == nil {
		return kdb.PrincipalRecord{}, false, nil
	}
	record, ok := s.records[principalKey(name)]
	if !ok {
		return kdb.PrincipalRecord{}, false, nil
	}
	record.Keys = copyKeys(record.Keys)
	return record, true, nil
}

func parseRecord(line string) (kdb.PrincipalRecord, error) {
	fields := strings.Split(line, "\t")
	if len(fields) < 16 || fields[0] != "princ" {
		return kdb.PrincipalRecord{}, fmt.Errorf("malformed principal record")
	}
	if strings.HasSuffix(fields[len(fields)-1], ";") {
		fields[len(fields)-1] = strings.TrimSuffix(fields[len(fields)-1], ";")
	} else {
		return kdb.PrincipalRecord{}, fmt.Errorf("record missing terminator")
	}
	cursor := 1
	header := make([]uint64, 5)
	for i := range header {
		value, err := parseUint(fields[cursor], "header")
		if err != nil {
			return kdb.PrincipalRecord{}, err
		}
		header[i] = value
		cursor++
	}
	if header[2] > uint64(len(fields)) || header[3] > uint64(len(fields)) {
		return kdb.PrincipalRecord{}, fmt.Errorf("tagged or key data count is too large")
	}
	if cursor >= len(fields) {
		return kdb.PrincipalRecord{}, fmt.Errorf("truncated principal name")
	}
	name, err := principal.Parse(fields[cursor])
	if err != nil {
		return kdb.PrincipalRecord{}, fmt.Errorf("principal name: %w", err)
	}
	if int(header[1]) != len(fields[cursor]) {
		return kdb.PrincipalRecord{}, fmt.Errorf("principal name length mismatch")
	}
	cursor++
	if cursor+7 >= len(fields) {
		return kdb.PrincipalRecord{}, fmt.Errorf("truncated principal attributes")
	}
	attributes, err := parseInt(fields[cursor], "attributes")
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	if attributes < 0 {
		return kdb.PrincipalRecord{}, fmt.Errorf("attributes are negative")
	}
	maxLife, err := parseDurationSeconds(fields[cursor+1], "maximum lifetime")
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	maxRenew, err := parseDurationSeconds(fields[cursor+2], "maximum renewable lifetime")
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	expiration, err := parseEpoch(fields[cursor+3], "expiration")
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	passwordExpiration, err := parseEpoch(fields[cursor+4], "password expiration")
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	cursor += 8
	for i := uint64(0); i < header[2]; i++ {
		if cursor+2 >= len(fields) {
			return kdb.PrincipalRecord{}, fmt.Errorf("truncated tagged data")
		}
		length, err := parseUint(fields[cursor+1], "tagged data length")
		if err != nil {
			return kdb.PrincipalRecord{}, err
		}
		if err := validateOctets(fields[cursor+2], length, "tagged data"); err != nil {
			return kdb.PrincipalRecord{}, err
		}
		cursor += 3
	}
	keys := make(map[int32]kdb.Key)
	for i := uint64(0); i < header[3]; i++ {
		if cursor+1 >= len(fields) {
			return kdb.PrincipalRecord{}, fmt.Errorf("truncated key data")
		}
		keyVersion, err := parseUint(fields[cursor], "key data version")
		if err != nil {
			return kdb.PrincipalRecord{}, err
		}
		if keyVersion == 0 || keyVersion > 2 {
			return kdb.PrincipalRecord{}, fmt.Errorf("unsupported key data version %d", keyVersion)
		}
		kvno, err := parseUint(fields[cursor+1], "key version number")
		if err != nil || kvno == 0 {
			if err == nil {
				err = fmt.Errorf("key version number must be nonzero")
			}
			return kdb.PrincipalRecord{}, err
		}
		cursor += 2
		var enctype int32
		var keyBytes []byte
		for j := uint64(0); j < keyVersion; j++ {
			if cursor+2 >= len(fields) {
				return kdb.PrincipalRecord{}, fmt.Errorf("truncated key data contents")
			}
			keyType, err := parseInt(fields[cursor], "key enctype")
			if err != nil {
				return kdb.PrincipalRecord{}, err
			}
			length, err := parseUint(fields[cursor+1], "key length")
			if err != nil {
				return kdb.PrincipalRecord{}, err
			}
			content, err := parseOctets(fields[cursor+2], length, "key data")
			if err != nil {
				return kdb.PrincipalRecord{}, err
			}
			if j == 0 {
				enctype = int32(keyType)
				keyBytes = content
			}
			cursor += 3
		}
		if _, exists := keys[enctype]; exists {
			return kdb.PrincipalRecord{}, fmt.Errorf("duplicate key enctype %d", enctype)
		}
		keys[enctype] = kdb.Key{Enctype: enctype, KVNO: uint32(kvno), Key: keyBytes}
	}
	if cursor >= len(fields) {
		return kdb.PrincipalRecord{}, fmt.Errorf("truncated extra data")
	}
	if err := validateOctets(fields[cursor], header[4], "extra data"); err != nil {
		return kdb.PrincipalRecord{}, err
	}
	if cursor+1 != len(fields) {
		return kdb.PrincipalRecord{}, fmt.Errorf("unexpected fields after extra data")
	}
	if len(keys) == 0 {
		return kdb.PrincipalRecord{}, fmt.Errorf("principal has no keys")
	}
	var kvno uint32
	for _, key := range keys {
		if key.KVNO > kvno {
			kvno = key.KVNO
		}
	}
	return kdb.PrincipalRecord{
		Name: *name, Keys: keys, KVNO: kvno, Flags: uint32(attributes),
		MaxLife: maxLife, MaxRenew: maxRenew,
		Expiration: expiration, PasswordExpiration: passwordExpiration,
	}, nil
}

func parseUint(value, field string) (uint64, error) {
	if value == "" {
		return 0, fmt.Errorf("empty %s", field)
	}
	result, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	return result, nil
}

func parseInt(value, field string) (int64, error) {
	result, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	return result, nil
}

func parseDurationSeconds(value, field string) (time.Duration, error) {
	seconds, err := parseInt(value, field)
	if err != nil {
		return 0, err
	}
	if seconds < 0 {
		return 0, fmt.Errorf("%s is negative", field)
	}
	if seconds > int64((time.Duration(1<<63-1))/time.Second) {
		return 0, fmt.Errorf("%s is too large", field)
	}
	return time.Duration(seconds) * time.Second, nil
}

func parseEpoch(value, field string) (time.Time, error) {
	seconds, err := parseUint(value, field)
	if err != nil {
		return time.Time{}, err
	}
	if seconds == 0 {
		return time.Time{}, nil
	}
	if seconds > uint64(^uint64(0)>>1) {
		return time.Time{}, fmt.Errorf("%s is too large", field)
	}
	return time.Unix(int64(seconds), 0).UTC(), nil
}

func validateOctets(value string, length uint64, field string) error {
	if value == "-1" {
		if length != 0 {
			return fmt.Errorf("%s is -1 with nonzero length", field)
		}
		return nil
	}
	if length > uint64(^uint(0)>>1)/2 {
		return fmt.Errorf("%s is too large", field)
	}
	if uint64(len(value)) != length*2 {
		return fmt.Errorf("%s length mismatch", field)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("invalid %s hex: %w", field, err)
	}
	return nil
}

func parseOctets(value string, length uint64, field string) ([]byte, error) {
	if err := validateOctets(value, length, field); err != nil {
		return nil, err
	}
	if value == "-1" {
		return nil, nil
	}
	result, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s hex: %w", field, err)
	}
	return result, nil
}

func principalKey(name principal.Principal) string {
	return name.Realm + "\x00" + strings.Join(name.Components, "\x00")
}

func isForeignTGT(name principal.Principal) bool {
	return len(name.Components) == 2 && name.Components[0] == "krbtgt" &&
		name.Components[1] != name.Realm
}

func copyKeys(keys map[int32]kdb.Key) map[int32]kdb.Key {
	result := make(map[int32]kdb.Key, len(keys))
	for enctype, key := range keys {
		key.Key = append([]byte(nil), key.Key...)
		result[enctype] = key
	}
	return result
}
