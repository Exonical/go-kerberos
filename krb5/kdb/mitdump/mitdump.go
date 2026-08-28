// Package mitdump reads the tagged text dump format emitted by MIT
// Kerberos kdb5_util.
package mitdump

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	headerVersion6       = "kdb5_util load_dump version 6"
	headerVersion7       = "kdb5_util load_dump version 7"
	maxLineSize          = 16 << 20
	defaultMasterEnctype = crypto.EnctypeAES256SHA1
)

// FileStore is a read-only principal store loaded from an MIT dump. Use Dump
// or Write to export an in-memory KDB in the same format.
type FileStore struct {
	Realm   string
	records map[string]kdb.PrincipalRecord
}

// Dump serializes db in MIT kdb5_util load_dump version 7 format.  Principal
// key data is encrypted with an AES master key derived from masterPassword
// using the K/M salt (realm + "KM").  The returned bytes are safe to pass to
// kdb5_util load; key material is never included in errors.
func Dump(db *kdb.Database, masterPassword string) ([]byte, error) {
	return DumpWithMasterPassword(db, masterPassword)
}

// DumpWithMasterPassword serializes db using a password-derived master key.
// If masterEnctype is omitted, AES256-SHA1 (enctype 18) is used.
func DumpWithMasterPassword(db *kdb.Database, masterPassword string,
	masterEnctype ...int32) ([]byte, error) {
	if masterPassword == "" {
		return nil, fmt.Errorf("MIT dump master password is empty")
	}
	if db == nil {
		return nil, fmt.Errorf("MIT dump database is nil")
	}
	if db.Realm == "" {
		return nil, fmt.Errorf("MIT dump database realm is empty")
	}
	enctype := int32(defaultMasterEnctype)
	if len(masterEnctype) > 1 {
		return nil, fmt.Errorf("MIT dump accepts at most one master enctype")
	}
	if len(masterEnctype) == 1 {
		enctype = masterEnctype[0]
	}
	etype, err := crypto.NewRegistry().Get(enctype)
	if err != nil {
		return nil, fmt.Errorf("MIT dump master enctype: %w", err)
	}
	masterKey, err := etype.StringToKey([]byte(masterPassword),
		[]byte(db.Realm+"KM"), nil)
	if err != nil {
		return nil, fmt.Errorf("MIT dump master key: %w", err)
	}
	return dumpWithMasterKey(db, enctype, masterKey)
}

// DumpWithMasterKey serializes db using the supplied AES master key.  The
// master key is written as the K/M principal's encrypted key, allowing MIT
// tooling and ParseWithMasterPassword to identify its enctype.
func DumpWithMasterKey(db *kdb.Database, masterEnctype int32, masterKey []byte) ([]byte, error) {
	return dumpWithMasterKey(db, masterEnctype, masterKey)
}

// Write writes the same version 7 dump produced by Dump to w.
func Write(w io.Writer, db *kdb.Database, masterPassword string) error {
	return WriteWithMasterPassword(w, db, masterPassword)
}

// WriteWithMasterPassword writes a password-derived version 7 dump. If
// masterEnctype is omitted, AES256-SHA1 (enctype 18) is used.
func WriteWithMasterPassword(w io.Writer, db *kdb.Database,
	masterPassword string, masterEnctype ...int32) error {
	if w == nil {
		return fmt.Errorf("MIT dump writer is nil")
	}
	data, err := DumpWithMasterPassword(db, masterPassword, masterEnctype...)
	if err != nil {
		return err
	}
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("write MIT dump: %w", err)
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// WriteWithMasterKey writes a version 7 dump using an explicit AES master key.
func WriteWithMasterKey(w io.Writer, db *kdb.Database, masterEnctype int32,
	masterKey []byte) error {
	if w == nil {
		return fmt.Errorf("MIT dump writer is nil")
	}
	data, err := DumpWithMasterKey(db, masterEnctype, masterKey)
	if err != nil {
		return err
	}
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("write MIT dump: %w", err)
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func dumpWithMasterKey(db *kdb.Database, masterEnctype int32,
	masterKey []byte) ([]byte, error) {
	if db == nil {
		return nil, fmt.Errorf("MIT dump database is nil")
	}
	if db.Realm == "" {
		return nil, fmt.Errorf("MIT dump database realm is empty")
	}
	masterEType, err := crypto.NewRegistry().Get(masterEnctype)
	if err != nil {
		return nil, fmt.Errorf("unsupported MIT dump master enctype %d", masterEnctype)
	}
	if len(masterKey) != masterEType.KeySize() {
		return nil, fmt.Errorf("MIT dump master key has invalid length")
	}

	masterName, err := principal.Parse("K/M@" + db.Realm)
	if err != nil {
		return nil, fmt.Errorf("MIT dump K/M principal: %w", err)
	}
	records := make([]kdb.PrincipalRecord, 0, len(db.ListPrincipals())+1)
	records = append(records, kdb.PrincipalRecord{
		Name: *masterName,
		Keys: map[int32]kdb.Key{masterEnctype: {
			Enctype: masterEnctype,
			KVNO:    1,
			Key:     append([]byte(nil), masterKey...),
			Salt:    db.Realm + "KM",
		}},
		KVNO: 1,
	})
	for _, name := range db.ListPrincipals() {
		parsed, err := principal.Parse(name)
		if err != nil {
			return nil, fmt.Errorf("MIT dump principal %q: %w", name, err)
		}
		if parsed.Realm == db.Realm && len(parsed.Components) == 2 &&
			parsed.Components[0] == "K" && parsed.Components[1] == "M" {
			continue
		}
		record, ok, err := db.Lookup(*parsed)
		if err != nil {
			return nil, fmt.Errorf("MIT dump principal %q: %w", name, err)
		}
		if !ok {
			return nil, fmt.Errorf("MIT dump principal %q disappeared", name)
		}
		records = append(records, record)
	}

	var out bytes.Buffer
	out.WriteString(headerVersion7)
	out.WriteByte('\n')
	for _, record := range records {
		if err := writePrincipalRecord(&out, record, masterEType, masterKey); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func writePrincipalRecord(out io.Writer, record kdb.PrincipalRecord,
	masterEType crypto.EType, masterKey []byte) error {
	name, err := record.Name.Format()
	if err != nil {
		return fmt.Errorf("MIT dump principal: %w", err)
	}
	if len(name) > int(^uint32(0)>>1) {
		return fmt.Errorf("MIT dump principal name is too long")
	}
	if len(record.Keys) == 0 {
		return fmt.Errorf("MIT dump principal %q has no keys", name)
	}
	if len(record.Keys) > int(^uint16(0)) {
		return fmt.Errorf("MIT dump principal %q has too many keys", name)
	}
	tlData := append([]kdb.TLData(nil), record.TLData...)
	if record.Policy != "" && !hasKADMData(tlData) {
		data, err := encodeKADMData(record.Policy)
		if err != nil {
			return fmt.Errorf("MIT dump principal %q policy: %w", name, err)
		}
		tlData = append(tlData, kdb.TLData{Type: 3, Data: data})
	}
	if len(tlData) > int(^uint16(0)) {
		return fmt.Errorf("MIT dump principal %q has too much tagged data", name)
	}
	attributes, err := dumpAttributes(record.Flags)
	if err != nil {
		return fmt.Errorf("MIT dump principal %q: %w", name, err)
	}
	maxLife, err := dumpDuration(record.MaxLife, "maximum lifetime")
	if err != nil {
		return fmt.Errorf("MIT dump principal %q: %w", name, err)
	}
	maxRenew, err := dumpDuration(record.MaxRenew, "maximum renewable lifetime")
	if err != nil {
		return fmt.Errorf("MIT dump principal %q: %w", name, err)
	}
	expiration, err := dumpEpoch(record.Expiration, "expiration")
	if err != nil {
		return fmt.Errorf("MIT dump principal %q: %w", name, err)
	}
	passwordExpiration, err := dumpEpoch(record.PasswordExpiration, "password expiration")
	if err != nil {
		return fmt.Errorf("MIT dump principal %q: %w", name, err)
	}

	keys := make([]kdb.Key, 0, len(record.Keys))
	for _, key := range record.Keys {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Enctype != keys[j].Enctype {
			return keys[i].Enctype < keys[j].Enctype
		}
		return keys[i].KVNO < keys[j].KVNO
	})

	var line strings.Builder
	lastSuccess, err := dumpEpoch(record.LastSuccess, "last success")
	if err != nil {
		return fmt.Errorf("MIT dump principal %q: %w", name, err)
	}
	lastFailed, err := dumpEpoch(record.LastFailed, "last failed")
	if err != nil {
		return fmt.Errorf("MIT dump principal %q: %w", name, err)
	}
	fmt.Fprintf(&line, "princ\t38\t%d\t%d\t%d\t0\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d",
		len(name), len(tlData), len(keys), name, attributes, maxLife,
		maxRenew, expiration, passwordExpiration, lastSuccess, lastFailed,
		record.FailAuthCount)
	for _, data := range tlData {
		if data.Type < 0 {
			return fmt.Errorf("MIT dump principal %q has invalid tagged-data type", name)
		}
		if len(data.Data) > int(^uint16(0)) {
			return fmt.Errorf("MIT dump principal %q tagged data is too long", name)
		}
		line.WriteByte('\t')
		fmt.Fprintf(&line, "%d\t%d\t%s", data.Type, len(data.Data),
			dumpOctets(data.Data))
	}
	for _, key := range keys {
		encoded, err := encodeKeyData(record.Name, key, masterEType, masterKey)
		if err != nil {
			return fmt.Errorf("MIT dump principal %q: %w", name, err)
		}
		line.WriteByte('\t')
		line.WriteString(encoded)
	}
	line.WriteString("\t-1;\n")
	if _, err := io.WriteString(out, line.String()); err != nil {
		return fmt.Errorf("write MIT dump principal: %w", err)
	}
	return nil
}

func dumpOctets(data []byte) string {
	if len(data) == 0 {
		return "-1"
	}
	return hex.EncodeToString(data)
}

func hasKADMData(data []kdb.TLData) bool {
	for _, item := range data {
		if item.Type == 3 {
			return true
		}
	}
	return false
}

func encodeKADMData(policy string) ([]byte, error) {
	if len(policy) == 0 {
		return nil, fmt.Errorf("policy name is empty")
	}
	if len(policy) > int(^uint32(0)-1) {
		return nil, fmt.Errorf("policy name is too long")
	}
	var out bytes.Buffer
	var word [4]byte
	binary.BigEndian.PutUint32(word[:], 0x12345c01)
	out.Write(word[:])
	binary.BigEndian.PutUint32(word[:], uint32(len(policy)+1))
	out.Write(word[:])
	out.WriteString(policy)
	out.WriteByte(0)
	for out.Len()%4 != 0 {
		out.WriteByte(0)
	}
	binary.BigEndian.PutUint32(word[:], 0x00000800) // KADM5_POLICY
	out.Write(word[:])
	binary.BigEndian.PutUint32(word[:], 0) // old_key_next
	out.Write(word[:])
	binary.BigEndian.PutUint32(word[:], 2) // INITIAL_HIST_KVNO
	out.Write(word[:])
	binary.BigEndian.PutUint32(word[:], 0) // old_keys array length
	out.Write(word[:])
	return out.Bytes(), nil
}

func encodeKeyData(name principal.Principal, key kdb.Key,
	masterEType crypto.EType, masterKey []byte) (string, error) {
	etype, err := crypto.NewRegistry().Get(key.Enctype)
	if err != nil {
		return "", fmt.Errorf("unsupported key enctype %d", key.Enctype)
	}
	if len(key.Key) != etype.KeySize() {
		return "", fmt.Errorf("key enctype %d has invalid key length", key.Enctype)
	}
	if key.KVNO == 0 || key.KVNO > uint32(^uint16(0)) {
		return "", fmt.Errorf("key enctype %d has invalid KVNO", key.Enctype)
	}
	if len(key.Key) > int(^uint16(0)) {
		return "", fmt.Errorf("key enctype %d key is too long", key.Enctype)
	}
	ciphertext, err := masterEType.Encrypt(masterKey, 0, key.Key)
	if err != nil {
		return "", fmt.Errorf("encrypt key enctype %d: %w", key.Enctype, err)
	}
	contents := make([]byte, 2+len(ciphertext))
	binary.LittleEndian.PutUint16(contents, uint16(len(key.Key)))
	copy(contents[2:], ciphertext)

	normalSalt := name.Realm + strings.Join(name.Components, "")
	saltType, salt := 0, []byte(nil)
	version := 1
	if key.Salt != "" && key.Salt != normalSalt {
		version = 2
		saltType = 4 // KRB5_KDB_SALTTYPE_SPECIAL
		salt = []byte(key.Salt)
		if len(salt) > int(^uint16(0)) {
			return "", fmt.Errorf("key enctype %d salt is too long", key.Enctype)
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "%d\t%d\t%d\t%d\t%s", version, key.KVNO,
		key.Enctype, len(contents), hex.EncodeToString(contents))
	if version == 2 {
		fmt.Fprintf(&out, "\t%d\t%d\t%s", saltType, len(salt),
			hex.EncodeToString(salt))
	}
	return out.String(), nil
}

func dumpAttributes(flags uint32) (string, error) {
	if flags > uint32(^uint32(0)>>1) {
		return "", fmt.Errorf("flags exceed MIT signed attribute range")
	}
	return strconv.FormatUint(uint64(flags), 10), nil
}

func dumpDuration(value time.Duration, field string) (string, error) {
	if value < 0 || value%time.Second != 0 {
		return "", fmt.Errorf("%s is invalid", field)
	}
	seconds := value / time.Second
	if uint64(seconds) > uint64(^uint32(0)>>1) {
		return "", fmt.Errorf("%s is too large", field)
	}
	return strconv.FormatInt(int64(seconds), 10), nil
}

func dumpEpoch(value time.Time, field string) (string, error) {
	if value.IsZero() {
		return "0", nil
	}
	value = value.UTC()
	if value.Unix() < 0 || uint64(value.Unix()) > uint64(^uint32(0)) {
		return "", fmt.Errorf("%s is outside MIT timestamp range", field)
	}
	return strconv.FormatInt(value.Unix(), 10), nil
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
	lastSuccess, err := parseEpoch(fields[cursor+5], "last success")
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	lastFailed, err := parseEpoch(fields[cursor+6], "last failed")
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	failAuthCount, err := parseUint(fields[cursor+7], "failure count")
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	if failAuthCount > uint64(^uint32(0)) {
		return kdb.PrincipalRecord{}, fmt.Errorf("failure count is too large")
	}
	cursor += 8
	tlData := make([]kdb.TLData, 0, header[2])
	var policy string
	for i := uint64(0); i < header[2]; i++ {
		if cursor+2 >= len(fields) {
			return kdb.PrincipalRecord{}, fmt.Errorf("truncated tagged data")
		}
		tagType, err := parseInt(fields[cursor], "tagged data type")
		if err != nil {
			return kdb.PrincipalRecord{}, err
		}
		if tagType < 0 || tagType > int64(^uint16(0)>>1) {
			return kdb.PrincipalRecord{}, fmt.Errorf("tagged data type is out of range")
		}
		length, err := parseUint(fields[cursor+1], "tagged data length")
		if err != nil {
			return kdb.PrincipalRecord{}, err
		}
		if err := validateOctets(fields[cursor+2], length, "tagged data"); err != nil {
			return kdb.PrincipalRecord{}, err
		}
		data, err := parseOctets(fields[cursor+2], length, "tagged data")
		if err != nil {
			return kdb.PrincipalRecord{}, err
		}
		tlData = append(tlData, kdb.TLData{Type: int16(tagType), Data: data})
		if tagType == 3 {
			if parsedPolicy, ok := decodeKADMPolicy(data); ok {
				policy = parsedPolicy
			}
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
		var saltType int64
		var saltBytes []byte
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
			} else {
				saltType = int64(keyType)
				saltBytes = content
			}
			cursor += 3
		}
		if _, exists := keys[enctype]; exists {
			return kdb.PrincipalRecord{}, fmt.Errorf("duplicate key enctype %d", enctype)
		}
		salt := name.Realm + strings.Join(name.Components, "")
		if keyVersion == 2 {
			switch saltType {
			case 0:
				salt = name.Realm + strings.Join(name.Components, "")
			case 2:
				salt = strings.Join(name.Components, "")
			case 3:
				salt = name.Realm
			default:
				salt = string(saltBytes)
			}
		}
		keys[enctype] = kdb.Key{Enctype: enctype, KVNO: uint32(kvno),
			Key: keyBytes, Salt: salt}
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
		LastSuccess: lastSuccess, LastFailed: lastFailed,
		FailAuthCount: uint32(failAuthCount), TLData: tlData, Policy: policy,
	}, nil
}

func decodeKADMPolicy(data []byte) (string, bool) {
	if len(data) < 20 || binary.BigEndian.Uint32(data[:4]) != 0x12345c01 {
		return "", false
	}
	offset := 4
	length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4
	if length == 0 || length > len(data)-offset {
		return "", false
	}
	raw := data[offset : offset+length]
	if raw[length-1] != 0 {
		return "", false
	}
	policy := string(raw[:length-1])
	offset += length
	offset = (offset + 3) &^ 3
	if offset+16 > len(data) {
		return "", false
	}
	auxAttributes := binary.BigEndian.Uint32(data[offset : offset+4])
	if auxAttributes&0x00000800 == 0 {
		return "", false
	}
	return policy, true
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
