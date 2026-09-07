package keytab

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/internal/binfmt"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// Version is the MIT FILE keytab format version.
const Version uint16 = 0x0502

// Entry mirrors an MIT keytab principal-key record.
type Entry struct {
	Principal principal.Principal
	Timestamp int64
	KVNO      uint32
	Enctype   int32
	Key       []byte
}

// Keytab is a collection of MIT keytab entries.
type Keytab struct {
	Entries []Entry
	mu      *sync.RWMutex
}

var (
	memoryMu      sync.Mutex
	memoryKeytabs = make(map[string]*Keytab)
	keytabMu      sync.Mutex
)

// Resolve opens a keytab name. FILE paths and FILE: names are read from disk;
// MEMORY:name resolves to a process-local keytab which persists for the
// lifetime of the process and is shared by all resolves of that name.
func Resolve(name string) (*Keytab, error) {
	if name == "" {
		return nil, fmt.Errorf("resolve keytab: empty name")
	}
	if strings.HasPrefix(name, "MEMORY:") {
		residual := strings.TrimPrefix(name, "MEMORY:")
		if residual == "" {
			return nil, fmt.Errorf("resolve keytab: empty MEMORY name")
		}
		memoryMu.Lock()
		defer memoryMu.Unlock()
		if kt := memoryKeytabs[residual]; kt != nil {
			return kt, nil
		}
		kt := &Keytab{mu: &sync.RWMutex{}}
		memoryKeytabs[residual] = kt
		return kt, nil
	}
	if strings.HasPrefix(name, "FILE:") {
		name = strings.TrimPrefix(name, "FILE:")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("resolve keytab: %w", err)
	}
	defer file.Close()
	return Read(file)
}

// ResolveWithConfig resolves a configured keytab name. An explicit name takes
// precedence; otherwise KRB5_KTNAME, default_keytab_name, and the conventional
// system keytab path are considered in that order.
func ResolveWithConfig(name string, cfg *config.Config) (*Keytab, error) {
	return resolveWithConfig(name, cfg, false)
}

// ResolveClientWithConfig resolves the configured client keytab name using
// MIT's KRB5_CLIENT_KTNAME, default_client_keytab_name, and compile-time
// default chain. It does not consult KRB5_KTNAME or default_keytab_name.
func ResolveClientWithConfig(name string, cfg *config.Config) (*Keytab, error) {
	return resolveWithConfig(name, cfg, true)
}

func resolveWithConfig(name string, cfg *config.Config, client bool) (*Keytab, error) {
	expand := false
	if name == "" {
		if client {
			name = os.Getenv("KRB5_CLIENT_KTNAME")
		} else {
			name = os.Getenv("KRB5_KTNAME")
		}
	}
	if name == "" && cfg != nil {
		if client {
			name = cfg.DefaultClientKeytabName
		} else {
			name = cfg.DefaultKeytabName
		}
		expand = name != ""
	}
	if name == "" {
		if client {
			name = "FILE:/var/kerberos/krb5/user/%{euid}/client.keytab"
			expand = true
		} else {
			name = "/etc/krb5.keytab"
		}
	}
	if expand {
		var err error
		name, err = config.ExpandPathTokens(name)
		if err != nil {
			return nil, err
		}
	}
	return Resolve(name)
}

// AddEntry adds an entry to a keytab. MEMORY keytabs use this method to
// publish keys to all handles resolved with the same name.
func (kt *Keytab) AddEntry(entry Entry) error {
	if kt == nil {
		return fmt.Errorf("add keytab entry: nil keytab")
	}
	mu := kt.mutex()
	mu.Lock()
	kt.Entries = append(kt.Entries, cloneEntry(entry))
	mu.Unlock()
	return nil
}

// RemoveEntry removes matching entries from a keytab.
func (kt *Keytab) RemoveEntry(entry Entry) error {
	if kt == nil {
		return fmt.Errorf("remove keytab entry: nil keytab")
	}
	mu := kt.mutex()
	mu.Lock()
	defer mu.Unlock()
	filtered := kt.Entries[:0]
	for _, candidate := range kt.Entries {
		if !entriesEqual(candidate, entry) {
			filtered = append(filtered, candidate)
		}
	}
	kt.Entries = filtered
	return nil
}

func (kt *Keytab) mutex() *sync.RWMutex {
	keytabMu.Lock()
	defer keytabMu.Unlock()
	if kt.mu == nil {
		kt.mu = &sync.RWMutex{}
	}
	return kt.mu
}

func cloneEntry(entry Entry) Entry {
	entry.Principal.Components = append([]string(nil), entry.Principal.Components...)
	entry.Key = append([]byte(nil), entry.Key...)
	return entry
}

// EntriesSnapshot returns a deep copy of the current keytab entries.
func (kt *Keytab) EntriesSnapshot() []Entry {
	if kt == nil {
		return nil
	}
	mu := kt.mutex()
	mu.RLock()
	defer mu.RUnlock()
	entries := make([]Entry, len(kt.Entries))
	for i, entry := range kt.Entries {
		entries[i] = cloneEntry(entry)
	}
	return entries
}

func entriesEqual(left, right Entry) bool {
	if !principalEqual(left.Principal, right.Principal) ||
		left.Timestamp != right.Timestamp || left.KVNO != right.KVNO ||
		left.Enctype != right.Enctype || len(left.Key) != len(right.Key) {
		return false
	}
	for i := range left.Key {
		if left.Key[i] != right.Key[i] {
			return false
		}
	}
	return true
}

// Read decodes an MIT FILE keytab from r.
func Read(r io.Reader) (*Keytab, error) {
	if r == nil {
		return nil, fmt.Errorf("read keytab: nil reader")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read keytab: %w", err)
	}
	if len(data) < 2 {
		return nil, fmt.Errorf("read keytab: truncated version")
	}
	if binary.BigEndian.Uint16(data[:2]) != Version {
		return nil, fmt.Errorf("read keytab: unsupported version")
	}

	kt := &Keytab{mu: &sync.RWMutex{}}
	offset := 2
	for offset < len(data) {
		if len(data)-offset < 4 {
			return nil, fmt.Errorf("read keytab: truncated record length")
		}
		length := int64(int32(binary.BigEndian.Uint32(data[offset:])))
		offset += 4
		if length == 0 {
			break
		}
		size := length
		if size < 0 {
			size = -size
		}
		if size > int64(len(data)-offset) {
			return nil, fmt.Errorf("read keytab: truncated record")
		}
		if length < 0 {
			offset += int(size)
			continue
		}
		body := data[offset : offset+int(size)]
		offset += int(size)
		entry, err := parseEntry(body)
		if err != nil {
			return nil, fmt.Errorf("read keytab record: %w", err)
		}
		kt.Entries = append(kt.Entries, entry)
	}
	return kt, nil
}

// Write encodes kt in the MIT FILE keytab format.
func Write(w io.Writer, kt *Keytab) error {
	if w == nil {
		return fmt.Errorf("write keytab: nil writer")
	}
	if kt == nil {
		return fmt.Errorf("write keytab: nil keytab")
	}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.BigEndian, Version); err != nil {
		return fmt.Errorf("write keytab version: %w", err)
	}
	for _, entry := range kt.EntriesSnapshot() {
		body, err := marshalEntry(entry)
		if err != nil {
			return fmt.Errorf("write keytab entry: %w", err)
		}
		if err := binary.Write(&data, binary.BigEndian, int32(len(body))); err != nil {
			return fmt.Errorf("write keytab record length: %w", err)
		}
		if _, err := data.Write(body); err != nil {
			return fmt.Errorf("write keytab record: %w", err)
		}
	}
	n, err := w.Write(data.Bytes())
	if err != nil {
		return fmt.Errorf("write keytab: %w", err)
	}
	if n != data.Len() {
		return fmt.Errorf("write keytab: %w", io.ErrShortWrite)
	}
	return nil
}

// LookupPrincipal returns entries matching name.
func (kt *Keytab) LookupPrincipal(name principal.Principal) ([]Entry, error) {
	if kt == nil {
		return nil, fmt.Errorf("lookup keytab principal: nil keytab")
	}
	entries := make([]Entry, 0)
	for _, entry := range kt.EntriesSnapshot() {
		if principalEqual(entry.Principal, name) {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// LookupEnctype returns entries using enctype.
func (kt *Keytab) LookupEnctype(enctype int32) ([]Entry, error) {
	if kt == nil {
		return nil, fmt.Errorf("lookup keytab enctype: nil keytab")
	}
	entries := make([]Entry, 0)
	for _, entry := range kt.EntriesSnapshot() {
		if entry.Enctype == enctype {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// LookupKVNO returns entries using kvno.
func (kt *Keytab) LookupKVNO(kvno uint32) ([]Entry, error) {
	if kt == nil {
		return nil, fmt.Errorf("lookup keytab kvno: nil keytab")
	}
	entries := make([]Entry, 0)
	for _, entry := range kt.EntriesSnapshot() {
		if entry.KVNO == kvno {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func parseEntry(data []byte) (Entry, error) {
	d := binfmt.NewReader(data)
	count, err := d.U16()
	if err != nil {
		return Entry{}, err
	}
	realm, err := d.Counted16()
	if err != nil {
		return Entry{}, err
	}
	components := make([]string, 0, int(count))
	for i := uint16(0); i < count; i++ {
		component, err := d.Counted16()
		if err != nil {
			return Entry{}, err
		}
		components = append(components, string(component))
	}
	nameType, err := d.U32()
	if err != nil {
		return Entry{}, err
	}
	timestamp, err := d.U32()
	if err != nil {
		return Entry{}, err
	}
	kvno8, err := d.U8()
	if err != nil {
		return Entry{}, err
	}
	enctype, err := d.U16()
	if err != nil {
		return Entry{}, err
	}
	key, err := d.Counted16()
	if err != nil {
		return Entry{}, err
	}
	kvno := uint32(kvno8)
	if d.Remaining() >= 4 {
		kvno32, err := d.U32()
		if err != nil {
			return Entry{}, err
		}
		if kvno32 != 0 {
			kvno = kvno32
		}
	}
	return Entry{
		Principal: principal.Principal{
			Realm:      string(realm),
			NameType:   principal.NameType(int32(nameType)),
			Components: components,
		},
		Timestamp: int64(timestamp),
		KVNO:      kvno,
		Enctype:   int32(enctype),
		Key:       append([]byte(nil), key...),
	}, nil
}

func marshalEntry(entry Entry) ([]byte, error) {
	if len(entry.Principal.Components) > int(^uint16(0)) {
		return nil, fmt.Errorf("too many principal components")
	}
	if len(entry.Principal.Realm) > int(^uint16(0)) {
		return nil, fmt.Errorf("realm is too long")
	}
	if entry.Timestamp < 0 || entry.Timestamp > int64(^uint32(0)) {
		return nil, fmt.Errorf("timestamp out of range")
	}
	if entry.Enctype < 0 || entry.Enctype > int32(^uint16(0)) {
		return nil, fmt.Errorf("enctype out of range")
	}
	if len(entry.Key) > int(^uint16(0)) {
		return nil, fmt.Errorf("key is too long")
	}
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, uint16(len(entry.Principal.Components)))
	binfmt.WriteCounted16(&body, []byte(entry.Principal.Realm))
	for _, component := range entry.Principal.Components {
		if len(component) > int(^uint16(0)) {
			return nil, fmt.Errorf("principal component is too long")
		}
		binfmt.WriteCounted16(&body, []byte(component))
	}
	_ = binary.Write(&body, binary.BigEndian, uint32(entry.Principal.NameType))
	_ = binary.Write(&body, binary.BigEndian, uint32(entry.Timestamp))
	_ = body.WriteByte(byte(entry.KVNO))
	_ = binary.Write(&body, binary.BigEndian, uint16(entry.Enctype))
	binfmt.WriteCounted16(&body, entry.Key)
	_ = binary.Write(&body, binary.BigEndian, entry.KVNO)
	if body.Len() > 1<<31-1 {
		return nil, fmt.Errorf("keytab entry is too long")
	}
	return body.Bytes(), nil
}

func principalEqual(left, right principal.Principal) bool {
	if left.Realm != right.Realm || left.NameType != right.NameType ||
		len(left.Components) != len(right.Components) {
		return false
	}
	for i := range left.Components {
		if left.Components[i] != right.Components[i] {
			return false
		}
	}
	return true
}
