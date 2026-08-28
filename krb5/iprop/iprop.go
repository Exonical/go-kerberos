// Package iprop implements the MIT Kerberos incremental propagation protocol.
package iprop

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	Program uint32 = 100423
	Version uint32 = 1

	ProcNull          uint32 = 0
	ProcGetUpdates    uint32 = 1
	ProcFullResync    uint32 = 2
	ProcFullResyncExt uint32 = 3

	UpdateOK               UpdateStatus = 0
	UpdateError            UpdateStatus = 1
	UpdateFullResyncNeeded UpdateStatus = 2
	UpdateBusy             UpdateStatus = 3
	UpdateNil              UpdateStatus = 4
	UpdatePermDenied       UpdateStatus = 5
)

type UpdateStatus int32

type Time struct {
	Seconds  uint32
	Useconds uint32
}

func timeValue(value time.Time) Time {
	if value.IsZero() {
		return Time{}
	}
	value = value.UTC()
	return Time{Seconds: uint32(value.Unix()), Useconds: uint32(value.Nanosecond() / 1000)}
}

func (t Time) Time() time.Time {
	if t.Seconds == 0 && t.Useconds == 0 {
		return time.Time{}
	}
	return time.Unix(int64(t.Seconds), int64(t.Useconds)*1000).UTC()
}

type Last struct {
	LastSno  uint32
	LastTime Time
}

type Data struct {
	Magic int32
	Data  []byte
}

type Principal struct {
	Realm      []byte
	Components []Data
	NameType   int32
}

type Key struct {
	Version  int32
	KVNO     int32
	Enctypes []int32
	Contents [][]byte
}

type TL struct {
	Type int16
	Data []byte
}

const (
	ATAttrFlags AttrType = iota
	ATMaxLife
	ATMaxRenewLife
	ATExp
	ATPWExp
	ATLastSuccess
	ATLastFailed
	ATFailAuthCount
	ATPrinc
	ATKeyData
	ATTlData
	ATLen
	ATModPrinc
	ATModTime
	ATModWhere
	ATPWLastChange
	ATPWPolicy
	ATPWPolicySwitch
	ATPWHistKVNO
	ATPWHist
)

type AttrType int32

type Value struct {
	Type      AttrType
	Uint32    uint32
	Int16     int16
	Bool      bool
	Principal Principal
	Keys      []Key
	// PasswordHistory is the nested key array used by AT_PW_HIST.
	PasswordHistory [][]Key
	TLData          []TL
	String          []byte
	Extension       []byte
}

type Entry []Value

type Update struct {
	PrincipalName string
	EntrySno      uint32
	Time          Time
	Entry         Entry
	Deleted       bool
	Commit        bool
	KDCSSeenBy    []string
	Futures       []byte
}

type IncrementalResult struct {
	LastEntry Last
	Updates   []Update
	Ret       UpdateStatus
}

type FullResyncResult struct {
	LastEntry Last
	Ret       UpdateStatus
}

func MarshalLast(value Last) []byte {
	var w writer
	w.u32(value.LastSno)
	marshalTime(&w, value.LastTime)
	return w.bytes()
}
func (v Last) MarshalXDR() []byte { return MarshalLast(v) }
func UnmarshalLast(data []byte) (Last, error) {
	r := reader{data: data}
	v, err := unmarshalLast(&r)
	if err == nil {
		err = r.done()
	}
	return v, err
}

func (v IncrementalResult) MarshalXDR() []byte {
	var w writer
	marshalLast(&w, v.LastEntry)
	w.updates(v.Updates)
	w.i32(int32(v.Ret))
	return w.bytes()
}
func UnmarshalIncrementalResult(data []byte) (IncrementalResult, error) {
	r := reader{data: data}
	v, err := unmarshalIncremental(&r)
	if err == nil {
		err = r.done()
	}
	return v, err
}
func (v FullResyncResult) MarshalXDR() []byte {
	var w writer
	marshalLast(&w, v.LastEntry)
	w.i32(int32(v.Ret))
	return w.bytes()
}
func UnmarshalFullResyncResult(data []byte) (FullResyncResult, error) {
	r := reader{data: data}
	v, err := unmarshalFull(&r)
	if err == nil {
		err = r.done()
	}
	return v, err
}

func EntryFromRecord(record kdb.PrincipalRecord) (Entry, error) {
	return entryFromRecord(record, nil, nil)
}

// EntryFromRecordWithMasterKey encodes key data in the encrypted representation
// stored by MIT's KDB and transmitted in its update log.
func EntryFromRecordWithMasterKey(record kdb.PrincipalRecord, masterEnctype int32,
	masterKey []byte) (Entry, error) {
	etype, err := crypto.NewRegistry().Get(masterEnctype)
	if err != nil {
		return nil, fmt.Errorf("iprop master enctype: %w", err)
	}
	if len(masterKey) != etype.KeySize() {
		return nil, fmt.Errorf("iprop master key has invalid length")
	}
	return entryFromRecord(record, etype, masterKey)
}

func entryFromRecord(record kdb.PrincipalRecord, masterEType crypto.EType,
	masterKey []byte) (Entry, error) {
	keys, err := keyValues(record.Name, record.Keys, masterEType, masterKey)
	if err != nil {
		return nil, err
	}
	entry := Entry{
		{Type: ATAttrFlags, Uint32: record.Flags},
		{Type: ATMaxLife, Uint32: seconds(record.MaxLife)},
		{Type: ATMaxRenewLife, Uint32: seconds(record.MaxRenew)},
		{Type: ATExp, Uint32: unix(record.Expiration)},
		{Type: ATPWExp, Uint32: unix(record.PasswordExpiration)},
		{Type: ATLastSuccess, Uint32: unix(record.LastSuccess)},
		{Type: ATLastFailed, Uint32: unix(record.LastFailed)},
		{Type: ATFailAuthCount, Uint32: record.FailAuthCount},
		{Type: ATPrinc, Principal: principalValue(record.Name)},
		{Type: ATKeyData, Keys: keys},
		{Type: ATTlData, TLData: tlValues(record.TLData)},
		{Type: ATLen, Int16: 38},
		{Type: ATPWLastChange, Uint32: unix(record.LastPasswordChange)},
	}
	if record.Policy != "" {
		entry = append(entry, Value{Type: ATPWPolicy, String: []byte(record.Policy)})
	}
	return entry, nil
}

func RecordFromEntry(name principal.Principal, entry Entry) (kdb.PrincipalRecord, error) {
	return recordFromEntry(name, entry, nil, nil)
}

// RecordFromEntryWithMasterKey decodes key data encrypted with the MIT KDB
// master key, as received from a real MIT iprop update log.
func RecordFromEntryWithMasterKey(name principal.Principal, entry Entry,
	masterEnctype int32, masterKey []byte) (kdb.PrincipalRecord, error) {
	etype, err := crypto.NewRegistry().Get(masterEnctype)
	if err != nil {
		return kdb.PrincipalRecord{}, fmt.Errorf("iprop master enctype: %w", err)
	}
	if len(masterKey) != etype.KeySize() {
		return kdb.PrincipalRecord{}, fmt.Errorf("iprop master key has invalid length")
	}
	return recordFromEntry(name, entry, etype, masterKey)
}

func recordFromEntry(name principal.Principal, entry Entry,
	masterEType crypto.EType, masterKey []byte) (kdb.PrincipalRecord, error) {
	record := kdb.PrincipalRecord{Name: name, Strings: make(map[string]string)}
	for _, value := range entry {
		switch value.Type {
		case ATAttrFlags:
			record.Flags = value.Uint32
		case ATMaxLife:
			record.MaxLife = time.Duration(value.Uint32) * time.Second
		case ATMaxRenewLife:
			record.MaxRenew = time.Duration(value.Uint32) * time.Second
		case ATExp:
			record.Expiration = fromUnix(value.Uint32)
		case ATPWExp:
			record.PasswordExpiration = fromUnix(value.Uint32)
		case ATLastSuccess:
			record.LastSuccess = fromUnix(value.Uint32)
		case ATLastFailed:
			record.LastFailed = fromUnix(value.Uint32)
		case ATFailAuthCount:
			record.FailAuthCount = value.Uint32
		case ATPrinc:
			converted, err := principalFromValue(value.Principal)
			if err != nil {
				return kdb.PrincipalRecord{}, err
			}
			record.Name = converted
		case ATKeyData:
			var err error
			record.Keys, err = keyMapWithMaster(value.Keys, record.Name,
				masterEType, masterKey)
			if err != nil {
				return kdb.PrincipalRecord{}, err
			}
		case ATPWHist:
			for _, history := range value.PasswordHistory {
				keys, err := keyMapWithMaster(history, record.Name,
					masterEType, masterKey)
				if err != nil {
					return kdb.PrincipalRecord{}, err
				}
				record.PasswordHistory = append(record.PasswordHistory, keys)
			}
		case ATTlData:
			record.TLData = tlMap(value.TLData)
		case ATPWLastChange:
			record.LastPasswordChange = fromUnix(value.Uint32)
		case ATPWPolicy:
			record.Policy = string(value.String)
		}
	}
	if record.Keys == nil {
		record.Keys = make(map[int32]kdb.Key)
	}
	return record, nil
}

func principalValue(value principal.Principal) Principal {
	out := Principal{Realm: []byte(value.Realm), NameType: int32(value.NameType)}
	for _, component := range value.Components {
		// The Go principal model does not expose krb5_data's internal magic
		// marker. It is not semantically part of a principal component.
		out.Components = append(out.Components, Data{Data: []byte(component)})
	}
	return out
}

func principalFromValue(value Principal) (principal.Principal, error) {
	if len(value.Realm) == 0 || len(value.Components) == 0 {
		return principal.Principal{}, fmt.Errorf("iprop: invalid principal")
	}
	out := principal.Principal{Realm: string(value.Realm), NameType: principal.NameType(value.NameType)}
	for _, c := range value.Components {
		out.Components = append(out.Components, string(c.Data))
	}
	return out, nil
}

func keyValues(name principal.Principal, values map[int32]kdb.Key,
	masterEType crypto.EType, masterKey []byte) ([]Key, error) {
	keys := make([]Key, 0, len(values))
	for _, value := range values {
		content := append([]byte(nil), value.Key...)
		if masterEType != nil {
			ciphertext, err := masterEType.Encrypt(masterKey, 0, value.Key)
			if err != nil {
				return nil, fmt.Errorf("iprop encrypt key enctype %d: %w", value.Enctype, err)
			}
			content = make([]byte, 2+len(ciphertext))
			binary.LittleEndian.PutUint16(content, uint16(len(value.Key)))
			copy(content[2:], ciphertext)
		}
		key := Key{Version: 1, KVNO: int32(value.KVNO),
			Enctypes: []int32{value.Enctype},
			Contents: [][]byte{content}}
		normalSalt := name.Realm + strings.Join(name.Components, "")
		if value.Salt != "" && value.Salt != normalSalt {
			key.Version = 2
			saltType, salt := saltData(name, value.Salt)
			key.Enctypes = append(key.Enctypes, saltType)
			key.Contents = append(key.Contents, salt)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func saltData(name principal.Principal, salt string) (int32, []byte) {
	normal := name.Realm + strings.Join(name.Components, "")
	switch salt {
	case normal:
		return 0, nil
	case strings.Join(name.Components, ""):
		return 2, nil
	case name.Realm:
		return 3, nil
	default:
		return 4, []byte(salt)
	}
}

func keyMap(values []Key, name principal.Principal) map[int32]kdb.Key {
	out, _ := keyMapWithMaster(values, name, nil, nil)
	return out
}

func keyMapWithMaster(values []Key, name principal.Principal,
	masterEType crypto.EType, masterKey []byte) (map[int32]kdb.Key, error) {
	out := make(map[int32]kdb.Key)
	for _, value := range values {
		if len(value.Enctypes) == 0 || len(value.Contents) == 0 {
			continue
		}
		content := append([]byte(nil), value.Contents[0]...)
		if masterEType != nil {
			if len(content) < 2 {
				return nil, fmt.Errorf("iprop key data is truncated")
			}
			keyLength := int(binary.LittleEndian.Uint16(content))
			etype, err := crypto.NewRegistry().Get(value.Enctypes[0])
			if err != nil {
				return nil, err
			}
			if keyLength != etype.KeySize() {
				return nil, fmt.Errorf("iprop key data has invalid key length")
			}
			plain, err := masterEType.Decrypt(masterKey, 0, content[2:])
			if err != nil {
				return nil, fmt.Errorf("iprop key data integrity check failed")
			}
			if len(plain) < keyLength {
				return nil, fmt.Errorf("iprop key data is truncated")
			}
			content = plain[:keyLength]
		}
		key := kdb.Key{Enctype: value.Enctypes[0], KVNO: uint32(value.KVNO),
			Key: content}
		if value.Version >= 2 && len(value.Enctypes) > 1 &&
			len(value.Contents) > 1 {
			switch value.Enctypes[1] {
			case 0:
				key.Salt = name.Realm + strings.Join(name.Components, "")
			case 2:
				key.Salt = strings.Join(name.Components, "")
			case 3:
				key.Salt = name.Realm
			default:
				key.Salt = string(value.Contents[1])
			}
		}
		out[key.Enctype] = key
	}
	return out, nil
}
func tlValues(values []kdb.TLData) []TL {
	out := make([]TL, 0, len(values))
	for _, v := range values {
		out = append(out, TL{Type: v.Type, Data: append([]byte(nil), v.Data...)})
	}
	return out
}
func tlMap(values []TL) []kdb.TLData {
	out := make([]kdb.TLData, 0, len(values))
	for _, v := range values {
		out = append(out, kdb.TLData{Type: v.Type, Data: append([]byte(nil), v.Data...)})
	}
	return out
}
func seconds(value time.Duration) uint32 {
	if value <= 0 {
		return 0
	}
	return uint32(value / time.Second)
}
func unix(value time.Time) uint32 {
	if value.IsZero() {
		return 0
	}
	return uint32(value.Unix())
}
func fromUnix(value uint32) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(int64(value), 0).UTC()
}

type writer struct{ b []byte }

func (w *writer) u32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.b = append(w.b, b[:]...)
}
func (w *writer) i32(v int32) { w.u32(uint32(v)) }
func (w *writer) i16(v int16) { w.i32(int32(v)) }
func (w *writer) bool(v bool) {
	if v {
		w.u32(1)
	} else {
		w.u32(0)
	}
}
func (w *writer) opaque(v []byte) {
	w.u32(uint32(len(v)))
	w.b = append(w.b, v...)
	for len(w.b)%4 != 0 {
		w.b = append(w.b, 0)
	}
}
func (w *writer) raw(v []byte)  { w.b = append(w.b, v...) }
func (w *writer) bytes() []byte { return append([]byte(nil), w.b...) }
func (w *writer) time(v Time)   { marshalTime(w, v) }
func (w *writer) principal(v Principal) {
	w.opaque(v.Realm)
	w.u32(uint32(len(v.Components)))
	for _, c := range v.Components {
		w.i32(c.Magic)
		w.opaque(c.Data)
	}
	w.i32(v.NameType)
}
func (w *writer) key(v Key) {
	w.i32(v.Version)
	w.i32(v.KVNO)
	w.u32(uint32(len(v.Enctypes)))
	for _, e := range v.Enctypes {
		w.i32(e)
	}
	w.u32(uint32(len(v.Contents)))
	for _, c := range v.Contents {
		w.opaque(c)
	}
}
func (w *writer) value(v Value) {
	w.i32(int32(v.Type))
	switch v.Type {
	case ATAttrFlags, ATMaxLife, ATMaxRenewLife, ATExp, ATPWExp, ATLastSuccess, ATLastFailed, ATFailAuthCount, ATPWLastChange, ATPWHistKVNO:
		w.u32(v.Uint32)
	case ATPrinc, ATModPrinc:
		w.principal(v.Principal)
	case ATKeyData:
		w.u32(uint32(len(v.Keys)))
		for _, k := range v.Keys {
			w.key(k)
		}
	case ATPWHist:
		w.u32(uint32(len(v.PasswordHistory)))
		for _, history := range v.PasswordHistory {
			w.u32(uint32(len(history)))
			for _, k := range history {
				w.key(k)
			}
		}
	case ATTlData:
		w.u32(uint32(len(v.TLData)))
		for _, t := range v.TLData {
			w.i16(t.Type)
			w.opaque(t.Data)
		}
	case ATLen:
		w.i16(v.Int16)
	case ATModTime:
		w.u32(v.Uint32)
	case ATModWhere, ATPWPolicy:
		w.opaque(v.String)
	case ATPWPolicySwitch:
		w.bool(v.Bool)
	default:
		w.opaque(v.Extension)
	}
}
func (w *writer) entry(v Entry) {
	w.u32(uint32(len(v)))
	for _, a := range v {
		w.value(a)
	}
}
func (w *writer) update(v Update) {
	w.opaque([]byte(v.PrincipalName))
	w.u32(v.EntrySno)
	w.time(v.Time)
	w.entry(v.Entry)
	w.bool(v.Deleted)
	w.bool(v.Commit)
	w.u32(uint32(len(v.KDCSSeenBy)))
	for _, n := range v.KDCSSeenBy {
		w.opaque([]byte(n))
	}
	w.opaque(v.Futures)
}
func (w *writer) updates(v []Update) {
	w.u32(uint32(len(v)))
	for _, u := range v {
		w.update(u)
	}
}
func (w *writer) auth(flavor uint32, body []byte) { w.u32(flavor); w.opaque(body) }
func marshalLast(w *writer, value Last) {
	w.u32(value.LastSno)
	marshalTime(w, value.LastTime)
}
func marshalTime(w *writer, v Time) { w.u32(v.Seconds); w.u32(v.Useconds) }

type reader struct {
	data []byte
	off  int
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.data)-r.off {
		return nil, fmt.Errorf("iprop: truncated XDR")
	}
	v := r.data[r.off : r.off+n]
	r.off += n
	return v, nil
}
func (r *reader) u32() (uint32, error) {
	b, e := r.take(4)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint32(b), nil
}
func (r *reader) i32() (int32, error) { v, e := r.u32(); return int32(v), e }
func (r *reader) i16() (int16, error) {
	v, e := r.i32()
	if e != nil {
		return 0, e
	}
	if v < -32768 || v > 32767 {
		return 0, fmt.Errorf("iprop: int16 out of range")
	}
	return int16(v), nil
}
func (r *reader) boolean() (bool, error) {
	v, e := r.u32()
	if e != nil {
		return false, e
	}
	if v > 1 {
		return false, fmt.Errorf("iprop: invalid boolean")
	}
	return v == 1, nil
}
func (r *reader) opaque() ([]byte, error) {
	n, e := r.u32()
	if e != nil {
		return nil, e
	}
	v, e := r.take(int(n))
	if e != nil {
		return nil, e
	}
	pad := (4 - int(n)%4) % 4
	if _, e = r.take(pad); e != nil {
		return nil, e
	}
	return append([]byte(nil), v...), nil
}
func (r *reader) done() error {
	if r.off != len(r.data) {
		return fmt.Errorf("iprop: trailing XDR data")
	}
	return nil
}
func (r *reader) auth() (uint32, []byte, error) {
	flavor, e := r.u32()
	if e != nil {
		return 0, nil, e
	}
	body, e := r.opaque()
	return flavor, body, e
}
func (r *reader) time() (Time, error) {
	s, e := r.u32()
	if e != nil {
		return Time{}, e
	}
	u, e := r.u32()
	return Time{Seconds: s, Useconds: u}, e
}
func (r *reader) principal() (Principal, error) {
	realm, e := r.opaque()
	if e != nil {
		return Principal{}, e
	}
	n, e := r.u32()
	if e != nil || n > 1<<20 {
		return Principal{}, fmt.Errorf("iprop: invalid principal components")
	}
	out := Principal{Realm: realm}
	for i := uint32(0); i < n; i++ {
		m, e := r.i32()
		if e != nil {
			return Principal{}, e
		}
		d, e := r.opaque()
		if e != nil {
			return Principal{}, e
		}
		out.Components = append(out.Components, Data{Magic: m, Data: d})
	}
	nt, e := r.i32()
	out.NameType = nt
	return out, e
}
func (r *reader) key() (Key, error) {
	v, e := r.i32()
	if e != nil {
		return Key{}, e
	}
	kv, e := r.i32()
	if e != nil {
		return Key{}, e
	}
	n, e := r.u32()
	if e != nil || n > 1<<20 {
		return Key{}, fmt.Errorf("iprop: invalid key enctypes")
	}
	out := Key{Version: v, KVNO: kv}
	for i := uint32(0); i < n; i++ {
		x, e := r.i32()
		if e != nil {
			return Key{}, e
		}
		out.Enctypes = append(out.Enctypes, x)
	}
	n, e = r.u32()
	if e != nil || n > 1<<20 {
		return Key{}, fmt.Errorf("iprop: invalid key contents")
	}
	for i := uint32(0); i < n; i++ {
		x, e := r.opaque()
		if e != nil {
			return Key{}, e
		}
		out.Contents = append(out.Contents, x)
	}
	return out, nil
}
func (r *reader) value() (Value, error) {
	t, e := r.i32()
	if e != nil {
		return Value{}, e
	}
	v := Value{Type: AttrType(t)}
	switch v.Type {
	case ATAttrFlags, ATMaxLife, ATMaxRenewLife, ATExp, ATPWExp, ATLastSuccess, ATLastFailed, ATFailAuthCount, ATPWLastChange, ATPWHistKVNO:
		v.Uint32, e = r.u32()
	case ATPrinc, ATModPrinc:
		v.Principal, e = r.principal()
	case ATKeyData:
		var n uint32
		n, e = r.u32()
		if e == nil && n > 1<<20 {
			e = fmt.Errorf("iprop: too many keys")
		}
		for i := uint32(0); e == nil && i < n; i++ {
			var x Key
			x, e = r.key()
			v.Keys = append(v.Keys, x)
		}
	case ATPWHist:
		var n uint32
		n, e = r.u32()
		if e == nil && n > 1<<20 {
			e = fmt.Errorf("iprop: too many password-history entries")
		}
		for i := uint32(0); e == nil && i < n; i++ {
			var count uint32
			count, e = r.u32()
			if e != nil {
				break
			}
			if count > 1<<20 {
				e = fmt.Errorf("iprop: too many password-history keys")
				break
			}
			history := make([]Key, 0, count)
			for j := uint32(0); j < count; j++ {
				var x Key
				x, e = r.key()
				if e != nil {
					break
				}
				history = append(history, x)
			}
			v.PasswordHistory = append(v.PasswordHistory, history)
		}
	case ATTlData:
		var n uint32
		n, e = r.u32()
		if e == nil && n > 1<<20 {
			e = fmt.Errorf("iprop: too many TL data")
		}
		for i := uint32(0); e == nil && i < n; i++ {
			var x TL
			x.Type, e = r.i16()
			if e == nil {
				x.Data, e = r.opaque()
			}
			v.TLData = append(v.TLData, x)
		}
	case ATLen:
		v.Int16, e = r.i16()
	case ATModTime:
		v.Uint32, e = r.u32()
	case ATModWhere, ATPWPolicy:
		v.String, e = r.opaque()
	case ATPWPolicySwitch:
		v.Bool, e = r.boolean()
	default:
		v.Extension, e = r.opaque()
	}
	return v, e
}
func (r *reader) entry() (Entry, error) {
	n, e := r.u32()
	if e != nil || n > 1<<20 {
		return nil, fmt.Errorf("iprop: invalid entry")
	}
	out := make(Entry, 0, n)
	for i := uint32(0); i < n; i++ {
		v, e := r.value()
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r *reader) update() (Update, error) {
	name, e := r.opaque()
	if e != nil {
		return Update{}, e
	}
	s, e := r.u32()
	if e != nil {
		return Update{}, e
	}
	tm, e := r.time()
	if e != nil {
		return Update{}, e
	}
	ent, e := r.entry()
	if e != nil {
		return Update{}, e
	}
	del, e := r.boolean()
	if e != nil {
		return Update{}, e
	}
	com, e := r.boolean()
	if e != nil {
		return Update{}, e
	}
	n, e := r.u32()
	if e != nil || n > 1<<20 {
		return Update{}, fmt.Errorf("iprop: invalid seen-by list")
	}
	out := Update{PrincipalName: string(name), EntrySno: s, Time: tm, Entry: ent, Deleted: del, Commit: com}
	for i := uint32(0); i < n; i++ {
		x, e := r.opaque()
		if e != nil {
			return Update{}, e
		}
		out.KDCSSeenBy = append(out.KDCSSeenBy, string(x))
	}
	out.Futures, e = r.opaque()
	return out, e
}
func unmarshalLast(r *reader) (Last, error) {
	s, e := r.u32()
	if e != nil {
		return Last{}, e
	}
	t, e := r.time()
	return Last{LastSno: s, LastTime: t}, e
}
func unmarshalIncremental(r *reader) (IncrementalResult, error) {
	last, e := unmarshalLast(r)
	if e != nil {
		return IncrementalResult{}, e
	}
	n, e := r.u32()
	if e != nil || n > 1<<20 {
		return IncrementalResult{}, fmt.Errorf("iprop: invalid updates")
	}
	out := IncrementalResult{LastEntry: last}
	for i := uint32(0); i < n; i++ {
		u, e := r.update()
		if e != nil {
			return IncrementalResult{}, e
		}
		out.Updates = append(out.Updates, u)
	}
	ret, e := r.i32()
	out.Ret = UpdateStatus(ret)
	return out, e
}
func unmarshalFull(r *reader) (FullResyncResult, error) {
	last, e := unmarshalLast(r)
	if e != nil {
		return FullResyncResult{}, e
	}
	ret, e := r.i32()
	return FullResyncResult{LastEntry: last, Ret: UpdateStatus(ret)}, e
}
