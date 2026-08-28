package kdb

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/Exonical/go-kerberos/krb5/crypto"
)

const (
	// KADMDataType is KRB5_TL_KADM_DATA in MIT's KDB.
	KADMDataType    int16 = 3
	kadmDataVersion       = 0x12345c01
	kadmPolicy            = 0x00000800
)

// KADMData is the decoded osa_princ_ent_rec stored in KRB5_TL_KADM_DATA.
// OldKeys is ordered newest first, like PrincipalRecord.PasswordHistory.
type KADMData struct {
	Policy           string
	AuxAttributes    uint32
	OldKeyNext       uint32
	AdminHistoryKVNO uint32
	NormalSalt       string
	OldKeys          []map[int32]Key
}

// ParseKADMDataMetadata parses the non-key fields of MIT KADM_DATA without
// requiring the kadmin/history key.
func ParseKADMDataMetadata(data []byte) (KADMData, error) {
	r := xdrReader{data: data}
	version, err := r.u32()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data version: %w", err)
	}
	if version != kadmDataVersion {
		return KADMData{}, fmt.Errorf("unsupported KADM data version %#x", version)
	}
	policy, err := r.nullString()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data policy: %w", err)
	}
	aux, err := r.u32()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data auxiliary attributes: %w", err)
	}
	next, err := r.u32()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data history cursor: %w", err)
	}
	histKVNO, err := r.u32()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data history KVNO: %w", err)
	}
	count, err := r.u32()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data history count: %w", err)
	}
	if uint64(count) > uint64(len(data))/4 {
		return KADMData{}, fmt.Errorf("KADM data history count is too large")
	}
	return KADMData{Policy: policy, AuxAttributes: aux, OldKeyNext: next,
		AdminHistoryKVNO: histKVNO, OldKeys: make([]map[int32]Key, count)}, nil
}

// EncodeKADMData encodes MIT's osa_princ_ent_rec. Historical keys are
// encrypted with historyKey using Kerberos usage zero. A nil history key is
// valid when there are no historical keys.
func EncodeKADMData(data KADMData, historyKey *Key) ([]byte, error) {
	if data.Policy == "" && data.AuxAttributes&kadmPolicy != 0 {
		return nil, fmt.Errorf("KADM data policy is empty")
	}
	if data.Policy != "" {
		data.AuxAttributes |= kadmPolicy
	}
	if data.AdminHistoryKVNO == 0 && historyKey != nil {
		data.AdminHistoryKVNO = historyKey.KVNO
	}
	if len(data.OldKeys) > int(^uint32(0)) {
		return nil, fmt.Errorf("KADM data has too many history entries")
	}
	if len(data.OldKeys) > 0 && historyKey == nil {
		return nil, fmt.Errorf("KADM data history key is unavailable")
	}

	var out xdrBuffer
	out.u32(kadmDataVersion)
	out.nullString(data.Policy)
	out.u32(data.AuxAttributes)
	if len(data.OldKeys) > 0 {
		// OldKeys is exposed newest-first; MIT stores its circular queue
		// oldest-first and points at the next slot to overwrite.
		physical := make([]map[int32]Key, len(data.OldKeys))
		for i := range data.OldKeys {
			physical[len(data.OldKeys)-1-i] = data.OldKeys[i]
		}
		data.OldKeys = physical
	}
	out.u32(data.OldKeyNext)
	out.u32(data.AdminHistoryKVNO)
	out.u32(uint32(len(data.OldKeys)))
	for _, history := range data.OldKeys {
		keys := make([]Key, 0, len(history))
		for _, key := range history {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].Enctype < keys[j].Enctype
		})
		if len(keys) > int(^uint32(0)) {
			return nil, fmt.Errorf("KADM data history entry has too many keys")
		}
		out.u32(uint32(len(keys)))
		for _, key := range keys {
			if historyKey == nil {
				return nil, fmt.Errorf("KADM data history key is unavailable")
			}
			etype, err := crypto.NewRegistry().Get(historyKey.Enctype)
			if err != nil {
				return nil, fmt.Errorf("KADM data history enctype %d: %w", historyKey.Enctype, err)
			}
			keyEType, err := crypto.NewRegistry().Get(key.Enctype)
			if err != nil {
				return nil, fmt.Errorf("KADM data key enctype %d: %w", key.Enctype, err)
			}
			if len(key.Key) != keyEType.KeySize() {
				return nil, fmt.Errorf("KADM data key enctype %d has invalid length", key.Enctype)
			}
			if key.KVNO > uint32(^uint16(0)) {
				return nil, fmt.Errorf("KADM data key enctype %d has invalid KVNO", key.Enctype)
			}
			encrypted, err := etype.Encrypt(historyKey.Key, 0, key.Key)
			if err != nil {
				return nil, fmt.Errorf("KADM data key enctype %d: %w", key.Enctype, err)
			}
			contents := make([]byte, 2+len(encrypted))
			binary.LittleEndian.PutUint16(contents, uint16(len(key.Key)))
			copy(contents[2:], encrypted)
			if len(contents) > int(^uint16(0)) {
				return nil, fmt.Errorf("KADM data key enctype %d is too long", key.Enctype)
			}
			version := int16(1)
			saltType := int16(0)
			var salt []byte
			if key.Salt != "" && key.Salt != data.NormalSalt {
				version = 2
				saltType = 4
				salt = []byte(key.Salt)
				if len(salt) > int(^uint16(0)) {
					return nil, fmt.Errorf("KADM data key enctype %d salt is too long", key.Enctype)
				}
			}
			out.i16(version)
			out.u16(uint16(key.KVNO))
			out.i16(int16(key.Enctype))
			out.i16(saltType)
			out.u16(uint16(len(contents)))
			out.u16(uint16(len(salt)))
			out.bytes(contents)
			out.bytes(salt)
		}
	}
	return out.data(), nil
}

// DecodeKADMData decodes MIT's osa_princ_ent_rec and decrypts historical
// keys using any compatible key in historyKeys. normalSalt is assigned to
// historical keys whose KADM key-data has the normal salt type.
func DecodeKADMData(data []byte, historyKeys []Key, normalSalt string) (KADMData, error) {
	r := xdrReader{data: data}
	version, err := r.u32()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data version: %w", err)
	}
	if version != kadmDataVersion {
		return KADMData{}, fmt.Errorf("unsupported KADM data version %#x", version)
	}
	policy, err := r.nullString()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data policy: %w", err)
	}
	aux, err := r.u32()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data auxiliary attributes: %w", err)
	}
	next, err := r.u32()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data history cursor: %w", err)
	}
	histKVNO, err := r.u32()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data history KVNO: %w", err)
	}
	count, err := r.u32()
	if err != nil {
		return KADMData{}, fmt.Errorf("KADM data history count: %w", err)
	}
	if uint64(count) > uint64(len(data))/4 {
		return KADMData{}, fmt.Errorf("KADM data history count is too large")
	}
	out := KADMData{Policy: policy, AuxAttributes: aux, OldKeyNext: next,
		AdminHistoryKVNO: histKVNO, OldKeys: make([]map[int32]Key, 0, count)}
	for i := uint32(0); i < count; i++ {
		keyCount, err := r.u32()
		if err != nil {
			return KADMData{}, fmt.Errorf("KADM data history entry: %w", err)
		}
		if uint64(keyCount) > uint64(len(data))/24 {
			return KADMData{}, fmt.Errorf("KADM data key count is too large")
		}
		entry := make(map[int32]Key, keyCount)
		for j := uint32(0); j < keyCount; j++ {
			keyVersion, err := r.i16()
			if err != nil {
				return KADMData{}, err
			}
			if keyVersion != 1 && keyVersion != 2 {
				return KADMData{}, fmt.Errorf("unsupported KADM key-data version %d", keyVersion)
			}
			kvno, err := r.u16()
			if err != nil {
				return KADMData{}, err
			}
			enctype, err := r.i16()
			if err != nil {
				return KADMData{}, err
			}
			saltType, err := r.i16()
			if err != nil {
				return KADMData{}, err
			}
			keyLength, err := r.u16()
			if err != nil {
				return KADMData{}, err
			}
			saltLength, err := r.u16()
			if err != nil {
				return KADMData{}, err
			}
			contents, err := r.bytes(keyLength)
			if err != nil {
				return KADMData{}, err
			}
			salt, err := r.bytes(saltLength)
			if err != nil {
				return KADMData{}, err
			}
			if keyLength < 2 {
				return KADMData{}, fmt.Errorf("KADM key-data contents are truncated")
			}
			plainLength := int(binary.LittleEndian.Uint16(contents[:2]))
			if plainLength == 0 {
				return KADMData{}, fmt.Errorf("KADM key-data plaintext is empty")
			}
			plain, err := decryptHistoryKey(contents[2:], historyKeys)
			if err != nil {
				return KADMData{}, fmt.Errorf("KADM key-data decryption: %w", err)
			}
			if len(plain) != plainLength {
				return KADMData{}, fmt.Errorf("KADM key-data plaintext length mismatch")
			}
			keySalt := normalSalt
			if keyVersion == 2 && saltType == 4 {
				keySalt = string(salt)
			}
			entry[int32(enctype)] = Key{Enctype: int32(enctype), KVNO: uint32(kvno),
				Key: append([]byte(nil), plain...), Salt: keySalt}
		}
		out.OldKeys = append(out.OldKeys, entry)
	}
	if r.remaining() != 0 {
		return KADMData{}, fmt.Errorf("KADM data has trailing bytes")
	}
	// MIT stores a circular queue oldest-first. Present it newest-first.
	if len(out.OldKeys) > 0 {
		ordered := make([]map[int32]Key, 0, len(out.OldKeys))
		next := int(out.OldKeyNext) % len(out.OldKeys)
		for i := 1; i <= len(out.OldKeys); i++ {
			ordered = append(ordered, out.OldKeys[(next-i+len(out.OldKeys))%len(out.OldKeys)])
		}
		out.OldKeys = ordered
	}
	return out, nil
}

func decryptHistoryKey(ciphertext []byte, keys []Key) ([]byte, error) {
	var lastErr error
	for _, key := range keys {
		etype, err := crypto.NewRegistry().Get(key.Enctype)
		if err != nil {
			lastErr = err
			continue
		}
		plain, err := etype.Decrypt(key.Key, 0, ciphertext)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no history keys available")
	}
	return nil, lastErr
}

type xdrBuffer struct{ b []byte }

func (w *xdrBuffer) u16(v uint16) {
	w.u32(uint32(v))
}
func (w *xdrBuffer) i16(v int16) { w.u32(uint32(int32(v))) }
func (w *xdrBuffer) u32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.b = append(w.b, b[:]...)
}
func (w *xdrBuffer) bytes(v []byte) {
	w.u32(uint32(len(v)))
	w.b = append(w.b, v...)
	for len(w.b)%4 != 0 {
		w.b = append(w.b, 0)
	}
}
func (w *xdrBuffer) nullString(v string) { w.bytes(append([]byte(v), 0)) }
func (w *xdrBuffer) data() []byte        { return append([]byte(nil), w.b...) }

type xdrReader struct {
	data []byte
	off  int
}

func (r *xdrReader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.data)-r.off {
		return nil, fmt.Errorf("KADM data is truncated")
	}
	v := r.data[r.off : r.off+n]
	r.off += n
	return v, nil
}
func (r *xdrReader) u16() (uint16, error) {
	v, err := r.u32()
	if err != nil {
		return 0, err
	}
	if v > uint32(^uint16(0)) {
		return 0, fmt.Errorf("KADM data 16-bit value is out of range")
	}
	return uint16(v), nil
}
func (r *xdrReader) i16() (int16, error) {
	v, err := r.u32()
	if err != nil {
		return 0, err
	}
	signed := int64(int32(v))
	if signed < -1<<15 || signed > 1<<15-1 {
		return 0, fmt.Errorf("KADM data 16-bit value is out of range")
	}
	return int16(signed), nil
}
func (r *xdrReader) u32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}
func (r *xdrReader) bytes(n uint16) ([]byte, error) {
	length, err := r.u32()
	if err != nil || length != uint32(n) {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("KADM data length mismatch")
	}
	v, err := r.take(int(length))
	if err != nil {
		return nil, err
	}
	pad := (4 - int(length)%4) % 4
	if _, err := r.take(pad); err != nil {
		return nil, err
	}
	return v, nil
}
func (r *xdrReader) nullString() (string, error) {
	length, err := r.u32()
	if err != nil {
		return "", err
	}
	if length == 0 || length > uint32(len(r.data)-r.off) {
		return "", fmt.Errorf("KADM data string is invalid")
	}
	raw, err := r.take(int(length))
	if err != nil {
		return "", err
	}
	if raw[len(raw)-1] != 0 {
		return "", fmt.Errorf("KADM data string is not terminated")
	}
	pad := (4 - int(length)%4) % 4
	if _, err := r.take(pad); err != nil {
		return "", err
	}
	return string(raw[:len(raw)-1]), nil
}
func (r *xdrReader) remaining() int { return len(r.data) - r.off }
