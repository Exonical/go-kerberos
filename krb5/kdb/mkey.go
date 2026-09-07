package kdb

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	// MIT tagged-data types for master-key lifecycle metadata.
	MKVNOType   int16 = 0x0008
	ACTKVNOType int16 = 0x0009
	MKEYAuxType int16 = 0x000a
)

// ActKVNO identifies the time at which a master-key version became active.
type ActKVNO struct {
	KVNO    uint16
	ActTime int64
}

// MKeyAuxEntry stores the newest master key encrypted by an older key.
// LatestKeyData is the MIT key_data_contents payload, including its two-byte
// plaintext length prefix.
type MKeyAuxEntry struct {
	MKeyKVNO         uint16
	LatestKeyKVNO    uint16
	LatestKeyEnctype int32
	LatestKeyData    []byte
}

// EncodeMKVNO encodes KRB5_TL_MKVNO.
func EncodeMKVNO(kvno uint32) ([]byte, error) {
	if kvno == 0 || kvno > math.MaxUint16 {
		return nil, fmt.Errorf("master-key version %d is out of range", kvno)
	}
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data, uint16(kvno))
	return data, nil
}

// DecodeMKVNO decodes KRB5_TL_MKVNO. An empty value means no explicit MKVNO.
func DecodeMKVNO(data []byte) (uint32, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if len(data) != 2 {
		return 0, fmt.Errorf("invalid MKVNO data length %d", len(data))
	}
	return uint32(binary.LittleEndian.Uint16(data)), nil
}

// MKVNO returns the explicit master-key version in tagged data, or zero when
// the principal has no KRB5_TL_MKVNO entry.
func MKVNO(values []TLData) (uint32, error) {
	for _, value := range values {
		if value.Type == MKVNOType {
			return DecodeMKVNO(value.Data)
		}
	}
	return 0, nil
}

// EncodeACTKVNO encodes version-one KRB5_TL_ACTKVNO data.
func EncodeACTKVNO(values []ActKVNO) ([]byte, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("active master-key list is empty")
	}
	data := make([]byte, 2+len(values)*6)
	binary.LittleEndian.PutUint16(data, 1)
	for i, value := range values {
		if value.KVNO == 0 {
			return nil, fmt.Errorf("active master-key version is zero")
		}
		if value.ActTime < math.MinInt32 || value.ActTime > math.MaxInt32 {
			return nil, fmt.Errorf("active master-key time %d is out of range", value.ActTime)
		}
		offset := 2 + i*6
		binary.LittleEndian.PutUint16(data[offset:], value.KVNO)
		binary.LittleEndian.PutUint32(data[offset+2:], uint32(int32(value.ActTime)))
	}
	return data, nil
}

// DecodeACTKVNO decodes version-one KRB5_TL_ACTKVNO data.
func DecodeACTKVNO(data []byte) ([]ActKVNO, error) {
	if len(data) < 8 || (len(data)-2)%6 != 0 {
		return nil, fmt.Errorf("invalid ACTKVNO data length %d", len(data))
	}
	if binary.LittleEndian.Uint16(data) != 1 {
		return nil, fmt.Errorf("unsupported ACTKVNO version %d", binary.LittleEndian.Uint16(data))
	}
	values := make([]ActKVNO, 0, (len(data)-2)/6)
	for offset := 2; offset < len(data); offset += 6 {
		kvno := binary.LittleEndian.Uint16(data[offset:])
		if kvno == 0 {
			return nil, fmt.Errorf("active master-key version is zero")
		}
		values = append(values, ActKVNO{
			KVNO: kvno, ActTime: int64(int32(binary.LittleEndian.Uint32(data[offset+2:]))),
		})
	}
	return values, nil
}

// EncodeMKEYAux encodes version-one KRB5_TL_MKEY_AUX data.
func EncodeMKEYAux(values []MKeyAuxEntry) ([]byte, error) {
	if len(values) == 0 {
		return nil, nil
	}
	size := 2
	for _, value := range values {
		if value.MKeyKVNO == 0 || value.LatestKeyKVNO == 0 {
			return nil, fmt.Errorf("master-key auxiliary version is zero")
		}
		if value.LatestKeyEnctype < 0 || value.LatestKeyEnctype > math.MaxUint16 {
			return nil, fmt.Errorf("master-key auxiliary enctype is out of range")
		}
		if len(value.LatestKeyData) > math.MaxUint16 {
			return nil, fmt.Errorf("master-key auxiliary data is too long")
		}
		size += 8 + len(value.LatestKeyData)
	}
	data := make([]byte, size)
	binary.LittleEndian.PutUint16(data, 1)
	offset := 2
	for _, value := range values {
		binary.LittleEndian.PutUint16(data[offset:], value.MKeyKVNO)
		binary.LittleEndian.PutUint16(data[offset+2:], value.LatestKeyKVNO)
		binary.LittleEndian.PutUint16(data[offset+4:], uint16(value.LatestKeyEnctype))
		binary.LittleEndian.PutUint16(data[offset+6:], uint16(len(value.LatestKeyData)))
		copy(data[offset+8:], value.LatestKeyData)
		offset += 8 + len(value.LatestKeyData)
	}
	return data, nil
}

// DecodeMKEYAux decodes version-one KRB5_TL_MKEY_AUX data.
func DecodeMKEYAux(data []byte) ([]MKeyAuxEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < 10 || binary.LittleEndian.Uint16(data) != 1 {
		return nil, fmt.Errorf("invalid MKEY_AUX data")
	}
	var values []MKeyAuxEntry
	for offset := 2; offset < len(data); {
		if offset+8 > len(data) {
			return nil, fmt.Errorf("truncated MKEY_AUX entry")
		}
		length := int(binary.LittleEndian.Uint16(data[offset+6:]))
		if length > len(data)-offset-8 {
			return nil, fmt.Errorf("truncated MKEY_AUX key data")
		}
		values = append(values, MKeyAuxEntry{
			MKeyKVNO:         binary.LittleEndian.Uint16(data[offset:]),
			LatestKeyKVNO:    binary.LittleEndian.Uint16(data[offset+2:]),
			LatestKeyEnctype: int32(binary.LittleEndian.Uint16(data[offset+4:])),
			LatestKeyData:    append([]byte(nil), data[offset+8:offset+8+length]...),
		})
		offset += 8 + length
	}
	return values, nil
}
