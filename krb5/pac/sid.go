package pac

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// SID is an MS-DTYP security identifier.
type SID struct {
	Revision            byte
	IdentifierAuthority uint64
	SubAuthorities      []uint32
}

func (s SID) String() string {
	parts := []string{"S", strconv.Itoa(int(s.Revision)), strconv.FormatUint(s.IdentifierAuthority, 10)}
	for _, sub := range s.SubAuthorities {
		parts = append(parts, strconv.FormatUint(uint64(sub), 10))
	}
	return strings.Join(parts, "-")
}

// ParseSID parses the canonical S-1-... SID notation.
func ParseSID(value string) (SID, error) {
	parts := strings.Split(value, "-")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "S") {
		return SID{}, fmt.Errorf("PAC: invalid SID %q", value)
	}
	revision, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return SID{}, fmt.Errorf("PAC: invalid SID revision: %w", err)
	}
	authority, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return SID{}, fmt.Errorf("PAC: invalid SID authority: %w", err)
	}
	s := SID{Revision: byte(revision), IdentifierAuthority: authority}
	if len(parts)-3 > 15 {
		return SID{}, fmt.Errorf("PAC: too many SID subauthorities")
	}
	for _, part := range parts[3:] {
		sub, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return SID{}, fmt.Errorf("PAC: invalid SID subauthority: %w", err)
		}
		s.SubAuthorities = append(s.SubAuthorities, uint32(sub))
	}
	return s, nil
}

// MarshalBinary encodes a SID as an MS-DTYP RPC_SID body.
func (s SID) MarshalBinary() ([]byte, error) {
	if len(s.SubAuthorities) > 15 {
		return nil, fmt.Errorf("PAC: too many SID subauthorities")
	}
	if s.IdentifierAuthority >= 1<<48 {
		return nil, fmt.Errorf("PAC: SID authority exceeds 48 bits")
	}
	out := make([]byte, 8+4*len(s.SubAuthorities))
	out[0] = s.Revision
	out[1] = byte(len(s.SubAuthorities))
	for i := 0; i < 6; i++ {
		out[2+i] = byte(s.IdentifierAuthority >> (40 - 8*i))
	}
	for i, sub := range s.SubAuthorities {
		binary.LittleEndian.PutUint32(out[8+i*4:], sub)
	}
	return out, nil
}

// ParseSIDBinary decodes an MS-DTYP RPC_SID body.
func ParseSIDBinary(data []byte) (SID, int, error) {
	if len(data) < 8 {
		return SID{}, 0, fmt.Errorf("PAC: truncated SID")
	}
	count := int(data[1])
	n := 8 + 4*count
	if n > len(data) {
		return SID{}, 0, fmt.Errorf("PAC: truncated SID subauthorities")
	}
	var authority uint64
	for i := 0; i < 6; i++ {
		authority = authority<<8 | uint64(data[2+i])
	}
	s := SID{Revision: data[0], IdentifierAuthority: authority, SubAuthorities: make([]uint32, count)}
	for i := range s.SubAuthorities {
		s.SubAuthorities[i] = binary.LittleEndian.Uint32(data[8+i*4:])
	}
	return s, n, nil
}
