package pac

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

const UPNDNSInfoHasSAMNameAndSID uint32 = 0x2
const UPNDNSInfoNoUPNSet uint32 = 0x1

// UPNDNSInfoData is the MS-PAC UPN_DNS_INFO buffer (type 12).
type UPNDNSInfoData struct {
	UPN           string
	DNSDomainName string
	Flags         uint32
	SAMName       string
	SID           *SID
}

func encodeUTF16(value string) ([]byte, error) {
	units := utf16.Encode([]rune(value))
	if len(units) > 0x7fff {
		return nil, fmt.Errorf("PAC: UTF-16 string is too long")
	}
	out := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(out[i*2:], unit)
	}
	return out, nil
}

func decodeUTF16(data []byte) (string, error) {
	if len(data)%2 != 0 {
		return "", fmt.Errorf("PAC: odd UTF-16 string length")
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(units)), nil
}

func align4(value int) int { return (value + 3) &^ 3 }

// MarshalBinary encodes UPN_DNS_INFO with aligned, self-relative offsets.
func (u UPNDNSInfoData) MarshalBinary() ([]byte, error) {
	upn, err := encodeUTF16(u.UPN)
	if err != nil {
		return nil, err
	}
	dns, err := encodeUTF16(u.DNSDomainName)
	if err != nil {
		return nil, err
	}
	extended := u.Flags&UPNDNSInfoHasSAMNameAndSID != 0
	var sam, sid []byte
	if extended {
		sam, err = encodeUTF16(u.SAMName)
		if err != nil {
			return nil, err
		}
		if u.SID != nil {
			sid, err = u.SID.MarshalBinary()
			if err != nil {
				return nil, err
			}
		}
	}
	headerLen := 12
	if extended {
		headerLen = 20
	}
	offset := align4(headerLen)
	place := func(value []byte) (int, error) {
		at := offset
		offset = align4(offset + len(value))
		if at > 0xffff || len(value) > 0xffff {
			return 0, fmt.Errorf("PAC: UPN_DNS_INFO field exceeds uint16")
		}
		return at, nil
	}
	upnOffset, err := place(upn)
	if err != nil {
		return nil, err
	}
	dnsOffset, err := place(dns)
	if err != nil {
		return nil, err
	}
	samOffset, sidOffset := 0, 0
	if extended {
		samOffset, err = place(sam)
		if err != nil {
			return nil, err
		}
		sidOffset, err = place(sid)
		if err != nil {
			return nil, err
		}
	}
	out := make([]byte, offset)
	binary.LittleEndian.PutUint16(out, uint16(len(upn)))
	binary.LittleEndian.PutUint16(out[2:], uint16(upnOffset))
	binary.LittleEndian.PutUint16(out[4:], uint16(len(dns)))
	binary.LittleEndian.PutUint16(out[6:], uint16(dnsOffset))
	binary.LittleEndian.PutUint32(out[8:], u.Flags)
	if extended {
		binary.LittleEndian.PutUint16(out[12:], uint16(len(sam)))
		binary.LittleEndian.PutUint16(out[14:], uint16(samOffset))
		binary.LittleEndian.PutUint16(out[16:], uint16(len(sid)))
		binary.LittleEndian.PutUint16(out[18:], uint16(sidOffset))
	}
	copy(out[upnOffset:], upn)
	copy(out[dnsOffset:], dns)
	if extended {
		copy(out[samOffset:], sam)
		copy(out[sidOffset:], sid)
	}
	return out, nil
}

// ParseUPNDNSInfo decodes a UPN_DNS_INFO buffer.
func ParseUPNDNSInfo(data []byte) (UPNDNSInfoData, error) {
	if len(data) < 12 {
		return UPNDNSInfoData{}, fmt.Errorf("PAC: truncated UPN_DNS_INFO")
	}
	u := UPNDNSInfoData{Flags: binary.LittleEndian.Uint32(data[8:])}
	upnLen, upnOff := int(binary.LittleEndian.Uint16(data)), int(binary.LittleEndian.Uint16(data[2:]))
	dnsLen, dnsOff := int(binary.LittleEndian.Uint16(data[4:])), int(binary.LittleEndian.Uint16(data[6:]))
	read := func(offset, length int) ([]byte, error) {
		if offset%4 != 0 || offset < 12 || offset > len(data)-length {
			return nil, fmt.Errorf("PAC: invalid UPN_DNS_INFO offset")
		}
		return data[offset : offset+length], nil
	}
	upn, err := read(upnOff, upnLen)
	if err != nil {
		return UPNDNSInfoData{}, err
	}
	dns, err := read(dnsOff, dnsLen)
	if err != nil {
		return UPNDNSInfoData{}, err
	}
	u.UPN, err = decodeUTF16(upn)
	if err != nil {
		return UPNDNSInfoData{}, err
	}
	u.DNSDomainName, err = decodeUTF16(dns)
	if err != nil {
		return UPNDNSInfoData{}, err
	}
	if u.Flags&UPNDNSInfoHasSAMNameAndSID != 0 {
		if len(data) < 20 {
			return UPNDNSInfoData{}, fmt.Errorf("PAC: truncated extended UPN_DNS_INFO")
		}
		samLen, samOff := int(binary.LittleEndian.Uint16(data[12:])), int(binary.LittleEndian.Uint16(data[14:]))
		sidLen, sidOff := int(binary.LittleEndian.Uint16(data[16:])), int(binary.LittleEndian.Uint16(data[18:]))
		sam, err := read(samOff, samLen)
		if err != nil {
			return UPNDNSInfoData{}, err
		}
		sid, err := read(sidOff, sidLen)
		if err != nil {
			return UPNDNSInfoData{}, err
		}
		u.SAMName, err = decodeUTF16(sam)
		if err != nil {
			return UPNDNSInfoData{}, err
		}
		parsedSID, used, err := ParseSIDBinary(sid)
		if err != nil || used != len(sid) {
			return UPNDNSInfoData{}, fmt.Errorf("PAC: invalid UPN_DNS_INFO SID")
		}
		u.SID = &parsedSID
	}
	return u, nil
}
