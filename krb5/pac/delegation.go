package pac

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// DelegationInfo is the MS-PAC S4U_DELEGATION_INFO buffer (type 11).
type DelegationInfo struct {
	ProxyTarget       string
	TransitedServices []string
}

func delegationPointer(pointer *uint32, out *bytes.Buffer) {
	if *pointer == 0 {
		*pointer = ndrPointerValue
	}
	_ = binary.Write(out, binary.LittleEndian, *pointer)
	*pointer += 4
}

func marshalDelegationWChars(value string) ([]byte, int, error) {
	data, err := encodeUTF16(value)
	if err != nil {
		return nil, 0, err
	}
	if len(data)/2 > int(^uint16(0))-1 {
		return nil, 0, fmt.Errorf("PAC: delegation string is too long")
	}
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(data)/2+1))
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(data)/2))
	_, _ = out.Write(data)
	if (len(data)/2)%2 != 0 {
		_ = binary.Write(&out, binary.LittleEndian, uint16(0))
	}
	return out.Bytes(), len(data) / 2, nil
}

// MarshalBinary encodes the MIT/Windows NDR32 S4U_DELEGATION_INFO layout.
func (d DelegationInfo) MarshalBinary() ([]byte, error) {
	proxy, proxyChars, err := marshalDelegationWChars(d.ProxyTarget)
	if err != nil {
		return nil, err
	}
	services := make([][]byte, len(d.TransitedServices))
	serviceChars := make([]int, len(d.TransitedServices))
	for i, service := range d.TransitedServices {
		services[i], serviceChars[i], err = marshalDelegationWChars(service)
		if err != nil {
			return nil, err
		}
	}
	if len(d.TransitedServices) > int(^uint32(0)) {
		return nil, fmt.Errorf("PAC: too many transited services")
	}

	var out bytes.Buffer
	_, _ = out.Write([]byte{1, 0x10, 8, 0})
	_ = binary.Write(&out, binary.LittleEndian, uint32(0xcccccccc))
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))
	var pointer uint32
	delegationPointer(&pointer, &out)
	_ = binary.Write(&out, binary.LittleEndian, uint16(2*proxyChars))
	_ = binary.Write(&out, binary.LittleEndian, uint16(2*(proxyChars+1)))
	delegationPointer(&pointer, &out)
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(d.TransitedServices)))
	delegationPointer(&pointer, &out)
	_, _ = out.Write(proxy)
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(d.TransitedServices)))
	for i := range services {
		_ = binary.Write(&out, binary.LittleEndian, uint16(2*serviceChars[i]))
		_ = binary.Write(&out, binary.LittleEndian, uint16(2*(serviceChars[i]+1)))
		delegationPointer(&pointer, &out)
	}
	for _, service := range services {
		_, _ = out.Write(service)
	}
	if out.Len()%8 != 0 {
		_ = binary.Write(&out, binary.LittleEndian, uint32(0))
	}
	result := append([]byte(nil), out.Bytes()...)
	binary.LittleEndian.PutUint32(result[8:], uint32(len(result)-16))
	return result, nil
}

// Marshal is an alias for MarshalBinary.
func (d DelegationInfo) Marshal() ([]byte, error) { return d.MarshalBinary() }

type delegationReader struct {
	data []byte
	off  int
}

func (r *delegationReader) bytes(n int) ([]byte, error) {
	if n < 0 || n > len(r.data)-r.off {
		return nil, fmt.Errorf("PAC: truncated delegation-info data")
	}
	v := r.data[r.off : r.off+n]
	r.off += n
	return v, nil
}

func (r *delegationReader) u16() (uint16, error) {
	v, err := r.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(v), nil
}

func (r *delegationReader) u32() (uint32, error) {
	v, err := r.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(v), nil
}

func (r *delegationReader) wcharPointer() (string, error) {
	maximum, err := r.u32()
	if err != nil {
		return "", err
	}
	_, err = r.u32() // NDR offset is intentionally not interpreted.
	if err != nil {
		return "", err
	}
	actual, err := r.u32()
	if err != nil {
		return "", err
	}
	if actual > maximum || actual > uint32((len(r.data)-r.off)/2) {
		return "", fmt.Errorf("PAC: invalid delegation-info string length")
	}
	raw, err := r.bytes(int(actual) * 2)
	if err != nil {
		return "", err
	}
	value, err := decodeUTF16(raw)
	if err != nil {
		return "", err
	}
	if actual%2 != 0 {
		if _, err := r.u16(); err != nil {
			return "", err
		}
	}
	return value, nil
}

// ParseDelegationInfo decodes an NDR32 S4U_DELEGATION_INFO buffer.
func ParseDelegationInfo(data []byte) (DelegationInfo, error) {
	if len(data) < 16 || len(data)%8 != 0 {
		return DelegationInfo{}, fmt.Errorf("PAC: invalid delegation-info length")
	}
	if data[0] != 1 || data[1] != 0x10 ||
		binary.LittleEndian.Uint16(data[2:]) != 8 {
		return DelegationInfo{}, fmt.Errorf("PAC: invalid delegation-info header")
	}
	if binary.LittleEndian.Uint32(data[8:]) != uint32(len(data)-16) {
		return DelegationInfo{}, fmt.Errorf("PAC: invalid delegation-info object length")
	}
	r := delegationReader{data: data, off: 16}
	if _, err := r.u32(); err != nil { // top-level proxy pointer
		return DelegationInfo{}, err
	}
	if _, err := r.u16(); err != nil { // proxy Length
		return DelegationInfo{}, err
	}
	if _, err := r.u16(); err != nil { // proxy MaximumLength
		return DelegationInfo{}, err
	}
	if _, err := r.u32(); err != nil { // proxy deferred pointer
		return DelegationInfo{}, err
	}
	nservices, err := r.u32()
	if err != nil {
		return DelegationInfo{}, err
	}
	if nservices > uint32((len(data)-r.off)/8) {
		return DelegationInfo{}, fmt.Errorf("PAC: delegation-info service count is too large")
	}
	if _, err := r.u32(); err != nil { // transited array pointer
		return DelegationInfo{}, err
	}
	proxy, err := r.wcharPointer()
	if err != nil {
		return DelegationInfo{}, err
	}
	encodedCount, err := r.u32()
	if err != nil || encodedCount != nservices {
		return DelegationInfo{}, fmt.Errorf("PAC: delegation-info service count mismatch")
	}
	type serviceHeader struct {
		length, maximum uint16
	}
	headers := make([]serviceHeader, nservices)
	for i := range headers {
		headers[i].length, err = r.u16()
		if err != nil {
			return DelegationInfo{}, err
		}
		headers[i].maximum, err = r.u16()
		if err != nil {
			return DelegationInfo{}, err
		}
		if _, err := r.u32(); err != nil {
			return DelegationInfo{}, err
		}
		if headers[i].length > headers[i].maximum ||
			headers[i].length%2 != 0 || headers[i].maximum < headers[i].length {
			return DelegationInfo{}, fmt.Errorf("PAC: invalid delegation-info service header")
		}
	}
	result := DelegationInfo{ProxyTarget: proxy, TransitedServices: make([]string, nservices)}
	for i := range result.TransitedServices {
		result.TransitedServices[i], err = r.wcharPointer()
		if err != nil {
			return DelegationInfo{}, err
		}
		if uint32(len([]rune(result.TransitedServices[i]))) > uint32(headers[i].maximum/2) {
			return DelegationInfo{}, fmt.Errorf("PAC: delegation-info service exceeds maximum")
		}
	}
	if r.off != len(data) {
		padding := data[r.off:]
		if len(padding) != 4 || !bytes.Equal(padding, []byte{0, 0, 0, 0}) {
			return DelegationInfo{}, fmt.Errorf("PAC: trailing delegation-info data")
		}
	}
	return result, nil
}

// Unmarshal decodes an NDR32 S4U_DELEGATION_INFO buffer.
func (d *DelegationInfo) Unmarshal(data []byte) error {
	if d == nil {
		return fmt.Errorf("PAC: nil DelegationInfo")
	}
	value, err := ParseDelegationInfo(data)
	if err != nil {
		return err
	}
	*d = value
	return nil
}
