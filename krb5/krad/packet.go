package krad

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

type Code uint8

const (
	AccessRequest      Code = 1
	AccessAccept       Code = 2
	AccessReject       Code = 3
	AccountingRequest  Code = 4
	AccountingResponse Code = 5
	AccessChallenge    Code = 11
)

var codeNames = map[Code]string{
	1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
	4: "Accounting-Request", 5: "Accounting-Response", 6: "Accounting-Status",
	7: "Password-Request", 8: "Password-Ack", 9: "Password-Reject",
	10: "Accounting-Message", 11: "Access-Challenge", 12: "Status-Server",
	13: "Status-Client", 21: "Resource-Free-Request",
	22: "Resource-Free-Response", 23: "Resource-Query-Request",
	24: "Resource-Query-Response", 25: "Alternate-Resource-Reclaim-Request",
	26: "NAS-Reboot-Request", 27: "NAS-Reboot-Response", 29: "Next-Passcode",
	30: "New-Pin", 31: "Terminate-Session", 32: "Password-Expired",
	33: "Event-Request", 34: "Event-Response", 40: "Disconnect-Request",
	41: "Disconnect-Ack", 42: "Disconnect-Nak", 43: "Change-Filters-Request",
	44: "Change-Filters-Ack", 45: "Change-Filters-Nak",
	50: "IP-Address-Allocate", 51: "IP-Address-Release",
}

func CodeName2Num(name string) Code {
	for code, value := range codeNames {
		if value == name {
			return code
		}
	}
	return 0
}

func CodeNum2Name(code Code) string { return codeNames[code] }

type Packet struct {
	Code          Code
	ID            uint8
	Authenticator [16]byte
	Attributes    *Attributes

	request bool
}

func NewRequest(code Code, attrs *Attributes, secret ...string) (*Packet, error) {
	if code == 0 {
		return nil, errors.New("invalid RADIUS code")
	}
	var packet Packet
	packet.Code = code
	packet.Attributes = attrs.Copy()
	if _, err := rand.Read(packet.Authenticator[:]); err != nil {
		return nil, err
	}
	now := uint32(time.Now().Unix())
	binary.LittleEndian.PutUint32(packet.Authenticator[:4], now)
	if _, err := rand.Read(packet.Authenticator[4:]); err != nil {
		return nil, err
	}
	var id [1]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	packet.ID = id[0]
	packet.request = true
	if len(secret) > 0 && secret[0] != "" && code == AccessRequest {
		// The authenticator is finalized by Bytes, after the ID has been
		// selected. This branch exists to make request intent explicit.
	}
	return &packet, nil
}

func NewResponse(code Code, request *Packet, attrs *Attributes, secret ...string) (*Packet, error) {
	if request == nil {
		return nil, errors.New("nil RADIUS request")
	}
	packet := &Packet{Code: code, ID: request.ID, Attributes: attrs.Copy()}
	copy(packet.Authenticator[:], request.Authenticator[:])
	return packet, nil
}

func (p *Packet) Bytes(secret ...string) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil RADIUS packet")
	}
	value := ""
	if len(secret) > 0 {
		value = secret[0]
	}
	return p.encode(value, nil)
}

func (p *Packet) Marshal(secret ...string) ([]byte, error) { return p.Bytes(secret...) }

func (p *Packet) encode(secret string, requestAuth *[16]byte) ([]byte, error) {
	attrs, err := p.encodeAttributes(secret, requestAuth)
	if err != nil {
		return nil, err
	}
	length := 20 + len(attrs)
	if length > PacketSizeMax || length > 0xffff {
		return nil, errors.New("RADIUS packet too large")
	}
	packet := make([]byte, length)
	packet[0] = byte(p.Code)
	packet[1] = p.ID
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	copy(packet[4:20], p.Authenticator[:])
	copy(packet[20:], attrs)
	if p.Code != AccessRequest {
		auth := p.Authenticator
		if requestAuth != nil {
			auth = *requestAuth
		}
		responseAuth := responseAuthenticator(packet, secret, auth)
		copy(packet[4:20], responseAuth[:])
		if hasMessageAuthenticator(packet) {
			mac := messageAuthenticator(packet, secret, auth)
			if position := messageAuthenticatorPosition(packet); position >= 0 {
				copy(packet[position+2:position+18], mac[:])
			}
		}
	} else if hasMessageAuthenticator(packet) {
		mac := messageAuthenticator(packet, secret, p.Authenticator)
		if position := messageAuthenticatorPosition(packet); position >= 0 {
			copy(packet[position+2:position+18], mac[:])
		}
	}
	return packet, nil
}

func (p *Packet) encodeAttributes(secret string, requestAuth *[16]byte) ([]byte, error) {
	attrs := p.Attributes
	if attrs == nil {
		attrs = &Attributes{}
	}
	requireMAC := secret != "" && (p.Code == AccessRequest ||
		p.Code == AccessAccept || p.Code == AccessReject || p.Code == AccessChallenge)
	hasMAC := false
	for _, value := range attrs.values {
		if value.attr == MessageAuthenticator {
			hasMAC = true
		}
	}
	out := make([]byte, 0, PacketSizeMax-20)
	if requireMAC && !hasMAC {
		out = append(out, byte(MessageAuthenticator), 18)
		out = append(out, make([]byte, 16)...)
	}
	auth := p.Authenticator
	if requestAuth != nil {
		auth = *requestAuth
	}
	for _, value := range attrs.values {
		encoded := append([]byte(nil), value.value...)
		if value.attr == UserPassword {
			encoded = encodeUserPassword(secret, auth, encoded)
		}
		if !validAttr(value.attr, encoded) {
			return nil, fmt.Errorf("invalid RADIUS attribute %d length %d", value.attr, len(encoded))
		}
		if len(encoded)+2 > 255 {
			return nil, errors.New("RADIUS attribute too large")
		}
		out = append(out, byte(value.attr), byte(len(encoded)+2))
		out = append(out, encoded...)
	}
	return out, nil
}

func DecodeRequest(data []byte, secret ...string) (*Packet, error) {
	value := ""
	if len(secret) > 0 {
		value = secret[0]
	}
	packet, err := decode(data, value)
	if err != nil {
		return nil, err
	}
	packet.request = true
	if value != "" && packet.Code == AccessRequest && !hasMessageAuthenticator(data) {
		return nil, errors.New("missing RADIUS Message-Authenticator")
	}
	if hasMessageAuthenticator(data) {
		if !verifyMessageAuthenticator(data, value, packet.Authenticator) {
			return nil, errors.New("invalid RADIUS Message-Authenticator")
		}
	}
	return packet, nil
}

func DecodeResponse(data []byte, request *Packet, secret ...string) (*Packet, error) {
	if request == nil {
		return nil, errors.New("nil RADIUS request")
	}
	value := ""
	if len(secret) > 0 {
		value = secret[0]
	}
	packet, err := decode(data, value)
	if err != nil {
		return nil, err
	}
	expected := responseAuthenticator(data, value, request.Authenticator)
	if !equalBytes(packet.Authenticator[:], expected[:]) {
		zeroed := append([]byte(nil), data...)
		if position := messageAuthenticatorPosition(zeroed); position >= 0 {
			for i := 0; i < 16; i++ {
				zeroed[position+2+i] = 0
			}
			expected = responseAuthenticator(zeroed, value, request.Authenticator)
		}
	}
	if !equalBytes(packet.Authenticator[:], expected[:]) {
		return nil, errors.New("invalid RADIUS response authenticator")
	}
	if hasMessageAuthenticator(data) &&
		!verifyMessageAuthenticator(data, value, request.Authenticator) {
		return nil, errors.New("invalid RADIUS Message-Authenticator")
	}
	if packet.ID != request.ID {
		return nil, errors.New("RADIUS response identifier mismatch")
	}
	if value != "" && (packet.Code == AccessRequest || packet.Code == AccessAccept ||
		packet.Code == AccessReject || packet.Code == AccessChallenge) &&
		!hasMessageAuthenticator(data) {
		return nil, errors.New("missing RADIUS Message-Authenticator")
	}
	return packet, nil
}

func decode(data []byte, secret string) (*Packet, error) {
	if len(data) < 20 || len(data) > PacketSizeMax {
		return nil, errors.New("invalid RADIUS packet length")
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 20 || length > len(data) || length > PacketSizeMax {
		return nil, errors.New("invalid RADIUS packet length field")
	}
	data = data[:length]
	packet := &Packet{Code: Code(data[0]), ID: data[1], Attributes: &Attributes{}}
	copy(packet.Authenticator[:], data[4:20])
	for offset := 20; offset < len(data); {
		if offset+2 > len(data) {
			return nil, errors.New("truncated RADIUS attribute")
		}
		attr := Attr(data[offset])
		size := int(data[offset+1])
		if size < 2 || offset+size > len(data) {
			return nil, errors.New("invalid RADIUS attribute length")
		}
		raw := data[offset+2 : offset+size]
		if !validAttr(attr, raw) {
			return nil, fmt.Errorf("invalid RADIUS attribute %d length %d", attr, len(raw))
		}
		value := append([]byte(nil), raw...)
		if attr == UserPassword {
			decoded, err := decodeUserPassword(secret, packet.Authenticator, value)
			if err != nil {
				return nil, err
			}
			value = decoded
		}
		packet.Attributes.values = append(packet.Attributes.values, attribute{attr, value})
		offset += size
	}
	return packet, nil
}

func BytesNeeded(data []byte) int {
	if len(data) < 20 {
		return 20 - len(data)
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length > PacketSizeMax {
		return -1
	}
	if len(data) > length {
		return 0
	}
	return length - len(data)
}

func responseAuthenticator(packet []byte, secret string, requestAuth [16]byte) [16]byte {
	value := append([]byte(nil), packet...)
	copy(value[4:20], requestAuth[:])
	value = append(value, []byte(secret)...)
	return md5.Sum(value)
}

func messageAuthenticator(packet []byte, secret string, auth [16]byte) [16]byte {
	value := append([]byte(nil), packet...)
	copy(value[4:20], auth[:])
	position := messageAuthenticatorPosition(value)
	if position >= 0 {
		for i := 0; i < 16; i++ {
			value[position+2+i] = 0
		}
	}
	mac := hmac.New(md5.New, []byte(secret))
	_, _ = mac.Write(value)
	var result [16]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func verifyMessageAuthenticator(packet []byte, secret string, auth [16]byte) bool {
	position := messageAuthenticatorPosition(packet)
	if position < 0 || position+18 > len(packet) {
		return false
	}
	expected := messageAuthenticator(packet, secret, auth)
	return equalBytes(packet[position+2:position+18], expected[:])
}

func hasMessageAuthenticator(packet []byte) bool {
	return messageAuthenticatorPosition(packet) >= 0
}

func messageAuthenticatorPosition(packet []byte) int {
	for offset := 20; offset+2 <= len(packet); {
		size := int(packet[offset+1])
		if size < 2 || offset+size > len(packet) {
			return -1
		}
		if Attr(packet[offset]) == MessageAuthenticator && size == 18 {
			return offset
		}
		offset += size
	}
	return -1
}

func ReadPacket(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < 20 || length > PacketSizeMax {
		return nil, errors.New("invalid RADIUS packet length")
	}
	packet := make([]byte, length)
	copy(packet, header)
	if _, err := io.ReadFull(r, packet[4:]); err != nil {
		return nil, err
	}
	return packet, nil
}
