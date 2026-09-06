// Package krad implements the RADIUS packet primitives used by OTP.
package krad

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	PacketSizeMax = 4096
	MaxAttrSize   = 253
)

type Attr uint8

const (
	UserName               Attr = 1
	UserPassword           Attr = 2
	CHAPPassword           Attr = 3
	NASIPAddress           Attr = 4
	NASPort                Attr = 5
	ServiceType            Attr = 6
	FramedProtocol         Attr = 7
	FramedIPAddress        Attr = 8
	FramedIPNetmask        Attr = 9
	FramedRouting          Attr = 10
	FilterID               Attr = 11
	FramedMTU              Attr = 12
	FramedCompression      Attr = 13
	LoginIPHost            Attr = 14
	LoginService           Attr = 15
	LoginTCPPort           Attr = 16
	ReplyMessage           Attr = 18
	CallbackNumber         Attr = 19
	CallbackID             Attr = 20
	FramedRoute            Attr = 22
	FramedIPXNetwork       Attr = 23
	State                  Attr = 24
	Class                  Attr = 25
	VendorSpecific         Attr = 26
	SessionTimeout         Attr = 27
	IdleTimeout            Attr = 28
	TerminationAction      Attr = 29
	CalledStationID        Attr = 30
	CallingStationID       Attr = 31
	NASIdentifier          Attr = 32
	ProxyState             Attr = 33
	LoginLATService        Attr = 34
	LoginLATNode           Attr = 35
	LoginLATGroup          Attr = 36
	FramedAppleTalkLink    Attr = 37
	FramedAppleTalkNetwork Attr = 38
	FramedAppleTalkZone    Attr = 39
	CHAPChallenge          Attr = 60
	NASPortType            Attr = 61
	PortLimit              Attr = 62
	LoginLATPort           Attr = 63
	PasswordRetry          Attr = 75
	Prompt                 Attr = 76
	ConnectInfo            Attr = 77
	ConfigurationToken     Attr = 78
	EAPMessage             Attr = 79
	MessageAuthenticator   Attr = 80
)

type attrInfo struct {
	name string
	min  int
	max  int
}

var attrTable = map[Attr]attrInfo{
	UserName:               {"User-Name", 1, MaxAttrSize},
	UserPassword:           {"User-Password", 1, 128},
	CHAPPassword:           {"CHAP-Password", 17, 17},
	NASIPAddress:           {"NAS-IP-Address", 4, 4},
	NASPort:                {"NAS-Port", 4, 4},
	ServiceType:            {"Service-Type", 4, 4},
	FramedProtocol:         {"Framed-Protocol", 4, 4},
	FramedIPAddress:        {"Framed-IP-Address", 4, 4},
	FramedIPNetmask:        {"Framed-IP-Netmask", 4, 4},
	FramedRouting:          {"Framed-Routing", 4, 4},
	FilterID:               {"Filter-Id", 1, MaxAttrSize},
	FramedMTU:              {"Framed-MTU", 4, 4},
	FramedCompression:      {"Framed-Compression", 4, 4},
	LoginIPHost:            {"Login-IP-Host", 4, 4},
	LoginService:           {"Login-Service", 4, 4},
	LoginTCPPort:           {"Login-TCP-Port", 4, 4},
	ReplyMessage:           {"Reply-Message", 1, MaxAttrSize},
	CallbackNumber:         {"Callback-Number", 1, MaxAttrSize},
	CallbackID:             {"Callback-Id", 1, MaxAttrSize},
	FramedRoute:            {"Framed-Route", 1, MaxAttrSize},
	FramedIPXNetwork:       {"Framed-IPX-Network", 4, 4},
	State:                  {"State", 1, MaxAttrSize},
	Class:                  {"Class", 1, MaxAttrSize},
	VendorSpecific:         {"Vendor-Specific", 5, MaxAttrSize},
	SessionTimeout:         {"Session-Timeout", 4, 4},
	IdleTimeout:            {"Idle-Timeout", 4, 4},
	TerminationAction:      {"Termination-Action", 4, 4},
	CalledStationID:        {"Called-Station-Id", 1, MaxAttrSize},
	CallingStationID:       {"Calling-Station-Id", 1, MaxAttrSize},
	NASIdentifier:          {"NAS-Identifier", 1, MaxAttrSize},
	ProxyState:             {"Proxy-State", 1, MaxAttrSize},
	LoginLATService:        {"Login-LAT-Service", 1, MaxAttrSize},
	LoginLATNode:           {"Login-LAT-Node", 1, MaxAttrSize},
	LoginLATGroup:          {"Login-LAT-Group", 32, 32},
	FramedAppleTalkLink:    {"Framed-AppleTalk-Link", 4, 4},
	FramedAppleTalkNetwork: {"Framed-AppleTalk-Network", 4, 4},
	FramedAppleTalkZone:    {"Framed-AppleTalk-Zone", 1, MaxAttrSize},
	CHAPChallenge:          {"CHAP-Challenge", 5, MaxAttrSize},
	NASPortType:            {"NAS-Port-Type", 4, 4},
	PortLimit:              {"Port-Limit", 4, 4},
	LoginLATPort:           {"Login-LAT-Port", 1, MaxAttrSize},
	MessageAuthenticator:   {"Message-Authenticator", 16, 16},
}

func AttrName2Num(name string) Attr {
	for attr, info := range attrTable {
		if info.name == name {
			return attr
		}
	}
	return 0
}

func AttrNum2Name(attr Attr) string { return attrTable[attr].name }

func validAttr(attr Attr, value []byte) bool {
	info, ok := attrTable[attr]
	return ok && len(value) >= info.min && len(value) <= info.max
}

type attribute struct {
	attr  Attr
	value []byte
}

// Attributes is an ordered multiset of RADIUS attributes.
type Attributes struct {
	values []attribute
}

func NewAttributes() *Attributes { return &Attributes{} }

func (a *Attributes) Add(attr Attr, value []byte) error {
	if !validAttr(attr, value) {
		return fmt.Errorf("invalid RADIUS attribute %d length %d", attr, len(value))
	}
	a.values = append(a.values, attribute{attr: attr, value: append([]byte(nil), value...)})
	return nil
}

func (a *Attributes) AddString(attr Attr, value string) error {
	return a.Add(attr, []byte(value))
}

func (a *Attributes) AddNumber(attr Attr, value uint32) error {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return a.Add(attr, encoded[:])
}

func (a *Attributes) Get(attr Attr, index int) []byte {
	if a == nil || index < 0 {
		return nil
	}
	for _, value := range a.values {
		if value.attr != attr {
			continue
		}
		if index == 0 {
			return append([]byte(nil), value.value...)
		}
		index--
	}
	return nil
}

func (a *Attributes) Del(attr Attr, index int) bool {
	if a == nil || index < 0 {
		return false
	}
	for i, value := range a.values {
		if value.attr != attr {
			continue
		}
		if index == 0 {
			a.values = append(a.values[:i], a.values[i+1:]...)
			return true
		}
		index--
	}
	return false
}

func (a *Attributes) Copy() *Attributes {
	if a == nil {
		return &Attributes{}
	}
	result := &Attributes{values: make([]attribute, 0, len(a.values))}
	for _, value := range a.values {
		result.values = append(result.values, attribute{value.attr, append([]byte(nil), value.value...)})
	}
	return result
}

func (a *Attributes) Len() int {
	if a == nil {
		return 0
	}
	return len(a.values)
}

func (a *Attributes) Values() []struct {
	Attr  Attr
	Value []byte
} {
	result := make([]struct {
		Attr  Attr
		Value []byte
	}, 0, a.Len())
	if a == nil {
		return result
	}
	for _, value := range a.values {
		result = append(result, struct {
			Attr  Attr
			Value []byte
		}{value.attr, append([]byte(nil), value.value...)})
	}
	return result
}

func encodeUserPassword(secret string, auth [16]byte, value []byte) []byte {
	length := (len(value) + 15) / 16 * 16
	if length == 0 {
		length = 16
	}
	out := make([]byte, length)
	copy(out, value)
	prev := auth[:]
	for offset := 0; offset < length; offset += 16 {
		input := append([]byte(secret), prev...)
		hash := md5.Sum(input)
		for i := 0; i < 16; i++ {
			out[offset+i] ^= hash[i]
		}
		prev = out[offset : offset+16]
	}
	return out
}

func decodeUserPassword(secret string, auth [16]byte, value []byte) ([]byte, error) {
	if len(value) == 0 || len(value)%16 != 0 || len(value) > 128 {
		return nil, errors.New("invalid User-Password length")
	}
	out := make([]byte, len(value))
	prev := auth[:]
	for offset := 0; offset < len(value); offset += 16 {
		input := append([]byte(secret), prev...)
		hash := md5.Sum(input)
		for i := 0; i < 16; i++ {
			out[offset+i] = value[offset+i] ^ hash[i]
		}
		prev = value[offset : offset+16]
	}
	return []byte(strings.TrimRight(string(out), "\x00")), nil
}

func equalBytes(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
