package gssapi

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const (
	kerbAuthDataAPOptions = 143
	kerbAPOptionsCBT      = 0x4000
)

// ChannelBindings contains the RFC 2744 channel-binding fields.
//
// Address types use the GSS address-type values, and all byte slices are
// copied only while computing the binding checksum.
type ChannelBindings struct {
	InitiatorAddrType uint32
	InitiatorAddress  []byte
	AcceptorAddrType  uint32
	AcceptorAddress   []byte
	ApplicationData   []byte
}

// GSSChannelBoundFlag indicates that the established context matched
// channel bindings. It is not carried in the RFC 4121 authenticator flags.
const GSSChannelBoundFlag uint32 = 1 << 11

// GSS_C_CHANNEL_BOUND_FLAG is the RFC 2744 name for GSSChannelBoundFlag.
const GSS_C_CHANNEL_BOUND_FLAG = GSSChannelBoundFlag

// ChecksumChannelBindings returns the RFC 1964 channel-binding MD5 value.
// A nil binding represents GSS_C_NO_CHANNEL_BINDINGS and produces 16 zero
// bytes, as required by the Kerberos GSS checksum format.
func ChecksumChannelBindings(bindings *ChannelBindings) [16]byte {
	if bindings == nil {
		return [16]byte{}
	}
	var encoded []byte
	appendField := func(value uint32) {
		var field [4]byte
		binary.LittleEndian.PutUint32(field[:], value)
		encoded = append(encoded, field[:]...)
	}
	appendBytes := func(value []byte) {
		appendField(uint32(len(value)))
		encoded = append(encoded, value...)
	}
	appendField(bindings.InitiatorAddrType)
	appendBytes(bindings.InitiatorAddress)
	appendField(bindings.AcceptorAddrType)
	appendBytes(bindings.AcceptorAddress)
	appendBytes(bindings.ApplicationData)
	return md5.Sum(encoded)
}

func channelBindingsEqual(checksum []byte, bindings *ChannelBindings) bool {
	if len(checksum) != 16 {
		return false
	}
	expected := ChecksumChannelBindings(bindings)
	for index := range expected {
		if checksum[index] != expected[index] {
			return false
		}
	}
	return true
}

func channelBindingsPresent(checksum []byte) bool {
	for _, value := range checksum {
		if value != 0 {
			return true
		}
	}
	return false
}

func cloneChannelBindings(bindings *ChannelBindings) *ChannelBindings {
	if bindings == nil {
		return nil
	}
	return &ChannelBindings{
		InitiatorAddrType: bindings.InitiatorAddrType,
		InitiatorAddress:  append([]byte(nil), bindings.InitiatorAddress...),
		AcceptorAddrType:  bindings.AcceptorAddrType,
		AcceptorAddress:   append([]byte(nil), bindings.AcceptorAddress...),
		ApplicationData:   append([]byte(nil), bindings.ApplicationData...),
	}
}

func channelBoundFlag(bindings *ChannelBindings) uint32 {
	if bindings == nil {
		return 0
	}
	return GSSChannelBoundFlag
}

func verifyChannelBindings(checksum *protocol.Checksum, expected *ChannelBindings) error {
	if checksum == nil || checksum.ChecksumType != 0x8003 {
		return nil
	}
	if len(checksum.Checksum) < 24 {
		return fmt.Errorf("GSS channel bindings: %w", ErrBadBindings)
	}
	if binary.LittleEndian.Uint32(checksum.Checksum[:4]) != 16 {
		return fmt.Errorf("GSS channel bindings: invalid checksum channel-binding length")
	}
	if expected == nil {
		return nil
	}
	token := checksum.Checksum[4:20]
	if channelBindingsPresent(token) && !channelBindingsEqual(token, expected) {
		return fmt.Errorf("GSS channel bindings: %w", ErrBadBindings)
	}
	return nil
}

func channelBoundFlagForChecksum(checksum *protocol.Checksum, expected *ChannelBindings) uint32 {
	if checksum == nil || expected == nil || checksum.ChecksumType != 0x8003 ||
		len(checksum.Checksum) < 24 ||
		binary.LittleEndian.Uint32(checksum.Checksum[:4]) != 16 {
		return 0
	}
	token := checksum.Checksum[4:20]
	if channelBindingsPresent(token) && channelBindingsEqual(token, expected) {
		return GSSChannelBoundFlag
	}
	return 0
}

func channelBindingAuthData() protocol.AuthorizationData {
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, kerbAPOptionsCBT)
	inner, err := asn1.Marshal(protocol.AuthorizationData{{
		ADType: kerbAuthDataAPOptions,
		ADData: flags,
	}})
	if err != nil {
		return nil
	}
	return protocol.AuthorizationData{{
		ADType: protocol.ADIfRelevant,
		ADData: inner,
	}}
}

func channelBindingAsserted(data protocol.AuthorizationData) (bool, error) {
	for _, outer := range data {
		if outer.ADType != protocol.ADIfRelevant {
			continue
		}
		var inner protocol.AuthorizationData
		if err := asn1.Unmarshal(outer.ADData, &inner); err != nil {
			return false, fmt.Errorf("GSS channel bindings: invalid AP options authdata: %w", err)
		}
		for _, entry := range inner {
			if entry.ADType != kerbAuthDataAPOptions {
				continue
			}
			if len(entry.ADData) != 4 {
				return false, fmt.Errorf("GSS channel bindings: invalid AP options authdata")
			}
			return binary.LittleEndian.Uint32(entry.ADData)&kerbAPOptionsCBT != 0, nil
		}
	}
	return false, nil
}
