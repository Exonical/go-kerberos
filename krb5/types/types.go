package types

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Clock supplies the current time to protocol code.
type Clock interface {
	Now() time.Time
}

// UTF8String is an ASN.1 UTF8String value. KerberosString fields use Go's
// built-in string type and are encoded as GeneralString instead.
type UTF8String string

// ObjectIdentifier stores the DER value octets of an ASN.1 OBJECT IDENTIFIER.
// It is used by protocol structures whose algorithm identifiers must preserve
// the original OID while using the Kerberos ASN.1 codec.
type ObjectIdentifier []byte

// RawDER stores one complete DER value, including its tag and length.
type RawDER []byte

// OTPFlags is the 32-bit flags value used by RFC 6560 OTP structures.
type OTPFlags uint32

// RandomSource is the injectable source used for security-sensitive
// randomness. Production code should use crypto/rand.Reader.
type RandomSource io.Reader

// KerberosTime carries a protocol timestamp and its separate microseconds
// field. GeneralizedTime itself has no fractional seconds (RFC 4120,
// section 5.2.3).
type KerberosTime struct {
	Time         time.Time
	Microseconds int32
	Present      bool
}

// ParseKerberosTime parses RFC 4120 GeneralizedTime.
func ParseKerberosTime(value string) (KerberosTime, error) {
	if value == "" {
		return KerberosTime{}, nil
	}
	if len(value) != len("20060102150405Z") || value[len(value)-1] != 'Z' {
		return KerberosTime{}, fmt.Errorf("parse GeneralizedTime: want YYYYMMDDHHMMSSZ")
	}
	for i := 0; i < len(value)-1; i++ {
		if value[i] < '0' || value[i] > '9' {
			return KerberosTime{}, fmt.Errorf("parse GeneralizedTime: non-digit at offset %d", i)
		}
	}
	parsed, err := time.ParseInLocation("20060102150405Z", value, time.UTC)
	if err != nil {
		return KerberosTime{}, fmt.Errorf("parse GeneralizedTime: %w", err)
	}
	return KerberosTime{Time: parsed.UTC(), Present: true}, nil
}

// EncodeGeneralizedTime encodes a KerberosTime without fractional seconds.
func (t KerberosTime) EncodeGeneralizedTime() (string, error) {
	if !t.Present {
		return "", nil
	}
	return t.Time.UTC().Truncate(time.Second).Format("20060102150405Z"), nil
}

// KDCOptions is the 32-bit KDC-options field from RFC 4120, section 5.4.1.
type KDCOptions uint32

const (
	KDCForwardable      KDCOptions = 1 << 1
	KDCForwarded        KDCOptions = 1 << 2
	KDCProxiable        KDCOptions = 1 << 3
	KDCProxy            KDCOptions = 1 << 4
	KDCAllowPostdate    KDCOptions = 1 << 5
	KDCPostdated        KDCOptions = 1 << 6
	KDCRenewable        KDCOptions = 1 << 8
	KDCCanonicalize     KDCOptions = 1 << 15
	KDCRequestAnonymous KDCOptions = 1 << 16
	// KDCCNameInAddlTkt requests constrained delegation ([MS-SFU] S4U2Proxy).
	KDCCNameInAddlTkt        KDCOptions = 1 << 14
	KDCDisableTransitedCheck KDCOptions = 1 << 26
	KDCRenewableOK           KDCOptions = 1 << 27
	KDCEncTktInSkey          KDCOptions = 1 << 28
	KDCRenew                 KDCOptions = 1 << 30
	KDCValidate              KDCOptions = 1 << 31
)

// TicketFlags is the 32-bit ticket-flags field from RFC 4120, section 5.3.1.
type TicketFlags uint32

const (
	TicketForwardable  TicketFlags = 1 << 1
	TicketForwarded    TicketFlags = 1 << 2
	TicketProxiable    TicketFlags = 1 << 3
	TicketProxy        TicketFlags = 1 << 4
	TicketMayPostdate  TicketFlags = 1 << 5
	TicketPostdated    TicketFlags = 1 << 6
	TicketInvalid      TicketFlags = 1 << 7
	TicketRenewable    TicketFlags = 1 << 8
	TicketInitial      TicketFlags = 1 << 9
	TicketPreAuthent   TicketFlags = 1 << 10
	TicketHWAuthent    TicketFlags = 1 << 11
	TicketTransited    TicketFlags = 1 << 12
	TicketOKAsDelegate TicketFlags = 1 << 13
	TicketAnonymous    TicketFlags = 1 << 16
)

// APOptions is the 32-bit AP-options field from RFC 4120, section 5.5.1.
type APOptions uint32

const (
	APUseSessionKey  APOptions = 1 << 1
	APMutualRequired APOptions = 1 << 2
)

// EncodeFlags returns the RFC 4120 BIT STRING representation.
func EncodeFlags(flags uint32) ([]byte, error) {
	der := []byte{0x03, 0x05, 0x00, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(der[3:], flagsToBytes(flags))
	return der, nil
}

// DecodeFlags decodes the canonical 32-bit RFC 4120 KerberosFlags BIT STRING.
func DecodeFlags(der []byte) (uint32, error) {
	if len(der) != 7 || der[0] != 0x03 || der[1] != 0x05 || der[2] != 0 {
		return 0, fmt.Errorf("decode KerberosFlags: invalid DER BIT STRING")
	}
	return bytesToFlags(der[3:]), nil
}

func flagsToBytes(flags uint32) uint32 {
	var encoded uint32
	for bit := uint(0); bit < 32; bit++ {
		if flags&(uint32(1)<<bit) != 0 {
			encoded |= uint32(1) << (31 - bit)
		}
	}
	return encoded
}

func bytesToFlags(encoded []byte) uint32 {
	value := binary.BigEndian.Uint32(encoded)
	var flags uint32
	for bit := uint(0); bit < 32; bit++ {
		if value&(uint32(1)<<(31-bit)) != 0 {
			flags |= uint32(1) << bit
		}
	}
	return flags
}
