package types

import (
	"io"
	"time"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

// Clock supplies the current time to protocol code.
type Clock interface {
	Now() time.Time
}

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
	return KerberosTime{}, krberrors.ErrNotImplemented
}

// EncodeGeneralizedTime encodes a KerberosTime without fractional seconds.
func (t KerberosTime) EncodeGeneralizedTime() (string, error) {
	return "", krberrors.ErrNotImplemented
}

// KDCOptions is the 32-bit KDC-options field from RFC 4120, section 5.4.1.
type KDCOptions uint32

const (
	KDCForwardable           KDCOptions = 1 << 1
	KDCForwarded             KDCOptions = 1 << 2
	KDCProxiable             KDCOptions = 1 << 3
	KDCProxy                 KDCOptions = 1 << 4
	KDCAllowPostdate         KDCOptions = 1 << 5
	KDCPostdated             KDCOptions = 1 << 6
	KDCRenewable             KDCOptions = 1 << 8
	KDCCanonicalize          KDCOptions = 1 << 15
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
	TicketAnonymous    TicketFlags = 1 << 14
)

// APOptions is the 32-bit AP-options field from RFC 4120, section 5.5.1.
type APOptions uint32

const (
	APUseSessionKey  APOptions = 1 << 1
	APMutualRequired APOptions = 1 << 2
)

// EncodeFlags returns the RFC 4120 BIT STRING representation.
func EncodeFlags(flags uint32) ([]byte, error) {
	return nil, krberrors.ErrNotImplemented
}
