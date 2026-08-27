package principal

import (
	"fmt"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

// NameType identifies the type of a Kerberos principal name (RFC 4120,
// section 6.2).
type NameType int32

const (
	NTUnknown       NameType = 0
	NTPrincipal     NameType = 1
	NTSrvInstance   NameType = 2
	NTSrvHst        NameType = 3
	NTSrvXhst       NameType = 4
	NTUID           NameType = 5
	NTX500Principal NameType = 6
	NTSMTPName      NameType = 7
	NTEnterprise    NameType = 10
)

// Principal is a structured Kerberos principal. Components are not collapsed
// into a single string so escaping and name-type semantics remain explicit.
type Principal struct {
	Realm      string
	NameType   NameType
	Components []string
}

// Parse parses a display-form principal name.
func Parse(name string) (*Principal, error) {
	_ = name
	return nil, fmt.Errorf("parse principal: %w", krberrors.ErrNotImplemented)
}

// Format returns the escaped display form of a principal.
func (p Principal) Format() (string, error) {
	return "", fmt.Errorf("format principal: %w", krberrors.ErrNotImplemented)
}
