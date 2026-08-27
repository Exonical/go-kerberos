package asn1

import (
	"fmt"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

// Marshal encodes a Kerberos ASN.1 value using canonical DER.
func Marshal(value any) ([]byte, error) {
	_ = value
	return nil, fmt.Errorf("marshal kerberos ASN.1: %w", krberrors.ErrNotImplemented)
}

// Unmarshal decodes a Kerberos ASN.1 value from canonical DER.
func Unmarshal(data []byte, value any) error {
	_, _ = data, value
	return fmt.Errorf("unmarshal kerberos ASN.1: %w", krberrors.ErrNotImplemented)
}
