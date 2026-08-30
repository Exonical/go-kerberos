// Package cammac implements the RFC 7751 CAMMAC authorization-data container.
package cammac

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const (
	// KeyUsage is KRB5_KEYUSAGE_CAMMAC.
	KeyUsage uint32 = 64
)

var (
	ErrNotFound = errors.New("CAMMAC not found")
	ErrInvalid  = errors.New("invalid CAMMAC")
)

func checksumType(enctype int32) (int32, error) {
	switch enctype {
	case crypto.EnctypeAES128SHA1:
		return crypto.ChecksumHMACSHA196AES128, nil
	case crypto.EnctypeAES256SHA1:
		return crypto.ChecksumHMACSHA196AES256, nil
	case crypto.EnctypeAES128SHA256:
		return crypto.ChecksumHMACSHA256128AES128, nil
	case crypto.EnctypeAES256SHA384:
		return crypto.ChecksumHMACSHA384192AES256, nil
	case crypto.EnctypeCamellia128:
		return crypto.ChecksumCMACCamellia128, nil
	case crypto.EnctypeCamellia256:
		return crypto.ChecksumCMACCamellia256, nil
	default:
		return 0, fmt.Errorf("CAMMAC: unsupported checksum enctype %d", enctype)
	}
}

func encodeAuthData(value protocol.AuthorizationData) ([]byte, error) {
	encoded, err := asn1.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("CAMMAC authorization data: %w", err)
	}
	return encoded, nil
}

func encodeKDCPart(ticket protocol.EncTicketPart, elements protocol.AuthorizationData) ([]byte, error) {
	ticket.AuthorizationData = elements
	encoded, err := asn1.Marshal(ticket)
	if err != nil {
		return nil, fmt.Errorf("CAMMAC KDC verifier input: %w", err)
	}
	return encoded, nil
}

// Marshal creates a CAMMAC wrapped in AD-IF-RELEVANT. Both verifiers use the
// RFC 4120 checksum usage 64. The KDC verifier covers EncTicketPart with the
// CAMMAC elements as authorization data; the service verifier covers the
// encoded elements alone.
func Marshal(elements protocol.AuthorizationData, ticket protocol.EncTicketPart,
	kdcKey, serviceKey protocol.EncryptionKey, kdcKVNO uint32) (protocol.AuthorizationData, error) {
	if len(elements) == 0 {
		return nil, fmt.Errorf("CAMMAC: %w: empty elements", ErrInvalid)
	}
	if len(kdcKey.KeyValue) == 0 || len(serviceKey.KeyValue) == 0 {
		return nil, fmt.Errorf("CAMMAC: %w: incomplete verifier key", ErrInvalid)
	}
	kdcType, err := checksumType(kdcKey.KeyType)
	if err != nil {
		return nil, err
	}
	serviceType, err := checksumType(serviceKey.KeyType)
	if err != nil {
		return nil, err
	}
	kdcEType, err := crypto.NewRegistry().Get(kdcKey.KeyType)
	if err != nil {
		return nil, err
	}
	serviceEType, err := crypto.NewRegistry().Get(serviceKey.KeyType)
	if err != nil {
		return nil, err
	}
	kdcInput, err := encodeKDCPart(ticket, elements)
	if err != nil {
		return nil, err
	}
	elementDER, err := encodeAuthData(elements)
	if err != nil {
		return nil, err
	}
	kdcSum, err := kdcEType.Checksum(kdcKey.KeyValue, KeyUsage, kdcInput)
	if err != nil {
		return nil, fmt.Errorf("CAMMAC KDC verifier: %w", err)
	}
	serviceSum, err := serviceEType.Checksum(serviceKey.KeyValue, KeyUsage, elementDER)
	if err != nil {
		return nil, fmt.Errorf("CAMMAC service verifier: %w", err)
	}
	kdcKVNOCopy := kdcKVNO
	cammac := protocol.CAMMAC{
		Elements: elements,
		KDCVerifier: &protocol.VerifierMAC{
			KVNO:     &kdcKVNOCopy,
			Checksum: protocol.Checksum{ChecksumType: kdcType, Checksum: kdcSum},
		},
		SVCVerifier: &protocol.VerifierMAC{
			Checksum: protocol.Checksum{ChecksumType: serviceType, Checksum: serviceSum},
		},
	}
	encoded, err := asn1.Marshal(cammac)
	if err != nil {
		return nil, fmt.Errorf("CAMMAC: %w", err)
	}
	inner, err := asn1.Marshal(protocol.AuthorizationData{
		{ADType: protocol.ADCAMMAC, ADData: encoded},
	})
	if err != nil {
		return nil, fmt.Errorf("CAMMAC wrapper: %w", err)
	}
	return protocol.AuthorizationData{{ADType: protocol.ADIfRelevant, ADData: inner}}, nil
}

// Parse decodes a raw CAMMAC DER value.
func Parse(data []byte) (*protocol.CAMMAC, error) {
	var value protocol.CAMMAC
	if err := asn1.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("CAMMAC: %w", err)
	}
	if len(value.Elements) == 0 {
		return nil, fmt.Errorf("CAMMAC: %w: missing elements", ErrInvalid)
	}
	if value.KDCVerifier == nil && value.SVCVerifier == nil && len(value.OtherVerifiers) == 0 {
		return nil, fmt.Errorf("CAMMAC: %w: missing verifiers", ErrInvalid)
	}
	return &value, nil
}

func find(data protocol.AuthorizationData) ([]*protocol.CAMMAC, error) {
	var result []*protocol.CAMMAC
	for _, outer := range data {
		if outer.ADType != protocol.ADIfRelevant {
			continue
		}
		var inner protocol.AuthorizationData
		if err := asn1.Unmarshal(outer.ADData, &inner); err != nil {
			return nil, fmt.Errorf("CAMMAC IF-RELEVANT: %w", err)
		}
		for _, entry := range inner {
			if entry.ADType != protocol.ADCAMMAC {
				continue
			}
			value, err := Parse(entry.ADData)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return nil, ErrNotFound
	}
	return result, nil
}

// VerifyService verifies CAMMAC service verifiers and returns the protected
// authorization data. A missing CAMMAC returns ErrNotFound.
func VerifyService(data protocol.AuthorizationData, key protocol.EncryptionKey) (protocol.AuthorizationData, error) {
	values, err := find(data)
	if err != nil {
		return nil, err
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, err
	}
	var result protocol.AuthorizationData
	for _, value := range values {
		if value.SVCVerifier == nil {
			return nil, fmt.Errorf("CAMMAC: %w: missing service verifier", ErrInvalid)
		}
		encoded, err := encodeAuthData(value.Elements)
		if err != nil {
			return nil, err
		}
		if err := etype.VerifyChecksum(key.KeyValue, KeyUsage, encoded,
			value.SVCVerifier.Checksum.Checksum); err != nil {
			return nil, fmt.Errorf("CAMMAC service verifier: %w", err)
		}
		result = append(result, value.Elements...)
	}
	return result, nil
}

// VerifyKDC verifies all KDC verifiers against the supplied ticket and key.
// A missing CAMMAC returns ErrNotFound.
func VerifyKDC(data protocol.AuthorizationData, ticket protocol.EncTicketPart,
	key protocol.EncryptionKey) error {
	values, err := find(data)
	if err != nil {
		return err
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return err
	}
	for _, value := range values {
		if value.KDCVerifier == nil {
			return fmt.Errorf("CAMMAC: %w: missing KDC verifier", ErrInvalid)
		}
		input, err := encodeKDCPart(ticket, value.Elements)
		if err != nil {
			return err
		}
		if err := etype.VerifyChecksum(key.KeyValue, KeyUsage, input,
			value.KDCVerifier.Checksum.Checksum); err != nil {
			return fmt.Errorf("CAMMAC KDC verifier: %w", err)
		}
	}
	return nil
}

// ProtectedElements returns CAMMAC elements without verifying a service key.
// It is useful to inspect KDC authdata before selecting the acceptor key.
func ProtectedElements(data protocol.AuthorizationData) (protocol.AuthorizationData, error) {
	values, err := find(data)
	if err != nil {
		return nil, err
	}
	var result protocol.AuthorizationData
	for _, value := range values {
		result = append(result, value.Elements...)
	}
	return result, nil
}

// HasCAMMAC reports whether authorization data contains an AD-CAMMAC entry.
func HasCAMMAC(data protocol.AuthorizationData) bool {
	_, err := find(data)
	return err == nil
}

// EqualElements compares protected elements by their canonical DER encoding.
func EqualElements(a, b protocol.AuthorizationData) bool {
	left, leftErr := encodeAuthData(a)
	right, rightErr := encodeAuthData(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}
