package pac

import (
	"errors"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

// ErrNotFound indicates that authorization data contains no PAC.
var ErrNotFound = errors.New("PAC not found")

const (
	ADIfRelevant = 1
	ADWin2KPac   = 128
)

// AuthorizationData wraps a PAC in the AD-IF-RELEVANT/AD-WIN2K-PAC
// containers used by MIT krb5.
func AuthorizationData(value []byte) (protocol.AuthorizationData, error) {
	if _, err := Parse(value); err != nil {
		return nil, err
	}
	inner, err := asn1.Marshal(protocol.AuthorizationData{
		{ADType: ADWin2KPac, ADData: append([]byte(nil), value...)},
	})
	if err != nil {
		return nil, fmt.Errorf("PAC authorization data: %w", err)
	}
	return protocol.AuthorizationData{{ADType: ADIfRelevant, ADData: inner}}, nil
}

// AddAuthorizationData returns data with a PAC element added to the existing
// authorization-data list. An existing PAC is replaced while unrelated
// authorization data, including other AD-IF-RELEVANT elements, is retained.
func AddAuthorizationData(data protocol.AuthorizationData, value []byte) (protocol.AuthorizationData, error) {
	if _, err := Parse(value); err != nil {
		return nil, err
	}
	out := make(protocol.AuthorizationData, 0, len(data)+1)
	replaced := false
	for _, outer := range data {
		if outer.ADType != ADIfRelevant {
			out = append(out, outer)
			continue
		}
		var inner protocol.AuthorizationData
		if err := asn1.Unmarshal(outer.ADData, &inner); err != nil {
			return nil, fmt.Errorf("PAC authorization data: %w", err)
		}
		hasPAC := false
		for _, entry := range inner {
			if entry.ADType == ADWin2KPac {
				hasPAC = true
				break
			}
		}
		if hasPAC && !replaced {
			filtered := make(protocol.AuthorizationData, 0, len(inner))
			for _, entry := range inner {
				if entry.ADType != ADWin2KPac {
					filtered = append(filtered, entry)
				}
			}
			filtered = append(filtered, protocol.AuthorizationDataEntry{
				ADType: ADWin2KPac, ADData: append([]byte(nil), value...),
			})
			encoded, err := asn1.Marshal(filtered)
			if err != nil {
				return nil, fmt.Errorf("PAC authorization data: %w", err)
			}
			outer.ADData = encoded
			replaced = true
		}
		out = append(out, outer)
	}
	if !replaced {
		wrapped, err := AuthorizationData(value)
		if err != nil {
			return nil, err
		}
		out = append(out, wrapped...)
	}
	return out, nil
}

// FromAuthorizationData locates and decodes a nested PAC. Unknown
// authorization-data entries are ignored and remain available to the caller.
func FromAuthorizationData(data protocol.AuthorizationData) (*PAC, error) {
	for _, outer := range data {
		if outer.ADType != ADIfRelevant {
			continue
		}
		var inner protocol.AuthorizationData
		if err := asn1.Unmarshal(outer.ADData, &inner); err != nil {
			return nil, fmt.Errorf("PAC authorization data: %w", err)
		}
		for _, entry := range inner {
			if entry.ADType == ADWin2KPac {
				p, err := Parse(entry.ADData)
				if err != nil {
					return nil, err
				}
				return p, nil
			}
		}
	}
	return nil, fmt.Errorf("PAC authorization data: %w", ErrNotFound)
}

// FromTicket extracts and verifies the PAC in a decrypted ticket. The server
// checksum is always checked; the KDC checksum is checked when privsvrKey is
// non-nil and contains a usable key.
func FromTicket(part protocol.EncTicketPart, serverKey Key, privsvrKey *Key) (*PAC, error) {
	p, err := FromAuthorizationData(part.AuthorizationData)
	if err != nil {
		return nil, err
	}
	var kdcKey Key
	if privsvrKey != nil {
		kdcKey = *privsvrKey
	}
	if err := p.Verify(serverKey, kdcKey); err != nil {
		return nil, err
	}
	return p, nil
}
