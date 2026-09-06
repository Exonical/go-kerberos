package pkinit

import (
	"crypto/ecdh"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// DHGroup identifies a PKINIT key-exchange group.
type DHGroup int

const (
	GroupMODP2048 DHGroup = 2048
	GroupP256     DHGroup = 3072
	GroupP384     DHGroup = 7680
	GroupP521     DHGroup = 15360
)

const (
	// PADataTDHParameters is TD-DH-PARAMETERS from RFC 4556.
	PADataTDHParameters int32 = 109
	defaultDHMinBits          = 2048
)

var (
	idDHPublicNumber = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}
	idECPublicKey    = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	curveP256OID     = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	curveP384OID     = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	curveP521OID     = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// GroupPolicyError indicates that a received public value does not meet the
// configured PKINIT minimum and includes the groups the peer may retry.
type GroupPolicyError struct {
	Group     DHGroup
	MinBits   int
	Supported []DHGroup
}

func (e *GroupPolicyError) Error() string {
	return fmt.Sprintf("pkinit: %s group does not meet minimum strength %d",
		GroupName(e.Group), e.MinBits)
}

// ParseDHMinBits implements MIT's pkinit_dh_min_bits normalization.
func ParseDHMinBits(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultDHMinBits
	}
	switch strings.ToUpper(value) {
	case "P-256":
		return int(GroupP256)
	case "P-384":
		return int(GroupP384)
	case "P-521":
		return int(GroupP521)
	}
	n, err := strconv.ParseInt(value, 0, 64)
	if err != nil {
		return defaultDHMinBits
	}
	switch {
	case n == 1024:
		return 1024
	case n > 1024 && n <= 2048:
		return 2048
	case n > 2048 && n <= 4096:
		return 4096
	default:
		return defaultDHMinBits
	}
}

// GroupName returns the MIT-compatible display name for a group.
func GroupName(group DHGroup) string {
	switch group {
	case GroupMODP2048:
		return "2048-bit DH"
	case GroupP256:
		return "P-256"
	case GroupP384:
		return "P-384"
	case GroupP521:
		return "P-521"
	default:
		return "unknown"
	}
}

func groupStrength(group DHGroup) int {
	switch group {
	case GroupMODP2048:
		return 2048
	case GroupP256:
		return int(GroupP256)
	case GroupP384:
		return int(GroupP384)
	case GroupP521:
		return int(GroupP521)
	default:
		return -1
	}
}

func curveForGroup(group DHGroup) (ecdh.Curve, asn1.ObjectIdentifier, bool) {
	switch group {
	case GroupP256:
		return ecdh.P256(), curveP256OID, true
	case GroupP384:
		return ecdh.P384(), curveP384OID, true
	case GroupP521:
		return ecdh.P521(), curveP521OID, true
	default:
		return nil, nil, false
	}
}

func groupForCurveOID(oid asn1.ObjectIdentifier) (DHGroup, ecdh.Curve, bool) {
	switch {
	case oid.Equal(curveP256OID):
		return GroupP256, ecdh.P256(), true
	case oid.Equal(curveP384OID):
		return GroupP384, ecdh.P384(), true
	case oid.Equal(curveP521OID):
		return GroupP521, ecdh.P521(), true
	default:
		return 0, nil, false
	}
}

func supportedGroups(minBits int) []DHGroup {
	all := []DHGroup{GroupP256, GroupP384, GroupP521, GroupMODP2048}
	out := make([]DHGroup, 0, len(all))
	for _, group := range all {
		if groupStrength(group) >= minBits {
			out = append(out, group)
		}
	}
	return out
}

// SupportedDHGroups returns the groups MIT would advertise for a minimum.
func SupportedDHGroups(value string) []DHGroup {
	return supportedGroups(ParseDHMinBits(value))
}

func marshalDHAlgorithm(group DHGroup) ([]byte, error) {
	switch group {
	case GroupMODP2048:
		q := new(big.Int).Sub(group14P, bigOne)
		q.Div(q, bigTwo)
		return derSeq(derOID(idDHPublicNumber),
			derSeq(derIntBig(group14P), derIntBig(group14G), derIntBig(q))), nil
	case GroupP256, GroupP384, GroupP521:
		_, oid, ok := curveForGroup(group)
		if !ok {
			return nil, errors.New("pkinit: unsupported EC group")
		}
		return derSeq(derOID(idECPublicKey), derOID(oid)), nil
	default:
		return nil, fmt.Errorf("pkinit: unsupported DH group %d", group)
	}
}

// MarshalDHParameters encodes TD-DH-PARAMETERS.
func MarshalDHParameters(groups []DHGroup) ([]byte, error) {
	var values []byte
	for _, group := range groups {
		algorithm, err := marshalDHAlgorithm(group)
		if err != nil {
			return nil, err
		}
		values = append(values, algorithm...)
	}
	return der(0x30, values), nil
}

// ParseDHParameters decodes TD-DH-PARAMETERS.
func ParseDHParameters(data []byte) ([]DHGroup, error) {
	fields, err := sequenceFields(data)
	if err != nil {
		return nil, fmt.Errorf("pkinit: malformed TD-DH-PARAMETERS: %w", err)
	}
	groups := make([]DHGroup, 0, len(fields))
	for _, field := range fields {
		parts, err := sequenceFields(field)
		if err != nil || len(parts) < 2 {
			return nil, errors.New("pkinit: malformed DH algorithm identifier")
		}
		oid, err := parseOID(parts[0])
		if err != nil {
			return nil, err
		}
		if oid.Equal(idDHPublicNumber) {
			parameters, err := sequenceFields(parts[1])
			if err != nil || len(parameters) < 2 {
				continue
			}
			p, err := parseInteger(parameters[0])
			if err != nil {
				continue
			}
			g, err := parseInteger(parameters[1])
			if err != nil || p.Cmp(group14P) != 0 || g.Cmp(group14G) != 0 {
				continue
			}
			groups = append(groups, GroupMODP2048)
			continue
		}
		if !oid.Equal(idECPublicKey) {
			continue
		}
		curveOID, err := parseOID(parts[1])
		if err != nil {
			return nil, err
		}
		group, _, ok := groupForCurveOID(curveOID)
		if !ok {
			continue
		}
		groups = append(groups, group)
	}
	if len(groups) == 0 {
		return nil, errors.New("pkinit: no supported DH groups")
	}
	return groups, nil
}

func parseOID(data []byte) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(data, &oid); err != nil {
		return nil, fmt.Errorf("pkinit: malformed algorithm OID: %w", err)
	}
	return oid, nil
}

var (
	bigOne = big.NewInt(1)
	bigTwo = big.NewInt(2)
)
