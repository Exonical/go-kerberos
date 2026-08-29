package spake

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"

	"filippo.io/nistec"
)

type nistGroup struct {
	id      int32
	name    string
	multLen int
	elemLen int
	hashLen int
	newHash func() hash.Hash
	m       []byte
	n       []byte
	order   *big.Int
}

var nistGroupDefs = map[int32]nistGroup{
	GroupP256: {
		id: GroupP256, name: "P-256", multLen: 32, elemLen: 33, hashLen: 32,
		newHash: func() hash.Hash { return sha256Hash() },
		m:       []byte{0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f},
		n:       []byte{0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49},
		order:   mustBigInt("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
	},
	GroupP384: {
		id: GroupP384, name: "P-384", multLen: 48, elemLen: 49, hashLen: 48,
		newHash: sha384Hash,
		m:       []byte{0x03, 0x0f, 0xf0, 0x89, 0x5a, 0xe5, 0xeb, 0xf6, 0x18, 0x70, 0x80, 0xa8, 0x2d, 0x82, 0xb4, 0x2e, 0x27, 0x65, 0xe3, 0xb2, 0xf8, 0x74, 0x9c, 0x7e, 0x05, 0xeb, 0xa3, 0x66, 0x43, 0x4b, 0x36, 0x3d, 0x3d, 0xc3, 0x6f, 0x15, 0x31, 0x47, 0x39, 0x07, 0x4d, 0x2e, 0xb8, 0x61, 0x3f, 0xce, 0xec, 0x28, 0x53},
		n:       []byte{0x02, 0xc7, 0x2c, 0xf2, 0xe3, 0x90, 0x85, 0x3a, 0x1c, 0x1c, 0x4a, 0xd8, 0x16, 0xa6, 0x2f, 0xd1, 0x58, 0x24, 0xf5, 0x60, 0x78, 0x91, 0x8f, 0x43, 0xf9, 0x22, 0xca, 0x21, 0x51, 0x8f, 0x9c, 0x54, 0x3b, 0xb2, 0x52, 0xc5, 0x49, 0x02, 0x14, 0xcf, 0x9a, 0xa3, 0xf0, 0xba, 0xab, 0x4b, 0x66, 0x5c, 0x10},
		order:   mustBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
	},
	GroupP521: {
		id: GroupP521, name: "P-521", multLen: 66, elemLen: 67, hashLen: 64,
		newHash: sha512Hash,
		m:       []byte{0x02, 0x00, 0x3f, 0x06, 0xf3, 0x81, 0x31, 0xb2, 0xba, 0x26, 0x00, 0x79, 0x1e, 0x82, 0x48, 0x8e, 0x8d, 0x20, 0xab, 0x88, 0x9a, 0xf7, 0x53, 0xa4, 0x18, 0x06, 0xc5, 0xdb, 0x18, 0xd3, 0x7d, 0x85, 0x60, 0x8c, 0xfa, 0xe0, 0x6b, 0x82, 0xe4, 0xa7, 0x2c, 0xd7, 0x44, 0xc7, 0x19, 0x19, 0x35, 0x62, 0xa6, 0x53, 0xea, 0x1f, 0x11, 0x9e, 0xef, 0x93, 0x56, 0x90, 0x7e, 0xdc, 0x9b, 0x56, 0x97, 0x99, 0x62, 0xd7, 0xaa},
		n:       []byte{0x02, 0x00, 0xc7, 0x92, 0x4b, 0x9e, 0xc0, 0x17, 0xf3, 0x09, 0x45, 0x62, 0x89, 0x43, 0x36, 0xa5, 0x3c, 0x50, 0x16, 0x7b, 0xa8, 0xc5, 0x96, 0x38, 0x76, 0x88, 0x05, 0x42, 0xbc, 0x66, 0x9e, 0x49, 0x4b, 0x25, 0x32, 0xd7, 0x6c, 0x5b, 0x53, 0xdf, 0xb3, 0x49, 0xfd, 0xf6, 0x91, 0x54, 0xb9, 0xe0, 0x04, 0x8c, 0x58, 0xa4, 0x2e, 0x8e, 0xd0, 0x4c, 0xef, 0x05, 0x2a, 0x3b, 0xc3, 0x49, 0xd9, 0x55, 0x75, 0xcd, 0x25},
		order:   mustBigInt("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
	},
}

func mustBigInt(value string) *big.Int {
	n, ok := new(big.Int).SetString(value, 16)
	if !ok {
		panic("invalid SPAKE group order")
	}
	return n
}

func sha256Hash() hash.Hash { return sha256.New() }
func sha384Hash() hash.Hash { return sha512.New384() }
func sha512Hash() hash.Hash { return sha512.New() }

func nistScalar(group nistGroup, value []byte) ([]byte, error) {
	if len(value) != group.multLen {
		return nil, fmt.Errorf("SPAKE scalar must be %d bytes", group.multLen)
	}
	n := new(big.Int).Mod(new(big.Int).SetBytes(value), group.order)
	out := make([]byte, group.multLen)
	b := n.Bytes()
	copy(out[len(out)-len(b):], b)
	return out, nil
}

func nistPoint(group nistGroup, value []byte) (any, error) {
	if len(value) != group.elemLen {
		return nil, fmt.Errorf("SPAKE point must be %d bytes", group.elemLen)
	}
	switch group.id {
	case GroupP256:
		return nistec.NewP256Point().SetBytes(value)
	case GroupP384:
		return nistec.NewP384Point().SetBytes(value)
	case GroupP521:
		return nistec.NewP521Point().SetBytes(value)
	default:
		return nil, fmt.Errorf("unsupported NIST group")
	}
}

func nistKeygen(group nistGroup, w, private []byte, useM bool) ([]byte, error) {
	scalar, err := nistScalar(group, private)
	if err != nil {
		return nil, err
	}
	switch group.id {
	case GroupP256:
		g, err := nistec.NewP256Point().ScalarBaseMult(scalar)
		if err != nil {
			return nil, err
		}
		mask, err := nistec.NewP256Point().SetBytes(func() []byte {
			if useM {
				return group.m
			}
			return group.n
		}())
		if err != nil {
			return nil, err
		}
		mask, err = nistec.NewP256Point().ScalarMult(mask, w)
		if err != nil {
			return nil, err
		}
		return nistec.NewP256Point().Add(g, mask).BytesCompressed(), nil
	case GroupP384:
		g, err := nistec.NewP384Point().ScalarBaseMult(scalar)
		if err != nil {
			return nil, err
		}
		mask, err := nistec.NewP384Point().SetBytes(func() []byte {
			if useM {
				return group.m
			}
			return group.n
		}())
		if err != nil {
			return nil, err
		}
		mask, err = nistec.NewP384Point().ScalarMult(mask, w)
		if err != nil {
			return nil, err
		}
		return nistec.NewP384Point().Add(g, mask).BytesCompressed(), nil
	case GroupP521:
		g, err := nistec.NewP521Point().ScalarBaseMult(scalar)
		if err != nil {
			return nil, err
		}
		mask, err := nistec.NewP521Point().SetBytes(func() []byte {
			if useM {
				return group.m
			}
			return group.n
		}())
		if err != nil {
			return nil, err
		}
		mask, err = nistec.NewP521Point().ScalarMult(mask, w)
		if err != nil {
			return nil, err
		}
		return nistec.NewP521Point().Add(g, mask).BytesCompressed(), nil
	default:
		return nil, fmt.Errorf("unsupported NIST group")
	}
}

func nistResult(group nistGroup, w, private, peer []byte, useM bool) ([]byte, error) {
	scalar, err := nistScalar(group, private)
	if err != nil {
		return nil, err
	}
	constant := group.n
	if useM {
		constant = group.m
	}
	switch group.id {
	case GroupP256:
		p, err := nistec.NewP256Point().SetBytes(peer)
		if err != nil {
			return nil, fmt.Errorf("SPAKE peer point: %w", err)
		}
		if p.IsInfinity() != 0 {
			return nil, fmt.Errorf("SPAKE peer point is identity")
		}
		mask, err := nistec.NewP256Point().SetBytes(constant)
		if err != nil {
			return nil, err
		}
		mask, err = nistec.NewP256Point().ScalarMult(mask, w)
		if err != nil {
			return nil, err
		}
		mask.Negate(mask)
		p.Add(p, mask)
		if p.IsInfinity() != 0 {
			return nil, fmt.Errorf("SPAKE result is identity")
		}
		p, err = nistec.NewP256Point().ScalarMult(p, scalar)
		if err != nil {
			return nil, err
		}
		return p.BytesCompressed(), nil
	case GroupP384:
		p, err := nistec.NewP384Point().SetBytes(peer)
		if err != nil {
			return nil, fmt.Errorf("SPAKE peer point: %w", err)
		}
		if p.IsInfinity() != 0 {
			return nil, fmt.Errorf("SPAKE peer point is identity")
		}
		mask, err := nistec.NewP384Point().SetBytes(constant)
		if err != nil {
			return nil, err
		}
		mask, err = nistec.NewP384Point().ScalarMult(mask, w)
		if err != nil {
			return nil, err
		}
		mask.Negate(mask)
		p.Add(p, mask)
		if p.IsInfinity() != 0 {
			return nil, fmt.Errorf("SPAKE result is identity")
		}
		p, err = nistec.NewP384Point().ScalarMult(p, scalar)
		if err != nil {
			return nil, err
		}
		return p.BytesCompressed(), nil
	case GroupP521:
		p, err := nistec.NewP521Point().SetBytes(peer)
		if err != nil {
			return nil, fmt.Errorf("SPAKE peer point: %w", err)
		}
		if p.IsInfinity() != 0 {
			return nil, fmt.Errorf("SPAKE peer point is identity")
		}
		mask, err := nistec.NewP521Point().SetBytes(constant)
		if err != nil {
			return nil, err
		}
		mask, err = nistec.NewP521Point().ScalarMult(mask, w)
		if err != nil {
			return nil, err
		}
		mask.Negate(mask)
		p.Add(p, mask)
		if p.IsInfinity() != 0 {
			return nil, fmt.Errorf("SPAKE result is identity")
		}
		p, err = nistec.NewP521Point().ScalarMult(p, scalar)
		if err != nil {
			return nil, err
		}
		return p.BytesCompressed(), nil
	default:
		return nil, fmt.Errorf("unsupported NIST group")
	}
}
