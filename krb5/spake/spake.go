// Package spake implements the PA-SPAKE mechanism.
package spake

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	edwards25519 "filippo.io/edwards25519"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const (
	GroupEdwards25519 int32  = 1
	GroupP256         int32  = 2
	GroupP384         int32  = 3
	GroupP521         int32  = 4
	FactorNone        int32  = 1
	KeyUsage          uint32 = 65
)

var (
	spakeM = mustPoint([]byte{
		0xd0, 0x48, 0x03, 0x2c, 0x6e, 0xa0, 0xb6, 0xd6,
		0x97, 0xdd, 0xc2, 0xe8, 0x6b, 0xda, 0x85, 0xa3,
		0x3a, 0xda, 0xc9, 0x20, 0xf1, 0xbf, 0x18, 0xe1,
		0xb0, 0xc6, 0xd1, 0x66, 0xa5, 0xce, 0xcd, 0xaf,
	})
	spakeN = mustPoint([]byte{
		0xd3, 0xbf, 0xb5, 0x18, 0xf4, 0x4f, 0x34, 0x30,
		0xf2, 0x9d, 0x0c, 0x92, 0xaf, 0x50, 0x38, 0x65,
		0xa1, 0xed, 0x32, 0x81, 0xdc, 0x69, 0xb3, 0x5d,
		0xd8, 0x68, 0xba, 0x85, 0xf8, 0x86, 0xc4, 0xab,
	})
)

func mustPoint(data []byte) *edwards25519.Point {
	point, err := new(edwards25519.Point).SetBytes(data)
	if err != nil {
		panic(err)
	}
	return point
}

func checkGroup(group int32) error {
	if group == GroupEdwards25519 {
		return nil
	}
	_, ok := nistGroupDefs[group]
	if !ok {
		return fmt.Errorf("SPAKE group %d is unsupported", group)
	}
	return nil
}

// GroupInfo returns the group's name, scalar width, element width, and hash
// width.
func GroupInfo(group int32) (name string, multLen, elemLen, hashLen int, err error) {
	if group == GroupEdwards25519 {
		return "edwards25519", 32, 32, sha256.Size, nil
	}
	def, ok := nistGroupDefs[group]
	if !ok {
		return "", 0, 0, 0, fmt.Errorf("SPAKE group %d is unsupported", group)
	}
	return def.name, def.multLen, def.elemLen, def.hashLen, nil
}

// DeriveW derives the SPAKE multiplier from the initial reply key.
func DeriveW(etype crypto.EType, initialKey []byte, group int32) ([]byte, error) {
	if err := checkGroup(group); err != nil {
		return nil, err
	}
	input := make([]byte, len("SPAKEsecret")+4)
	copy(input, "SPAKEsecret")
	binary.BigEndian.PutUint32(input[len("SPAKEsecret"):], uint32(group))
	if group == GroupEdwards25519 {
		return prfPlus(etype, initialKey, input, 32)
	}
	return prfPlus(etype, initialKey, input, nistGroupDefs[group].multLen)
}

func prfPlus(etype crypto.EType, key, input []byte, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	for counter := byte(1); len(out) < size; counter++ {
		part, err := crypto.PRF(etype, key, append([]byte{counter}, input...))
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
		if counter == 0 {
			return nil, fmt.Errorf("SPAKE PRF+ overflow")
		}
	}
	return out[:size], nil
}

func scalar(data []byte) (*edwards25519.Scalar, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("SPAKE scalar must be 32 bytes")
	}
	// SetUniformBytes performs the reduction modulo the group order.
	wide := make([]byte, 64)
	copy(wide, data)
	value, err := new(edwards25519.Scalar).SetUniformBytes(wide)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// KeygenWithPrivate computes a masked public value from a supplied private
// scalar. It is useful for deterministic vectors and test harnesses.
func KeygenWithPrivate(group int32, w, private []byte, useM bool) ([]byte, error) {
	if err := checkGroup(group); err != nil {
		return nil, err
	}
	if group != GroupEdwards25519 {
		return nistKeygen(nistGroupDefs[group], w, private, useM)
	}
	s, err := scalar(private)
	if err != nil {
		return nil, err
	}
	return maskedPublic(w, s, useM)
}

// Keygen generates a private scalar and masked public value. useM selects M
// (the KDC side); false selects N (the client side).
func Keygen(group int32, w []byte, useM bool) (private, public []byte, err error) {
	if err = checkGroup(group); err != nil {
		return nil, nil, err
	}
	privateLen := 32
	if group != GroupEdwards25519 {
		privateLen = nistGroupDefs[group].multLen
	}
	private = make([]byte, privateLen)
	if _, err = io.ReadFull(crypto.RandomSource, private); err != nil {
		return nil, nil, err
	}
	if group != GroupEdwards25519 {
		public, err = nistKeygen(nistGroupDefs[group], w, private, useM)
		if err != nil {
			return nil, nil, err
		}
		private, err = nistScalar(nistGroupDefs[group], private)
		return private, public, err
	}
	s, err := scalar(private)
	if err != nil {
		return nil, nil, err
	}
	public, err = maskedPublic(w, s, useM)
	if err != nil {
		return nil, nil, err
	}
	return s.Bytes(), public, nil
}

func maskedPublic(w []byte, private *edwards25519.Scalar, useM bool) ([]byte, error) {
	mask, err := scalar(w)
	if err != nil {
		return nil, err
	}
	point := spakeN
	if useM {
		point = spakeM
	}
	masked := new(edwards25519.Point).Add(
		new(edwards25519.Point).ScalarBaseMult(private),
		new(edwards25519.Point).ScalarMult(mask, point),
	)
	return append([]byte(nil), masked.Bytes()...), nil
}

// Result computes the unmasked SPAKE shared element. useM selects M as the
// peer mask (client side); false selects N (KDC side).
func Result(group int32, w, private, peer []byte, useM bool) ([]byte, error) {
	if err := checkGroup(group); err != nil {
		return nil, err
	}
	if group != GroupEdwards25519 {
		return nistResult(nistGroupDefs[group], w, private, peer, useM)
	}
	our, err := scalar(private)
	if err != nil {
		return nil, err
	}
	peerPoint, err := new(edwards25519.Point).SetBytes(peer)
	if err != nil {
		return nil, fmt.Errorf("SPAKE peer point: %w", err)
	}
	if new(edwards25519.Point).MultByCofactor(peerPoint).Equal(
		edwards25519.NewIdentityPoint()) == 1 {
		return nil, fmt.Errorf("SPAKE peer point has small order")
	}
	mask, err := scalar(w)
	if err != nil {
		return nil, err
	}
	peerMask := spakeN
	if useM {
		peerMask = spakeM
	}
	unmasked := new(edwards25519.Point).Subtract(peerPoint,
		new(edwards25519.Point).ScalarMult(mask, peerMask))
	result := new(edwards25519.Point).ScalarMult(our, unmasked)
	return append([]byte(nil), result.Bytes()...), nil
}

// Transcript updates the SHA-256 transcript hash as specified by PA-SPAKE.
func Transcript(previous, data1, data2 []byte) []byte {
	return TranscriptForGroup(GroupEdwards25519, previous, data1, data2)
}

// TranscriptForGroup updates the transcript hash using the group's hash.
func TranscriptForGroup(group int32, previous, data1, data2 []byte) []byte {
	if group == GroupEdwards25519 {
		if len(previous) == 0 {
			previous = make([]byte, sha256.Size)
		}
		h := sha256.New()
		_, _ = h.Write(previous)
		_, _ = h.Write(data1)
		_, _ = h.Write(data2)
		return h.Sum(nil)
	}
	def, ok := nistGroupDefs[group]
	if !ok {
		return nil
	}
	if len(previous) == 0 {
		previous = make([]byte, def.hashLen)
	}
	h := def.newHash()
	_, _ = h.Write(previous)
	_, _ = h.Write(data1)
	_, _ = h.Write(data2)
	return h.Sum(nil)
}

// DeriveKey computes K'[n] using MIT's SPAKEkey construction.
func DeriveKey(etype crypto.EType, initialKey, w, result, transcript, derReq []byte,
	group int32, n uint32) ([]byte, error) {
	if err := checkGroup(group); err != nil {
		return nil, err
	}
	if etype == nil {
		return nil, fmt.Errorf("SPAKE nil enctype")
	}
	var groupBytes, enctypeBytes, nBytes [4]byte
	binary.BigEndian.PutUint32(groupBytes[:], uint32(group))
	binary.BigEndian.PutUint32(enctypeBytes[:], uint32(etype.ID()))
	binary.BigEndian.PutUint32(nBytes[:], n)
	seedInput := make([]byte, 0, 8+32+len(w)+len(result)+len(transcript)+len(derReq)+4)
	seedInput = append(seedInput, []byte("SPAKEkey")...)
	seedInput = append(seedInput, groupBytes[:]...)
	seedInput = append(seedInput, enctypeBytes[:]...)
	seedInput = append(seedInput, w...)
	seedInput = append(seedInput, result...)
	seedInput = append(seedInput, transcript...)
	seedInput = append(seedInput, derReq...)
	seedInput = append(seedInput, nBytes[:]...)
	seedInput = append(seedInput, 1)
	var seed []byte
	if group == GroupEdwards25519 {
		digest := sha256.Sum256(seedInput)
		seed = digest[:]
	} else {
		def, ok := nistGroupDefs[group]
		if !ok {
			return nil, fmt.Errorf("SPAKE group %d is unsupported", group)
		}
		digest := def.newHash()
		_, _ = digest.Write(seedInput)
		seed = digest.Sum(nil)
	}
	if len(seed) < etype.KeySize() {
		return nil, fmt.Errorf("SPAKE hash output is shorter than key")
	}
	seed = seed[:etype.KeySize()]
	hkey := append([]byte(nil), seed...)
	return crypto.CF2(etype, initialKey, hkey, []byte("SPAKE"), []byte("keyderiv"))
}

// EncodeSupport returns a PA-SPAKE support padata value.
func EncodeSupport(groups []int32) ([]byte, error) {
	return asn1.Marshal(protocol.PASPAKE{Support: &protocol.SPAKESupport{Groups: groups}})
}

// EncodeChallenge returns a PA-SPAKE challenge padata value.
func EncodeChallenge(group int32, pubkey []byte) ([]byte, error) {
	return asn1.Marshal(protocol.PASPAKE{Challenge: &protocol.SPAKEChallenge{
		Group: group, PubKey: pubkey,
		Factors: []protocol.SPAKESecondFactor{{Type: FactorNone}},
	}})
}

// EncodeResponse returns a PA-SPAKE response padata value.
func EncodeResponse(pubkey []byte, factor []byte, etype int32) ([]byte, error) {
	return asn1.Marshal(protocol.PASPAKE{Response: &protocol.SPAKEResponse{
		PubKey: pubkey,
		Factor: protocol.EncryptedData{EType: etype, Cipher: factor},
	}})
}

// EncodeFactor encodes SF-NONE.
func EncodeFactor() ([]byte, error) {
	return asn1.Marshal(protocol.SPAKESecondFactor{Type: FactorNone})
}

// Decode decodes and validates a PA-SPAKE value.
func Decode(data []byte) (protocol.PASPAKE, error) {
	var msg protocol.PASPAKE
	if err := asn1.Unmarshal(data, &msg); err != nil {
		return msg, err
	}
	return msg, nil
}
