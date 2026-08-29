// Package otp implements RFC 6560 preauthentication payloads.
package otp

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const (
	PADataChallenge int32 = 141
	PADataRequest   int32 = 142

	KeyUsageRequest uint32 = 45

	FlagNextOTP int32 = 1

	FormatHexadecimal  int32 = 1
	FormatAlphanumeric int32 = 2
	FormatBinary       int32 = 3
	FormatBase64       int32 = 4
)

type TokenInfo = protocol.OTPTokenInfo
type Challenge = protocol.PAOTPChallenge
type Request = protocol.PAOTPRequest
type EncRequest = protocol.PAOTPEncRequest

func EncodeChallenge(value Challenge) ([]byte, error) { return asn1.Marshal(value) }
func DecodeChallenge(data []byte) (Challenge, error) {
	var value Challenge
	if err := asn1.Unmarshal(data, &value); err != nil {
		return value, err
	}
	return value, nil
}
func EncodeRequest(value Request) ([]byte, error) { return asn1.Marshal(value) }
func DecodeRequest(data []byte) (Request, error) {
	var value Request
	if err := asn1.Unmarshal(data, &value); err != nil {
		return value, err
	}
	return value, nil
}
func EncodeEncRequest(value EncRequest) ([]byte, error) { return asn1.Marshal(value) }
func DecodeEncRequest(data []byte) (EncRequest, error) {
	var value EncRequest
	if err := asn1.Unmarshal(data, &value); err != nil {
		return value, err
	}
	return value, nil
}

// NewNonce returns MIT's timestamp-prefixed nonce. The random suffix is the
// FAST armor key length, matching otp_state's nonce verification.
func NewNonce(now time.Time, armorKeyLength int) ([]byte, error) {
	if armorKeyLength < 0 {
		return nil, fmt.Errorf("OTP nonce: negative key length")
	}
	value := make([]byte, 4+armorKeyLength)
	binary.BigEndian.PutUint32(value, uint32(now.Unix()))
	if _, err := io.ReadFull(crypto.RandomSource, value[4:]); err != nil {
		return nil, err
	}
	return value, nil
}

func ValidateNonce(nonce []byte, armorKeyLength int, now time.Time, skew time.Duration) error {
	if len(nonce) != 4+armorKeyLength {
		return fmt.Errorf("OTP nonce length mismatch")
	}
	seconds := int64(binary.BigEndian.Uint32(nonce))
	ts := time.Unix(seconds, 0)
	if skew < 0 {
		skew = -skew
	}
	if skew == 0 {
		skew = 5 * time.Minute
	}
	if ts.Before(now.Add(-skew)) || ts.After(now.Add(skew)) {
		return fmt.Errorf("OTP nonce clock skew")
	}
	return nil
}

// EncryptNonce wraps the challenge nonce in PA-OTP-ENC-REQUEST and encrypts
// it directly with the FAST armor key, as MIT does (usage 45).
func EncryptNonce(etype crypto.EType, armorKey, nonce []byte) (protocol.EncryptedData, error) {
	if etype == nil || len(armorKey) == 0 {
		return protocol.EncryptedData{}, fmt.Errorf("OTP: incomplete armor key")
	}
	plain, err := EncodeEncRequest(EncRequest{Nonce: nonce})
	if err != nil {
		return protocol.EncryptedData{}, err
	}
	cipher, err := etype.Encrypt(armorKey, KeyUsageRequest, plain)
	if err != nil {
		return protocol.EncryptedData{}, err
	}
	return protocol.EncryptedData{EType: etype.ID(), Cipher: cipher}, nil
}

func DecryptNonce(etype crypto.EType, armorKey []byte, enc protocol.EncryptedData) ([]byte, error) {
	if etype == nil || enc.EType != etype.ID() {
		return nil, fmt.Errorf("OTP: enctype mismatch")
	}
	plain, err := etype.Decrypt(armorKey, KeyUsageRequest, enc.Cipher)
	if err != nil {
		return nil, err
	}
	value, err := DecodeEncRequest(plain)
	if err != nil {
		return nil, err
	}
	return value.Nonce, nil
}
