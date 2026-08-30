package otp

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestChallengeAndRequestRoundTrip(t *testing.T) {
	length, format := int32(6), FormatHexadecimal
	challenge := Challenge{
		Nonce: []byte{1, 2, 3, 4, 5, 6},
		TokenInfo: []TokenInfo{{
			Vendor: func() *types.UTF8String { value := types.UTF8String("vendor"); return &value }(),
			Length: &length, Format: &format,
			TokenID:        []byte("token"),
			AlgID:          func() *types.UTF8String { value := types.UTF8String("sha1"); return &value }(),
			IterationCount: &length,
		}},
	}
	encoded, err := EncodeChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeChallenge(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Nonce, challenge.Nonce) ||
		decoded.TokenInfo[0].Vendor == nil || string(*decoded.TokenInfo[0].Vendor) != "vendor" ||
		*decoded.TokenInfo[0].Length != length || *decoded.TokenInfo[0].Format != format {
		t.Fatalf("challenge mismatch: %#v", decoded)
	}
	request := Request{Flags: FlagNextOTP, OTPValue: []byte("123456"),
		EncData: protocol.EncryptedData{EType: crypto.EnctypeAES128SHA1, Cipher: encoded}}
	requestDER, err := EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(requestDER); err != nil {
		t.Fatal(err)
	}
}

func TestChallengeDERGolden(t *testing.T) {
	length, format := int32(6), FormatHexadecimal
	value := Challenge{
		Nonce: []byte{1, 2, 3, 4, 5, 6},
		TokenInfo: []TokenInfo{{
			Vendor: func() *types.UTF8String { value := types.UTF8String("vendor"); return &value }(),
			Length: &length, Format: &format,
			TokenID:        []byte("token"),
			AlgID:          func() *types.UTF8String { value := types.UTF8String("sha1"); return &value }(),
			IterationCount: &length,
		}},
	}
	encoded, err := EncodeChallenge(value)
	if err != nil {
		t.Fatal(err)
	}
	const want = "30318006010203040506a227302580050000000000810676656e646f728301068401018505746f6b656e860473686131880106"
	if got := hex.EncodeToString(encoded); got != want {
		t.Fatalf("challenge DER = %s, want %s", got, want)
	}
}

func TestRequestDERGolden(t *testing.T) {
	value := Request{
		Flags: 1, Nonce: []byte{9, 8},
		EncData: protocol.EncryptedData{
			EType: crypto.EnctypeAES128SHA1, Cipher: []byte{0xaa, 0xbb},
		},
		OTPValue: []byte("123456"),
		PIN:      func() *types.UTF8String { value := types.UTF8String("42"); return &value }(),
	}
	encoded, err := EncodeRequest(value)
	if err != nil {
		t.Fatal(err)
	}
	const want = "30248005008000000081020908a20ba003020111a2040402aabb850631323334353686023432"
	if got := hex.EncodeToString(encoded); got != want {
		t.Fatalf("request DER = %s, want %s", got, want)
	}
}

func TestDecodeRejectsMalformedDER(t *testing.T) {
	if _, err := DecodeChallenge([]byte{0x30, 0x03, 0xa0, 0x01, 0x00}); err == nil {
		t.Fatal("malformed challenge accepted")
	}
	if _, err := DecodeRequest([]byte{0x30, 0x03, 0xa0, 0x01, 0x00}); err == nil {
		t.Fatal("malformed request accepted")
	}
}

func TestNonceValidation(t *testing.T) {
	now := time.Unix(1700000000, 0)
	nonce, err := NewNonce(now, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNonce(nonce, 16, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := ValidateNonce(nonce[:len(nonce)-1], 16, now, time.Minute); err == nil {
		t.Fatal("short nonce accepted")
	}
}

func TestEncryptNonceUsesOTPUsage(t *testing.T) {
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x42}, etype.KeySize())
	enc, err := EncryptNonce(etype, key, []byte("nonce"))
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := DecryptNonce(etype, key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(nonce) != "nonce" {
		t.Fatalf("nonce = %q", nonce)
	}
}
