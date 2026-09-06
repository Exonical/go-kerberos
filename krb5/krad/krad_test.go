package krad

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestUserPasswordGolden(t *testing.T) {
	var auth [16]byte
	raw, err := hex.DecodeString("ac9dc16208c4c78ba12f250ac41d3641")
	if err != nil {
		t.Fatal(err)
	}
	copy(auth[:], raw)
	encoded := encodeUserPassword("foo", auth, []byte("accept"))
	want, _ := hex.DecodeString("bafced50e1eba6c3c17520e910cec2cb")
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded password = %x, want %x", encoded, want)
	}
	decoded, err := decodeUserPassword("foo", auth, encoded)
	if err != nil || string(decoded) != "accept" {
		t.Fatalf("decoded password = %q, %v", decoded, err)
	}
}

func TestPacketRoundTrip(t *testing.T) {
	attrs := NewAttributes()
	if err := attrs.AddString(UserName, "testUser"); err != nil {
		t.Fatal(err)
	}
	if err := attrs.Add(UserPassword, []byte("accept")); err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest(AccessRequest, attrs)
	if err != nil {
		t.Fatal(err)
	}
	request.ID = 7
	copy(request.Authenticator[:], []byte("0123456789abcdef"))
	wire, err := request.Bytes("foo")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRequest(wire, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(decoded.Attributes.Get(UserName, 0)); got != "testUser" {
		t.Fatalf("username = %q", got)
	}
	if got := string(decoded.Attributes.Get(UserPassword, 0)); got != "accept" {
		t.Fatalf("password = %q", got)
	}
}

func TestResponseAuthenticationUsesFinalMessageAuthenticator(t *testing.T) {
	request, err := NewRequest(AccessRequest, NewAttributes())
	if err != nil {
		t.Fatal(err)
	}
	request.ID = 7
	copy(request.Authenticator[:], []byte("0123456789abcdef"))
	response, err := NewResponse(AccessAccept, request, NewAttributes())
	if err != nil {
		t.Fatal(err)
	}
	wire, err := response.Bytes("secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(wire, request, "secret"); err != nil {
		t.Fatalf("strict response validation failed: %v", err)
	}

	mutated := append([]byte(nil), wire...)
	position := messageAuthenticatorPosition(mutated)
	if position < 0 {
		t.Fatal("response has no Message-Authenticator")
	}
	for i := 0; i < 16; i++ {
		mutated[position+2+i] = 0
	}
	auth := responseAuthenticator(mutated, "secret", request.Authenticator)
	copy(mutated[4:20], auth[:])
	if _, err := DecodeResponse(mutated, request, "secret"); err == nil {
		t.Fatal("accepted response authenticated over zeroed Message-Authenticator")
	}
}

func TestResponseWithoutMessageAuthenticatorIsAccepted(t *testing.T) {
	request, err := NewRequest(AccessRequest, NewAttributes())
	if err != nil {
		t.Fatal(err)
	}
	request.ID = 7
	copy(request.Authenticator[:], []byte("0123456789abcdef"))
	response, err := NewResponse(AccessAccept, request, NewAttributes())
	if err != nil {
		t.Fatal(err)
	}
	wire, err := response.Bytes("secret")
	if err != nil {
		t.Fatal(err)
	}
	position := messageAuthenticatorPosition(wire)
	if position < 0 {
		t.Fatal("response has no Message-Authenticator")
	}
	withoutMAC := append([]byte(nil), wire[:position]...)
	withoutMAC = append(withoutMAC, wire[position+18:]...)
	binary.BigEndian.PutUint16(withoutMAC[2:4], uint16(len(withoutMAC)))
	auth := responseAuthenticator(withoutMAC, "secret", request.Authenticator)
	copy(withoutMAC[4:20], auth[:])
	if _, err := DecodeResponse(withoutMAC, request, "secret"); err != nil {
		t.Fatalf("response without Message-Authenticator rejected: %v", err)
	}
}

func TestBytesNeeded(t *testing.T) {
	if got := BytesNeeded(nil); got != 20 {
		t.Fatalf("short header = %d", got)
	}
	header := []byte{byte(AccessRequest), 1, 0, 20}
	if got := BytesNeeded(header); got != 16 {
		t.Fatalf("short header = %d", got)
	}
	if got := BytesNeeded(append(header, make([]byte, 16)...)); got != 0 {
		t.Fatalf("complete packet = %d", got)
	}
}
