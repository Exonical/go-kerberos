package krad

import (
	"bytes"
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
