package kkdcp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/asn1"
)

func TestEncodeDecodeGolden(t *testing.T) {
	encoded, err := Encode([]byte{0x6a, 0x02, 0x01, 0x00}, "TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("301aa00a0408000000046a020100a10c1b0a544553542e5245414c4d")
	if !bytes.Equal(encoded, want) {
		t.Fatalf("KKDCP encoding = %x, want %x", encoded, want)
	}
	message, realm, err := Decode(encoded, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, []byte{0x6a, 0x02, 0x01, 0x00}) || realm != "TEST.REALM" {
		t.Fatalf("decoded message = %x, realm %q", message, realm)
	}
}

func TestDecodeRejectsMalformedWrapper(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x30, 0x03, 0xa0, 0x01, 0x04},
	}
	for _, data := range cases {
		if _, _, err := Decode(data, 1024); err == nil {
			t.Fatalf("malformed wrapper %x accepted", data)
		}
	}
	valid, err := Encode([]byte{1}, "")
	if err != nil {
		t.Fatal(err)
	}
	var value Message
	if err := asn1.Unmarshal(valid, &value); err != nil {
		t.Fatal(err)
	}
	value.KerbMessage[3] = 2
	mutated, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(mutated, 1024); err == nil {
		t.Fatal("length mismatch accepted")
	}
}

func TestOptionalFieldsRoundTrip(t *testing.T) {
	target := "TEST.REALM"
	hint := int32(7)
	value := Message{
		KerbMessage:   []byte{0, 0, 0, 1, 0x6a},
		TargetDomain:  &target,
		DCLocatorHint: &hint,
	}
	encoded, err := EncodeMessage(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.TargetDomain == nil || *decoded.TargetDomain != target ||
		decoded.DCLocatorHint == nil || *decoded.DCLocatorHint != hint {
		t.Fatalf("optional fields not preserved: %+v", decoded)
	}
}

func TestHandlerAndClient(t *testing.T) {
	server := httptest.NewTLSServer(&Handler{
		Backend: func(_ context.Context, message []byte) ([]byte, error) {
			return append([]byte("reply:"), message...), nil
		},
		RequireTargetURL: "/KdcProxy",
	})
	defer server.Close()
	client := &Client{HTTPClient: server.Client()}
	result, err := client.Exchange(context.Background(), server.URL+"/KdcProxy", "TEST.REALM", []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, []byte("reply:request")) {
		t.Fatalf("proxy result = %q", result)
	}
}

func TestClientRootCAs(t *testing.T) {
	server := httptest.NewTLSServer(&Handler{
		Backend: func(_ context.Context, message []byte) ([]byte, error) {
			return message, nil
		},
	})
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	result, err := (&Client{RootCAs: roots}).Exchange(
		context.Background(), server.URL, "", []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, []byte("request")) {
		t.Fatalf("proxy result = %q", result)
	}
}

func TestHandlerRejectsContentTypeAndMethod(t *testing.T) {
	handler := &Handler{Backend: func(context.Context, []byte) ([]byte, error) {
		return []byte("ok"), nil
	}}
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/", nil))
	if get.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d", get.Code)
	}
	post := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte{1, 2, 3}))
	request.Header.Set("Content-Type", "text/plain")
	handler.ServeHTTP(post, request)
	if post.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status = %d", post.Code)
	}
}
