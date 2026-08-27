package ccache

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// These bytes follow the MIT FILE ccache v4 format:
// https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
func syntheticCCache() []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, Version)
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	_ = binary.Write(&b, binary.BigEndian, uint32(0))
	return b.Bytes()
}

func TestReadCCacheV4(t *testing.T) {
	cache, err := Read(bytes.NewReader(syntheticCCache()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cache.DefaultPrincipal == "" {
		t.Fatal("default principal is empty")
	}
	if len(cache.Credentials) != 2 {
		t.Fatalf("credentials = %d, want 2", len(cache.Credentials))
	}
}

func TestWriteCCacheWithCredentials(t *testing.T) {
	cache := &Cache{
		Header:           Header{TimeOffset: 3600, Usec: 123456},
		DefaultPrincipal: "alice@REALM",
		Credentials: []Credential{
			{Client: "alice@REALM", Server: "krbtgt/REALM@REALM", TicketFlags: 1, Addresses: []string{"127.0.0.1"}, AuthData: []string{"ad-if-relevant"}, Ticket: []byte{1, 2}},
			{Client: "alice@REALM", Server: "X-CACHECONF:/krb5.conf", SecondTicket: []byte{3, 4}},
		},
	}
	var out bytes.Buffer
	if err := Write(&out, cache); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("Write produced empty cache")
	}
}

func TestCCacheMalformedInput(t *testing.T) {
	for _, input := range [][]byte{{}, {0x05, 0x04}, {0x05, 0x04, 0, 0, 0, 0, 0xff}} {
		if _, err := Read(bytes.NewReader(input)); err == nil {
			t.Fatalf("malformed ccache %x unexpectedly accepted", input)
		}
	}
}
