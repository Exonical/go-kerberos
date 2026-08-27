package ccache

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

// These bytes follow the MIT FILE ccache v4 format:
// https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
func counted32(w io.Writer, value []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(value))); err != nil {
		return err
	}
	_, err := w.Write(value)
	return err
}

func writePrincipal(w io.Writer, p principal.Principal) error {
	if err := binary.Write(w, binary.BigEndian, uint32(p.NameType)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(p.Components))); err != nil {
		return err
	}
	if err := counted32(w, []byte(p.Realm)); err != nil {
		return err
	}
	for _, component := range p.Components {
		if err := counted32(w, []byte(component)); err != nil {
			return err
		}
	}
	return nil
}

func writeCredential(w io.Writer, client, server principal.Principal, flags uint32, ticket, second []byte) error {
	if err := writePrincipal(w, client); err != nil {
		return err
	}
	if err := writePrincipal(w, server); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint16(17)); err != nil {
		return err
	}
	if err := counted32(w, []byte{1, 2, 3, 4}); err != nil {
		return err
	}
	for _, timestamp := range []uint32{10, 20, 30, 40} {
		if err := binary.Write(w, binary.BigEndian, timestamp); err != nil {
			return err
		}
	}
	if err := binary.Write(w, binary.BigEndian, uint8(0)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, flags); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(1)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint16(2)); err != nil {
		return err
	}
	if err := counted32(w, []byte{127, 0, 0, 1}); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(1)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint16(1)); err != nil {
		return err
	}
	if err := counted32(w, []byte("ad-if-relevant")); err != nil {
		return err
	}
	if err := counted32(w, ticket); err != nil {
		return err
	}
	return counted32(w, second)
}

func writeConfigCredential(w io.Writer, client, server principal.Principal, ticket []byte) error {
	if err := writePrincipal(w, client); err != nil {
		return err
	}
	if err := writePrincipal(w, server); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint16(0)); err != nil {
		return err
	}
	if err := counted32(w, nil); err != nil {
		return err
	}
	for range 4 {
		if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
			return err
		}
	}
	if err := binary.Write(w, binary.BigEndian, uint8(0)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
		return err
	}
	if err := counted32(w, ticket); err != nil {
		return err
	}
	return counted32(w, nil)
}

func syntheticCCache() ([]byte, error) {
	defaultPrincipal := principal.Principal{
		Realm:      "REALM",
		NameType:   principal.NTPrincipal,
		Components: []string{"alice"},
	}
	tgt := principal.Principal{
		Realm:      "REALM",
		NameType:   principal.NTPrincipal,
		Components: []string{"krbtgt", "REALM"},
	}
	configServer := principal.Principal{
		Realm:      "X-CACHECONF:",
		NameType:   principal.NTPrincipal,
		Components: []string{"krb5_ccache_conf_data", "fast_avail"},
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.BigEndian, Version); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, uint16(12)); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, uint16(1)); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, uint16(8)); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(3600)); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(123456)); err != nil {
		return nil, err
	}
	if err := writePrincipal(&b, defaultPrincipal); err != nil {
		return nil, err
	}
	if err := writeCredential(&b, defaultPrincipal, tgt, 0x40000000, []byte{0xaa, 0xbb}, nil); err != nil {
		return nil, err
	}
	if err := writeConfigCredential(&b, defaultPrincipal, configServer, []byte("yes")); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func TestReadCCacheV4(t *testing.T) {
	data, err := syntheticCCache()
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	cache, err := Read(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cache.Header.TimeOffset != 3600 || cache.Header.Usec != 123456 {
		t.Fatalf("header = %#v", cache.Header)
	}
	if cache.DefaultPrincipal.Realm != "REALM" ||
		cache.DefaultPrincipal.NameType != principal.NTPrincipal ||
		len(cache.DefaultPrincipal.Components) != 1 ||
		cache.DefaultPrincipal.Components[0] != "alice" {
		t.Fatalf("default principal = %#v", cache.DefaultPrincipal)
	}
	if len(cache.Credentials) != 2 {
		t.Fatalf("credentials = %d, want 2", len(cache.Credentials))
	}
	credential := cache.Credentials[0]
	if credential.Server.Components[0] != "krbtgt" ||
		credential.TicketFlags != 0x40000000 ||
		credential.AuthTime != 10 || credential.StartTime != 20 ||
		credential.EndTime != 30 || credential.RenewTill != 40 ||
		len(credential.Addresses) != 1 || credential.Addresses[0].Type != 2 ||
		!bytes.Equal(credential.Addresses[0].Data, []byte{127, 0, 0, 1}) ||
		!bytes.Equal(credential.Ticket, []byte{0xaa, 0xbb}) {
		t.Fatalf("credential = %#v", credential)
	}
	config := cache.Credentials[1]
	if config.Server.Realm != "X-CACHECONF:" ||
		len(config.Server.Components) != 2 ||
		config.Server.Components[0] != "krb5_ccache_conf_data" ||
		config.Server.Components[1] != "fast_avail" ||
		!bytes.Equal(config.Ticket, []byte("yes")) {
		t.Fatalf("config credential = %#v", config)
	}
}

func TestWriteCCacheWithCredentials(t *testing.T) {
	p := principal.Principal{Realm: "REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	cache := &Cache{
		Header:           Header{TimeOffset: 3600, Usec: 123456},
		DefaultPrincipal: p,
		Credentials: []Credential{
			{Client: p, Server: p, TicketFlags: 1, Addresses: []Address{{Type: 2, Data: []byte("addr")}}, AuthData: []AuthData{{Type: 1, Data: []byte("ad")}}, Ticket: []byte{1, 2}},
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
	for _, input := range [][]byte{
		{},
		{0x05, 0x04},
		{0x05, 0x04, 0, 12, 0, 1, 0, 8, 0, 0, 0, 0},
	} {
		if _, err := Read(bytes.NewReader(input)); err == nil {
			t.Fatalf("malformed ccache %x unexpectedly accepted", input)
		}
	}
}
