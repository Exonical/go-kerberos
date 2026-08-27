package keytab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

// These bytes follow the MIT FILE keytab v2 format:
// https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html
func syntheticKeytab() []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, Version)
	record := bytes.NewBuffer(nil)
	_ = binary.Write(record, binary.BigEndian, uint32(1))
	_ = binary.Write(record, binary.BigEndian, uint32(1))
	_, _ = record.WriteString("alice")
	_ = binary.Write(record, binary.BigEndian, uint32(0))
	_, _ = record.WriteString("REALM")
	_ = binary.Write(record, binary.BigEndian, uint32(100))
	_ = binary.Write(record, binary.BigEndian, uint32(17))
	_ = binary.Write(record, binary.BigEndian, uint16(4))
	_, _ = record.Write([]byte{1, 2, 3, 4})
	_ = binary.Write(record, binary.BigEndian, uint32(7))
	_ = binary.Write(&b, binary.BigEndian, int32(record.Len()))
	_, _ = b.Write(record.Bytes())
	return b.Bytes()
}

func TestReadKeytabV2(t *testing.T) {
	kt, err := Read(bytes.NewReader(syntheticKeytab()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(kt.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(kt.Entries))
	}
	entry := kt.Entries[0]
	if entry.Principal != "alice@REALM" || entry.KVNO != 7 || entry.Enctype != 17 || entry.Timestamp != 100 {
		t.Fatalf("entry metadata = %#v", entry)
	}
}

func TestWriteKeytabAndLookups(t *testing.T) {
	kt := &Keytab{Entries: []Entry{
		{Principal: "alice@REALM", Timestamp: 100, KVNO: 7, Enctype: 17, Key: []byte{1, 2, 3, 4}},
		{Principal: "alice@REALM", Timestamp: 101, KVNO: 8, Enctype: 18, Key: []byte{5, 6, 7, 8}},
	}}
	var out bytes.Buffer
	if err := Write(&out, kt); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for _, lookup := range []func() ([]Entry, error){
		func() ([]Entry, error) { return kt.LookupPrincipal("alice@REALM") },
		func() ([]Entry, error) { return kt.LookupEnctype(18) },
		func() ([]Entry, error) { return kt.LookupKVNO(8) },
	} {
		entries, err := lookup()
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if len(entries) == 0 {
			t.Fatal("lookup returned no entries")
		}
	}
}

func TestKeytabMalformedRecords(t *testing.T) {
	tests := [][]byte{
		{0x05, 0x02, 0, 0, 0, 4, 0, 0},
		{0x05, 0x02, 0xff, 0xff, 0xff, 0xff},
		append([]byte{0x05, 0x02, 0, 0, 0, 20}, syntheticKeytab()[6:]...),
	}
	for _, input := range tests {
		if _, err := Read(bytes.NewReader(input)); err == nil {
			t.Fatalf("malformed keytab %x unexpectedly accepted", input)
		}
	}
}

func TestKeytabStubErrorIsClassifiable(t *testing.T) {
	if _, err := Read(bytes.NewReader(nil)); !errors.Is(err, krberrors.ErrNotImplemented) {
		t.Fatalf("Read error = %v, want wrapped ErrNotImplemented", err)
	}
}
