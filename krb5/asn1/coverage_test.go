package asn1

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/types"
)

type implicitCoverageValue struct {
	Number int32            `krb5:"tag:0,implicit"`
	Text   types.UTF8String `krb5:"tag:1,implicit"`
}

type applicationCoverageValue struct {
	Value int32 `krb5:"tag:0,implicit"`
}

func (applicationCoverageValue) ApplicationTag() int { return 3 }

func TestDERContextAndFieldHelpers(t *testing.T) {
	inner := encodeTLV(0x02, []byte{0x2a})
	wrapped, err := WrapContext(2, inner)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := UnwrapContext(wrapped, 2); err != nil || !bytes.Equal(got, inner) {
		t.Fatalf("unwrap = %x/%v", got, err)
	}
	if _, err := WrapContext(-1, inner); err == nil {
		t.Fatal("negative context tag accepted")
	}
	if _, err := WrapContext(31, inner); err == nil {
		t.Fatal("high context tag accepted")
	}
	if _, err := WrapContext(0, nil); err == nil {
		t.Fatal("empty context value accepted")
	}
	if _, err := UnwrapContext(wrapped, 1); err == nil {
		t.Fatal("wrong context tag accepted")
	}
	sequence := encodeTLV(tagSequence, append(encodeTLV(0xa0, inner), encodeTLV(0xa1, []byte("x"))...))
	if got, err := Field(sequence, 1); err != nil || !bytes.Equal(got, encodeTLV(0xa1, []byte("x"))) {
		t.Fatalf("field = %x/%v", got, err)
	}
	if got, err := FieldContent(sequence, 1); err != nil || string(got) != "x" {
		t.Fatalf("field content = %x/%v", got, err)
	}
	if _, err := Field(sequence); err == nil {
		t.Fatal("empty field path accepted")
	}
	if _, err := Field(sequence, 31); err == nil {
		t.Fatal("out-of-range field path accepted")
	}
}

func TestDERIntegerLengthAndImplicitSemantics(t *testing.T) {
	for _, value := range []int64{0, 127, 128, -1, -128, -129, 1 << 40} {
		encoded := encodeInteger(value)
		got, err := decodeInteger(encoded)
		if err != nil || got != value {
			t.Fatalf("integer %d = %x -> %d/%v", value, encoded, got, err)
		}
	}
	for _, value := range []uint64{0, 127, 128, 1 << 31} {
		encoded := encodeUnsignedInteger(value)
		got, err := decodeUnsignedInteger(encoded)
		if err != nil || got != value {
			t.Fatalf("unsigned %d = %x -> %d/%v", value, encoded, got, err)
		}
	}
	for _, bad := range [][]byte{{}, {0, 0}, {0xff, 0x80}} {
		if _, err := decodeInteger(bad); err == nil {
			t.Fatalf("noncanonical integer %x accepted", bad)
		}
	}
	for _, bad := range [][]byte{{}, {0, 0}, {0x80}, {1, 0, 0, 0, 0, 0}} {
		if _, err := decodeUnsignedInteger(bad); err == nil {
			t.Fatalf("invalid unsigned integer %x accepted", bad)
		}
	}
	for _, length := range []int{0, 127, 128, 255, 65535} {
		encoded := encodeLength(length)
		got, _, err := readLength(encoded)
		if err != nil || got != length {
			t.Fatalf("length %d = %x -> %d/%v", length, encoded, got, err)
		}
	}
	for _, bad := range [][]byte{{}, {0x80}, {0x81}, {0x81, 0x7f}, {0x85, 1, 2, 3, 4, 5}} {
		if _, _, err := readLength(bad); err == nil {
			t.Fatalf("invalid DER length %x accepted", bad)
		}
	}
	value := implicitCoverageValue{Number: 42, Text: types.UTF8String("hello")}
	encoded, err := Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded implicitCoverageValue
	if err := Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, value) {
		t.Fatalf("implicit round trip = %#v, want %#v", decoded, value)
	}
	app, err := Marshal(applicationCoverageValue{Value: 9})
	if err != nil || len(app) == 0 || app[0] != 0x63 {
		t.Fatalf("application encoding = %x/%v", app, err)
	}
}

func TestDERValidationAndTags(t *testing.T) {
	if _, err := Marshal(nil); err == nil {
		t.Fatal("nil value marshaled")
	}
	if err := Unmarshal(nil, nil); err == nil {
		t.Fatal("nil destination accepted")
	}
	if err := Unmarshal([]byte{2, 1, 1}, 1); err == nil {
		t.Fatal("non-pointer destination accepted")
	}
	if _, _, _, err := readTLV([]byte{0x02, 0x02, 1}); err == nil {
		t.Fatal("truncated TLV accepted")
	}
	if _, err := Field(encodeTLV(tagSequence, []byte{0xa0, 1, 1}), 1); err == nil {
		t.Fatal("malformed child accepted")
	}
	if _, _, err := parseFieldTag(reflect.StructField{Tag: `krb5:"tag:31"`}); err == nil {
		t.Fatal("out-of-range struct tag accepted")
	}
	if _, _, err := parseFieldTag(reflect.StructField{Tag: `krb5:"unknown"`}); err == nil {
		t.Fatal("unknown struct option accepted")
	}
	if _, _, err := parseFieldTag(reflect.StructField{Tag: `krb5:"tag:x"`}); err == nil {
		t.Fatal("invalid struct tag accepted")
	}
}
