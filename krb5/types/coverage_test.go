package types

import "testing"

func TestKerberosTimeAndFlagsEdgeCases(t *testing.T) {
	if got, err := ParseKerberosTime(""); err != nil || got.Present {
		t.Fatalf("empty time = %#v/%v", got, err)
	}
	for _, value := range []string{"20260101", "20260101120000", "2026x101120000Z", "20261301120000Z"} {
		if _, err := ParseKerberosTime(value); err == nil {
			t.Fatalf("invalid time %q accepted", value)
		}
	}
	value, err := ParseKerberosTime("20260102123456Z")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := value.EncodeGeneralizedTime(); err != nil || got != "20260102123456Z" {
		t.Fatalf("time encoding = %q/%v", got, err)
	}
	if got, err := (KerberosTime{}).EncodeGeneralizedTime(); err != nil || got != "" {
		t.Fatalf("absent time = %q/%v", got, err)
	}
	for _, flags := range []uint32{0, 1, 1 << 31, ^uint32(0)} {
		encoded, err := EncodeFlags(flags)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeFlags(encoded)
		if err != nil || got != flags {
			t.Fatalf("flags %08x = %x -> %08x/%v", flags, encoded, got, err)
		}
	}
	for _, bad := range [][]byte{nil, {0x03}, {0x03, 0x04, 0, 0, 0, 0}, {0x03, 0x05, 1, 0, 0, 0, 0}} {
		if _, err := DecodeFlags(bad); err == nil {
			t.Fatalf("invalid flags %x accepted", bad)
		}
	}
}
